<?php
class GarenaAuth
{
    private string $skinJson;
    private array $skinData;
    private string $skinCatalogPath;
    private array $skinCatalog;
    private array $heroDefaults;
    private array $skinLookup;
    private string $cookiePath;
    private string $datadomeSessionStorePath;
    private ?array $proxyConfig;

    /** Thời gian tái dùng cookie Datadome (giây); tránh replay body /js/ cho mọi request. */
    private const DATADOME_SESSION_CACHE_TTL = 2700;

    /** Tối đa N lần dùng lại một cookie trong TTL (chống lạm dụng một phiên đến giới hạn). */
    private const DATADOME_SESSION_MAX_USES = 40;

    /** Khoảng cách tối thiểu (giây) giữa hai lần gọi check acc tới SSO — giảm error_too_many_requests. */
    private const SSO_PACE_MIN_SECONDS = 5;

    public ?array $lastOauthRawResponse = null;
    public ?string $connectLoginId = null;
    public ?array $lastConnectRawResponse = null;
    private const DEFAULT_ROTATING_PROXY = '';

    public function __construct()
    {
        $this->proxyConfig = null;
        $this->cookiePath = __DIR__ . '/cookie';
        $this->datadomeSessionStorePath = __DIR__ . '/cookie/datadome_session.store.json';
        $this->skinCatalogPath = __DIR__ . '/all-heroes-skins.json';

        // Kiểm tra file skin.json tồn tại
        $skinFile = __DIR__ . '/skin.json';
        if (!file_exists($skinFile)) {
            // Tạo file skin.json mặc định nếu không tồn tại
            $defaultSkin = ['heroes' => []];
            file_put_contents($skinFile, json_encode($defaultSkin, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            $this->skinJson = json_encode($defaultSkin);
            $this->skinData = $defaultSkin;
        }
        else {
            $this->skinJson = file_get_contents($skinFile);
            $this->skinData = json_decode($this->skinJson, true);

            // Kiểm tra JSON hợp lệ
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->skinData = ['heroes' => []];
            }
        }

        if (!is_dir($this->cookiePath)) {
            mkdir($this->cookiePath, 0755, true);
        }

        $cached = $this->tryLoadBuiltSkinMaps();
        if ($cached !== null) {
            $this->skinCatalog = [];
            $this->heroDefaults = $cached['heroDefaults'];
            $this->skinLookup = $cached['skinLookup'];
        } else {
            $this->skinCatalog = $this->loadSkinCatalog();
            $this->heroDefaults = $this->buildHeroDefaults($this->skinCatalog);
            $this->skinLookup = $this->buildSkinLookup($this->skinCatalog);
            $this->writeBuiltSkinMapsCache($this->heroDefaults, $this->skinLookup);
            $this->skinCatalog = [];
        }
    }

    private function proxyIsIpv4(string $segment): bool
    {
        return filter_var($segment, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /** Tên máy chủ proxy (FQDN đơn giản, không chứa dấu :). */
    private function proxyIsLikelyHostname(string $segment): bool
    {
        $segment = trim($segment);
        if ($segment === '' || strlen($segment) > 253) {
            return false;
        }

        if (stripos($segment, 'localhost') === 0) {
            return true;
        }

        return (bool)preg_match(
            '/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/',
            $segment,
        );
    }

    /** Cổng 1–65535 (chuỗi toàn chữ số). */
    private function proxyPortSegmentNumeric(string $segment): bool
    {
        if ($segment === '' || !ctype_digit($segment)) {
            return false;
        }

        $p = (int)$segment;

        return $p >= 1 && $p <= 65535;
    }

    /**
     * Chỉ dùng khi explode(":") không cắt nhầm IPv4 (host là FQDN/localhost trong 4 cụm).
     *
     * @param array<int, string> $parts
     *
     * @return array{address: string, auth: string}|null
     */
    private function parseColonProxyFourParts(array $parts): ?array
    {
        if (count($parts) !== 4) {
            return null;
        }

        [$w, $x, $y, $z] = $parts;

        if (!$this->proxyPortSegmentNumeric($z) || $this->proxyIsIpv4($y)) {
            return null;
        }

        if (strtolower($y) === 'localhost' || $this->proxyIsLikelyHostname($y)) {
            return [
                'address' => $y . ':' . $z,
                'auth' => $w . ':' . $x,
            ];
        }

        // host một nhãn (gateway) — chỉ nhận khi không trùng dạng số/port
        if ($y !== '' && !str_contains($y, '.')) {
            return [
                'address' => $y . ':' . $z,
                'auth' => $w . ':' . $x,
            ];
        }

        return null;
    }

    public function configureProxy(?string $proxy, bool $enabled): void
    {
        if (!$enabled) {
            $this->proxyConfig = null;
            return;
        }

        $proxyValue = trim((string)$proxy);

        // Nếu để trống proxy nhưng vẫn bật dùng proxy, sử dụng proxy xoay mặc định
        if ($proxyValue === '') {
            $proxyValue = self::DEFAULT_ROTATING_PROXY;
        }

        // Trường hợp 1: Proxy dạng URL (http://user:pass@host:port)
        if (preg_match('/^https?:\/\//i', $proxyValue)) {
            $parsed = parse_url($proxyValue);
            $host = $parsed['host'] ?? '';
            $port = $parsed['port'] ?? 80;
            $user = $parsed['user'] ?? '';
            $pass = $parsed['pass'] ?? '';

            $config = [
                'address' => $host . ':' . $port,
            ];
            if ($user !== '' || $pass !== '') {
                $config['auth'] = $user . ':' . $pass;
            }
            $this->proxyConfig = $config;
            return;
        }

        // Trường hợp 2: Proxy dạng user:pass@host:port
        if (strpos($proxyValue, '@') !== false) {
            [$auth, $address] = explode('@', $proxyValue);
            $this->proxyConfig = [
                'address' => $address,
                'auth' => $auth
            ];
            return;
        }

        // IPv4:PORT:user:pass — phải trước explode vì không dùng : cắt IPv4 được
        if (preg_match(
            '/^(?<ip>\d{1,3}(?:\.\d{1,3}){3}):(?<port>\d{1,5}):(?<u>[^:]+):(?<p>[^:]+)$/',
            $proxyValue,
            $mm
        )) {
            $ipRaw = $mm['ip'];
            if (!$this->proxyIsIpv4($ipRaw)) {
                throw new InvalidArgumentException('Proxy ipv4:dport:user:pass — dia chi IP khong hop le.');
            }
            if (!$this->proxyPortSegmentNumeric($mm['port'])) {
                throw new InvalidArgumentException('Proxy ipv4:dport:user:pass — port khong hop le.');
            }

            $this->proxyConfig = [
                'address' => $ipRaw . ':' . $mm['port'],
                'auth' => $mm['u'] . ':' . $mm['p'],
            ];

            return;
        }

        // user:password:IPv4:PORT — đúng với ziokatz:minhhuy:171.x.x.x:63200
        if (preg_match(
            '/^(?<user>[^:]+?):(?<pwd>[^:]+?):(?<ip>\d{1,3}(?:\.\d{1,3}){3}):(?<port>\d{1,5})$/',
            $proxyValue,
            $mm
        )) {
            $ipSuffix = $mm['ip'];
            if (!$this->proxyIsIpv4($ipSuffix) || !$this->proxyPortSegmentNumeric($mm['port'])) {
                throw new InvalidArgumentException('Proxy user:pass:ipv4:port — ipv4/port khong hop le.');
            }

            $this->proxyConfig = [
                'address' => $ipSuffix . ':' . $mm['port'],
                'auth' => $mm['user'] . ':' . $mm['pwd'],
            ];

            return;
        }

        // ...host:63100 không chứa : trong HOST — ví dụ user:pwd:FQDN:rời cuối
        if (
            preg_match('/^(.+):(\d{1,5})$/', $proxyValue, $tm)
            && $this->proxyPortSegmentNumeric($tm[2])
        ) {
            $pre = $tm[1];
            // user:pwd:IPv4 rời + PORT (suffix IPv4 không có trong pre nếu pre đã chứa đủ 4 octet)
            if (
                preg_match(
                    '/^(?<user>[^:]+?):(?<pwd>[^:]+?):(?<ip>\d{1,3}(?:\.\d{1,3}){3})$/',
                    $pre,
                    $qm
                )
                && $this->proxyIsIpv4($qm['ip'])
            ) {
                $this->proxyConfig = [
                    'address' => $qm['ip'] . ':' . $tm[2],
                    'auth' => $qm['user'] . ':' . $qm['pwd'],
                ];

                return;
            }

            if (
                preg_match('/^(?<user>[^:]+?):(?<pwd>[^:]+?):(?<host>[^\s:]+)$/u', $pre, $qm)
                && (
                    $this->proxyIsLikelyHostname($qm['host'])
                    || strtolower($qm['host']) === 'localhost'
                )
            ) {
                $this->proxyConfig = [
                    'address' => $qm['host'] . ':' . $tm[2],
                    'auth' => $qm['user'] . ':' . $qm['pwd'],
                ];

                return;
            }
        }

        // Phần còn lại chỉ đáng explode khi KHÔNG có dotted IPv4 dạng xxx.xxx.xxx.xxx
        $parts = explode(':', $proxyValue);

        // session:IPv4|host:PORT
        if (count($parts) === 3 && $this->proxyPortSegmentNumeric($parts[2])) {
            $this->proxyConfig = [
                'address' => $parts[1] . ':' . $parts[2],
                'auth' => $parts[0] . ':',
            ];

            return;
        }

        if (strpos($proxyValue, '.') !== false && preg_match('/\d{1,3}(?:\.\d{1,3}){3}/', $proxyValue)) {
            throw new InvalidArgumentException(
                'Proxy chua IPv4: dùng user:password:IPv4:port, ipv4:port:user:pass hoặc https://user:pass@IPv4:port'
            );
        }

        // host:PORT + auth (hostname không chứa dấu chấm cho IPv4)
        $four = $this->parseColonProxyFourParts($parts);
        if ($four !== null) {
            $this->proxyConfig = $four;

            return;
        }

        $pc = count($parts);
        if ($pc === 2) {
            $this->proxyConfig = ['address' => $parts[0] . ':' . $parts[1]];

            return;
        }

        if ($pc === 4) {
            $this->proxyConfig = [
                'address' => $parts[0] . ':' . $parts[1],
                'auth' => $parts[2] . ':' . $parts[3],
            ];

            return;
        }

        throw new InvalidArgumentException(
            'Proxy khong hop le. VD: ziokatz:pass:171.x.x.x:63200 ; user:pass@host:63100 ; http://… ; session:host:port ; ipv4:port:user:pass'
        );
    }

    private function loadSkinCatalog(): array
    {
        if (!file_exists($this->skinCatalogPath)) {
            return [];
        }

        $parsed = json_decode(file_get_contents($this->skinCatalogPath), true);
        return is_array($parsed) ? $parsed : [];
    }

    private function skinCatalogCachePath(): string
    {
        return __DIR__ . '/all-heroes-skins.cache.php';
    }

    /** @return array{heroDefaults: array, skinLookup: array}|null */
    private function tryLoadBuiltSkinMaps(): ?array
    {
        $jsonPath = $this->skinCatalogPath;
        $cachePath = $this->skinCatalogCachePath();
        if (!is_file($jsonPath) || !is_readable($cachePath)) {
            return null;
        }

        $data = include $cachePath;
        if (!is_array($data)) {
            return null;
        }

        $mtime = filemtime($jsonPath);
        if ($mtime === false || (int) ($data['mtime'] ?? 0) !== (int) $mtime) {
            return null;
        }

        $heroDefaults = $data['heroDefaults'] ?? null;
        $skinLookup = $data['skinLookup'] ?? null;
        if (!is_array($heroDefaults) || !is_array($skinLookup)) {
            return null;
        }

        return ['heroDefaults' => $heroDefaults, 'skinLookup' => $skinLookup];
    }

    private function writeBuiltSkinMapsCache(array $heroDefaults, array $skinLookup): void
    {
        $jsonPath = $this->skinCatalogPath;
        if (!is_file($jsonPath)) {
            return;
        }

        $mtime = filemtime($jsonPath);
        if ($mtime === false) {
            $mtime = time();
        }

        $payload = [
            'mtime' => (int) $mtime,
            'heroDefaults' => $heroDefaults,
            'skinLookup' => $skinLookup,
        ];
        $export = var_export($payload, true);
        $php = "<?php\nreturn " . $export . ";\n";
        file_put_contents($this->skinCatalogCachePath(), $php, LOCK_EX);
    }

    private function buildHeroDefaults(array $catalog): array
    {
        $defaults = [];
        foreach ($catalog as $heroName => $skins) {
            if (!is_array($skins)) {
                continue;
            }

            $defaultSkin = null;
            foreach ($skins as $skin) {
                if (is_array($skin) && (($skin['type'] ?? null) === 'default' || ($skin['name'] ?? null) === 'Mặc định')) {
                    $defaultSkin = $skin;
                    break;
                }
            }

            $defaults[$heroName] = [
                'hero' => $heroName,
                'default_skin_id' => isset($defaultSkin['skin_id']) ? (string)$defaultSkin['skin_id'] : null,
                'default_img' => $defaultSkin['img'] ?? null,
                'default_avatar' => $defaultSkin['avatar'] ?? null,
            ];
        }

        return $defaults;
    }

    private function buildSkinLookup(array $catalog): array
    {
        $lookup = [];
        foreach ($catalog as $heroName => $skins) {
            if (!is_array($skins)) {
                continue;
            }

            foreach ($skins as $skin) {
                if (!is_array($skin) || !isset($skin['skin_id']) || $skin['skin_id'] === null || $skin['skin_id'] === '') {
                    continue;
                }

                $id = (string)$skin['skin_id'];
                $entry = [
                    'id' => $id,
                    'hero' => $heroName,
                    'name' => $skin['name'] ?? 'Khong ro',
                    'skin_name' => $skin['name'] ?? 'Khong ro',
                    'grade' => $skin['grade'] ?? null,
                    'type' => $skin['type'] ?? null,
                    'series' => $skin['series'] ?? null,
                    'img' => $skin['img'] ?? null,
                    'avatar' => $skin['avatar'] ?? null,
                    'label_text' => $skin['label_text'] ?? null,
                    'label_group' => $skin['label_group'] ?? null,
                    'is_default' => (($skin['type'] ?? null) === 'default' || ($skin['name'] ?? null) === 'Mặc định'),
                ];

                $lookup[$id] = $entry;

                if (!empty($skin['alias_ids']) && is_array($skin['alias_ids'])) {
                    foreach ($skin['alias_ids'] as $aliasId) {
                        $normalizedAliasId = (string)$aliasId;
                        if ($normalizedAliasId === '') {
                            continue;
                        }

                        $lookup[$normalizedAliasId] = array_merge($entry, [
                            'id' => $normalizedAliasId,
                            'canonical_skin_id' => $id,
                        ]);
                    }
                }
            }
        }

        return $lookup;
    }

    private function compareCollectionItems(array $left, array $right): int
    {
        $leftHero = (string)($left['hero'] ?? '');
        $rightHero = (string)($right['hero'] ?? '');
        if ($leftHero !== $rightHero) {
            return strnatcasecmp($leftHero, $rightHero);
        }

        return strnatcasecmp((string)($left['id'] ?? ''), (string)($right['id'] ?? ''));
    }

    private function isAnimeSkin(array $skin): bool
    {
        return ($skin['series'] ?? null) === 'Anime'
            || ($skin['label_text'] ?? null) === 'Anime'
            || ($skin['label_group'] ?? null) === 'Anime'
            || ($skin['type'] ?? null) === 'anime';
    }

    private function isCollabSkin(array $skin): bool
    {
        if ($this->isAnimeSkin($skin)) {
            return false;
        }

        return ($skin['type'] ?? null) === 'collab'
            || ($skin['label_text'] ?? null) === 'COLLAB'
            || ($skin['label_group'] ?? null) === 'COLLAB';
    }

    private function buildCollectionSummary(array $ownedItemIdList): array
    {
        $heroes = [];
        $skins = [];
        $ssSkins = [];
        $sssSkins = [];
        $normalSkins = [];
        $unknownItems = [];
        $gradeCounts = [];
        $typeCounts = [];
        $seriesCounts = [];
        $heroSkinCounts = [];
        $animeSkinCount = 0;
        $collabSkinCount = 0;

        foreach ($ownedItemIdList as $itemId) {
            $id = (string)$itemId;
            $item = $this->skinLookup[$id] ?? null;

            if (!$item) {
                $unknownItems[$id] = [
                    'id' => $id,
                    'hero' => null,
                    'name' => 'Khong tim thay du lieu skin',
                    'skin_name' => 'Khong tim thay du lieu skin',
                    'grade' => null,
                    'type' => null,
                    'series' => null,
                    'img' => null,
                    'avatar' => null,
                    'label_text' => null,
                    'label_group' => null,
                    'is_default' => false,
                ];
                continue;
            }

            $normalized = [
                'id' => $id,
                'hero' => $item['hero'],
                'name' => !empty($item['is_default']) ? $item['hero'] : $item['name'],
                'skin_name' => $item['skin_name'],
                'grade' => $item['grade'],
                'type' => $item['type'],
                'series' => $item['series'],
                'img' => $item['img'],
                'avatar' => $item['avatar'],
                'label_text' => $item['label_text'],
                'label_group' => $item['label_group'],
                'is_default' => $item['is_default'],
            ];

            if (!isset($heroes[$item['hero']])) {
                $heroDefault = $this->heroDefaults[$item['hero']] ?? [];
                $heroes[$item['hero']] = [
                    'hero' => $item['hero'],
                    'default_skin_id' => $heroDefault['default_skin_id'] ?? null,
                    'has_default_item' => false,
                    'default_img' => $heroDefault['default_img'] ?? null,
                    'default_avatar' => $heroDefault['default_avatar'] ?? null,
                    'owned_skin_count' => 0,
                ];
            }

            if (!empty($item['is_default'])) {
                $heroes[$item['hero']]['default_skin_id'] = $id;
                $heroes[$item['hero']]['has_default_item'] = true;
                $heroes[$item['hero']]['default_img'] = $item['img'];
                $heroes[$item['hero']]['default_avatar'] = $item['avatar'];
                continue;
            }

            $skins[$id] = $normalized;
            $heroSkinCounts[$normalized['hero']] = ($heroSkinCounts[$normalized['hero']] ?? 0) + 1;
            $heroes[$item['hero']]['owned_skin_count'] = $heroSkinCounts[$normalized['hero']];

            $gradeKey = $normalized['grade'] ?? 'ungraded';
            $gradeCounts[$gradeKey] = ($gradeCounts[$gradeKey] ?? 0) + 1;

            $typeKey = $normalized['type'] ?? 'untyped';
            $typeCounts[$typeKey] = ($typeCounts[$typeKey] ?? 0) + 1;

            if (!empty($normalized['series'])) {
                $seriesCounts[$normalized['series']] = ($seriesCounts[$normalized['series']] ?? 0) + 1;
            }

            if ($this->isAnimeSkin($normalized)) {
                $animeSkinCount++;
            }

            if ($this->isCollabSkin($normalized)) {
                $collabSkinCount++;
            }

            if (in_array($normalized['grade'], ['SSS', 'SSS+'], true)) {
                $sssSkins[$id] = $normalized;
            }
            elseif (in_array($normalized['grade'], ['SS', 'SS+'], true)) {
                $ssSkins[$id] = $normalized;
            }
            else {
                $normalSkins[$id] = $normalized;
            }
        }

        $heroItems = array_values(array_map(function ($item) use ($heroSkinCounts) {
            $item['owned_skin_count'] = $heroSkinCounts[$item['hero']] ?? 0;
            return $item;
        }, $heroes));
        usort($heroItems, fn($a, $b) => strnatcasecmp((string)($a['hero'] ?? ''), (string)($b['hero'] ?? '')));

        $skinItems = array_values($skins);
        usort($skinItems, fn($a, $b) => $this->compareCollectionItems($a, $b));

        $unknownItemList = array_values($unknownItems);
        usort($unknownItemList, fn($a, $b) => $this->compareCollectionItems($a, $b));

        return [
            'summary' => [
                'owned_item_count' => count($ownedItemIdList),
                'hero_count' => count($heroItems),
                'skin_count' => count($skinItems),
                'unknown_item_count' => count($unknownItemList),
                'tier_counts' => [
                    'sss' => count($sssSkins),
                    'ss' => count($ssSkins),
                    'normal' => count($normalSkins),
                ],
                'anime_skin_count' => $animeSkinCount,
                'collab_skin_count' => $collabSkinCount,
                'grade_counts' => $gradeCounts,
                'type_counts' => $typeCounts,
                'series_counts' => $seriesCounts,
            ],
            'heroes' => $heroItems,
            'skins' => $skinItems,
            'unknown_items' => $unknownItemList,
        ];
    }

    private function formatAccountInfo(array $userInfo): array
    {
        return [
            'uid' => $userInfo['uid'] ?? null,
            'username' => $userInfo['username'] ?? null,
            'nickname' => $userInfo['nickname'] ?? null,
            'region' => $userInfo['acc_country'] ?? null,
            'mobile_masked' => $userInfo['mobile_no'] ?? null,
            'country_code' => $userInfo['country_code'] ?? null,
            'avatar' => $userInfo['avatar'] ?? null,
            'email' => $userInfo['email'] ?? null,
            'security' => [
                'suspicious' => !empty($userInfo['suspicious']),
                'whitelistable' => !empty($userInfo['whitelistable']),
                'two_step_verify_enabled' => !empty($userInfo['two_step_verify_enable']),
                'authenticator_enabled' => !empty($userInfo['authenticator_enable']),
                'email_verified' => !empty($userInfo['email_v']),
                'mobile_binding_status' => $userInfo['mobile_binding_status'] ?? null,
                'password_status' => $userInfo['password_s'] ?? null,
            ],
        ];
    }

    private function toIsoTimestamp($value): ?string
    {
        $seconds = (int)$value;
        if ($seconds <= 0) {
            return null;
        }
        return gmdate('c', $seconds);
    }

    private function formatPlayerInfo(array $playerPayload): array
    {
        $player = isset($playerPayload['player']) && is_array($playerPayload['player']) ? $playerPayload['player'] : [];
        return [
            'name' => $player['name'] ?? null,
            'level' => $player['level'] ?? null,
            'register_time' => $player['registerTime'] ?? null,
            'register_time_iso' => $this->toIsoTimestamp($player['registerTime'] ?? null),
            'status' => $playerPayload['playerStatus'] ?? null,
            'ids' => [
                'gop_open_id' => $player['gopOpenId'] ?? null,
                'tencent_open_id' => $player['tencentOpenId'] ?? null,
            ],
        ];
    }

    private function formatWalletInfo(array $shopProfile): array
    {
        $cp = $shopProfile['cp'] ?? null;
        return [
            'quan_huy' => $cp,
            'cp' => $cp,
        ];
    }

    private function encodePassword(string $plaintext, string $key): string
    {
        $chiperRaw = openssl_encrypt(
            hex2bin($plaintext),
            "AES-256-ECB",
            hex2bin($key),
            OPENSSL_RAW_DATA
        );
        return substr(bin2hex($chiperRaw), 0, 32);
    }

    private function generateId(): int
    {
        return round(microtime(true) * 1000);
    }

    private function getCookieFilePath(string $account): string
    {
        // Làm sạch tên account để tránh lỗi đường dẫn
        $safeAccount = preg_replace('/[^a-zA-Z0-9]/', '_', $account);
        $cookieFile = $this->cookiePath . "/cookie_$safeAccount.txt";
        if (!file_exists($cookieFile)) {
            file_put_contents($cookieFile, "");
        }
        return $cookieFile;
    }

    private function loadDatadomePostFields(): string
    {
        $paramsFile = __DIR__ . '/datadome_params.json';
        if (!file_exists($paramsFile)) {
            return '';
        }

        $paramsJson = file_get_contents($paramsFile);
        $params = json_decode($paramsJson, true);
        if (!is_array($params)) {
            return '';
        }

        foreach (['Referer', 'request'] as $key) {
            if (!isset($params[$key]) || !is_string($params[$key])) {
                continue;
            }

            $decoded = urldecode($params[$key]);
            if ($decoded !== '') {
                $params[$key] = $decoded;
            }
        }

        return http_build_query($params);
    }

    /**
     * Header Origin/Referer khớp form POST (thường là trang SSO), tránh lệch với body datadome_params.
     */
    private function datadomeRequestHttpHeaders(): array
    {
        $defaultRef = 'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN';
        $ref = $defaultRef;

        $paramsFile = __DIR__ . '/datadome_params.json';
        if (is_readable($paramsFile)) {
            $params = json_decode((string)file_get_contents($paramsFile), true);
            if (is_array($params) && isset($params['Referer']) && is_string($params['Referer']) && $params['Referer'] !== '') {
                $decoded = urldecode($params['Referer']);
                $ref = $decoded !== '' ? $decoded : $params['Referer'];
            }
        }

        $parts = parse_url($ref);
        $scheme = $parts['scheme'] ?? 'https';
        $host = $parts['host'] ?? 'sso.garena.com';
        $origin = $scheme . '://' . $host;

        return [
            'accept: */*',
            'content-type: application/x-www-form-urlencoded',
            'origin: ' . $origin,
            'referer: ' . $ref,
        ];
    }

    private function truncateForDebug(string $text, int $max = 600): string
    {
        $clean = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', ' ', $text) ?? $text;
        if (function_exists('mb_substr')) {
            return mb_strlen($clean) > $max ? mb_substr($clean, 0, $max) . '…' : $clean;
        }

        return strlen($clean) > $max ? substr($clean, 0, $max) . '…' : $clean;
    }

    /**
     * POST datadome /js/ + meta debug (http code, curl lỗi, preview body).
     *
     * @return array{ok:bool, cookie:?string, decoded:?array, debug:array<string,mixed>}
     */
    private function fetchDatadomeJs(): array
    {
        $paramsFile = __DIR__ . '/datadome_params.json';
        $postFields = $this->loadDatadomePostFields();

        $debug = [
            'params_path' => $paramsFile,
            'params_exists' => file_exists($paramsFile),
            'params_readable' => is_readable($paramsFile),
            'post_body_bytes' => strlen($postFields),
            'post_body_empty' => $postFields === '',
            'using_proxy' => $this->proxyConfig !== null,
        ];

        if ($postFields === '') {
            $debug['hint'] = 'post_body_empty: kiểm tra datadome_params.json (JSON lỗi hoặc thiếu file).';

            return ['ok' => false, 'cookie' => null, 'decoded' => null, 'debug' => $debug];
        }

        $url = 'https://datadome.garena.com/js/';
        $headers = $this->datadomeRequestHttpHeaders();

        $curl = curl_init();
        if ($curl === false) {
            $debug['curl_setup'] = 'curl_init_failed';

            return ['ok' => false, 'cookie' => null, 'decoded' => null, 'debug' => $debug];
        }

        try {
            $defaultHeaders = [
                'Accept: application/json, text/plain, */*',
                'Accept-Language: vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5',
                'Cache-Control: no-cache',
                'Connection: keep-alive',
                'Pragma: no-cache',
                'Sec-Fetch-Dest: empty',
                'Sec-Fetch-Mode: cors',
                'Sec-Fetch-Site: same-site',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                'sec-ch-ua: "Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
                'sec-ch-ua-mobile: ?0',
                'sec-ch-ua-platform: "Windows"',
            ];

            $options = [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $postFields,
                CURLOPT_HTTPHEADER => array_merge($defaultHeaders, $headers),
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ];

            if ($this->proxyConfig) {
                $options[CURLOPT_PROXY] = $this->proxyConfig['address'];
                $options[CURLOPT_PROXYTYPE] = CURLPROXY_HTTP;
                if (!empty($this->proxyConfig['auth'])) {
                    $options[CURLOPT_PROXYUSERPWD] = $this->proxyConfig['auth'];
                }
            }

            curl_setopt_array($curl, $options);
            $response = curl_exec($curl);
            $curlErr = curl_error($curl);
            $httpCode = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            curl_close($curl);

            $debug['http_code'] = $httpCode;
            $debug['curl_error'] = $curlErr !== '' ? $curlErr : null;
            foreach ($headers as $h) {
                if (stripos($h, 'referer:') === 0) {
                    $debug['referer_sent'] = trim(substr($h, strlen('referer:')));
                }
                if (stripos($h, 'origin:') === 0) {
                    $debug['origin_sent'] = trim(substr($h, strlen('origin:')));
                }
            }

            if ($curlErr !== '') {
                $debug['body_preview'] = null;

                return ['ok' => false, 'cookie' => null, 'decoded' => null, 'debug' => $debug];
            }

            if (!is_string($response)) {
                $debug['body_preview'] = null;

                return ['ok' => false, 'cookie' => null, 'decoded' => null, 'debug' => $debug];
            }

            $debug['raw_body_bytes'] = strlen($response);
            $debug['body_preview'] = $this->truncateForDebug($response, 720);

            $decoded = json_decode($response, true);
            $debug['json_last_error'] = json_last_error();
            $debug['json_last_error_msg'] = json_last_error() === JSON_ERROR_NONE ? null : json_last_error_msg();
            if (!is_array($decoded)) {
                return ['ok' => false, 'cookie' => null, 'decoded' => null, 'debug' => $debug];
            }

            $debug['response_keys'] = array_keys($decoded);
            $apiStatus = isset($decoded['status']) ? (int)$decoded['status'] : null;
            $debug['api_status'] = $apiStatus;
            $debug['cookie_field_present'] = isset($decoded['cookie']) && is_string($decoded['cookie']) && $decoded['cookie'] !== '';

            $ok = $apiStatus === 200 && $debug['cookie_field_present'];

            if (!$ok) {
                $debug['api_message_hint'] = $decoded['status'] ?? $decoded['msg'] ?? $decoded['error'] ?? null;
            }

            return [
                'ok' => $ok,
                'cookie' => $ok ? $decoded['cookie'] : null,
                'decoded' => $decoded,
                'debug' => $debug,
            ];
        }
        catch (Exception $e) {
            $debug['exception'] = $e->getMessage();

            return ['ok' => false, 'cookie' => null, 'decoded' => null, 'debug' => $debug];
        }
    }

    private function datadomeProxyCacheKey(): string
    {
        if ($this->proxyConfig === null) {
            return 'direct';
        }

        return hash('sha256', ($this->proxyConfig['address'] ?? '') . "\0" . ($this->proxyConfig['auth'] ?? ''));
    }

    /**
     * Lấy cookie Datadome đã lưu (cùng proxy / direct), tăng bộ đếm dùng trong file lock.
     */
    private function tryConsumeCachedDatadomeSession(): array
    {
        $path = $this->datadomeSessionStorePath;
        if (!is_readable($path)) {
            return ['hit' => false];
        }

        $fh = fopen($path, 'c+');
        if ($fh === false) {
            return ['hit' => false];
        }

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return ['hit' => false];
        }

        try {
            rewind($fh);
            $raw = stream_get_contents($fh) ?: '';
            $store = json_decode($raw, true);
            if (!is_array($store)) {
                $store = [];
            }

            $key = $this->datadomeProxyCacheKey();
            if (!isset($store[$key])) {
                return ['hit' => false];
            }

            $entry = $store[$key];
            $cookie = (string)($entry['cookie'] ?? '');
            $savedAt = (int)($entry['saved_at'] ?? 0);
            $uses = (int)($entry['uses'] ?? 0);

            if ($cookie === ''
                || (time() - $savedAt) >= self::DATADOME_SESSION_CACHE_TTL
                || $uses >= self::DATADOME_SESSION_MAX_USES
            ) {
                return ['hit' => false];
            }

            $entry['uses'] = $uses + 1;
            $store[$key] = $entry;

            rewind($fh);
            ftruncate($fh, 0);
            fwrite($fh, json_encode($store, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            fflush($fh);

            return ['hit' => true, 'cookie' => $cookie];
        }
        finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    private function writeFreshDatadomeSession(string $cookie): void
    {
        $path = $this->datadomeSessionStorePath;
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $fh = fopen($path, 'c+');
        if ($fh === false) {
            return;
        }

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return;
        }

        try {
            rewind($fh);
            $raw = stream_get_contents($fh) ?: '';
            $store = json_decode($raw, true);
            if (!is_array($store)) {
                $store = [];
            }

            $key = $this->datadomeProxyCacheKey();
            $store[$key] = [
                'cookie' => $cookie,
                'saved_at' => time(),
                'uses' => 0,
            ];

            rewind($fh);
            ftruncate($fh, 0);
            fwrite($fh, json_encode($store, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            fflush($fh);
        }
        finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    private function invalidateDatadomeSessionEntry(): void
    {
        $path = $this->datadomeSessionStorePath;
        if (!is_readable($path)) {
            return;
        }

        $fh = fopen($path, 'c+');
        if ($fh === false) {
            return;
        }

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return;
        }

        try {
            rewind($fh);
            $raw = stream_get_contents($fh) ?: '';
            $store = json_decode($raw, true);
            if (!is_array($store)) {
                $store = [];
            }

            $key = $this->datadomeProxyCacheKey();
            unset($store[$key]);

            rewind($fh);
            ftruncate($fh, 0);
            fwrite($fh, json_encode($store, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            fflush($fh);
        }
        finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /**
     * @return array{ok:bool, cookie?:string, from_cache:bool, message?:string}
     */
    private function resolveDatadomeSession(bool $forceRefresh): array
    {
        if (!$forceRefresh) {
            $cached = $this->tryConsumeCachedDatadomeSession();
            if (!empty($cached['hit']) && isset($cached['cookie']) && $cached['cookie'] !== '') {
                return ['ok' => true, 'cookie' => $cached['cookie'], 'from_cache' => true];
            }
        }

        $dd = $this->fetchDatadomeJs();
        if (!$dd['ok'] || empty($dd['cookie'])) {
            return [
                'ok' => false,
                'from_cache' => false,
                'message' => 'Không thể lấy cookie datadome',
                '_debug_datadome' => $dd['debug'],
            ];
        }

        $cookie = (string)$dd['cookie'];
        $this->writeFreshDatadomeSession($cookie);

        return ['ok' => true, 'cookie' => $cookie, 'from_cache' => false];
    }

    private function shouldRetryAuthenticateWithFreshDatadome(array $result): bool
    {
        if (($result['status'] ?? null) !== false) {
            return false;
        }

        $check = $result['check'] ?? [];
        if (is_array($check) && (($check['error'] ?? '') === 'error_too_many_requests')) {
            return false;
        }

        $msg = (string)($result['message'] ?? '');
        if (str_contains($msg, 'Garena đang chặn rate')) {
            return false;
        }

        if (str_contains($msg, 'Không có v1/v2')) {
            return true;
        }

        $checkUrl = $check['url'] ?? '';
        if (is_string($checkUrl) && str_contains($checkUrl, 'captcha-delivery.com')) {
            return true;
        }

        return false;
    }

    /**
     * Ghì lại thời điểm request; nếu gọi quá sớm so với lần trước thì chờ thêm (toàn server một file).
     */
    private function paceBeforeSsoBurst(): void
    {
        $path = $this->cookiePath . '/sso_last_request.ts';
        $min = self::SSO_PACE_MIN_SECONDS;
        if ($min <= 0) {
            return;
        }

        if (!is_dir($this->cookiePath)) {
            return;
        }

        $fh = fopen($path, 'c+');
        if ($fh === false) {
            return;
        }

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return;
        }

        try {
            rewind($fh);
            $raw = trim((string)stream_get_contents($fh));
            $last = ($raw !== '' && is_numeric($raw)) ? (int)$raw : 0;
            $now = time();
            if ($last > 0) {
                $elapsed = $now - $last;
                if ($elapsed < $min) {
                    $sleep = $min - $elapsed;
                    flock($fh, LOCK_UN);
                    fclose($fh);
                    sleep((int)$sleep);
                    $fh = fopen($path, 'c+');
                    if ($fh === false || !flock($fh, LOCK_EX)) {
                        return;
                    }
                    $now = time();
                }
            }

            rewind($fh);
            ftruncate($fh, 0);
            fwrite($fh, (string)$now);
            fflush($fh);
        }
        finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    private function formatPreloginFailureMessage(array $check): string
    {
        $err = isset($check['error']) ? (string)$check['error'] : '';
        if ($err === 'error_too_many_requests') {
            return 'Garena đang chặn rate (prelogin — quá nhiều request). Nghỉ 10–30 phút, kiểm tra chậm lại (đã có khoảng cách tối thiểu giữa các lần trên server), hoặc đổi IP/proxy.';
        }

        $url = isset($check['url']) ? (string)$check['url'] : '';
        if ($url !== '' && str_contains($url, 'captcha-delivery.com')) {
            return 'Lỗi prelogin: SSO yêu cầu captcha. Thử làm mới datadome_params / proxy / IP.';
        }

        if ($err !== '') {
            return 'Lỗi prelogin: ' . $err;
        }

        return 'Lỗi prelogin: Không có v1/v2';
    }

    private function createCurlRequest(string $url, string $method = 'GET', array $headers = [], string $postFields = '', string $cookieFile = ''): array
    {
        try {
            $curl = curl_init();
            if ($curl === false) {
                return ['error' => 'curl_init_failed'];
            }

            $defaultHeaders = [
                'Accept: application/json, text/plain, */*',
                'Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                'Cache-Control: no-cache',
                'Connection: keep-alive',
                'Pragma: no-cache',
                'Sec-Fetch-Dest: empty',
                'Sec-Fetch-Mode: cors',
                'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                'sec-ch-ua: "Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
                'sec-ch-ua-mobile: ?0',
                'sec-ch-ua-platform: "Windows"',
            ];

            $options = [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => array_merge($defaultHeaders, $headers),
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ];

            if ($method === 'POST' && $postFields) {
                $options[CURLOPT_POSTFIELDS] = $postFields;
            }

            if ($cookieFile && file_exists($cookieFile)) {
                $options[CURLOPT_COOKIEJAR] = $cookieFile;
                $options[CURLOPT_COOKIEFILE] = $cookieFile;
            }

            if ($this->proxyConfig) {
                $options[CURLOPT_PROXY] = $this->proxyConfig['address'];
                $options[CURLOPT_PROXYTYPE] = CURLPROXY_HTTP;

                if (!empty($this->proxyConfig['auth'])) {
                    $options[CURLOPT_PROXYUSERPWD] = $this->proxyConfig['auth'];
                }
            }

            curl_setopt_array($curl, $options);
            $response = curl_exec($curl);

            $error = curl_error($curl);
            curl_close($curl);

            if ($error) {
                return ['error' => $error];
            }

            $decoded = json_decode($response, true);
            return $decoded ?: [];

        }
        catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Tạo cURL request trả về response dạng raw string (cho các API cần parse header)
     */
    private function createRawCurlRequest(string $url, string $method = 'GET', array $headers = [], string $postFields = '', string $cookieFile = '', bool $includeHeader = true): array
    {
        try {
            $curl = curl_init();
            if ($curl === false) {
                return ['error' => 'curl_init_failed'];
            }

            $options = [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 15,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_HEADER => $includeHeader,
            ];

            if ($method === 'POST' && $postFields !== '') {
                $options[CURLOPT_POSTFIELDS] = $postFields;
            }

            if ($cookieFile !== '' && file_exists($cookieFile)) {
                $options[CURLOPT_COOKIEJAR] = $cookieFile;
                $options[CURLOPT_COOKIEFILE] = $cookieFile;
            }

            if ($this->proxyConfig) {
                $options[CURLOPT_PROXY] = $this->proxyConfig['address'];
                $options[CURLOPT_PROXYTYPE] = CURLPROXY_HTTP;
                if (!empty($this->proxyConfig['auth'])) {
                    $options[CURLOPT_PROXYUSERPWD] = $this->proxyConfig['auth'];
                }
            }

            curl_setopt_array($curl, $options);
            $response = curl_exec($curl);

            $error = curl_error($curl);
            $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
            curl_close($curl);

            if ($error) {
                return ['error' => $error];
            }

            if ($includeHeader) {
                $rawHeaders = substr($response, 0, $headerSize);
                $body = substr($response, $headerSize);
            }
            else {
                $rawHeaders = '';
                $body = $response;
            }

            return [
                'raw' => $response,
                'headers' => $rawHeaders,
                'body' => $body,
                'json' => json_decode($body, true),
            ];
        }
        catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }


    public function getDatadomeCookie(): ?array
    {
        try {
            $dd = $this->fetchDatadomeJs();

            return $dd['decoded'] ?? null;
        }
        catch (Exception $e) {
            return null;
        }
    }

    public function checkAccount(string $cookie, string $account): ?array
    {
        $id = $this->generateId();
        $url = "https://sso.garena.com/api/prelogin?app_id=10100&account=$account&format=json&id=$id";
        $headers = [
            'Referer: https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN',
            'Cookie: ' . $cookie
        ];

        return $this->createCurlRequest($url, 'GET', $headers);
    }


    public function login(string $cookie, string $account, string $password): ?array
    {
        $id = $this->generateId();
        $this->connectLoginId = $id;

        $check = $this->checkAccount($cookie, $account);

        if (isset($check['error']) && $check['error'] === 'error_no_account') {
            return [
                'status' => false,
                'message' => 'Tài khoản không hợp lệ'
            ];
        }

        if (!isset($check['v1']) || !isset($check['v2'])) {
            return [
                'status' => false,
                'message' => $this->formatPreloginFailureMessage($check),
                'check' => $check,
            ];
        }

        $encrypted = $this->encodePassword(
            md5($password),
            hash('sha256', hash('sha256', md5($password) . $check['v1']) . $check['v2'])
        );

        $cookieFile = $this->getCookieFilePath($account);
        $connectUrl = "https://connect.garena.com/api/login?account=$account&password=$encrypted&format=json&id=$id&app_id=10100";

        $datadomeValue = '';
        if (preg_match('/datadome=([^;]+)/', $cookie, $matches)) {
            $datadomeValue = $matches[1];
        }

        $headers = [
            'Referer: https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN',
            'Cookie: ' . $cookie
        ];

        if ($datadomeValue) {
            $headers[] = 'x-datadome-clientid: ' . $datadomeValue;
        }

        $connectRes = $this->createRawCurlRequest($connectUrl, 'GET', $headers, '', $cookieFile, true);
        $this->lastConnectRawResponse = $connectRes;

        if (isset($connectRes['error'])) {
            return ['error' => $connectRes['error']];
        }

        return $connectRes['json'] ?? [];
    }

    public function getUserInfo(string $account, string $referer): ?array
    {
        $cookieFile = $this->getCookieFilePath($account);
        $url = 'https://account.garena.com/api/account/init';
        $headers = [
            'Accept: */*',
            'Referer: ' . $referer,
        ];

        return $this->createCurlRequest($url, 'GET', $headers, '', $cookieFile);
    }

    public function checkGrant(string $cookie, string $account): ?array
    {
        $id = $this->generateId();
        $cookieFile = $this->getCookieFilePath($account);

        $url = "https://auth.garena.com/api/universal/oauth?client_id=100054"
            . "&redirect_uri=https%3A%2F%2Fkientuong.lienquan.garena.vn%2Fauth%2Flogin%2Fcallback"
            . "&response_type=code"
            . "&platform=1"
            . "&locale=vi-VN"
            . "&format=json"
            . "&id=$id";

        $headers = [
            'Content-Type: application/x-www-form-urlencoded;charset=UTF-8',
            'Origin: https://auth.garena.com',
            'Referer: https://auth.garena.com/universal/oauth',
        ];

        $res = $this->createCurlRequest($url, 'GET', $headers, '', $cookieFile);

        if (!$res || empty($res['redirect_uri'])) {
            return null;
        }

        parse_str(parse_url($res['redirect_uri'], PHP_URL_QUERY), $query);

        $res['access_token'] = $query['code'] ?? null;

        return $res;
    }

    public function checkGrantSkin(string $cookie, string $account): ?array
    {
        $id = $this->generateId();
        $cookieFile = $this->getCookieFilePath($account);

        $url = "https://auth.garena.com/api/universal/oauth?client_id=100054"
            . "&redirect_uri=https%3A%2F%2Fsale.lienquan.garena.vn%2Flogin%2Fcallback"
            . "&response_type=code"
            . "&platform=1"
            . "&locale=vi-VN"
            . "&format=json"
            . "&id=$id";

        $headers = [
            'Content-Type: application/x-www-form-urlencoded;charset=UTF-8',
            'Origin: https://auth.garena.com',
            'Referer: https://auth.garena.com/universal/oauth',
        ];

        $res = $this->createCurlRequest($url, 'GET', $headers, '', $cookieFile);

        if (!$res || empty($res['redirect_uri'])) {
            return null;
        }

        parse_str(parse_url($res['redirect_uri'], PHP_URL_QUERY), $query);

        $res['access_token'] = $query['code'] ?? null;

        return $res;
    }

    public function playercallBack(string $url, $account)
    {
        $cookieFile = $this->getCookieFilePath($account);
        $headers = [
            'Accept: */*',
        ];

        return $this->createCurlRequest($url, 'GET', $headers, '', $cookieFile);
    }

    public function infoPlayer($account): ?array
    {
        $cookieFile = $this->getCookieFilePath($account);
        $url = 'https://kientuong.lienquan.garena.vn/api/player/get';
        $headers = [
            'Accept: */*'
        ];

        return $this->createCurlRequest($url, 'GET', $headers, '', $cookieFile);
    }

    public function salecallBack(string $token, $account)
    {
        $url = "https://sale.lienquan.garena.vn/login/callback?code=$token";
        $cookieFile = $this->getCookieFilePath($account);
        $headers = [
            'Accept: */*',
        ];

        return $this->createCurlRequest($url, 'GET', $headers, '', $cookieFile);
    }

    public function getUserShopInfo(string $account): ?array
    {
        $cookieFile = $this->getCookieFilePath($account);
        $url = 'https://sale.lienquan.garena.vn/graphql';
        $headers = [
            'Content-Type: application/json',
            'Origin: https://sale.lienquan.garena.vn',
            'Referer: https://sale.lienquan.garena.vn/'
        ];
        $postFields = json_encode([
            'query' => 'query getUser {
                getUser {
                    id
                    name
                    icon
                    profile {
                        id
                        shopItems
                        boxItems
                        flippedSlots
                        discount
                        cp
                        userPack {
                            id
                            tcid
                            packId
                            claimedSeq
                            startTime
                            duration
                            box_count
                            __typename
                        }
                        pickedItem
                        discountList
                        isBuy
                        ownedItemIdList
                        __typename
                    }
                    __typename
                }
            }',
            'variables' => []
        ]);

        return $this->createCurlRequest($url, 'POST', $headers, $postFields, $cookieFile);
    }

    public function checkFacebook(?array $fbAccount): string
    {
        if ($fbAccount === null || !isset($fbAccount['fb_uid'])) {
            return 'NO';
        }

        $fbUid = $fbAccount['fb_uid'];
        $url = "https://graph2.facebook.com/v3.3/{$fbUid}/picture?redirect=0";

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

        $response = curl_exec($ch);
        curl_close($ch);

        if ($response && strpos($response, 'data') !== false) {
            return 'LIVE';
        }

        return 'DIE';
    }

    public function getWeeklyReport(string $accessToken, string $account): array
    {
        $cookieFile = $this->getCookieFilePath($account);
        $headers = [
            'accept: application/json, text/plain, */*',
            'accept-language: vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
            "access-token: {$accessToken}",
            'partition: 1011',
            'priority: u=1, i',
            'referer: https://weeklyreport.moba.garena.vn/portrait/recall',
            'sec-fetch-dest: empty',
            'sec-fetch-mode: cors',
            'sec-fetch-site: same-origin',
            'user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
        ];

        return $this->createCurlRequest('https://weeklyreport.moba.garena.vn/api/profile', 'GET', $headers, '', $cookieFile);
    }

    public function getOAuthAccessToken(string $account): ?string
    {
        $id = $this->connectLoginId ?? $this->generateId();
        $cookieFile = $this->getCookieFilePath($account);

        // BƯỚC 1: Lấy Authorization Code từ Garena Auth bằng MSDK flow
        $grantUrl = "https://100054.connect.garena.com/oauth/token/grant";
        $grantPost = 'client_id=100054'
            . '&response_type=code'
            . '&redirect_uri=' . urlencode('gop100054://auth/')
            . '&login_scenario=normal'
            . '&format=json'
            . '&id=' . $id;

        $grantHeaders = [
            'Content-Type: application/x-www-form-urlencoded;charset=UTF-8',
            'Origin: https://100054.connect.garena.com',
            'Referer: https://100054.connect.garena.com/universal/oauth?redirect_uri=gop100054://auth/&response_type=code&client_id=100054&login_scenario=normal&locale=vi-VN',
            'User-Agent: Mozilla/5.0 (Linux; Android 9; OXF-AN10 Build/PQ3A.190605.02261134; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Mobile Safari/537.36'
        ];

        $resCode = $this->createRawCurlRequest($grantUrl, 'POST', $grantHeaders, $grantPost, $cookieFile, true);

        $code = $resCode['json']['code'] ?? null;
        if (!$code) {
            $this->lastOauthRawResponse = $resCode;
            return null;
        }

        $exchangeUrl = 'https://100054.connect.garena.com/oauth/token/exchange';
        $exchangePost = 'code=' . $code
            . '&grant_type=authorization_code'
            . '&login_scenario=normal'
            . '&redirect_uri=' . urlencode('gop100054://auth/')
            . '&source=2'
            . '&client_secret=027709b12673a3e18de16bf9b85723a2d55e9bffd3364aea67f176e533f69515'
            . '&client_id=100054';

        $exchangeHeaders = [
            'Content-Type: application/x-www-form-urlencoded',
            'User-Agent: GarenaMSDK/4.0.38(OXF-AN10 ;Android 9;vi;VN;)',
        ];

        $resToken = $this->createRawCurlRequest($exchangeUrl, 'POST', $exchangeHeaders, $exchangePost, $cookieFile, true);
        $this->lastOauthRawResponse = $resToken;

        return $resToken['json']['access_token'] ?? null;
    }


    /**
     * Lấy lịch sử nạp thẻ từ napthe.vn (60 ngày gần nhất)
     */
    public function getTopUpHistory(string $account): array
    {
        $cookieFile = $this->getCookieFilePath($account);
        $id = $this->generateId();

        // Bước 1: Lấy token napthe.vn
        $tokenRes = $this->createRawCurlRequest(
            'https://auth.garena.com/oauth/token/grant',
            'POST',
        [],
            'client_id=10017&redirect_uri=https%3A%2F%2Fnapthe.vn%2Fapp&response_type=token&platform=1&locale=vi-VN&theme=mshop_iframe_white&format=json&id=' . $id . '&app_id=10017',
            $cookieFile
        );

        if (isset($tokenRes['error'])) {
            return ['total' => 0, 'error' => $tokenRes['error']];
        }

        $tokenJson = $tokenRes['json'] ?? [];
        $napToken = $tokenJson['access_token'] ?? null;
        if (!$napToken) {
            return ['total' => 0, 'error' => 'missing_napthe_token'];
        }

        // Bước 2: Inspect token để lấy session cookie
        $inspectRes = $this->createRawCurlRequest(
            'https://napthe.vn/api/auth/inspect_token',
            'POST',
        [],
            json_encode(['token' => $napToken]),
            $cookieFile
        );

        if (isset($inspectRes['error'])) {
            return ['total' => 0, 'error' => $inspectRes['error']];
        }

        // Lấy Set-Cookie từ header
        $setCookie = '';
        $rawHeaders = $inspectRes['headers'] ?? '';
        if (preg_match('/Set-Cookie:\s*([^;]+)/i', $rawHeaders, $matches)) {
            $setCookie = trim($matches[1]);
        }

        // Bước 3: Lấy lịch sử nạp thẻ
        $startTs = strtotime('-60 days');
        $endTs = time();
        $historyUrl = "https://napthe.vn/api/shop/history?app_id=100054&start_ts={$startTs}&end_ts={$endTs}&region=VN&language=vi&limit=20&offset=0";

        $historyHeaders = [];
        if ($setCookie !== '') {
            $historyHeaders[] = 'Cookie: ' . $setCookie;
        }

        $historyRes = $this->createCurlRequest($historyUrl, 'GET', $historyHeaders, '', $cookieFile);

        $totalAmount = 0;
        if (isset($historyRes['items']) && is_array($historyRes['items'])) {
            foreach ($historyRes['items'] as $item) {
                $totalAmount += (int)($item['point_amount'] ?? 0);
            }
        }

        return [
            'total_60_days' => $totalAmount > 0 ? $totalAmount : 0,
            'has_history' => $totalAmount > 0,
        ];
    }

    /**
     * Phân loại trạng thái tài khoản
     */
    public function classifyAccountStatus(string $fbStatus, string $emailVerified, string $mobileBound, bool $suspicious): string
    {
        if (($fbStatus === 'NO' || $fbStatus === 'DIE') && $emailVerified === 'NO' && $mobileBound === 'NO' && !$suspicious) {
            return 'ACC TRẮNG THÔNG TIN';
        }
        if (($fbStatus === 'NO' || $fbStatus === 'DIE') && $emailVerified === 'NO' && $mobileBound === 'NO' && $suspicious) {
            return 'ACC TRẮNG LỖI PASS';
        }
        if ($emailVerified === 'YES' && $mobileBound === 'NO' && ($fbStatus === 'NO' || $fbStatus === 'DIE')) {
            return 'ACC DÍNH MAIL';
        }
        if ($emailVerified === 'NO' && $mobileBound === 'NO' && $fbStatus === 'LIVE') {
            return 'ACC DÍNH FB';
        }
        if ($emailVerified === 'YES' && $mobileBound === 'NO' && $fbStatus === 'LIVE') {
            return 'ACC DÍNH MAIL & FB';
        }
        return 'ACC FULL';
    }

    /**
     * Trích xuất thông tin ban từ player data
     */
    private function formatBanInfo(array $playerPayload): array
    {
        $player = $playerPayload['player'] ?? [];
        if (!isset($player['banInfo'])) {
            return ['banned' => false, 'unban_time' => null, 'unban_time_formatted' => null];
        }

        $unbanTime = $player['banInfo']['unbanTime'] ?? null;
        return [
            'banned' => true,
            'unban_time' => $unbanTime,
            'unban_time_formatted' => ($unbanTime && is_numeric($unbanTime)) ? date('d-m-Y', $unbanTime) : null,
        ];
    }

    /**
     * Trích xuất thông tin rank từ weekly report
     */
    private function formatRankInfo(array $weeklyData): array
    {
        $rankId = $weeklyData['player_info']['rank'] ?? null;
        $rankConfig = $weeklyData['rank_config'] ?? [];
        $rankName = 'KHÔNG XÁC ĐỊNH';

        if ($rankId !== null && isset($rankConfig[$rankId]['name'])) {
            $rankName = $rankConfig[$rankId]['name'];
        }

        return [
            'rank_id' => $rankId,
            'rank_name' => $rankName,
        ];
    }

    public function authenticate(string $account, string $password): array
    {
        try {
            $this->paceBeforeSsoBurst();

            $forceRefresh = false;
            $lastFailure = [];
            $lastUsedCachedDd = false;

            for ($round = 0; $round < 2; $round++) {
                $resolved = $this->resolveDatadomeSession($forceRefresh);

                if (!$resolved['ok'] || empty($resolved['cookie'])) {
                    $out = [
                        'status' => false,
                        'message' => $resolved['message'] ?? 'Không thể lấy cookie datadome',
                        '_datadome_reused' => false,
                    ];
                    if (!empty($resolved['_debug_datadome']) && is_array($resolved['_debug_datadome'])) {
                        $out['_debug_datadome'] = $resolved['_debug_datadome'];
                    }

                    return $out;
                }

                $lastUsedCachedDd = $resolved['from_cache'];

                $payload = $this->authenticateWithDatadomeCookie(
                    $resolved['cookie'],
                    $account,
                    $password,
                );

                if (($payload['status'] ?? false) === true) {
                    $payload['_datadome_reused'] = $resolved['from_cache'];

                    return $payload;
                }

                $lastFailure = $payload;

                if ($round === 0 && $this->shouldRetryAuthenticateWithFreshDatadome($payload)) {
                    $this->invalidateDatadomeSessionEntry();
                    $forceRefresh = true;
                    continue;
                }

                break;
            }

            if ($lastFailure !== []) {
                $lastFailure['_datadome_reused'] = $lastUsedCachedDd;
            }

            return $lastFailure !== []
                ? $lastFailure
                : ['status' => false, 'message' => 'Đăng nhập thất bại', '_datadome_reused' => false];
        }
        catch (Exception $e) {
            return [
                'status' => false,
                'message' => 'Lỗi hệ thống: ' . $e->getMessage()
            ];
        }
    }

    private function authenticateWithDatadomeCookie(string $ddCookie, string $account, string $password): array
    {
        try {

            $checkLogin = $this->login($ddCookie, $account, $password);

            if (isset($checkLogin['status']) && $checkLogin['status'] === false) {
                return $checkLogin;
            }

            if (!isset($checkLogin['session_key'])) {
                return ['status' => false, 'message' => 'Đăng nhập thất bại'];
            }

            // === Thông tin tài khoản ===
            $redirectUri = $checkLogin['redirect_uri'] ?? 'https://account.garena.com/';
            $info = $this->getUserInfo($checkLogin['username'], $redirectUri);

            if (!isset($info['user_info'])) {
                return ['status' => false, 'message' => 'Không thể lấy thông tin người dùng'];
            }

            if (isset($info['user_info']['send_otp_methods'])) {
                unset($info['user_info']['send_otp_methods']);
            }

            $userInfo = $info['user_info'];

            // === Security info ===
            $emailVerified = !empty($userInfo['email_v']) ? 'YES' : 'NO';
            $mobileBound = (isset($userInfo['mobile_no']) && strpos($userInfo['mobile_no'], '*') !== false) ? 'YES' : 'NO';
            $cmnd = (isset($userInfo['idcard']) && strpos($userInfo['idcard'], '*') !== false) ? 'YES' : 'NO';
            $authenticator = !empty($userInfo['authenticator_enable']) ? 'YES' : 'NO';
            $emailStatus = !empty($userInfo['email_verify_available']) ? 'ĐÃ XÁC THỰC' : 'CHƯA XÁC THỰC';
            $shell = isset($userInfo['shell']) ? number_format($userInfo['shell']) : '0';
            $shellRaw = $userInfo['shell'] ?? 0;
            $accCountry = $userInfo['acc_country'] ?? 'KHÔNG XÁC ĐỊNH';

            // === Facebook check ===
            $fbAccount = $userInfo['fb_account'] ?? null;
            $fbStatus = $this->checkFacebook($fbAccount);

            // === Login history ===
            $lastLogin = null;
            $lastLoginFormatted = 'KHÔNG XÁC ĐỊNH';
            if (isset($info['login_history']) && count($info['login_history']) > 0) {
                $lastLogin = $info['login_history'][0]['timestamp'] ?? null;
                if ($lastLogin) {
                    $lastLoginFormatted = date('H:i:s d-m-Y', $lastLogin);
                }
            }

            // === Account status classification ===
            $suspicious = $userInfo['suspicious'] ?? false;
            $accountStatus = $this->classifyAccountStatus($fbStatus, $emailVerified, $mobileBound, $suspicious);

            // Lấy OAUTH Token CHO RANK (Phải làm TRƯỚC checkGrant vì checkGrant sẽ tiêu thụ phiên auth)
            $oauthToken = $this->getOAuthAccessToken($account);

            // === Grant + Player info ===
            $grant = $this->checkGrant($ddCookie, $account);
            if (!isset($grant['access_token'])) {
                return ['status' => false, 'message' => 'Không thể lấy access token'];
            }

            // Player callback + info (dùng checkGrant redirect_uri)
            $redirect_uri = $grant['redirect_uri'];
            $this->playercallBack($redirect_uri, $account);
            $player = $this->infoPlayer($account);

            // === Ban info ===
            $banInfo = $this->formatBanInfo($player);

            // === Rank info (weekly report) ===
            // Cần real access_token (không phải auth code) cho weekly report API
            $rankInfo = ['rank_id' => null, 'rank_name' => 'KHÔNG XÁC ĐỊNH'];
            $rankDebug = [];

            // oauthToken đã được gọi ở phía trên
            $rankDebug['oauth_token'] = $oauthToken ? substr($oauthToken, 0, 20) . '...' : null;
            $rankDebug['oauth_token_full_length'] = $oauthToken ? strlen($oauthToken) : 0;

            if (!$oauthToken) {
                $cookieFile = $this->getCookieFilePath($account);

                // Debug: xem cookie file chứa gì
                $rankDebug['cookie_file_path'] = $cookieFile;
                $rankDebug['cookie_file_exists'] = file_exists($cookieFile);
                if (file_exists($cookieFile)) {
                    $cookieContent = file_get_contents($cookieFile);
                    // Lấy danh sách domains trong cookie file
                    preg_match_all('/^([^\s#]+)\s/m', $cookieContent, $matches);
                    $rankDebug['cookie_domains'] = array_unique($matches[1] ?? []);
                    $rankDebug['cookie_file_size'] = strlen($cookieContent);
                    // Lấy tên cookie (column 6 theo format Netscape)
                    preg_match_all('/^[^\s#]+\t[^\t]+\t[^\t]+\t[^\t]+\t[^\t]+\t([^\t]+)/m', $cookieContent, $nameMatches);
                    $rankDebug['cookie_names'] = $nameMatches[1] ?? [];
                }

                // Debug: thử connect login lại và xem response
                $id3 = $this->generateId();
                $check3 = $this->checkAccount($ddCookie, $account);
                $rankDebug['connect_prelogin'] = isset($check3['v1']) ? 'OK (has v1/v2)' : $check3;

                // Bây giờ thay vì tự login ở đây, mình in ra cái raw response lúc login chính thức
                $rankDebug['connect_login_raw'] = $this->lastConnectRawResponse;

                // Trực tiếp dump response từ lần gọi trước (tránh gọi lần 2 gây sai lệch)
                $rankDebug['oauth_raw_response'] = $this->lastOauthRawResponse ?? 'NOT_CALLED';
            }

            if ($oauthToken) {
                // Bước 2: Gọi weekly report
                $weeklyData = $this->getWeeklyReport($oauthToken, $account);
                $rankDebug['weekly_has_error'] = isset($weeklyData['error']);
                $rankDebug['weekly_has_player_info'] = isset($weeklyData['player_info']);
                $rankDebug['weekly_keys'] = is_array($weeklyData) ? array_keys($weeklyData) : 'not_array';
                $rankDebug['weekly_raw_full'] = $weeklyData;

                if (!isset($weeklyData['error']) && isset($weeklyData['player_info'])) {
                    $rankInfo = $this->formatRankInfo($weeklyData);
                    $rankDebug['rank_result'] = $rankInfo;
                }
                else {
                    $rankDebug['weekly_response_preview'] = is_array($weeklyData)
                        ? array_slice($weeklyData, 0, 5)
                        : $weeklyData;
                }
            }

            // === Skin / Collection ===
            $grantSkin = $this->checkGrantSkin($ddCookie, $account);
            if (!isset($grantSkin['access_token'])) {
                return ['status' => false, 'message' => 'Không thể lấy access token skin'];
            }

            $this->salecallBack($grantSkin['access_token'], $account);
            $userShop = $this->getUserShopInfo($account);

            if (!isset($userShop['data']['getUser'])) {
                return ['status' => false, 'message' => 'Không thể lấy thông tin tướng'];
            }

            $ownedItemIdList = $userShop['data']['getUser']['profile']['ownedItemIdList'] ?? [];
            $collection = $this->buildCollectionSummary($ownedItemIdList);

            // === Top-up history ===
            $topUp = $this->getTopUpHistory($account);

            // === Build response ===
            return [
                'status' => true,
                'account' => $this->formatAccountInfo($userInfo),
                'user_info' => $userInfo,
                'security' => [
                    'email_verified' => $emailVerified,
                    'email_status' => $emailStatus,
                    'mobile_bound' => $mobileBound,
                    'cmnd' => $cmnd,
                    'authenticator' => $authenticator,
                    'fb_status' => $fbStatus,
                    'suspicious' => $suspicious,
                    'account_status' => $accountStatus,
                ],
                'player' => array_merge($this->formatPlayerInfo($player), [
                    'rank' => $rankInfo,
                ]),
                'player_raw' => $player,
                'ban_info' => $banInfo,
                'wallet' => array_merge(
                $this->formatWalletInfo($userShop['data']['getUser']['profile'] ?? []),
                [
                    'shell' => $shellRaw,
                    'shell_formatted' => $shell,
                ]
            ),
                'login_history' => [
                    'last_login' => $lastLogin,
                    'last_login_formatted' => $lastLoginFormatted,
                ],
                'top_up' => $topUp,
                'collection' => $collection,
                '_debug_rank' => $rankDebug,
            ];

        }
        catch (Exception $e) {
            return [
                'status' => false,
                'message' => 'Lỗi hệ thống: ' . $e->getMessage()
            ];
        }
    }
}
