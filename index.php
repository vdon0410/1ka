<?php

// Khởi tạo và xử lý request
try {
    $requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($requestMethod === 'GET') {
        $page = isset($_GET['page']) ? strtolower(trim((string)$_GET['page'])) : 'home';
        $pages = [
            'home' => __DIR__ . '/index.html',
            'checker' => __DIR__ . '/account-checker.html',
        ];
        $htmlFile = $pages[$page] ?? $pages['home'];
        if (!is_readable($htmlFile)) {
            $htmlFile = $pages['checker'];
        }
        if (!is_readable($htmlFile)) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'status' => false,
                'message' => 'Khong tim thay giao dien web'
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            exit;
        }
        header('Content-Type: text/html; charset=utf-8');
        readfile($htmlFile);
        exit;
    }

    require_once __DIR__ . '/GarenaAuth.php';

    header('Content-Type: application/json; charset=utf-8');
    $auth = new GarenaAuth();

    if ($requestMethod === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        if (isset($input['account']) && isset($input['password'])) {
            $auth->configureProxy($input['proxy'] ?? null, !empty($input['use_proxy']));
            $result = $auth->authenticate($input['account'], $input['password']);
        }
        else {
            $result = ['status' => false, 'message' => 'Thiếu thông tin đăng nhập'];
        }
    }
    else {
        $result = ['status' => false, 'message' => 'Phuong thuc khong duoc ho tro'];
    }

    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);


}
catch (Exception $e) {
    echo json_encode([
        'status' => false,
        'message' => 'Lỗi: ' . $e->getMessage()
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}
?>
