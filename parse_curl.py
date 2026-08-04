import argparse
import json
import os
import shlex
import sys
from typing import List, Tuple
from urllib.parse import parse_qs

DEFAULT_INPUT = "curl.txt"
DEFAULT_OUTPUT = "datadome_params.json"


def parse_curl_parts(parts: List[str]) -> Tuple[str, str]:
    """Return (data_raw, referer_from_header)."""
    data_raw = ""
    referer = ""
    i = 0
    while i < len(parts):
        part = parts[i]
        if part in ("-H", "--header"):
            header_val = parts[i + 1]
            if header_val.lower().startswith("referer:"):
                referer = header_val.split(":", 1)[1].strip()
            i += 2
        elif part in ("--data-raw", "--data", "-d"):
            data_raw = parts[i + 1]
            i += 2
        else:
            i += 1
    return data_raw, referer


def parse_curl_file(input_file: str, output_file: str) -> int:
    if input_file == "-":
        curl_command = sys.stdin.read()
    else:
        if not os.path.exists(input_file):
            print(f"Error: {input_file} not found.", file=sys.stderr)
            return 1
        with open(input_file, encoding="utf-8") as f:
            curl_command = f.read()

    normalized = curl_command.replace("\\\n", " ").replace("\n", " ")
    try:
        parts = shlex.split(normalized)
    except ValueError as e:
        print(f"Error parsing curl command: {e}", file=sys.stderr)
        return 1

    data_raw, referer = parse_curl_parts(parts)
    if not data_raw:
        print("Error: no --data-raw / -d body found in curl.", file=sys.stderr)
        return 1

    params = parse_qs(data_raw)
    result = {
        "jspl": params.get("jspl", [""])[0],
        "eventCounters": params.get("eventCounters", ["[]"])[0],
        "jsType": params.get("jsType", ["ch"])[0],
        "cid": params.get("cid", [""])[0],
        "ddk": params.get("ddk", [""])[0],
        "Referer": params.get("Referer", [referer])[0],
        "request": params.get("request", ["/"])[0],
        "responsePage": params.get("responsePage", ["origin"])[0],
        "ddv": params.get("ddv", ["5.4.0"])[0],
    }

    if not result["jspl"]:
        print("Warning: jspl is empty — paste may be incomplete or wrong request.", file=sys.stderr)
    if not result["cid"]:
        print("Warning: cid is empty.", file=sys.stderr)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Successfully parsed curl and updated {output_file}")
    return 0


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Parse 'Copy as cURL' into datadome_params.json")
    parser.add_argument(
        "-i",
        "--input",
        default=os.path.join(here, DEFAULT_INPUT),
        help=f"Path to curl text file, or '-' for stdin (default: {DEFAULT_INPUT} in script dir)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=os.path.join(here, DEFAULT_OUTPUT),
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    return parse_curl_file(args.input, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
