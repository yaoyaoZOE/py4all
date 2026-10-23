import argparse
import ipaddress
import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class ShodanError(RuntimeError):
    """Raised when a Shodan API request fails."""


def query_host(ip: str, api_key: str) -> dict[str, Any]:
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc
    if not parsed_ip.is_global:
        raise ValueError("IP address must be public and globally routable.")
    normalized_ip = str(parsed_ip)

    url = (
        "https://api.shodan.io/shodan/host/"
        f"{quote(normalized_ip, safe='')}?key={quote(api_key, safe='')}"
    )
    request = Request(url, headers={"Accept": "application/json"})

    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ShodanError("Shodan returned an invalid JSON response.") from exc
    except HTTPError as exc:
        try:
            error_payload = json.loads(exc.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            error_payload = {}
        detail = (
            error_payload.get("error", f"HTTP {exc.code}")
            if isinstance(error_payload, dict)
            else f"HTTP {exc.code}"
        )
        raise ShodanError(f"Shodan API error: {detail}") from exc
    except URLError as exc:
        raise ShodanError(f"Network error: {exc.reason}") from exc

    if not isinstance(payload, dict):
        raise ShodanError("Shodan returned an invalid response.")
    if "error" in payload:
        raise ShodanError(f"Shodan API error: {payload['error']}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Look up one IP address you own or are authorized to assess."
    )
    parser.add_argument("ip", help="authorized public IP address")
    args = parser.parse_args(argv)

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print("Error: set the SHODAN_API_KEY environment variable.", file=sys.stderr)
        return 1

    try:
        host = query_host(args.ip, api_key)
    except (ValueError, ShodanError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    ports = host.get("ports", [])
    port_summary = ", ".join(map(str, ports)) if isinstance(ports, list) else "None"
    country = host.get("country_name") or host.get("country_code") or "Unknown"
    print(f"IP: {host.get('ip_str', args.ip)}")
    print(f"Organization: {host.get('org') or 'Unknown'}")
    print(f"Country: {country}")
    print(f"Open ports: {port_summary or 'None'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
