import argparse
import socket
import sys


SUPPORTED_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


class DnsDemoError(RuntimeError):
    """Raised when a system or DNS lookup cannot be completed."""


def resolve_system_addresses(hostname: str) -> dict[str, list[str]]:
    addresses = {"IPv4": [], "IPv6": []}
    try:
        results = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise DnsDemoError(f"System DNS lookup failed: {exc}") from exc
    except UnicodeEncodeError as exc:
        raise DnsDemoError(f"Invalid hostname: {exc.reason}") from exc

    family_names = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}
    for family, _, _, _, sockaddr in results:
        label = family_names.get(family)
        if label is not None and sockaddr[0] not in addresses[label]:
            addresses[label].append(sockaddr[0])
    return addresses


def resolve_record(hostname: str, record_type: str) -> list[str]:
    try:
        import dns.exception
        import dns.resolver
    except ImportError as exc:
        raise DnsDemoError(
            "Missing dnspython dependency. Install it with "
            "'python -m pip install -r requirements.txt'."
        ) from exc

    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=5.0)
    except dns.exception.DNSException as exc:
        raise DnsDemoError(f"DNS query failed: {exc}") from exc
    return [str(answer) for answer in answers]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve a hostname and query a DNS record.")
    parser.add_argument("hostname", help="hostname to resolve")
    parser.add_argument(
        "--type",
        choices=SUPPORTED_RECORD_TYPES,
        default="A",
        dest="record_type",
        help="DNS record type to query (default: A)",
    )
    args = parser.parse_args(argv)
    if not args.hostname.strip() or any(character.isspace() for character in args.hostname):
        parser.error("hostname must not be empty or contain whitespace")

    try:
        addresses = resolve_system_addresses(args.hostname)
        records = resolve_record(args.hostname, args.record_type)
    except DnsDemoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"System resolver addresses for {args.hostname}:")
    for label in ("IPv4", "IPv6"):
        values = ", ".join(addresses[label]) or "(none)"
        print(f"  {label}: {values}")
    print(f"DNS {args.record_type} records for {args.hostname}:")
    for record in records:
        print(f"  {record}")
    if not records:
        print("  (no answers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
