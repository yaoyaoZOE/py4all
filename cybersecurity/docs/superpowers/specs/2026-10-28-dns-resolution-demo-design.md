# DNS Resolution Demo Design

## Goal

Add a small Python CLI demo that illustrates both operating-system hostname
resolution and direct DNS record queries.

## Approach

Use Python's standard-library `socket.getaddrinfo` to display IPv4 and IPv6
addresses resolved through the operating system. Use `dnspython` for explicit
DNS record queries, avoiding hand-written DNS packet parsing. Keep the new
dependency in a dedicated `cybersecurity/requirements.txt` file.

## Behavior

- Accept a hostname and an optional record type; default to `A`.
- Support `A`, `AAAA`, `CNAME`, `MX`, `NS`, and `TXT`.
- Display the system resolver's IPv4 and IPv6 addresses, followed by answers
  for the selected record type using the system-configured DNS resolver.
- Report invalid input, system resolution failures, DNS failures, and missing
  dependencies clearly. Do not silently hide errors.
- Keep the implementation focused on read-only resolution and use no API keys.

## Files

- Add `cybersecurity/dns_demo.py` for the CLI and independently testable
  resolution helpers.
- Add `cybersecurity/requirements.txt` containing `dnspython`.
- Add `cybersecurity/tests/test_dns_demo.py` with network-independent tests.
- Update `cybersecurity/README.md` with installation and usage examples.

## Validation

Use `unittest` with mocked system and DNS resolver calls to cover successful
IPv4/IPv6 and record output, supported record types, and clear handling of
resolution failures and invalid arguments. Run the existing cybersecurity
tests as a regression check. No real DNS network request is required for tests.
