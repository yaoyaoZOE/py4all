# DNS Resolution Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Python CLI that shows system hostname resolution and queries one selected DNS record type.

**Architecture:** Keep the CLI and resolution helpers in `cybersecurity/dns_demo.py`. Use `socket.getaddrinfo` for the operating-system resolver and `dnspython` for explicit record queries through the configured DNS resolver; test both through mocks so the suite needs no network.

**Tech Stack:** Python standard library, `dnspython`, `unittest`.

## Global Constraints

- Accept a hostname and an optional record type; default to `A`.
- Support `A`, `AAAA`, `CNAME`, `MX`, `NS`, and `TXT`.
- Display the system resolver's IPv4 and IPv6 addresses, followed by answers for the selected record type using the system-configured DNS resolver.
- Report invalid input, system resolution failures, DNS failures, and missing dependencies clearly. Do not silently hide errors.
- Keep the implementation focused on read-only resolution and use no API keys.
- No real DNS network request is required for tests.

---

## File Structure

- Create `cybersecurity/dns_demo.py`: CLI, input validation, system resolver helper, and explicit DNS record helper.
- Create `cybersecurity/requirements.txt`: runtime dependency declaration for `dnspython`.
- Create `cybersecurity/tests/test_dns_demo.py`: network-independent unit tests in the existing `unittest` style.
- Modify `cybersecurity/README.md`: installation and command examples.

## Task 1: Implement and Test the DNS Resolution CLI

**Files:**
- Create: `cybersecurity/tests/test_dns_demo.py`
- Create: `cybersecurity/dns_demo.py`
- Create: `cybersecurity/requirements.txt`
- Modify: `cybersecurity/README.md`

**Interfaces:**
- `resolve_system_addresses(hostname: str) -> dict[str, list[str]]`: returns IPv4 and IPv6 lists from `socket.getaddrinfo`; raises `DnsDemoError` on `socket.gaierror`.
- `resolve_record(hostname: str, record_type: str) -> list[str]`: returns textual record data using `dnspython`; raises `DnsDemoError` for a missing dependency or DNS query failure.
- `main(argv: list[str] | None = None) -> int`: accepts the CLI arguments, prints both result sections, and returns `0` on success or `1` on resolution errors. `argparse` reports invalid options and record types.
- `SUPPORTED_RECORD_TYPES`: tuple of the six supported uppercase record types.

- [ ] **Step 1: Write offline tests first**

Create `cybersecurity/tests/test_dns_demo.py` with these test cases. The fake `dns` modules allow the DNS dependency boundary and failure handling to be tested without network access or requiring the package to be installed before the implementation is ready.

```python
import io
import socket
import sys
import types
import unittest
from unittest.mock import Mock, patch

import dns_demo


def fake_dns_modules(resolve):
    dns_package = types.ModuleType("dns")
    exception_module = types.ModuleType("dns.exception")
    resolver_module = types.ModuleType("dns.resolver")

    class DNSException(Exception):
        pass

    exception_module.DNSException = DNSException
    resolver_module.resolve = resolve
    dns_package.exception = exception_module
    dns_package.resolver = resolver_module
    return {
        "dns": dns_package,
        "dns.exception": exception_module,
        "dns.resolver": resolver_module,
    }, DNSException


class DnsDemoTests(unittest.TestCase):
    def test_resolve_system_addresses_groups_and_deduplicates_results(self):
        rows = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]
        with patch.object(dns_demo.socket, "getaddrinfo", return_value=rows):
            result = dns_demo.resolve_system_addresses("example.test")
        self.assertEqual(
            result, {"IPv4": ["192.0.2.1"], "IPv6": ["2001:db8::1"]}
        )

    def test_resolve_system_addresses_reports_lookup_failure(self):
        with patch.object(
            dns_demo.socket, "getaddrinfo", side_effect=socket.gaierror("offline")
        ):
            with self.assertRaisesRegex(dns_demo.DnsDemoError, "System DNS lookup failed"):
                dns_demo.resolve_system_addresses("example.test")

    def test_resolve_record_returns_text_answers_and_uses_record_type(self):
        resolve = Mock(return_value=["192.0.2.10", "192.0.2.11"])
        modules, _ = fake_dns_modules(resolve)
        with patch.dict(sys.modules, modules):
            result = dns_demo.resolve_record("example.test", "A")
        self.assertEqual(result, ["192.0.2.10", "192.0.2.11"])
        resolve.assert_called_once_with("example.test", "A", lifetime=5.0)

    def test_resolve_record_reports_dns_query_failure(self):
        def fail(*args, **kwargs):
            raise dns_exception("NXDOMAIN")

        modules, dns_exception = fake_dns_modules(fail)
        with patch.dict(sys.modules, modules):
            with self.assertRaisesRegex(dns_demo.DnsDemoError, "DNS query failed"):
                dns_demo.resolve_record("missing.example.test", "A")

    def test_resolve_record_reports_missing_dependency(self):
        with patch.dict(sys.modules, {"dns": None, "dns.exception": None, "dns.resolver": None}):
            with self.assertRaisesRegex(dns_demo.DnsDemoError, "dnspython"):
                dns_demo.resolve_record("example.test", "A")

    def test_main_prints_system_addresses_and_selected_records(self):
        stdout = io.StringIO()
        addresses = {"IPv4": ["192.0.2.1"], "IPv6": ["2001:db8::1"]}
        records = ["mail.example.test."]
        with patch.object(dns_demo, "resolve_system_addresses", return_value=addresses), patch.object(
            dns_demo, "resolve_record", return_value=records
        ) as resolve_record, patch.object(dns_demo.sys, "stdout", stdout):
            status = dns_demo.main(["example.test", "--type", "MX"])
        self.assertEqual(status, 0)
        resolve_record.assert_called_once_with("example.test", "MX")
        self.assertIn("192.0.2.1", stdout.getvalue())
        self.assertIn("2001:db8::1", stdout.getvalue())
        self.assertIn("mail.example.test.", stdout.getvalue())

    def test_main_defaults_to_a_records(self):
        stdout = io.StringIO()
        with patch.object(
            dns_demo, "resolve_system_addresses",
            return_value={"IPv4": [], "IPv6": []},
        ), patch.object(
            dns_demo, "resolve_record", return_value=["192.0.2.1"]
        ) as resolve_record, patch.object(dns_demo.sys, "stdout", stdout):
            status = dns_demo.main(["example.test"])
        self.assertEqual(status, 0)
        resolve_record.assert_called_once_with("example.test", "A")
        self.assertIn("DNS A records", stdout.getvalue())

    def test_main_reports_resolution_error(self):
        stderr = io.StringIO()
        with patch.object(
            dns_demo, "resolve_system_addresses",
            side_effect=dns_demo.DnsDemoError("System DNS lookup failed: offline"),
        ), patch.object(dns_demo.sys, "stderr", stderr):
            status = dns_demo.main(["example.test"])
        self.assertEqual(status, 1)
        self.assertIn("System DNS lookup failed", stderr.getvalue())

    def test_main_rejects_unsupported_record_type(self):
        with self.assertRaises(SystemExit) as result:
            dns_demo.main(["example.test", "--type", "PTR"])
        self.assertEqual(result.exception.code, 2)

    def test_main_rejects_hostname_with_whitespace(self):
        with self.assertRaises(SystemExit) as result:
            dns_demo.main(["bad hostname"])
        self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the focused tests and verify the expected initial failure**

Run from the repository root:

```powershell
Push-Location cybersecurity
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_dns_demo.py -v
Pop-Location
```

Expected: tests fail because `dns_demo.py` has not been created yet. Do not treat this import failure as an implementation success.

- [ ] **Step 3: Implement the CLI and dependency declaration**

Create `cybersecurity/dns_demo.py` with these imports, constants, and public helpers; add `argparse` handling in `main` as shown below. `resolve_record` imports `dnspython` on demand so the command can show a concise installation error when the dependency is absent.

```python
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
```

Create `cybersecurity/requirements.txt` with exactly:

```text
dnspython
```

- [ ] **Step 4: Run focused tests and verify they pass**

Run from the repository root:

```powershell
Push-Location cybersecurity
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_dns_demo.py -v
Pop-Location
```

Expected: all ten DNS demo tests pass without making network requests.

- [ ] **Step 5: Document setup and usage**

Append a `DNS Resolution Demo` section to `cybersecurity/README.md`:

````markdown
## DNS Resolution Demo

Install the DNS query dependency from this directory:

```powershell
python -m pip install -r requirements.txt
```

Resolve a hostname and query its A records:

```powershell
python .\dns_demo.py example.com
```

Choose another supported record type:

```powershell
python .\dns_demo.py example.com --type MX
```

The demo prints IPv4/IPv6 addresses from the operating-system resolver and
answers for one selected DNS record type using the system-configured DNS
resolver. Supported types are A, AAAA, CNAME, MX, NS, and TXT.
````

- [ ] **Step 6: Install the declared dependency and run the complete cybersecurity suite**

From the repository root:

```powershell
Push-Location cybersecurity
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
Pop-Location
```

Expected: dependency installation succeeds and all DNS and existing Shodan tests pass. Tests remain offline because all network-facing calls are mocked.

- [ ] **Step 7: Check whitespace and review the final diff**

Run:

```powershell
git diff --check
git status --short
```

Expected: no whitespace errors; only the four planned DNS demo files are added or modified.
