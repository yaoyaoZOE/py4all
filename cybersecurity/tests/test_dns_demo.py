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
