import io
import json
import os
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import shodan_demo


class ShodanDemoTests(unittest.TestCase):
    def test_query_host_uses_host_endpoint_and_returns_json(self):
        payload = {"ip_str": "8.8.8.8", "ports": [22, 443]}
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(payload).encode()

        with patch.object(shodan_demo, "urlopen", return_value=response) as urlopen:
            result = shodan_demo.query_host("8.8.8.8", "demo-key")

        self.assertEqual(result, payload)
        request = urlopen.call_args.args[0]
        self.assertIn("/shodan/host/8.8.8.8?", request.full_url)
        self.assertIn("key=demo-key", request.full_url)

    def test_query_host_rejects_invalid_ip_without_request(self):
        with patch.object(shodan_demo, "urlopen") as urlopen:
            with self.assertRaises(ValueError):
                shodan_demo.query_host("not-an-ip", "demo-key")
        urlopen.assert_not_called()

    def test_query_host_rejects_non_public_ip_without_request(self):
        with patch.object(shodan_demo, "urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "public"):
                shodan_demo.query_host("192.168.1.2", "demo-key")
        urlopen.assert_not_called()

    def test_query_host_reports_shodan_api_error(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(
            {"error": "Invalid API key"}
        ).encode()

        with patch.object(shodan_demo, "urlopen", return_value=response):
            with self.assertRaisesRegex(shodan_demo.ShodanError, "Invalid API key"):
                shodan_demo.query_host("8.8.8.8", "demo-key")

    def test_query_host_reports_http_error(self):
        error_body = io.BytesIO(json.dumps({"error": "Access denied"}).encode())
        http_error = HTTPError(
            "https://api.shodan.io/shodan/host/8.8.8.8",
            403,
            "Forbidden",
            {},
            error_body,
        )
        with patch.object(shodan_demo, "urlopen", side_effect=http_error):
            with self.assertRaisesRegex(shodan_demo.ShodanError, "Access denied"):
                shodan_demo.query_host("8.8.8.8", "demo-key")

    def test_query_host_reports_network_error(self):
        with patch.object(shodan_demo, "urlopen", side_effect=URLError("offline")):
            with self.assertRaisesRegex(shodan_demo.ShodanError, "Network error"):
                shodan_demo.query_host("8.8.8.8", "demo-key")

    def test_main_reports_missing_api_key(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch.object(
            shodan_demo.sys, "stderr", stderr
        ):
            status = shodan_demo.main(["8.8.8.8"])

        self.assertEqual(status, 1)
        self.assertIn("SHODAN_API_KEY", stderr.getvalue())

    def test_main_prints_host_summary(self):
        stdout = io.StringIO()
        payload = {
            "ip_str": "8.8.8.8",
            "org": "Example Org",
            "country_name": "Example Country",
            "ports": [22, 443],
        }
        with patch.dict(os.environ, {"SHODAN_API_KEY": "demo-key"}), patch.object(
            shodan_demo, "query_host", return_value=payload
        ), patch.object(shodan_demo.sys, "stdout", stdout):
            status = shodan_demo.main(["8.8.8.8"])

        self.assertEqual(status, 0)
        output = stdout.getvalue()
        self.assertIn("8.8.8.8", output)
        self.assertIn("Example Org", output)
        self.assertIn("Example Country", output)
        self.assertIn("22, 443", output)


if __name__ == "__main__":
    unittest.main()
