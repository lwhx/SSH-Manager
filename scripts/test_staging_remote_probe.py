import argparse
import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("staging_remote_probe.py")
SPEC = importlib.util.spec_from_file_location("staging_remote_probe", MODULE_PATH)
probe = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(probe)


def result(status, body=b"", headers=None):
    return {
        "status": status,
        "headers": headers or {},
        "body": body,
        "oversized": False,
        "error": "",
    }


class StagingRemoteProbeTests(unittest.TestCase):
    def test_https_origin_normalizes_trailing_slash(self):
        self.assertEqual(
            probe.https_origin("https://console-staging.example.com/"),
            "https://console-staging.example.com",
        )

    def test_https_origin_rejects_http_and_paths(self):
        for value in (
            "http://console.example.com",
            "https://console.example.com/api",
            "https://user@console.example.com",
            "https://console.example.com/?x=1",
        ):
            with self.assertRaises(argparse.ArgumentTypeError):
                probe.https_origin(value)

    def test_control_access_redirect_passes(self):
        status, _ = probe.evaluate_control(
            result(
                302,
                headers={"location": "https://team.cloudflareaccess.com/cdn-cgi/access/login/app"},
            )
        )
        self.assertEqual(status, "PASS")

    def test_control_public_health_fails(self):
        status, _ = probe.evaluate_control(
            result(200, b'{"status":"ok","ssh_writes_enabled":false}', {"content-type": "application/json"})
        )
        self.assertEqual(status, "FAIL")

    def test_control_403_is_warning_not_success(self):
        status, _ = probe.evaluate_control(result(403))
        self.assertEqual(status, "WARN")

    def test_gateway_contract_passes(self):
        body = (
            b'{"status":"ok","version":"0.1.0","agent_auth":"device-ed25519",'
            b'"browser_access_required":false,"ssh_writes_enabled":false}'
        )
        status, _ = probe.evaluate_gateway(
            result(200, body, {"content-type": "application/json; charset=utf-8"})
        )
        self.assertEqual(status, "PASS")

    def test_gateway_access_redirect_fails(self):
        status, _ = probe.evaluate_gateway(
            result(
                302,
                headers={"location": "https://team.cloudflareaccess.com/cdn-cgi/access/login/app"},
            )
        )
        self.assertEqual(status, "FAIL")

    def test_gateway_wrong_security_flags_fail(self):
        body = (
            b'{"status":"ok","agent_auth":"device-ed25519",'
            b'"browser_access_required":true,"ssh_writes_enabled":false}'
        )
        status, _ = probe.evaluate_gateway(
            result(200, body, {"content-type": "application/json"})
        )
        self.assertEqual(status, "FAIL")

    def test_agent_hostname_rejects_admin_api_and_static_files(self):
        for route_result in (result(404),):
            outcome, _ = probe.evaluate_agent_admin_isolation(route_result)
            self.assertEqual(outcome, "PASS")
        for code in (200, 302, 401, 403, 500):
            outcome, _ = probe.evaluate_agent_admin_isolation(result(code))
            self.assertEqual(outcome, "FAIL")

    def test_access_redirect_rejects_non_https_absolute_url(self):
        self.assertFalse(probe.access_redirect("http://example.com/cdn-cgi/access/login"))


if __name__ == "__main__":
    unittest.main()
