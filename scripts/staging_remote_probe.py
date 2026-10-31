#!/usr/bin/env python3
"""P3.4 read-only Cloudflare staging topology probe.

This tool sends no cookies, Access tokens, device keys, API tokens, SSH
credentials, or private keys. It only checks two HTTPS health routes:

- Control must be protected by Cloudflare Access at the edge.
- Agent Gateway must be directly reachable by devices and must NOT redirect
  browsers into Cloudflare Access.

No VPS or Cloudflare state is modified.
"""
from __future__ import annotations

import argparse
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_BODY = 32768
ACCESS_REDIRECT_CODES = {302, 303, 307, 308}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_origin(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise argparse.ArgumentTypeError(
            "must be an HTTPS origin only, with no path, query, fragment, or userinfo"
        )
    return urllib.parse.urlunsplit(("https", parsed.netloc, "", "", ""))


def request_once(url: str, timeout: int = 10) -> dict[str, Any]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": "ssh-manager-p3.4-staging-probe/1",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as res:
            body = res.read(MAX_BODY + 1)
            return {
                "status": int(res.status),
                "headers": {k.lower(): v for k, v in res.headers.items()},
                "body": body[:MAX_BODY],
                "oversized": len(body) > MAX_BODY,
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        return {
            "status": int(exc.code),
            "headers": {k.lower(): v for k, v in exc.headers.items()},
            "body": body[:MAX_BODY],
            "oversized": len(body) > MAX_BODY,
            "error": "",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "status": 0,
            "headers": {},
            "body": b"",
            "oversized": False,
            "error": type(exc).__name__,
        }


def parse_json_body(result: dict[str, Any]) -> dict[str, Any] | None:
    if result.get("oversized"):
        return None
    body = result.get("body", b"")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return None
    return value if isinstance(value, dict) else None


def access_redirect(location: str) -> bool:
    if not location:
        return False
    try:
        parsed = urllib.parse.urlsplit(location)
    except ValueError:
        return False
    if parsed.scheme and parsed.scheme != "https":
        return False
    return "/cdn-cgi/access/" in parsed.path


def evaluate_control(result: dict[str, Any]) -> tuple[str, str]:
    status = int(result.get("status", 0))
    headers = result.get("headers", {}) or {}
    if status in ACCESS_REDIRECT_CODES and access_redirect(str(headers.get("location", ""))):
        return "PASS", "control origin is intercepted by Cloudflare Access"
    if status in {401, 403}:
        return "WARN", "control origin is blocked, but an Access redirect was not observed"
    if status == 200:
        value = parse_json_body(result)
        if value and value.get("status") == "ok":
            return "FAIL", "control Worker health is reachable without Cloudflare Access"
        return "FAIL", "control origin returned an unexpected public 200 response"
    if status == 0:
        return "FAIL", "control origin could not be reached over verified HTTPS"
    return "FAIL", f"control origin returned unexpected HTTP {status}"


def evaluate_gateway(result: dict[str, Any]) -> tuple[str, str]:
    status = int(result.get("status", 0))
    headers = result.get("headers", {}) or {}
    if status in ACCESS_REDIRECT_CODES and access_redirect(str(headers.get("location", ""))):
        return "FAIL", "Agent Gateway is incorrectly protected by browser Cloudflare Access"
    if status != 200:
        if status == 0:
            return "FAIL", "Agent Gateway could not be reached over verified HTTPS"
        return "FAIL", f"Agent Gateway returned unexpected HTTP {status}"
    content_type = str(headers.get("content-type", "")).lower()
    if "application/json" not in content_type:
        return "FAIL", "Agent Gateway health did not return JSON"
    value = parse_json_body(result)
    expected = {
        "status": "ok",
        "agent_auth": "device-ed25519",
        "browser_access_required": False,
        "ssh_writes_enabled": False,
    }
    if not value or any(value.get(k) != v for k, v in expected.items()):
        return "FAIL", "Agent Gateway health contract or security flags do not match staging expectations"
    return "PASS", "Agent Gateway is directly reachable and advertises device-signature authentication"


def evaluate_agent_admin_isolation(result: dict[str, Any]) -> tuple[str, str]:
    status = int(result.get("status", 0))
    if status == 404:
        return "PASS", "Agent hostname refuses management API or website resources"
    return "FAIL", (
        "Agent hostname exposed a management or static asset route"
        if status == 200
        else f"Agent hostname boundary returned HTTP {status}; expected 404"
    )


def run(control_origin: str, gateway_origin: str) -> tuple[dict[str, Any], int]:
    checks: list[dict[str, str]] = []

    def add(section: str, status: str, detail: str) -> None:
        checks.append({"section": section, "status": status, "detail": detail})

    control_host = urllib.parse.urlsplit(control_origin).hostname
    gateway_host = urllib.parse.urlsplit(gateway_origin).hostname
    add(
        "separate_origins",
        "PASS" if control_host != gateway_host else "FAIL",
        "control and Agent Gateway use different hostnames"
        if control_host != gateway_host
        else "control and Agent Gateway must not share the same hostname",
    )

    control_result = request_once(control_origin + "/api/v1/health")
    status, detail = evaluate_control(control_result)
    add("control_access_boundary", status, detail)

    gateway_result = request_once(gateway_origin + "/agent/v1/health")
    status, detail = evaluate_gateway(gateway_result)
    add("agent_gateway_boundary", status, detail)

    for section, resource in (
        ("agent_rejects_management_api", "/api/v1/health"),
        ("agent_rejects_spa_root", "/"),
        ("agent_rejects_static_assets", "/index.html"),
    ):
        result = request_once(gateway_origin + resource)
        status, detail = evaluate_agent_admin_isolation(result)
        add(section, status, detail)

    fail_count = sum(x["status"] == "FAIL" for x in checks)
    warn_count = sum(x["status"] == "WARN" for x in checks)
    report = {
        "schema": "ssh-manager-p3.4-remote-topology-v1",
        "staging_only": True,
        "read_only": True,
        "network_calls": True,
        "secrets_sent": False,
        "control_origin": control_origin,
        "gateway_origin": gateway_origin,
        "checks": checks,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "remote_topology_ready": fail_count == 0 and warn_count == 0,
        "actual_ssh_login_proven": False,
        "cloudflare_d1_verified_state_proven": False,
    }
    return report, 2 if fail_count else (3 if warn_count else 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--staging-only",
        action="store_true",
        required=True,
        help="explicitly acknowledge that both origins belong to the isolated staging environment",
    )
    parser.add_argument("--control-url", required=True, type=https_origin)
    parser.add_argument("--gateway-url", required=True, type=https_origin)
    args = parser.parse_args()
    report, code = run(args.control_url, args.gateway_url)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
