#!/usr/bin/env python3
"""Read-only P3.3 staging VPS compatibility check.

Never changes sshd, authorized_keys, users, firewall, or systemd services.
Only run against an isolated staging VPS; does not attest real SSH success.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

HELPER_CONFIG = Path("/etc/ssh-manager/helper.json")
ROOT_PROOF_KEY = Path("/var/lib/ssh-manager-root/proof_ed25519")
ROOT_PROOF_SOCKET = Path("/run/ssh-manager-proof/proof.sock")
SSHD = "/usr/sbin/sshd"
JOURNALCTL = "/usr/bin/journalctl"
SSHD_EXECUTABLES = {
    "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session",
    "/usr/libexec/openssh/sshd-session",
    "/usr/libexec/sshd-session",
}
SSH_ACCEPTED_ED25519 = re.compile(
    r"^Accepted publickey for [a-z_][a-z0-9_-]{0,31}\$? "
    r"from [0-9a-fA-F:.]+ port [0-9]{1,5} ssh2: "
    r"ED25519 SHA256:[A-Za-z0-9+/]{43}$"
)
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")


def root_regular_private(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def root_private_directory(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) & 0o077 == 0
    )


def parse_sshd_effective(output: str) -> dict[str, str]:
    effective: dict[str, str] = {}
    for line in output.splitlines():
        name, separator, value = line.partition(" ")
        if separator and name and value:
            effective[name.lower()] = value.strip()
    return effective


def compatible_effective(effective: dict[str, str], login_user: str) -> list[str]:
    problems: list[str] = []
    if effective.get("pubkeyauthentication") != "yes":
        problems.append("publickeyauthentication is not enabled")
    allowed_keys = {
        ".ssh/authorized_keys",
        ".ssh/authorized_keys .ssh/authorized_keys2",
    }
    if effective.get("authorizedkeysfile") not in allowed_keys:
        problems.append("unsupported AuthorizedKeysFile")
    if effective.get("authenticationmethods", "any") != "any":
        problems.append("nonstandard AuthenticationMethods")
    if login_user == "root" and effective.get("permitrootlogin") not in {
        "yes", "prohibit-password", "without-password"
    }:
        problems.append("root SSH publickey login blocked")
    return problems


def has_trusted_ssh_auth(records: str) -> bool:
    for line in records.splitlines():
        try:
            item: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        if not (
            item.get("_TRANSPORT") in {"syslog", "journal"}
            and item.get("_EXE") in SSHD_EXECUTABLES
            and item.get("_UID") == "0"
            and str(item.get("_PID", "")).isdigit()
            and int(item["_PID"]) > 1
            and isinstance(item.get("MESSAGE"), str)
            and SSH_ACCEPTED_ED25519.fullmatch(item["MESSAGE"])
        ):
            continue
        return True
    return False


def command(argv: list[str], *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=timeout
    )


def run(config_path: Path) -> tuple[dict[str, Any], int]:
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, reason: str) -> None:
        checks.append({"check": name, "status": status, "reason": reason})

    if sys.platform != "linux":
        add("os", "FAIL", "Only Linux staging VPS is supported")
    else:
        add("os", "PASS", "Linux host detected")
    if os.geteuid() != 0:
        add("permission", "FAIL", "Run diagnostics as root; no files will be changed")
    else:
        add("permission", "PASS", "Privileged diagnostics allowed")
    if not Path("/proc/self/status").exists():
        add("procfs", "FAIL", "/proc/status unavailable")
    else:
        add("procfs", "PASS", "Kernel process inspection available")

    config: dict[str, Any] = {}
    if not root_regular_private(config_path):
        add("helper_config", "FAIL", "Root-owned, regular 0600 Helper config missing")
    else:
        try:
            if config_path.stat().st_size > 8192:
                raise ValueError("Helper config exceeds size limit")
            value = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("Helper config is not an object")
            config = value
            add("helper_config", "PASS", "Helper config read without exposing keys")
        except (OSError, ValueError, UnicodeError) as exc:
            add("helper_config", "FAIL", f"Cannot parse Helper config: {type(exc).__name__}")

    user = config.get("allowed_user")
    try:
        if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}\$?", user):
            raise ValueError("invalid Linux user")
        pwd.getpwnam(user)
        add("linux_user", "PASS", "Configured Linux user exists")
    except (KeyError, ValueError):
        add("linux_user", "FAIL", "Configured Linux user unavailable")

    try:
        if not UUID.fullmatch(str(config["node_id"])):
            raise ValueError("invalid node ID")
        ipaddress.ip_address(str(config["client_address"]))
        ipaddress.ip_address(str(config["local_address"]))
        port = int(config["ssh_port"])
        if not 1 <= port <= 65535:
            raise ValueError("invalid SSH port")
        add("ssh_context", "PASS", "Explicit node, source, local IP and port configured")
    except (KeyError, ValueError, TypeError):
        add("ssh_context", "FAIL", "Helper SSH inspection context is invalid")

    if not Path(SSHD).is_file():
        add("sshd", "FAIL", "Expected /usr/sbin/sshd missing")
    else:
        try:
            syntax = command([SSHD, "-t", "-f", "/etc/ssh/sshd_config"])
            if syntax.returncode:
                add("sshd", "FAIL", "OpenSSH syntax validation failed")
            else:
                add("sshd", "PASS", "OpenSSH syntax validated without modifying it")
                if isinstance(user, str) and all(
                    key in config for key in ("client_address", "local_address", "ssh_port")
                ):
                    match_context = (
                        f"user={user},host={config['client_address']},"
                        f"addr={config['client_address']},laddr={config['local_address']},"
                        f"lport={config['ssh_port']}"
                    )
                    effective = command(
                        [SSHD, "-T", "-f", "/etc/ssh/sshd_config", "-C", match_context]
                    )
                    if effective.returncode:
                        add("effective_policy", "FAIL", "Cannot inspect effective OpenSSH settings")
                    else:
                        problems = compatible_effective(
                            parse_sshd_effective(effective.stdout), user
                        )
                        add(
                            "effective_policy",
                            "FAIL" if problems else "PASS",
                            "; ".join(problems) if problems else "Daily-key policy eligible",
                        )
        except (OSError, subprocess.TimeoutExpired):
            add("sshd", "FAIL", "OpenSSH validation unavailable or timed out")

    if not root_private_directory(ROOT_PROOF_KEY.parent):
        add("proof_key_dir", "WARN", "Root-only state directory missing or unsafe")
    elif not root_regular_private(ROOT_PROOF_KEY):
        add("proof_key", "WARN", "Root-only proof private key not initialized")
    else:
        add("proof_key", "PASS", "Root proof key stored as root:root 0600")

    if not bool(config.get("enable_ssh_proof", False)):
        add("proof_flag", "WARN", "Proof socket feature disabled (safe default)")
    else:
        add("proof_flag", "PASS", "Proof socket explicitly enabled in Helper config")
    try:
        mode = ROOT_PROOF_SOCKET.lstat().st_mode
        if stat.S_ISSOCK(mode):
            add("proof_socket", "PASS", "Local Unix proof socket exists")
        else:
            add("proof_socket", "FAIL", "Expected proof socket path is not a socket")
    except FileNotFoundError:
        add("proof_socket", "WARN", "Local proof socket not running")

    if not Path(JOURNALCTL).is_file():
        add("journald", "WARN", "journalctl missing; no trusted authentication evidence")
    elif os.geteuid() != 0:
        add("journald", "WARN", "Requires root to inspect trusted journal metadata")
    else:
        try:
            records = command(
                [JOURNALCTL, "--quiet", "--no-pager", "--output=json",
                 "--since=-2h", "-n", "250", "--identifier=sshd",
                 "--identifier=sshd-session"],
                timeout=8,
            )
            if records.returncode != 0:
                add("journald", "WARN", "SSH journal unavailable on this host")
            elif has_trusted_ssh_auth(records.stdout):
                add("journald", "PASS", "Root-owned OpenSSH accepted-publickey event seen")
            else:
                add("journald", "WARN", "No compatible trusted SSH auth event in last 2h")
        except (OSError, subprocess.TimeoutExpired):
            add("journald", "WARN", "SSH journal inspection unavailable")

    report = {
        "tool": "ssh-manager-p3-staging-preflight",
        "read_only": True,
        "actual_ssh_login_proven": False,
        "cloudflare_end_to_end_verified": False,
        "ssh_configuration_modified": False,
        "checks": checks,
        "failed_count": sum(c["status"] == "FAIL" for c in checks),
        "warning_count": sum(c["status"] == "WARN" for c in checks),
    }
    return report, 2 if report["failed_count"] else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--staging-only",
        action="store_true",
        help="Explicitly acknowledge this is for an isolated test VPS",
    )
    parser.add_argument(
        "--config", type=Path, default=HELPER_CONFIG,
        help="Root-owned Helper config, defaults to the standard path",
    )
    args = parser.parse_args()
    if not args.staging_only:
        parser.error("refusing without --staging-only; production VPS usage is prohibited")
    result, code = run(args.config)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(code)
