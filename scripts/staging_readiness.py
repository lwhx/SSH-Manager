#!/usr/bin/env python3
"""P3.4 Linux staging-only evidence collector (read-only, stdlib only).

No SSH writes, no service reloads, no private-key reads, no API calls, and no
changes to Cloudflare or a VPS. NOT a proof of successful SSH authentication.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
from typing import Any

ROOT_CONFIG = pathlib.Path('/etc/ssh-manager/helper.json')
AGENT_CONFIG = pathlib.Path('/etc/ssh-manager/agent.json')
ROOT_DIR = pathlib.Path('/var/lib/ssh-manager-root')
AGENT_DIR = pathlib.Path('/var/lib/ssh-manager-agent')
ROOT_SOCK = pathlib.Path('/run/ssh-manager/helper.sock')
PROOF_SOCK = pathlib.Path('/run/ssh-manager-proof/proof.sock')
SSHD = '/usr/sbin/sshd'
SSH_IDENTITIES = frozenset({'/usr/sbin/sshd', '/usr/lib/openssh/sshd-session', '/usr/libexec/openssh/sshd-session', '/usr/libexec/sshd-session'})
EVENT = re.compile(r'^Accepted publickey for (?P<user>[a-z_][a-z0-9_-]{0,31}\$?) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d{1,5}) ssh2: ED25519 SHA256:[A-Za-z0-9+/]{43}$')
SECRET_FIELDS = frozenset({'device_key', 'private_key', 'command_private_key', 'pairing_token', 'nonce', 'token'})


def invoke(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    """Explicit allowlist of diagnostic binaries and flags; never invokes shell."""
    allowed = {'/usr/sbin/sshd', '/usr/bin/journalctl', '/usr/bin/systemctl'}
    if argv[0] not in allowed:
        raise ValueError('unapproved diagnostic executable')
    try:
        p = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''
    return p.returncode, p.stdout[:131072]


def check_meta(path: pathlib.Path, kind: str, uid: int | None, mode: int | None = None,
               forbid_other_writes: bool = True) -> tuple[str, str]:
    try:
        s = path.lstat()
    except FileNotFoundError:
        return 'WARN', 'not installed or not running'
    except OSError:
        return 'FAIL', 'cannot inspect path'
    if kind == 'file' and not stat.S_ISREG(s.st_mode):
        return 'FAIL', 'not a regular file (symlinks are not accepted)'
    if kind == 'dir' and not stat.S_ISDIR(s.st_mode):
        return 'FAIL', 'not a directory (symlinks are not accepted)'
    if kind == 'socket' and not stat.S_ISSOCK(s.st_mode):
        return 'FAIL', 'not a local Unix socket'
    if uid is not None and s.st_uid != uid:
        return 'FAIL', 'unexpected file owner'
    m = stat.S_IMODE(s.st_mode)
    if mode is not None and m != mode:
        return 'FAIL', f'unsafe mode {m:04o} (expected {mode:04o})'
    if kind == 'socket':
        # Root Helper intentionally grants the dedicated Agent group access
        # to its Unix socket (0660); reject *world* accessibility instead.
        if m & 0o007:
            return 'FAIL', 'Unix socket accessible to untrusted users'
    elif forbid_other_writes and m & 0o022:
        return 'FAIL', 'group/other write access prohibited'
    return 'PASS', 'path and ownership checked'


def get_user(name: str) -> tuple[int, int] | None:
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}\$?', name):
        return None
    try:
        u = pwd.getpwnam(name)
    except KeyError:
        return None
    return u.pw_uid, u.pw_gid


def systemd_properties(unit: str) -> dict[str, str]:
    rc, text = invoke(['/usr/bin/systemctl', 'show', unit,
                       '--property=LoadState,ActiveState,User,Group,StateDirectory,RuntimeDirectory,NoNewPrivileges',
                       '--no-pager'])
    if rc:
        return {}
    props = {}
    for line in text.splitlines():
        k, sep, v = line.partition('=')
        if sep:
            props[k] = v
    return props


def effective_options(raw: str) -> dict[str, str]:
    parsed = {}
    for line in raw.splitlines():
        k, sep, v = line.partition(' ')
        if sep:
            parsed[k.lower()] = v.strip()
    return parsed


def journal_check(records: str, login_user: str) -> tuple[int, int]:
    """Count trusted *candidates*, not successful attested sessions."""
    accepted, unsafe = 0, 0
    for line in records.splitlines():
        try:
            entry: Any = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        message = entry.get('MESSAGE')
        if not isinstance(message, str) or not message.startswith('Accepted publickey'):
            continue
        source = entry.get('_TRANSPORT')
        executable = entry.get('_EXE')
        uid = entry.get('_UID')
        pid = str(entry.get('_PID', ''))
        match = EVENT.fullmatch(message)
        if source in {'syslog', 'journal'} and executable in SSH_IDENTITIES and uid == '0' and pid.isdigit() and int(pid) > 1 and match and match.group('user') == login_user:
            accepted += 1
        else:
            unsafe += 1
    return accepted, unsafe


def run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    checks: list[dict[str, str]] = []
    def add(section: str, status: str, detail: str) -> None:
        checks.append({'section': section, 'status': status, 'detail': detail})

    add('scope', 'PASS', 'local staging host only; no writes or network calls')
    add('os', 'PASS' if sys.platform == 'linux' else 'FAIL', 'Linux OS required')
    add('permissions', 'PASS' if os.geteuid() == 0 else 'FAIL',
        'root required to examine trusted systemd and journald metadata')

    service = get_user('ssh-manager')
    add('agent_identity', 'PASS' if service else 'FAIL',
        'dedicated ssh-manager Unix account present' if service else 'dedicated account missing')
    login = get_user(args.login_user)
    add('login_identity', 'PASS' if login else 'FAIL',
        'target Linux user found' if login else 'invalid or missing target user')
    agent_uid = service[0] if service else -1

    checksums = [
        ('root_config', ROOT_CONFIG, 'file', 0, 0o600),
        ('agent_config', AGENT_CONFIG, 'file', agent_uid, 0o600),
        ('root_state', ROOT_DIR, 'dir', 0, 0o700),
        ('agent_state', AGENT_DIR, 'dir', agent_uid, 0o700),
        ('helper_socket', ROOT_SOCK, 'socket', 0, None),
        ('proof_socket', PROOF_SOCK, 'socket', 0, None),
    ]
    for section, p, kind, uid, mode in checksums:
        result, why = check_meta(p, kind, uid, mode)
        add(section, result, why)

    for unit, expected_user in (('ssh-manager-agent.service', 'ssh-manager'),
                                ('ssh-manager-helper.service', 'root')):
        p = systemd_properties(unit)
        if p.get('LoadState') != 'loaded':
            add(unit, 'WARN', 'unit not installed; cannot check live account')
        elif p.get('User', '') != expected_user:
            add(unit, 'FAIL', 'service account does not match minimum-privilege design')
        elif p.get('ActiveState') != 'active':
            add(unit, 'WARN', 'service installed but not active')
        else:
            add(unit, 'PASS', 'running under expected service account')
            desired_state = ('ssh-manager-agent' if expected_user == 'ssh-manager'
                             else 'ssh-manager-root')
            dirs = p.get('StateDirectory', '').split()
            add(unit + ':state_dir', 'PASS' if desired_state in dirs else 'FAIL',
                'expected dedicated systemd persistent state directory' if desired_state in dirs
                else 'systemd persistent directory missing or incorrect')
            if p.get('NoNewPrivileges') != 'yes':
                add(unit + ':privileges', 'WARN',
                    'NoNewPrivileges is not enabled; review the unit hardening')

    if not pathlib.Path(SSHD).is_file():
        add('sshd_syntax', 'FAIL', 'expected OpenSSH binary missing')
    else:
        rc, _ = invoke([SSHD, '-t', '-f', '/etc/ssh/sshd_config'])
        add('sshd_syntax', 'PASS' if rc == 0 else 'FAIL',
            'sshd -t succeeded' if rc == 0 else 'OpenSSH configuration could not be validated')
        if rc == 0:
            # Deliberately use the operator-supplied source and local addresses,
            # so Match rules are evaluated for the actual staging test path.
            context = f'user={args.login_user},host={args.client_ip},addr={args.client_ip},laddr={args.local_ip},lport={args.ssh_port}'
            rc, text = invoke([SSHD, '-T', '-f', '/etc/ssh/sshd_config', '-C', context])
            if rc:
                add('sshd_effective', 'FAIL', 'sshd -T -C failed for staging context')
            else:
                opts = effective_options(text)
                if opts.get('pubkeyauthentication') != 'yes':
                    add('sshd_effective', 'FAIL', 'public key authentication is not active')
                elif opts.get('authenticationmethods', 'any') != 'any':
                    add('sshd_effective', 'WARN', 'multi-factor/multi-method policy needs manual proof compatibility review')
                else:
                    add('sshd_effective', 'PASS', 'public key authentication enabled for selected context')
                # This diagnostic intentionally does not display credential paths
                # or suggest changes to PasswordAuthentication.
                add('sshd_config_change', 'PASS', 'no sshd configuration modifications attempted')

    rc, logs = invoke(['/usr/bin/journalctl', '--quiet', '--no-pager', '--output=json',
                       '--since=-2h', '-n', '500', '--identifier=sshd', '--identifier=sshd-session'])
    if rc:
        add('trusted_journal', 'WARN', 'journalctl unavailable or permission denied')
    else:
        good, other = journal_check(logs, args.login_user)
        if good:
            add('trusted_journal', 'PASS', 'trusted SSH accepted-publickey candidates exist (not an attestation)')
        elif other:
            add('trusted_journal', 'WARN', 'SSH messages found but they lack trusted origin or match')
        else:
            add('trusted_journal', 'WARN', 'no recent matching SSH authentication event')

    result = {
        'schema': 'ssh-manager-p3.4-host-readiness-v1',
        'staging_only': True,
        'read_only': True,
        'ssh_changes': False,
        'private_keys_examined': False,
        'actual_ssh_login_proven': False,
        'cloudflare_remote_e2e_verified': False,
        'checks': checks,
        'fail_count': sum(x['status'] == 'FAIL' for x in checks),
        'warn_count': sum(x['status'] == 'WARN' for x in checks),
    }
    return result, 2 if result['fail_count'] else 0


def ip_address(value: str) -> str:
    import ipaddress
    return str(ipaddress.ip_address(value))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging-only', action='store_true', required=True,
                        help='explicitly acknowledge that this is an isolated staging VPS')
    parser.add_argument('--login-user', required=True)
    parser.add_argument('--client-ip', required=True, type=ip_address,
                        help='IP that sshd sees as the client; not your private key')
    parser.add_argument('--local-ip', required=True, type=ip_address,
                        help='IP sshd listens on for the staging connection')
    parser.add_argument('--ssh-port', type=int, default=22)
    args = parser.parse_args()
    if not 1 <= args.ssh_port <= 65535:
        parser.error('--ssh-port must be from 1 through 65535')
    report, status = run(args)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(status)

if __name__ == '__main__':
    main()
