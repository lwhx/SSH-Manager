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
               forbid_other_writes: bool = True, expected_gid: int | None = None,
               required: bool = True) -> tuple[str, str]:
    try:
        s = path.lstat()
    except FileNotFoundError:
        return ('FAIL' if required else 'WARN'), 'required path missing' if required else 'not installed or not running'
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
    if expected_gid is not None and s.st_gid != expected_gid:
        return 'FAIL', 'unexpected file group'
    m = stat.S_IMODE(s.st_mode)
    if mode is not None and m != mode:
        return 'FAIL', f'unsafe mode {m:04o} (expected {mode:04o})'
    if kind == 'socket':
        # Root Helper intentionally grants the dedicated Agent group access
        # to its Unix socket (0660); reject *world* accessibility instead.
        if m & 0o007:
            return 'FAIL', 'Unix socket accessible to untrusted users'
        if m != 0o660:
            return 'FAIL', 'Unix socket must have mode 0660'
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


def helper_scope_matches(raw: object, args: argparse.Namespace) -> bool:
    """Compare only non-secret fields; never echo any config value."""
    if not isinstance(raw, dict):
        return False
    safe = raw
    return (
        safe.get('node_id') == args.node_id
        and safe.get('allowed_user') == args.login_user
        and safe.get('client_address') == args.client_ip
        and safe.get('local_address') == args.local_ip
        and type(safe.get('ssh_port')) is int
        and safe.get('ssh_port') == args.ssh_port
        and safe.get('enable_ssh_proof') is True
    )


def verify_helper_scope(path: pathlib.Path, args: argparse.Namespace) -> tuple[str, str]:
    """Check root-owned non-secret Helper configuration without printing it."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as f:
            if os.fstat(f.fileno()).st_size > 8192:
                return 'FAIL', 'Root Helper config too large'
            content = f.read(8193)
        if len(content) > 8192:
            return 'FAIL', 'Root Helper config too large'
        decoded = json.loads(content)
    except (OSError, ValueError, UnicodeError):
        return 'FAIL', 'cannot safely read non-secret Root Helper configuration'
    return ('PASS', 'selected node and login context matches Root Helper') if helper_scope_matches(decoded, args) else (
        'FAIL', 'Root Helper node, login path or explicit SSH proof setting differs from requested staging context'
    )


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
    agent_gid = service[1] if service else -1
    login_gid = login[1] if login else -1

    checksums = [
        ('root_config', ROOT_CONFIG, 'file', 0, 0o600),
        ('agent_config', AGENT_CONFIG, 'file', agent_uid, 0o600),
        ('root_state', ROOT_DIR, 'dir', 0, 0o700),
        ('agent_state', AGENT_DIR, 'dir', agent_uid, 0o700),
        ('helper_socket', ROOT_SOCK, 'socket', 0, 0o660),
        ('proof_socket', PROOF_SOCK, 'socket', 0, 0o660),
    ]
    for section, p, kind, uid, mode in checksums:
        expected_gid = agent_gid if section == 'helper_socket' else (login_gid if section == 'proof_socket' else None)
        result, why = check_meta(p, kind, uid, mode, expected_gid=expected_gid)
        add(section, result, why)
        if section == 'root_config' and result == 'PASS':
            scope_status, reason = verify_helper_scope(p, args)
            add('helper_scope', scope_status, reason)

    for unit, expected_user in (('ssh-manager-agent.service', 'ssh-manager'),
                                ('ssh-manager-helper.service', 'root')):
        p = systemd_properties(unit)
        if p.get('LoadState') != 'loaded':
            add(unit, 'FAIL', 'required service not installed')
            continue
        add(unit + ':account', 'PASS' if p.get('User') == expected_user else 'FAIL',
            'expected service user' if p.get('User') == expected_user else 'wrong service user')
        add(unit + ':group', 'PASS' if p.get('Group') == 'ssh-manager' else 'FAIL',
            'expected dedicated service group' if p.get('Group') == 'ssh-manager' else 'wrong service group')
        add(unit + ':active', 'PASS' if p.get('ActiveState') == 'active' else 'FAIL',
            'service active' if p.get('ActiveState') == 'active' else 'required service not active')
        desired_state = 'ssh-manager-agent' if expected_user == 'ssh-manager' else 'ssh-manager-root'
        dirs = p.get('StateDirectory', '').split()
        add(unit + ':state_dir', 'PASS' if desired_state in dirs else 'FAIL',
            'dedicated persistent state configured' if desired_state in dirs else 'persistent state directory missing')
        add(unit + ':privileges', 'PASS' if p.get('NoNewPrivileges') == 'yes' else 'FAIL',
            'NoNewPrivileges enabled' if p.get('NoNewPrivileges') == 'yes' else 'privilege hardening disabled')

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
                problems = []
                if opts.get('pubkeyauthentication') != 'yes':
                    problems.append('public key authentication inactive')
                if opts.get('authorizedkeysfile') not in {
                    '.ssh/authorized_keys', '.ssh/authorized_keys .ssh/authorized_keys2'
                }:
                    problems.append('unsupported authorized_keys location')
                if opts.get('authenticationmethods', 'any') != 'any':
                    problems.append('nonstandard AuthenticationMethods')
                if args.login_user == 'root' and opts.get('permitrootlogin') not in {
                    'yes', 'prohibit-password', 'without-password'
                }:
                    problems.append('root key login disabled')
                add('sshd_effective', 'FAIL' if problems else 'PASS',
                    '; '.join(problems) if problems else 'daily key policy compatible')
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
        'preflight_ready': all(x['status'] == 'PASS' for x in checks),
    }
    return result, 2 if result['fail_count'] else (3 if result['warn_count'] else 0)


def ip_address(value: str) -> str:
    import ipaddress
    return str(ipaddress.ip_address(value))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging-only', action='store_true', required=True,
                        help='explicitly acknowledge that this is an isolated staging VPS')
    parser.add_argument('--login-user', required=True)
    parser.add_argument('--node-id', required=True, help='selected single-VPS node UUID in SSH Manager')
    parser.add_argument('--client-ip', required=True, type=ip_address,
                        help='IP that sshd sees as the client; not your private key')
    parser.add_argument('--local-ip', required=True, type=ip_address,
                        help='IP sshd listens on for the staging connection')
    parser.add_argument('--ssh-port', type=int, default=22)
    args = parser.parse_args()
    if not 1 <= args.ssh_port <= 65535:
        parser.error('--ssh-port must be from 1 through 65535')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', args.node_id):
        parser.error('--node-id must be a canonical lowercase UUID')
    report, status = run(args)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(status)

if __name__ == '__main__':
    main()
