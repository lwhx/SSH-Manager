"""P3.4 collector tests; do not probe this runner's host during tests."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
import socket
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parent / 'staging_readiness.py'
spec = importlib.util.spec_from_file_location('staging_readiness', MODULE)
assert spec is not None and spec.loader is not None
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)


class CollectorTests(unittest.TestCase):
    def test_trusted_auth_requires_syslog_or_native_transport(self):
        event = ('Accepted publickey for root from 192.0.2.99 port 45119 ssh2: '
                 'ED25519 SHA256:' + 'A' * 43)
        source = {'_EXE': '/usr/sbin/sshd', '_UID': '0', '_PID': '1420',
                  '_TRANSPORT': 'syslog', 'MESSAGE': event}
        self.assertEqual(sr.journal_check(json.dumps(source), 'root'), (1, 0))
        for alteration in ({'_TRANSPORT': 'stdout'}, {'_UID': '1000'},
                           {'_PID': '0'}, {'_EXE': '/usr/bin/logger'},
                           {'MESSAGE': event.replace('root', 'admin')},
                           {'MESSAGE': event.replace('publickey', 'password')}):
            changed = {**source, **alteration}
            good, bad = sr.journal_check(json.dumps(changed), 'root')
            self.assertEqual(good, 0)
            # Non-publickey entries are ignored rather than counting as unsafe.
            self.assertIn(bad, (0, 1))
        omitted = {k: v for k, v in source.items() if k != '_TRANSPORT'}
        self.assertEqual(sr.journal_check(json.dumps(omitted), 'root'), (0, 1))

    def test_secret_field_in_helper_configuration_blocks_readiness(self):
        args = argparse.Namespace(node_id='10000000-0000-4000-8000-000000000001',
                                  login_user='root', client_ip='192.0.2.10',
                                  local_ip='192.0.2.11', ssh_port=22)
        configuration = {'node_id': args.node_id, 'allowed_user': 'root',
                         'client_address': args.client_ip, 'local_address': args.local_ip,
                         'ssh_port': 22, 'enable_ssh_proof': True,
                         'private_key': 'should-never-be-in-this-config'}
        self.assertFalse(sr.helper_scope_matches(configuration, args))

    def test_no_file_symlink_or_permission_bypass(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'agent.json'
            path.write_text('not-a-secret-test')
            path.chmod(0o600)
            uid = os.geteuid()
            self.assertEqual(sr.check_meta(path, 'file', uid, 0o600)[0], 'PASS')
            link = Path(d) / 'alias'
            link.symlink_to(path)
            self.assertEqual(sr.check_meta(link, 'file', uid, 0o600)[0], 'FAIL')
            path.chmod(0o644)
            self.assertEqual(sr.check_meta(path, 'file', uid, 0o600)[0], 'FAIL')

    def test_systemd_missing_blocks_preflight(self):
        args = argparse.Namespace(node_id='10000000-0000-4000-8000-000000000001', login_user='root', client_ip='192.0.2.10',
                                  local_ip='192.0.2.11', ssh_port=22)
        with patch.object(sr, 'invoke', return_value=(127, '')), \
             patch.object(sr, 'get_user', return_value=None), \
             patch.object(sr, 'check_meta', return_value=('WARN','not installed')), \
             patch.object(sr.pathlib.Path, 'is_file', return_value=False), \
             patch.object(sr.os, 'geteuid', return_value=0):
            doc, code = sr.run(args)
        self.assertEqual(code, 2)
        self.assertFalse(doc['actual_ssh_login_proven'])
        self.assertFalse(doc['cloudflare_remote_e2e_verified'])
        self.assertFalse(doc['ssh_changes'])
        self.assertFalse(doc['preflight_ready'])
        self.assertTrue(any(c['status'] == 'FAIL' for c in doc['checks']))

    def test_unix_socket_may_be_group_writable_but_not_world_writable(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'helper.sock'
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(p))
                p.chmod(0o660)
                self.assertEqual(sr.check_meta(p, 'socket', os.geteuid())[0], 'PASS')
                p.chmod(0o666)
                self.assertEqual(sr.check_meta(p, 'socket', os.geteuid())[0], 'FAIL')
            finally:
                sock.close()

    def test_helper_scope_requires_exact_node_login_and_explicit_proof_flag(self):
        args = argparse.Namespace(node_id='10000000-0000-4000-8000-000000000001',
                                  login_user='root', client_ip='192.0.2.10',
                                  local_ip='192.0.2.11', ssh_port=22)
        config = {'node_id': args.node_id, 'allowed_user': 'root',
                  'client_address': args.client_ip, 'local_address': args.local_ip,
                  'ssh_port': 22, 'enable_ssh_proof': True}
        self.assertTrue(sr.helper_scope_matches(config, args))
        for key, value in (('node_id','different'), ('allowed_user','ubuntu'),
                           ('client_address','203.0.113.9'), ('ssh_port', 2200),
                           ('enable_ssh_proof', False)):
            self.assertFalse(sr.helper_scope_matches({**config,key:value}, args))
        self.assertFalse(sr.helper_scope_matches({**config,'ssh_port':True}, args))
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory) / 'helper.json'
            p.write_text(json.dumps(config))
            self.assertEqual(sr.verify_helper_scope(p,args)[0], 'PASS')
            p.write_text('{garbled')
            self.assertEqual(sr.verify_helper_scope(p,args)[0], 'FAIL')

    def test_wrong_socket_group_blocks_staging(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'helper.sock'
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(str(p))
                p.chmod(0o660)
                self.assertEqual(sr.check_meta(p, 'socket', os.geteuid(),
                                               0o660, expected_gid=os.getegid())[0], 'PASS')
                self.assertEqual(sr.check_meta(p, 'socket', os.geteuid(),
                                               0o660, expected_gid=os.getegid() + 1)[0], 'FAIL')
            finally:
                sock.close()

    def test_missing_required_files_fail_not_warn(self):
        p = Path('/unlikely/p3-4-test-absent/ssh-manager.sock')
        self.assertEqual(sr.check_meta(p, 'socket', 0, 0o660)[0], 'FAIL')
        self.assertEqual(sr.check_meta(p, 'socket', 0, 0o660, required=False)[0], 'WARN')

    def test_options_and_binaries_are_not_executable_injections(self):
        self.assertEqual(sr.effective_options('pubkeyauthentication yes\npasswordauthentication no\n')['pubkeyauthentication'], 'yes')
        with self.assertRaises(ValueError):
            sr.invoke(['/bin/bash', '-c', 'touch /tmp/unsafe'])
        self.assertIsNone(sr.get_user('root; echo unsafe'))

if __name__ == '__main__':
    unittest.main()
