"""Read-only staging diagnostic logic tests: no VPS commands are executed."""
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parent / "staging_proof_preflight.py"
spec = importlib.util.spec_from_file_location("staging_preflight", MODULE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules["staging_preflight"] = module
spec.loader.exec_module(module)

class StagingPreflightTests(unittest.TestCase):
    def test_proof_journald_fails_closed_on_forged_exe_and_user(self):
        fingerprint = "WqyC1TNJwaA73QFZwyV9a7G2SpMUEMDwVZ7OEWHsMmg"
        message = ("Accepted publickey for root from 203.0.113.9 "
                   "port 54321 ssh2: ED25519 SHA256:" + fingerprint)
        valid = {"_EXE": "/usr/sbin/sshd", "_UID": "0", "_PID": "123", "_TRANSPORT": "syslog",
                 "MESSAGE": message}
        self.assertTrue(module.has_trusted_ssh_auth(json.dumps(valid)))
        self.assertFalse(module.has_trusted_ssh_auth(json.dumps({k:v for k,v in valid.items() if k!="_TRANSPORT"})))
        for change in (
            {"_EXE": "/usr/bin/logger"},
            {"_TRANSPORT": "stdout"},
            {"_TRANSPORT": "kernel"},
            {"_UID": "1000"},
            {"_PID": "-1"},
            {"MESSAGE": message + " injected"},
            {"MESSAGE": message.replace("publickey", "password")},
        ):
            altered = {**valid, **change}
            self.assertFalse(module.has_trusted_ssh_auth(json.dumps(altered)))

    def test_effective_policy_blocks_weaker_or_unsupported_methods(self):
        ok = module.parse_sshd_effective(
            "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"
            "authenticationmethods any\npermitrootlogin prohibit-password\n"
        )
        self.assertEqual(module.compatible_effective(ok, "root"), [])
        self.assertTrue(module.compatible_effective(
            {**ok, "authorizedkeysfile": "/tmp/keys"}, "root"
        ))
        self.assertTrue(module.compatible_effective(
            {**ok, "authenticationmethods": "publickey,password"}, "root"
        ))
        self.assertTrue(module.compatible_effective(
            {**ok, "permitrootlogin": "no"}, "root"
        ))

    def test_proof_key_mode_checks_fail_on_symlink(self):
        if hasattr(module.os, "geteuid") and module.os.geteuid() != 0:
            self.skipTest("requires root-owned fixture")
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "proof.key"
            key.write_text("test")
            key.chmod(0o600)
            self.assertTrue(module.root_regular_private(key))
            link = Path(tmp) / "link"
            link.symlink_to(key)
            self.assertFalse(module.root_regular_private(link))
            key.chmod(0o644)
            self.assertFalse(module.root_regular_private(key))

if __name__ == "__main__":
    unittest.main()
