"""Transactional SSH proof verification smoke tests against real D1 schema.

Tests the same WHERE predicates used by the Gateway's D1 batch. They do not
contact a VPS, mint a proof, or change SSH authentication configuration.
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path

MIGRATIONS = Path(__file__).resolve().parents[1] / "packages" / "db" / "migrations"
NODE = "00000000-0000-4000-8000-000000000001"
KEY = "10000000-0000-4000-8000-000000000001"
USER = "20000000-0000-4000-8000-000000000001"
VERIFY = "30000000-0000-4000-8000-000000000001"
PROOF = "40000000-0000-4000-8000-000000000001"
REVISION = "a" * 64
NONCE_HASH = "b" * 64

VERIFY_SQL = (
    "UPDATE ssh_verifications SET status='VERIFIED',verified_at=?,proof_id=?,proof_hash=? "
    "WHERE id=? AND node_id=? AND status='PENDING' AND prepared_at IS NOT NULL "
    "AND expires_at>? AND nonce_hash=? AND login_user=? AND key_fingerprint=? "
    "AND config_revision=? AND public_key_id=? "
    "AND EXISTS (SELECT 1 FROM nodes WHERE id=? AND login_user=? AND config_revision=? "
    "AND init_stage='WAITING_VERIFICATION') "
    "AND EXISTS (SELECT 1 FROM public_keys WHERE id=? AND purpose='daily' AND active=1) "
    "AND EXISTS (SELECT 1 FROM node_keys WHERE node_id=? AND public_key_id=? "
    "AND login_user=? AND purpose='daily' AND state='installed')"
)
MARK_KEY_SQL = (
    "UPDATE node_keys SET verified_at=COALESCE(verified_at,?) "
    "WHERE node_id=? AND public_key_id=? AND login_user=? AND purpose='daily' AND state='installed' "
    "AND EXISTS (SELECT 1 FROM ssh_verifications WHERE id=? AND node_id=? "
    "AND status='VERIFIED' AND proof_id=?)"
)
MARK_NODE_SQL = (
    "UPDATE nodes SET init_stage='KEY_VERIFIED' WHERE id=? "
    "AND init_stage='WAITING_VERIFICATION' AND config_revision=? "
    "AND EXISTS (SELECT 1 FROM ssh_verifications WHERE id=? AND node_id=? "
    "AND status='VERIFIED' AND proof_id=?)"
)
AUDIT_SQL = (
    "INSERT OR IGNORE INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "
    "SELECT ?,?,?,'ssh.verification.proof',NULL,'VERIFIED',?,? "
    "WHERE EXISTS (SELECT 1 FROM ssh_verifications WHERE id=? AND node_id=? "
    "AND status='VERIFIED' AND proof_id=?)"
)

class VerifiedTransitionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.execute("PRAGMA foreign_keys=ON")
        for file in sorted(MIGRATIONS.glob("*.sql")):
            self.db.executescript(file.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO users(id,email,role,created_at) VALUES (?,?,?,?)",
            (USER, "owner@example.com", "owner", 1),
        )
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,config_revision,init_stage,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (NODE, "staging", "192.0.2.10", "root", REVISION, "WAITING_VERIFICATION", 1),
        )
        self.db.execute(
            "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,created_by,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (KEY, "daily", "daily", "ssh-ed25519", "test-public-key", "SHA256:staging", 1, USER, 1),
        )
        self.db.execute(
            "INSERT INTO node_keys(id,node_id,public_key_id,login_user,purpose,state) "
            "VALUES (?,?,?,?,?,?)",
            ("50000000-0000-4000-8000-000000000001", NODE, KEY, "root", "daily", "installed"),
        )
        self.db.execute(
            "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,config_revision,nonce_hash,"
            "status,created_at,expires_at,public_key_id,issued_by,prepared_at) "
            "VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?,?)",
            (VERIFY, NODE, "SHA256:staging", "root", REVISION, NONCE_HASH, 100, 300, KEY, USER, 120),
        )

    def tearDown(self):
        self.db.close()

    def snapshot(self):
        return (
            self.db.execute("SELECT status,proof_id FROM ssh_verifications WHERE id=?", (VERIFY,)).fetchone(),
            self.db.execute("SELECT init_stage FROM nodes WHERE id=?", (NODE,)).fetchone(),
            self.db.execute("SELECT verified_at FROM node_keys WHERE node_id=?", (NODE,)).fetchone(),
            self.db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0],
        )

    def verify(self, *, time=150, fail_midway=False, nonce_hash=NONCE_HASH):
        self.db.execute("SAVEPOINT proof_transition")
        try:
            proof = PROOF
            changed = self.db.execute(
                VERIFY_SQL,
                (time, proof, "signed-payload-hash", VERIFY, NODE, time, nonce_hash, "root",
                 "SHA256:staging", REVISION, KEY, NODE, "root", REVISION, KEY, NODE, KEY, "root"),
            ).rowcount
            if changed != 1:
                raise ValueError("claim was not uniquely accepted")
            updated_key = self.db.execute(
                MARK_KEY_SQL, (time, NODE, KEY, "root", VERIFY, NODE, proof)
            ).rowcount
            updated_node = self.db.execute(
                MARK_NODE_SQL, (NODE, REVISION, VERIFY, NODE, proof)
            ).rowcount
            if updated_key != 1 or updated_node != 1:
                raise ValueError("node and key must be updated in this transaction")
            if fail_midway:
                raise RuntimeError("simulated D1 write failure before audit")
            audited = self.db.execute(
                AUDIT_SQL, (proof, USER, NODE, "root-proof=" + proof, time, VERIFY, NODE, proof)
            ).rowcount
            if audited != 1:
                raise ValueError("human-attributed root proof audit was not inserted")
        except Exception:
            self.db.execute("ROLLBACK TO proof_transition")
            self.db.execute("RELEASE proof_transition")
            raise
        else:
            self.db.execute("RELEASE proof_transition")

    def test_atomic_verified_records_all_four_entities(self):
        self.verify()
        self.assertEqual(self.snapshot(), (
            ("VERIFIED", PROOF), ("KEY_VERIFIED",), (150,), 1,
        ))
        self.assertEqual(
            self.db.execute("SELECT actor_id,action FROM audit_logs WHERE id=?", (PROOF,)).fetchone(),
            (USER, "ssh.verification.proof"),
        )
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.snapshot(), before, "replayed signed proof changed persisted state")

    def test_write_failure_rolls_back_verified_and_all_other_effects(self):
        before = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.verify(fail_midway=True)
        self.assertEqual(self.snapshot(), before)

    def test_invalidated_challenge_and_stale_install_never_verify(self):
        for sql, parameters in (
            ("UPDATE ssh_verifications SET prepared_at=NULL WHERE id=?", (VERIFY,)),
            ("UPDATE ssh_verifications SET expires_at=149 WHERE id=?", (VERIFY,)),
            ("UPDATE node_keys SET state='removed' WHERE node_id=?", (NODE,)),
            ("UPDATE public_keys SET active=0 WHERE id=?", (KEY,)),
            ("UPDATE nodes SET config_revision=? WHERE id=?", ("c"*64, NODE)),
        ):
            with self.subTest(sql=sql):
                self.db.execute("SAVEPOINT isolated")
                self.db.execute(sql, parameters)
                prior = self.snapshot()
                with self.assertRaises(ValueError):
                    self.verify()
                self.assertEqual(self.snapshot(), prior)
                self.db.execute("ROLLBACK TO isolated")
                self.db.execute("RELEASE isolated")

    def test_wrong_nonce_hash_never_accepts(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.verify(nonce_hash="f"*64)
        self.assertEqual(self.snapshot(), before)

if __name__ == "__main__":
    unittest.main()
