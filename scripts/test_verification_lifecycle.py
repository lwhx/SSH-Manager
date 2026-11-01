#!/usr/bin/env python3
"""Exercise the verification-start/cancel SQL using the real, local D1 schema.

Never accesses Cloudflare, production, or an SSH server. The SQL below mirrors
apps/control-worker/src/verificationLifecycle.ts in its exact D1.batch order.
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path

MIGRATIONS = Path(__file__).resolve().parents[1] / "packages/db/migrations"
NODE = "10000000-0000-4000-8000-000000000001"
OWNER = "20000000-0000-4000-8000-000000000001"
KEY = "30000000-0000-4000-8000-000000000001"
REVISION = "a" * 64
AT = 1800000000


class VerificationLifecycleSqlTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for migration in sorted(MIGRATIONS.glob("*.sql")):
            self.db.executescript(migration.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO users(id,email,role,created_at) VALUES (?,?,?,?)",
            (OWNER, "owner@fixture.invalid", "owner", AT - 100)
        )
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,status,init_stage,"
            "config_revision,last_seen_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (NODE, "staging-fixture", "192.0.2.4", "root", "online",
             "WAITING_VERIFICATION", REVISION, AT, AT - 100)
        )
        self.db.execute(
            "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,"
            "version,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (KEY, "daily", "fixture", "ssh-ed25519", "fixture-public", "SHA256:fixture",
             1, OWNER, AT)
        )
        self.db.execute(
            "INSERT INTO node_keys(id,node_id,public_key_id,login_user,purpose,state) "
            "VALUES (?,?,?,?,?,?)",
            ("40000000-0000-4000-8000-000000000001", NODE, KEY,
             "root", "daily", "installed")
        )
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def start(self, vid="verification-1", opid="operation-1", audit="audit-start"):
        with self.db:
            self.db.execute(
                "UPDATE ssh_verifications SET status='EXPIRED' "
                "WHERE node_id=? AND status='PENDING' AND expires_at<=?",
                (NODE, AT)
            )
            challenge = self.db.execute(
                "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,"
                "config_revision,nonce_hash,status,created_at,expires_at,public_key_id,issued_by) "
                "SELECT ?,?,?,?,?,?,'PENDING',?,?,?,? WHERE EXISTS ("
                "SELECT 1 FROM nodes n JOIN public_keys k "
                "ON k.id=? AND k.purpose='daily' AND k.active=1 "
                "WHERE n.id=? AND n.status='online' AND n.last_seen_at>? "
                "AND n.init_stage='WAITING_VERIFICATION' AND n.login_user=? "
                "AND n.config_revision=? "
                "AND EXISTS (SELECT 1 FROM node_keys nk "
                "WHERE nk.node_id=n.id AND nk.public_key_id=k.id "
                "AND nk.login_user=n.login_user AND nk.purpose='daily' "
                "AND nk.state='installed'))",
                (vid, NODE, "SHA256:fixture", "root", REVISION, "hashed-secret",
                 AT, AT + 300, KEY, OWNER, KEY, NODE, AT - 90, "root", REVISION)
            )
            operation = self.db.execute(
                "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"
                "expected_revision,command_json,signature,status,created_at,expires_at) "
                "SELECT ?,?,'ssh.verification.prepare',?,?,?,?,?,'CREATED',?,? "
                "WHERE changes()=1",
                (opid, NODE, OWNER, "verify-" + vid, REVISION,
                 '{"id":"signed-fixture"}', "signed-fixture", AT, AT + 45)
            )
            audited = self.db.execute(
                "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,"
                "result,reason,created_at) "
                "SELECT ?,?,?,'ssh.verification.start',?,'PENDING',NULL,? "
                "WHERE changes()=1",
                (audit, OWNER, NODE, vid, AT)
            )
            return challenge.rowcount, operation.rowcount, audited.rowcount

    def cancel(self, vid="verification-1", audit="audit-cancel", at=AT + 10):
        with self.db:
            updated = self.db.execute(
                "UPDATE ssh_verifications SET status='CANCELLED',invalidated_at=? "
                "WHERE id=? AND node_id=? AND status='PENDING' AND expires_at>?",
                (at, vid, NODE, at)
            )
            audited = self.db.execute(
                "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,"
                "result,reason,created_at) "
                "SELECT ?,?,?,'ssh.verification.cancel',?,'CANCELLED',NULL,? "
                "WHERE changes()=1",
                (audit, OWNER, NODE, vid, at)
            )
            return updated.rowcount, audited.rowcount

    def snapshot(self):
        return (
            self.db.execute("SELECT id,status FROM ssh_verifications ORDER BY id").fetchall(),
            self.db.execute("SELECT id,status FROM operations ORDER BY id").fetchall(),
            self.db.execute("SELECT action,operation_id FROM audit_logs ORDER BY id").fetchall(),
        )

    def test_start_then_cancel_is_audited_and_does_not_release_preparation(self):
        self.assertEqual(self.start(), (1, 1, 1))
        challenge = self.db.execute(
            "SELECT nonce_hash FROM ssh_verifications WHERE id='verification-1'"
        ).fetchone()[0]
        self.assertEqual(challenge, "hashed-secret")
        self.assertEqual(self.cancel(), (1, 1))
        self.assertEqual(self.cancel(), (0, 0), "a second cancellation must not be audited")
        self.assertEqual(
            self.db.execute("SELECT status FROM operations WHERE id='operation-1'").fetchone()[0],
            "CREATED", "cancelling a challenge must never clear a prepared operation slot"
        )
        self.assertEqual(
            self.db.execute(
                "SELECT action FROM audit_logs ORDER BY created_at,id"
            ).fetchall(),
            [("ssh.verification.start",), ("ssh.verification.cancel",)]
        )

    def test_expired_pending_is_safely_replaced_in_same_transaction(self):
        self.assertEqual(self.start(), (1, 1, 1))
        self.db.execute(
            "UPDATE ssh_verifications SET expires_at=? WHERE id='verification-1'",
            (AT - 1,)
        )
        self.db.execute("UPDATE operations SET status='SUCCEEDED' WHERE id='operation-1'")
        self.db.commit()
        self.assertEqual(self.start("verification-2", "operation-2", "audit-2"), (1, 1, 1))
        self.assertEqual(
            self.db.execute(
                "SELECT id,status FROM ssh_verifications ORDER BY id"
            ).fetchall(),
            [("verification-1", "EXPIRED"), ("verification-2", "PENDING")]
        )

    def test_pending_uniqueness_race_cannot_create_or_audit_second_task(self):
        self.start()
        previous = self.snapshot()
        with self.assertRaises(sqlite3.IntegrityError):
            self.start("verification-2", "operation-2", "audit-2")
        self.assertEqual(self.snapshot(), previous)

    def test_audit_failure_rolls_back_challenge_operation_and_cancellation(self):
        self.db.execute(
            "CREATE TRIGGER block_start BEFORE INSERT ON audit_logs "
            "WHEN NEW.action='ssh.verification.start' "
            "BEGIN SELECT RAISE(ABORT,'simulated audit failure'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.start()
        self.assertEqual(self.snapshot(), ([], [], []))
        self.db.execute("DROP TRIGGER block_start")
        self.assertEqual(self.start(), (1, 1, 1))
        before = self.snapshot()
        self.db.execute(
            "CREATE TRIGGER block_cancel BEFORE INSERT ON audit_logs "
            "WHEN NEW.action='ssh.verification.cancel' "
            "BEGIN SELECT RAISE(ABORT,'simulated cancel audit failure'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.cancel()
        self.assertEqual(self.snapshot(), before)
        self.db.execute("DROP TRIGGER block_cancel")

    def test_racing_verified_expired_or_stale_node_cannot_be_cancelled(self):
        self.start()
        self.db.execute(
            "UPDATE ssh_verifications SET status='VERIFIED' WHERE id='verification-1'"
        )
        self.db.commit()
        self.assertEqual(self.cancel(), (0, 0))
        self.assertEqual(self.db.execute(
            "SELECT status FROM ssh_verifications WHERE id='verification-1'"
        ).fetchone()[0], "VERIFIED")

    def test_stale_key_or_node_revision_cannot_start_a_new_challenge(self):
        self.db.execute("UPDATE public_keys SET active=0 WHERE id=?", (KEY,))
        self.db.commit()
        self.assertEqual(self.start(), (0, 0, 0))
        self.assertEqual(self.snapshot(), ([], [], []))
        self.db.execute("UPDATE public_keys SET active=1 WHERE id=?", (KEY,))
        self.db.execute(
            "UPDATE nodes SET config_revision=? WHERE id=?", ("b" * 64, NODE)
        )
        self.db.commit()
        self.assertEqual(self.start(), (0, 0, 0))
        self.assertEqual(self.snapshot(), ([], [], []))

    def test_single_flight_operation_race_rolls_back_challenge_and_audit(self):
        self.db.execute(
            "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"
            "expected_revision,command_json,signature,status,created_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("other-operation", NODE, "node.preflight", OWNER, "other",
             REVISION, "{}", "signature", "DISPATCHED", AT, AT + 45)
        )
        self.db.commit()
        previous = self.snapshot()
        with self.assertRaises(sqlite3.IntegrityError):
            self.start()
        self.assertEqual(self.snapshot(), previous)


if __name__ == "__main__":
    unittest.main()
