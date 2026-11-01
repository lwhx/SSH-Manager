"""A terminal Agent report must be a single CAS plus side effects and audit.

Runs against every real migration using only local SQLite. Mirrors the
Gateway's D1.batch order; does not contact Cloudflare or any VPS.
"""
from __future__ import annotations
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "packages/db/migrations"
GATEWAY = ROOT / "apps/agent-gateway/src/index.ts"
NODE = "10000000-0000-4000-8000-000000000001"
ACTOR = "20000000-0000-4000-8000-000000000001"
OP = "30000000-0000-4000-8000-000000000001"
CHALLENGE = "40000000-0000-4000-8000-000000000001"
KEY = "50000000-0000-4000-8000-000000000001"
REV = "a" * 64


class TerminalReportRaceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for path in sorted(MIGRATIONS.glob("*.sql")):
            self.db.executescript(path.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO users(id,email,role,created_at) VALUES (?,?,?,?)",
            (ACTOR, "test@example.invalid", "owner", 1),
        )
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,status,init_stage,config_revision,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (NODE, "test", "192.0.2.4", "root", "online", "WAITING_VERIFICATION", REV, 1),
        )
        self.db.execute(
            "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,created_by,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (KEY, "daily", "test", "ssh-ed25519", "fixture", "SHA256:fixture", 1, ACTOR, 1),
        )
        self.db.execute(
            "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,config_revision,nonce_hash,"
            "status,created_at,expires_at,public_key_id,issued_by) "
            "VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?)",
            (CHALLENGE, NODE, "SHA256:fixture", "root", REV, "b"*64, 1, 300, KEY, ACTOR),
        )
        self.db.execute(
            "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,expected_revision,"
            "command_json,signature,status,created_at,expires_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (OP, NODE, "ssh.verification.prepare", ACTOR, "fixture", REV, "{}", "sig", "DISPATCHED", 1, 300),
        )
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def terminal(self, *, prepared_id=CHALLENGE, audit_id="test-audit"):
        with self.db:
            self.db.execute(
                "UPDATE operations SET status='SUCCEEDED',result_code='VERIFICATION_PREPARED',"
                "detail='{}',finished_at=150 WHERE id=? AND node_id=? "
                "AND status IN ('DISPATCHED','RUNNING')", (OP, NODE),
            )
            # PRE-COMMIT: abort transaction if another report already won the CAS.
            self.db.execute(
                "INSERT INTO manual_ssh_assertions(value) SELECT 0 WHERE changes()!=1"
            )
            self.db.execute(
                "UPDATE ssh_verifications SET prepared_at=150 WHERE id=? AND node_id=? "
                "AND status='PENDING' AND expires_at>150 AND "
                "EXISTS (SELECT 1 FROM operations WHERE id=? AND node_id=? "
                "AND status='SUCCEEDED' AND result_code='VERIFICATION_PREPARED')",
                (prepared_id, NODE, OP, NODE),
            )
            # PRE-COMMIT: a missing mandatory side effect rolls back status.
            self.db.execute(
                "INSERT INTO manual_ssh_assertions(value) SELECT 0 WHERE changes()!=1"
            )
            self.db.execute(
                "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at)"
                " VALUES (?,?,?,'ssh.verification.prepare',?,'SUCCEEDED','VERIFICATION_PREPARED',150)",
                (audit_id, ACTOR, NODE, OP),
            )
            self.db.execute(
                "INSERT INTO manual_ssh_assertions(value) SELECT 0 WHERE changes()!=1"
            )

    def snapshot(self):
        return (
            self.db.execute("SELECT status FROM operations WHERE id=?", (OP,)).fetchone()[0],
            self.db.execute("SELECT prepared_at FROM ssh_verifications WHERE id=?", (CHALLENGE,)).fetchone()[0],
            self.db.execute("SELECT COUNT(*) FROM audit_logs WHERE operation_id=?", (OP,)).fetchone()[0],
        )

    def test_concurrent_pre_read_terminal_cannot_insert_second_audit(self):
        # Both requests observed DISPATCHED before either started the batch.
        assert self.snapshot() == ("DISPATCHED", None, 0)
        self.terminal()
        self.assertEqual(self.snapshot(), ("SUCCEEDED", 150, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.terminal(audit_id="replayed-audit")
        self.assertEqual(self.snapshot(), ("SUCCEEDED", 150, 1))

    def test_mismatched_side_effect_rolls_back_status_and_audit(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.terminal(prepared_id="70000000-0000-4000-8000-000000000001")
        self.assertEqual(self.snapshot(), ("DISPATCHED", None, 0))

    def test_audit_write_failure_rolls_back_terminal_and_challenge(self):
        self.db.execute(
            "CREATE TRIGGER fail_terminal_audit BEFORE INSERT ON audit_logs "
            "BEGIN SELECT RAISE(ABORT,'local synthetic audit outage'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.terminal()
        self.assertEqual(self.snapshot(), ("DISPATCHED", None, 0))

    def test_gateway_enforces_in_batch_assertion_not_only_post_batch_checks(self):
        source = GATEWAY.read_text(encoding="utf-8")
        handler = source.split('if(p==="/agent/v1/report"){', 1)[1]
        body = handler.split('if(p==="/agent/v1/ws"){', 1)[0]
        self.assertIn(
            "INSERT INTO manual_ssh_assertions(value) SELECT 0 WHERE changes()!=1",
            body
        )
        self.assertIn("requireChanged(", body)
        self.assertIn("const outcome=await env.DB.batch(steps);", body)


if __name__ == "__main__":
    unittest.main()
