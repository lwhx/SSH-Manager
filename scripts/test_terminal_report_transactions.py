"""SQLite/D1 contract checks for terminal Agent operation report transactions.

These use the repository's actual D1 schema and mirror the guarded SQL used by
apps/agent-gateway/src/index.ts. They do NOT claim a deployed Worker E2E.
"""
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "packages" / "db" / "migrations"
GATEWAY = ROOT / "apps" / "agent-gateway" / "src" / "index.ts"
NODE = "10000000-0000-4000-8000-000000000001"
ACTOR = "20000000-0000-4000-8000-000000000001"
KEY = "30000000-0000-4000-8000-000000000001"
OP = "40000000-0000-4000-8000-000000000001"
CHALLENGE = "50000000-0000-4000-8000-000000000001"
NEW_KEY_ROW = "60000000-0000-4000-8000-000000000001"
AUDIT = "70000000-0000-4000-8000-000000000001"
REV = "a" * 64
T = 150

COMMITTED = (
    "EXISTS (SELECT 1 FROM operations WHERE id=? AND node_id=? "
    "AND status=? AND result_code=?)"
)


class TerminalReportTransactionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for path in sorted(MIGRATIONS.glob("*.sql")):
            self.db.executescript(path.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO users(id,email,role,created_at) VALUES (?,?,?,?)",
            (ACTOR, "owner@example.com", "owner", 10),
        )
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,status,init_stage,config_revision,created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (NODE, "staging", "192.0.2.10", "root", "online", "WAITING_VERIFICATION", REV, 10),
        )
        self.db.execute(
            "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,created_by,created_at) "
            "VALUES (?,?,?,? ,?,?,?,?,?)",
            (KEY, "daily", "daily", "ssh-ed25519", "test", "SHA256:fixture", 1, ACTOR, 10),
        )
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def create_pending_op(self, action):
        self.db.execute(
            "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,expected_revision,"
            "command_json,signature,status,created_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (OP, NODE, action, ACTOR, "unique", REV, "{}", "ed25519-signature",
             "DISPATCHED", 100, 300),
        )
        self.db.commit()

    def pending_verification(self):
        self.db.execute(
            "INSERT INTO ssh_verifications("
            "id,node_id,key_fingerprint,login_user,config_revision,nonce_hash,status,"
            "created_at,expires_at,public_key_id,issued_by) "
            "VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?)",
            (CHALLENGE, NODE, "SHA256:fixture", "root", REV, "b" * 64, 100, 300, KEY, ACTOR),
        )
        self.db.commit()

    def run_terminal(self, action, status="SUCCEEDED", revision=REV):
        result_code = {
            "ssh.verification.prepare": "VERIFICATION_PREPARED",
            "ssh.daily.install": "DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF",
            "ssh.policy.inspect": "POLICY_INSPECTED",
        }[action] if status == "SUCCEEDED" else "ROOT_OPERATION_FAILED"
        guard = ""
        args = []
        if action == "ssh.verification.prepare" and status == "SUCCEEDED":
            guard = (" AND EXISTS (SELECT 1 FROM ssh_verifications WHERE id=? AND node_id=? "
                     "AND status='PENDING' AND expires_at>?)")
            args = [CHALLENGE, NODE, T]
        if status == "SUCCEEDED" and action in ("ssh.daily.install", "ssh.policy.inspect"):
            guard += " AND EXISTS (SELECT 1 FROM nodes WHERE id=?)"
            args.append(NODE)
        changed = self.db.execute(
            "UPDATE operations SET status=?,result_code=?,detail=?,finished_at=? "
            "WHERE id=? AND node_id=? AND status IN ('DISPATCHED','RUNNING')" + guard,
            (status, result_code, "{}", T, OP, NODE, *args),
        ).rowcount
        if changed != 1:
            raise ValueError("operation was already consumed or stale")
        extra = []
        if action == "ssh.verification.prepare":
            if status == "SUCCEEDED":
                extra.append(self.db.execute(
                    "UPDATE ssh_verifications SET prepared_at=? WHERE id=? AND node_id=? "
                    "AND status='PENDING' AND expires_at>? AND " + COMMITTED,
                    (T, CHALLENGE, NODE, T, OP, NODE, status, result_code),
                ).rowcount)
            else:
                self.db.execute(
                    "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? "
                    "WHERE id=? AND node_id=? AND status='PENDING' AND " + COMMITTED,
                    (T, CHALLENGE, NODE, OP, NODE, status, result_code),
                )
        if action == "ssh.policy.inspect" and status == "SUCCEEDED":
            old_rev, old_stage = self.db.execute(
                "SELECT config_revision,init_stage FROM nodes WHERE id=?", (NODE,)
            ).fetchone()
            preserve = old_rev == revision and old_stage in (
                "WAITING_VERIFICATION", "KEY_VERIFIED"
            )
            extra.append(self.db.execute(
                "UPDATE nodes SET config_revision=?,init_stage=? WHERE id=? AND " + COMMITTED,
                (revision, old_stage if preserve else "POLICY_INSPECTED",
                 NODE, OP, NODE, status, result_code),
            ).rowcount)
            if old_rev != revision:
                self.db.execute(
                    "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? "
                    "WHERE node_id=? AND status='PENDING' AND " + COMMITTED,
                    (T, NODE, OP, NODE, status, result_code),
                )
        if action == "ssh.daily.install" and status == "SUCCEEDED":
            extra.append(self.db.execute(
                "INSERT INTO node_keys(id,node_id,public_key_id,login_user,purpose,state) "
                "SELECT ?,?,?,?,'daily','installed' WHERE " + COMMITTED,
                (NEW_KEY_ROW, NODE, KEY, "root", OP, NODE, status, result_code),
            ).rowcount)
            extra.append(self.db.execute(
                "UPDATE nodes SET init_stage='WAITING_VERIFICATION' WHERE id=? AND " + COMMITTED,
                (NODE, OP, NODE, status, result_code),
            ).rowcount)
            self.db.execute(
                "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? "
                "WHERE node_id=? AND status='PENDING' AND " + COMMITTED,
                (T, NODE, OP, NODE, status, result_code),
            )
        audit = self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "
            "SELECT ?,?,?,?,?,?,?,? WHERE " + COMMITTED,
            (AUDIT, ACTOR, NODE, action, OP, status, result_code, T, OP, NODE, status, result_code),
        ).rowcount
        if not all(x == 1 for x in extra) or audit != 1:
            raise ValueError("transaction side effects incomplete")

    def test_signed_preparation_report_and_audit_commit_together(self):
        self.create_pending_op("ssh.verification.prepare")
        self.pending_verification()
        with self.db:
            self.run_terminal("ssh.verification.prepare")
        self.assertEqual(self.db.execute(
            "SELECT prepared_at,status FROM ssh_verifications WHERE id=?", (CHALLENGE,)
        ).fetchone(), (T, "PENDING"))
        self.assertEqual(self.db.execute(
            "SELECT status FROM operations WHERE id=?", (OP,)
        ).fetchone(), ("SUCCEEDED",))
        self.assertEqual(self.db.execute(
            "SELECT actor_id,action FROM audit_logs WHERE id=?", (AUDIT,)
        ).fetchone(), (ACTOR, "ssh.verification.prepare"))
        with self.assertRaises(ValueError):
            with self.db:
                self.run_terminal("ssh.verification.prepare")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0], 1)

    def test_invalidated_challenge_prevents_successful_terminal_report(self):
        self.create_pending_op("ssh.verification.prepare")
        self.pending_verification()
        self.db.execute(
            "UPDATE ssh_verifications SET status='INVALIDATED' WHERE id=?", (CHALLENGE,)
        )
        self.db.commit()
        with self.assertRaises(ValueError):
            with self.db:
                self.run_terminal("ssh.verification.prepare")
        self.assertEqual(self.db.execute(
            "SELECT status FROM operations WHERE id=?", (OP,)
        ).fetchone(), ("DISPATCHED",))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0], 0)

    def test_database_abort_rolls_back_prepared_and_operation_and_audit(self):
        self.create_pending_op("ssh.verification.prepare")
        self.pending_verification()
        self.db.executescript(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs "
            "BEGIN SELECT RAISE(ABORT, 'simulated D1 audit failure'); END;"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db:
                self.run_terminal("ssh.verification.prepare")
        self.assertEqual(self.db.execute(
            "SELECT status FROM operations WHERE id=?", (OP,)
        ).fetchone(), ("DISPATCHED",))
        self.assertIsNone(self.db.execute(
            "SELECT prepared_at FROM ssh_verifications WHERE id=?", (CHALLENGE,)
        ).fetchone()[0])

    def test_daily_install_is_atomic_and_invalidates_old_challenge(self):
        self.create_pending_op("ssh.daily.install")
        self.pending_verification()
        with self.db:
            self.run_terminal("ssh.daily.install")
        self.assertEqual(self.db.execute(
            "SELECT public_key_id,state FROM node_keys WHERE id=?", (NEW_KEY_ROW,)
        ).fetchone(), (KEY, "installed"))
        self.assertEqual(self.db.execute(
            "SELECT init_stage FROM nodes WHERE id=?", (NODE,)
        ).fetchone(), ("WAITING_VERIFICATION",))
        self.assertEqual(self.db.execute(
            "SELECT status FROM ssh_verifications WHERE id=?", (CHALLENGE,)
        ).fetchone(), ("INVALIDATED",))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0], 1)

    def test_failed_install_never_claims_an_installed_daily_key(self):
        self.create_pending_op("ssh.daily.install")
        with self.db:
            self.run_terminal("ssh.daily.install", status="FAILED")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM node_keys").fetchone()[0], 0)
        self.assertEqual(self.db.execute(
            "SELECT status FROM operations WHERE id=?", (OP,)
        ).fetchone(), ("FAILED",))

    def test_policy_inspection_preserves_same_revision_verified_stage(self):
        self.create_pending_op("ssh.policy.inspect")
        self.db.execute("UPDATE nodes SET init_stage='KEY_VERIFIED' WHERE id=?", (NODE,))
        self.db.commit()
        with self.db:
            self.run_terminal("ssh.policy.inspect")
        self.assertEqual(self.db.execute(
            "SELECT init_stage FROM nodes WHERE id=?", (NODE,)
        ).fetchone(), ("KEY_VERIFIED",))

    def test_changed_policy_revision_invalidates_pending_challenge(self):
        self.create_pending_op("ssh.policy.inspect")
        self.pending_verification()
        with self.db:
            self.run_terminal("ssh.policy.inspect", revision="c" * 64)
        self.assertEqual(self.db.execute(
            "SELECT config_revision,init_stage FROM nodes WHERE id=?", (NODE,)
        ).fetchone(), ("c" * 64, "POLICY_INSPECTED"))
        self.assertEqual(self.db.execute(
            "SELECT status FROM ssh_verifications WHERE id=?", (CHALLENGE,)
        ).fetchone(), ("INVALIDATED",))

    def test_daily_install_audit_failure_rolls_back_key_and_stage(self):
        self.create_pending_op("ssh.daily.install")
        self.db.execute("UPDATE nodes SET init_stage='POLICY_INSPECTED' WHERE id=?", (NODE,))
        self.db.commit()
        self.db.executescript(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs "
            "BEGIN SELECT RAISE(ABORT, 'audit outage'); END;"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db:
                self.run_terminal("ssh.daily.install")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM node_keys").fetchone()[0], 0)
        self.assertEqual(self.db.execute(
            "SELECT init_stage FROM nodes WHERE id=?", (NODE,)
        ).fetchone(), ("POLICY_INSPECTED",))
        self.assertEqual(self.db.execute(
            "SELECT status FROM operations WHERE id=?", (OP,)
        ).fetchone(), ("DISPATCHED",))

    def test_gateway_uses_single_batch_for_all_terminal_updates(self):
        source = GATEWAY.read_text(encoding="utf-8")
        handler = source.split('if(p==="/agent/v1/report"){', 1)[1]
        body = handler.split('if(p==="/agent/v1/ws"){', 1)[0]
        self.assertIn("const outcome=await env.DB.batch(steps);", body)
        self.assertIn("const committed=", body)
        self.assertIn("TERMINAL_REPORT_TRANSACTION_INCOMPLETE", body)
        self.assertIn("INSERT INTO manual_ssh_assertions(value) SELECT 0 WHERE changes()!=1", body)
        self.assertIn("requireChanged(", body)


if __name__ == "__main__":
    unittest.main()
