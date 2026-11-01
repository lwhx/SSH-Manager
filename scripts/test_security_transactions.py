#!/usr/bin/env python3
"""Executable SQLite regression tests for security-sensitive D1 batch statements.

These tests use the complete versioned migration set and never contact the
remote Cloudflare account, Agent, Root Helper, or real VPS.
"""
from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
MIGRATIONS = BASE / "packages" / "db" / "migrations"
OWNER = "20000000-0000-4000-8000-000000000001"
NODE = "10000000-0000-4000-8000-000000000001"
T = 1800000000


class SecurityTransactions(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for migration in sorted(MIGRATIONS.glob("*.sql")):
            self.db.executescript(migration.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO users(id,email,role,status,created_at) VALUES (?,?,?,?,?)",
            (OWNER, "owner@example.invalid", "owner", "active", T - 100),
        )
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,created_at) VALUES (?,?,?,?,?)",
            (NODE, "fixture", "192.0.2.10", "root", T - 100),
        )
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()

    def add_key(self, key_id: str, purpose: str, version: int = 1) -> None:
        self.db.execute(
            "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,"
            "version,active,created_by,created_at) VALUES (?,?,?,?,?,?,?,1,?,?)",
            (key_id, purpose, purpose, "ssh-ed25519", "fixture-public",
             "SHA256:fixture", version, OWNER, T),
        )
        self.db.commit()

    def pending_challenge(self, challenge_id: str, key_id: str) -> None:
        self.db.execute(
            "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,"
            "config_revision,nonce_hash,status,created_at,expires_at,"
            "public_key_id,issued_by) VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?)",
            (challenge_id, NODE, "SHA256:fixture", "root", "a" * 64, "hash",
             T, T + 300, key_id, OWNER),
        )
        self.db.commit()

    def rotate(self, purpose: str, key_id: str, audit_id: str) -> int:
        # Mirrors apps/control-worker/src/globalKeyRotation.ts, in D1 batch order.
        with self.db:
            self.db.execute("UPDATE public_keys SET active=0 WHERE purpose=?", (purpose,))
            inserted = self.db.execute(
                "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,"
                "fingerprint,version,active,created_by,created_at) "
                "SELECT ?,?,?,?,?,?,COALESCE(MAX(version),0) + 1,1,?,? "
                "FROM public_keys WHERE purpose=?",
                (key_id, purpose, purpose, "ssh-ed25519", "fixture-public",
                 "SHA256:fixture", OWNER, T + 1, purpose),
            )
            self.assertEqual(inserted.rowcount, 1)
            if purpose == "daily":
                self.db.execute(
                    "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? "
                    "WHERE status='PENDING'", (T + 1,),
                )
            self.db.execute(
                "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,"
                "result,reason,created_at) VALUES (?,?,NULL,?,NULL,'ok',?,?)",
                (audit_id, OWNER, "keys." + purpose + ".update",
                 "key_id=" + key_id, T + 1),
            )
            version, active = self.db.execute(
                "SELECT version,active FROM public_keys WHERE id=?", (key_id,)
            ).fetchone()
            self.assertEqual(active, 1)
            return version

    def test_key_rotation_versions_and_login_challenge_scope(self) -> None:
        daily1 = "30000000-0000-4000-8000-000000000001"
        daily2 = "30000000-0000-4000-8000-000000000002"
        daily3 = "30000000-0000-4000-8000-000000000003"
        rescue1 = "40000000-0000-4000-8000-000000000001"
        rescue2 = "40000000-0000-4000-8000-000000000002"
        challenge1 = "50000000-0000-4000-8000-000000000001"
        challenge2 = "50000000-0000-4000-8000-000000000002"
        self.add_key(daily1, "daily")
        self.add_key(rescue1, "rescue")
        self.pending_challenge(challenge1, daily1)
        self.assertEqual(self.rotate("daily", daily2, "audit-daily2"), 2)
        self.assertEqual(
            self.db.execute("SELECT status FROM ssh_verifications WHERE id=?",
                            (challenge1,)).fetchone()[0], "INVALIDATED")
        self.pending_challenge(challenge2, daily2)
        self.assertEqual(self.rotate("rescue", rescue2, "audit-rescue2"), 2)
        self.assertEqual(
            self.db.execute("SELECT status FROM ssh_verifications WHERE id=?",
                            (challenge2,)).fetchone()[0], "PENDING")
        self.assertEqual(self.rotate("daily", daily3, "audit-daily3"), 3)
        self.assertEqual(
            self.db.execute("SELECT status FROM ssh_verifications WHERE id=?",
                            (challenge2,)).fetchone()[0], "INVALIDATED")
        self.assertEqual(
            self.db.execute(
                "SELECT purpose,version FROM public_keys WHERE active=1 ORDER BY purpose"
            ).fetchall(), [("daily", 3), ("rescue", 2)])
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM audit_logs WHERE action LIKE 'keys.%.update'"
            ).fetchone()[0], 3)

    def test_key_rotation_audit_constraint_rolls_back_every_change(self) -> None:
        daily1 = "60000000-0000-4000-8000-000000000001"
        daily2 = "60000000-0000-4000-8000-000000000002"
        challenge = "70000000-0000-4000-8000-000000000001"
        self.add_key(daily1, "daily")
        self.pending_challenge(challenge, daily1)
        self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,action,result,created_at) "
            "VALUES (?,?,'fixture','ok',?)", ("duplicate-audit", OWNER, T)
        )
        self.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.rotate("daily", daily2, "duplicate-audit")
        self.assertEqual(
            self.db.execute("SELECT id,version FROM public_keys WHERE active=1").fetchall(),
            [(daily1, 1)])
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM public_keys WHERE id=?",
                            (daily2,)).fetchone()[0], 0)
        self.assertEqual(
            self.db.execute("SELECT status FROM ssh_verifications WHERE id=?",
                            (challenge,)).fetchone()[0], "PENDING")

    def issue_token(self, token_id: str, token_hash: str, audit_id: str) -> None:
        # Mirrors apps/control-worker/src/identityLinkStore.ts.
        with self.db:
            self.db.execute(
                "INSERT INTO identity_link_tokens(id,user_id,token_hash,expires_at,"
                "created_at) VALUES (?,?,?,?,?)",
                (token_id, OWNER, token_hash, T + 300, T),
            )
            self.db.execute(
                "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,"
                "result,reason,created_at) "
                "VALUES (?,?,NULL,'identity.link_token',NULL,'created',NULL,?)",
                (audit_id, OWNER, T),
            )

    def claim(self, subject: str, token_id: str, token_hash: str,
              audit_id: str) -> tuple[int, int, int]:
        with self.db:
            linked = self.db.execute(
                "INSERT OR IGNORE INTO user_identities(subject,user_id,provider,"
                "created_at) SELECT ?,?,'cloudflare-access',? WHERE EXISTS ("
                "SELECT 1 FROM identity_link_tokens t JOIN users u ON u.id=t.user_id "
                "WHERE t.id=? AND t.user_id=? AND t.token_hash=? AND t.used_at IS NULL "
                "AND t.expires_at>? AND u.status='active' AND lower(u.email)=?)",
                (subject, OWNER, T + 10, token_id, OWNER, token_hash, T + 10,
                 "owner@example.invalid"),
            )
            consumed = self.db.execute(
                "UPDATE identity_link_tokens SET used_at=? "
                "WHERE id=? AND user_id=? AND token_hash=? AND used_at IS NULL "
                "AND expires_at>? AND changes()=1",
                (T + 10, token_id, OWNER, token_hash, T + 10),
            )
            audited = self.db.execute(
                "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,"
                "result,reason,created_at) "
                "SELECT ?,?,NULL,'identity.link',NULL,'success',NULL,? "
                "WHERE changes()=1",
                (audit_id, OWNER, T + 10),
            )
            return linked.rowcount, consumed.rowcount, audited.rowcount

    def test_identity_claim_one_time_conflicts_and_audit_rollback(self) -> None:
        self.issue_token("token1", "hash1", "issued1")
        self.assertEqual(self.claim("access:2", "token1", "hash1", "claim1"), (1, 1, 1))
        self.assertEqual(self.claim("access:3", "token1", "hash1", "claim2"), (0, 0, 0))
        self.issue_token("token2", "hash2", "issued2")
        self.assertEqual(self.claim("access:2", "token2", "hash2", "claim3"), (0, 0, 0))
        self.assertIsNone(
            self.db.execute("SELECT used_at FROM identity_link_tokens WHERE id='token2'")
            .fetchone()[0], "duplicate subject incorrectly burned a second token")
        self.issue_token("token3", "hash3", "issued3")
        with self.assertRaises(sqlite3.IntegrityError):
            self.claim("access:4", "token3", "hash3", "claim1")
        self.assertIsNone(
            self.db.execute("SELECT used_at FROM identity_link_tokens WHERE id='token3'")
            .fetchone()[0], "audit failure consumed token")
        self.assertIsNone(
            self.db.execute("SELECT user_id FROM user_identities WHERE subject='access:4'")
            .fetchone(), "audit failure committed an identity")
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM audit_logs WHERE action='identity.link'"
            ).fetchone()[0], 1)

    def test_owner_bootstrap_audit_failure_rolls_back_privileges(self) -> None:
        self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,action,result,created_at) "
            "VALUES ('collision',?,'fixture','ok',?)", (OWNER, T)
        )
        self.db.commit()
        first = "80000000-0000-4000-8000-000000000001"
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db:
                self.db.execute(
                    "INSERT INTO users(id,email,role,status,created_at) "
                    "VALUES (?,?,'owner','active',?)",
                    (first, "first@example.invalid", T),
                )
                self.db.execute(
                    "INSERT INTO user_identities(subject,user_id,provider,created_at) "
                    "VALUES (?,?,'cloudflare-access',?)", ("access:first", first, T)
                )
                self.db.execute(
                    "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,"
                    "result,reason,created_at) "
                    "VALUES (?,?,NULL,'identity.owner.bootstrap',NULL,'success',NULL,?)",
                    ("collision", first, T),
                )
        self.assertIsNone(
            self.db.execute("SELECT id FROM users WHERE id=?", (first,)).fetchone())
        self.assertIsNone(
            self.db.execute("SELECT user_id FROM user_identities WHERE subject='access:first'")
            .fetchone())


if __name__ == "__main__":
    unittest.main()
