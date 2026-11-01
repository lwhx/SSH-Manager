"""Read-only D1 preflight tests; no Cloudflare credentials or network calls."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parent / "staging_d1_readonly_preflight.py"
spec = importlib.util.spec_from_file_location("staging_d1_readonly_preflight", SCRIPT)
assert spec and spec.loader
preflight = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = preflight
spec.loader.exec_module(preflight)

MIGRATIONS = SCRIPT.parents[1] / "packages" / "db" / "migrations"
UUID = "1e000000-0000-4000-8000-000000000001"
OTHER_UUID = "1e000000-0000-4000-8000-000000000002"
NODE = "20000000-0000-4000-8000-000000000001"
OWNER = "30000000-0000-4000-8000-000000000001"
KEY = "40000000-0000-4000-8000-000000000001"
REVISION = "a" * 64


class StagingD1ReadOnlyPreflightTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for file in sorted(MIGRATIONS.glob("*.sql")):
            self.db.executescript(file.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO users(id,email,role,status,created_at) VALUES (?,?,?,?,?)",
            (OWNER, "owner@fixture.invalid", "owner", "active", 10),
        )
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,status,init_stage,"
            "config_revision,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (NODE, "fixture", "192.0.2.10", "root", "online",
             "WAITING_VERIFICATION", REVISION, 10),
        )
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def assess(self):
        return preflight.evaluate(
            lambda sql: preflight.local_query(self.db, sql), "test_snapshot"
        )

    def statuses(self, report):
        return {c["id"]: c for c in report["checks"]}

    def seed_daily(self):
        self.db.execute(
            "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,"
            "fingerprint,version,active,created_by,created_at) "
            "VALUES (?,?,?,?,?,?,?,1,?,?)",
            (KEY, "daily", "fixture", "ssh-ed25519", "test-key",
             "SHA256:fixture", 1, OWNER, 10),
        )
        self.db.commit()

    def test_empty_migrated_staging_is_clean_but_not_ssh_verified(self):
        report, exit_code = self.assess()
        self.assertEqual(exit_code, 0)
        self.assertTrue(report["preflight_ready"])
        self.assertFalse(report["real_ssh_authentication_verified"])
        self.assertFalse(report["remote_deployment_performed"])
        self.assertFalse(report["network_calls"])
        self.assertEqual(report["fail_count"], 0)
        self.assertEqual(report["warn_count"], 0)
        self.assertEqual(len(report["checks"]), len(preflight.CHECKS) + 1)
        self.assertNotIn("owner@fixture.invalid", json.dumps(report))
        self.assertNotIn(NODE, json.dumps(report))

    def test_missing_root_pin_audit_blocks_and_no_key_data_leaks(self):
        self.db.execute(
            "INSERT INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at)"
            " VALUES (?,?,?,?,?)",
            (NODE, "this-is-an-intentionally-sensitive-test-public-key",
             "SHA256:root-fixture", OWNER, 50),
        )
        self.db.commit()
        report, exit_code = self.assess()
        self.assertEqual(exit_code, 2)
        self.assertEqual(self.statuses(report)["root_pin_missing_audit"]["count"], 1)
        self.assertFalse(report["preflight_ready"])
        self.assertNotIn("this-is-an-intentionally-sensitive-test-public-key",
                         json.dumps(report))
        self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,node_id,action,result,created_at)"
            " VALUES (?,?,?,?,?,?)",
            ("audit-pin", OWNER, NODE, "ssh.proof-key.pin", "ok", 50),
        )
        self.db.commit()
        report, exit_code = self.assess()
        self.assertEqual(exit_code, 0)
        self.assertEqual(self.statuses(report)["root_pin_missing_audit"]["count"], 0)

    def test_terminal_without_audit_and_expired_dispatched_fails_closed(self):
        self.db.execute(
            "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"
            "expected_revision,command_json,signature,status,created_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("op1", NODE, "node.preflight", OWNER, "idem-op1", REVISION,
             "{}", "test-signature", "DISPATCHED", 1, 9999999999),
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["unknown_terminal_result"]["count"], 1)
        self.db.execute(
            "UPDATE operations SET status='SUCCEEDED',finished_at=5 WHERE id='op1'"
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["terminal_missing_audit"]["count"], 1)
        self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            ("audit-one", OWNER, NODE, "node.preflight", "op1", "SUCCEEDED", 5),
        )
        self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            ("audit-two", OWNER, NODE, "node.preflight", "op1", "SUCCEEDED", 5),
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["terminal_duplicate_audit"]["count"], 1)

    def test_live_created_operation_and_pending_challenge_are_warnings_not_approval(self):
        self.seed_daily()
        self.db.execute(
            "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,"
            "config_revision,nonce_hash,status,created_at,expires_at,public_key_id,issued_by)"
            " VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?)",
            ("challenge-1", NODE, "SHA256:fixture", "root", REVISION, "hash",
             1, 2, KEY, OWNER),
        )
        self.db.execute(
            "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"
            "expected_revision,command_json,signature,status,created_at,expires_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("op2", NODE, "node.preflight", OWNER, "idem-op2", REVISION,
             "{}", "fixture", "CREATED", 1, 9999999999),
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 3)
        self.assertEqual(report["fail_count"], 0)
        self.assertEqual(report["warn_count"], 2)
        lookup = self.statuses(report)
        self.assertEqual(lookup["pending_challenge_present"]["count"], 1)
        self.assertEqual(lookup["queued_operation_present"]["count"], 1)
        self.assertFalse(report["preflight_ready"])

    def test_verified_without_root_proof_or_audit_blocks(self):
        self.seed_daily()
        self.db.execute(
            "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,"
            "config_revision,nonce_hash,status,created_at,expires_at,public_key_id,"
            "issued_by,verified_at) VALUES (?,?,?,?,?,?,'VERIFIED',?,?,?,?,?)",
            ("challenge-2", NODE, "SHA256:fixture", "root", REVISION, "hash",
             1, 300, KEY, OWNER, 50),
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        lookup = self.statuses(report)
        self.assertEqual(lookup["verified_incomplete_proof"]["count"], 1)
        self.assertEqual(lookup["verified_missing_audit"]["count"], 1)
        self.assertEqual(lookup["verified_missing_installed_key"]["count"], 1)

    def test_missing_schema_blocks_without_reading_undeclared_tables(self):
        empty = sqlite3.connect(":memory:")
        empty.row_factory = sqlite3.Row
        try:
            calls = []
            def query(sql):
                calls.append(sql)
                return preflight.local_query(empty, sql)
            report, code = preflight.evaluate(query, "empty")
            self.assertEqual(code, 2)
            self.assertFalse(report["preflight_ready"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(report["checks"][0]["id"], "required_schema")
        finally:
            empty.close()

    def test_incomplete_aggregate_response_fails_closed_and_redacts(self):
        def malicious(query):
            if query == preflight.SCHEMA_SQL:
                return preflight.local_query(self.db, query)
            return [{"check_id": "root_pin_missing_audit",
                     "n": "SECRET do not include in response"}]
        report, code = preflight.evaluate(malicious, "fake")
        self.assertEqual(code, 2)
        self.assertFalse(report["preflight_ready"])
        self.assertNotIn("SECRET", json.dumps(report))

    def test_snapshot_is_immutable_and_query_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "staging.sqlite"
            destination = sqlite3.connect(path)
            for file in sorted(MIGRATIONS.glob("*.sql")):
                destination.executescript(file.read_text(encoding="utf-8"))
            destination.close()
            read_only = preflight.open_snapshot(path)
            try:
                self.assertTrue(preflight.validate_schema(
                    preflight.local_query(read_only, preflight.SCHEMA_SQL)[0]
                ))
                with self.assertRaises(sqlite3.OperationalError):
                    read_only.execute(
                        "INSERT INTO users(id,email,role,status,created_at) "
                        "VALUES ('id','email','owner','active',1)"
                    )
                with self.assertRaises(ValueError):
                    preflight.local_query(read_only, "DELETE FROM users")
            finally:
                read_only.close()

    def safe_config(self, path):
        data = {
            "name": "ssh-manager-staging", "workers_dev": False,
            "preview_urls": False,
            "vars": {
                "CONTROL_HOSTNAME": "ssh-staging.example.invalid",
                "AGENT_HOSTNAME": "agent-staging.example.invalid",
                "MANUAL_SSH_ACTIONS_ENABLED": "false",
            },
            "routes": [
                {"pattern": "ssh-staging.example.invalid", "custom_domain": True},
                {"pattern": "agent-staging.example.invalid", "custom_domain": True},
            ],
            "assets": {"directory": "./apps/console/dist", "binding": "ASSETS",
                       "run_worker_first": True},
            "d1_databases": [{
                "binding": "DB", "database_name": "ssh-manager-staging",
                "database_id": UUID,
            }]
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o600)
        return data

    def test_staging_target_requires_exact_name_binding_uuid_and_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / preflight.CONFIG_NAME
            data = self.safe_config(path)
            with patch.object(preflight, "ROOT", root):
                self.assertEqual(preflight.staging_config(path, UUID), path.resolve())
                with self.assertRaises(ValueError):
                    preflight.staging_config(path, OTHER_UUID)
                for modification in (
                    lambda c: c["vars"].update(MANUAL_SSH_ACTIONS_ENABLED="true"),
                    lambda c: c.update(name="ssh-manager"),
                    lambda c: c["d1_databases"][0].update(database_name="production"),
                    lambda c: c["vars"].update(CONTROL_HOSTNAME="ssh.example.invalid"),
                    lambda c: c.update(env={"production": {}}),
                    lambda c: c["routes"].pop(),
                    lambda c: c["routes"][0].update(pattern="evil.example.invalid"),
                    lambda c: c["assets"].update(run_worker_first=False),
                ):
                    changed = json.loads(json.dumps(data))
                    modification(changed)
                    path.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        preflight.staging_config(path, UUID)
                outside = root.parent / preflight.CONFIG_NAME
                self.safe_config(outside)
                with self.assertRaises(ValueError):
                    preflight.staging_config(outside, UUID)

    def test_wrangler_failures_fail_closed(self):
        for payload in (
            "not-json", "[]", "[{}]",
            '[{"success":false,"results":[]}]',
            '[{"success":true,"results":null}]',
            '[{"success":true,"errors":[{"message":"failed"}],"results":[]}]',
            '[{"success":true,"results":[{"n":"secret"}]},'
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    preflight.parse_wrangler_json(payload)
        self.assertEqual(
            preflight.parse_wrangler_json(
                '[{"success":true,"results":[{"check_id":"a","n":0}]}]'
            ), [{"check_id": "a", "n": 0}]
        )

    def test_remote_runner_only_receives_allowlisted_select_without_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "node_modules" / "wrangler" / "bin" / "wrangler.js"
            binary.parent.mkdir(parents=True)
            binary.write_text("// dummy")
            config = root / preflight.CONFIG_NAME
            self.safe_config(config)
            commands = []
            def fake_runner(argv, **kwargs):
                commands.append((argv, kwargs))
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps([{"success": True, "results": [{"dummy": 1}]}]),
                    stderr="",
                )
            with patch.object(preflight, "ROOT", root), patch.object(
                preflight.shutil, "which", return_value="/usr/bin/node"
            ):
                rows = preflight.remote_query(config, preflight.SCHEMA_SQL, fake_runner)
                self.assertEqual(rows, [{"dummy": 1}])
                with self.assertRaises(ValueError):
                    preflight.remote_query(config, "DROP TABLE users", fake_runner)
            self.assertEqual(len(commands), 1)
            argv, opts = commands[0]
            self.assertEqual(argv[2:5], ["d1", "execute", "ssh-manager-staging"])
            self.assertIn("--remote", argv)
            self.assertIn("--json", argv)
            self.assertEqual(argv[argv.index("--command")+1], preflight.SCHEMA_SQL)
            self.assertNotIn("--file", argv)
            self.assertNotIn("--yes", argv)
            self.assertFalse(opts.get("shell", False))
            self.assertTrue(preflight.SCHEMA_SQL.startswith("SELECT "))

    def test_any_dispatched_or_running_operation_blocks_even_before_expiry(self):
        self.db.execute(
            "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"
            "expected_revision,command_json,signature,status,created_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("live-op", NODE, "node.preflight", OWNER, "live-op", REVISION,
             "{}", "fixture", "DISPATCHED", 1, 9999999999),
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["unknown_terminal_result"]["count"], 1)
        self.db.execute("UPDATE operations SET status='RUNNING' WHERE id='live-op'")
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["unknown_terminal_result"]["count"], 1)

    def test_agent_pair_audit_must_match_issuing_owner_and_token_use(self):
        self.db.execute(
            "INSERT INTO agent_credentials(node_id,public_key,paired_at,revoked_at) "
            "VALUES (?,?,?,NULL)", (NODE, "device-public-fixture", 50)
        )
        self.db.execute(
            "INSERT INTO pairing_tokens(id,node_id,token_hash,expires_at,used_at,created_by) "
            "VALUES (?,?,?,?,?,?)", ("pair-token", NODE, "hash", 60, 50, OWNER)
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["active_credential_missing_pair_audit"]["count"], 1)
        self.db.execute(
            "INSERT INTO audit_logs(id,actor_id,node_id,action,result,created_at) "
            "VALUES (?,?,?,?,?,?)", ("pair-audit", OWNER, NODE, "agent.pair", "success", 50)
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(self.statuses(report)["active_credential_missing_pair_audit"]["count"], 0)

    def test_same_root_proof_fingerprint_cannot_be_reused_across_nodes(self):
        self.db.execute(
            "INSERT INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at) "
            "VALUES (?,?,?,?,?)", (NODE, "key-one", "SHA256:same", OWNER, 50)
        )
        other = "20000000-0000-4000-8000-000000000002"
        self.db.execute(
            "INSERT INTO nodes(id,name,ssh_host,login_user,status,init_stage,config_revision,created_at) "
            "VALUES (?,?,?,?,?,?,?,?)", (other, "fixture2", "192.0.2.11", "root", "online",
                "WAITING_VERIFICATION", REVISION, 10)
        )
        self.db.execute(
            "INSERT INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at) "
            "VALUES (?,?,?,?,?)", (other, "key-two-format", "SHA256:same", OWNER, 51)
        )
        self.db.commit()
        report, code = self.assess()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["shared_root_proof_key"]["count"], 1)

    def test_constant_query_allowlist_has_no_write_statement(self):
        preflight.assert_fixed_read_queries()
        for sql in (preflight.SCHEMA_SQL, preflight.CHECKS_SQL):
            self.assertEqual(sql[:7], "SELECT ")
            self.assertNotIn(";", sql)
            self.assertFalse(re.search(
                r"\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|REPLACE|VACUUM|ATTACH|DETACH)\b",
                sql, re.I
            ))

    def test_remote_evidence_must_match_clean_reviewed_git_checkout(self):
        expected = "a" * 40
        calls = []

        def clean_runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(
                returncode=0,
                stdout=expected + "\n" if argv[1] == "rev-parse" else "",
            )

        preflight.verify_reviewed_checkout(expected, clean_runner)
        self.assertEqual(calls, [
            ["git", "rev-parse", "HEAD"],
            ["git", "status", "--porcelain", "--untracked-files=normal"],
        ])

        def wrong_commit(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout="b" * 40 + "\n")

        with self.assertRaises(ValueError):
            preflight.verify_reviewed_checkout(expected, wrong_commit)

        def dirty_script(argv, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=expected + "\n" if argv[1] == "rev-parse" else " M apps/control-worker/src/index.ts\n",
            )

        with self.assertRaises(ValueError):
            preflight.verify_reviewed_checkout(expected, dirty_script)

        with self.assertRaises(ValueError):
            preflight.verify_reviewed_checkout("not-a-full-sha", clean_runner)



if __name__ == "__main__":
    unittest.main()
