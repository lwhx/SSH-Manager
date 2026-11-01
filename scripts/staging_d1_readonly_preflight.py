#!/usr/bin/env python3
"""Fail-closed, aggregate-only SSH Manager Staging D1 release preflight.

Default: print the check plan and make NO network/database connections.
Local: inspect a read-only, immutable SQLite snapshot.
Remote: explicitly authorized Wrangler D1 execute --remote --json --command.

No arbitrary SQL, migrations, deploys, table rows, SSH, or remediation. The
report contains only check IDs, counts, statuses and operator-supplied Git SHA.
This is a release gate, NEVER evidence of successful SSH authentication.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
CONFIG_NAME = "wrangler.single.staging.local.jsonc"
DATABASE_NAME = "ssh-manager-staging"
DB_UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)
MAX_JSON_BYTES = 65536

REQUIRED_TABLES = (
    "users", "user_identities", "identity_link_tokens", "nodes",
    "agent_credentials", "public_keys", "node_keys", "ssh_verifications",
    "node_ssh_proof_keys", "operations", "audit_logs",
    "ssh_config_snapshots", "manual_ssh_assertions",
)
REQUIRED_INDEXES = (
    "idx_key_active", "idx_one_pending_verification_per_node",
    "idx_verification_unique_proof_id", "idx_one_unresolved_operation_per_node",
    "idx_one_active_rescue_per_node",
)
REQUIRED_COLUMNS = (
    ("nodes", "group_name"), ("nodes", "notes"),
    ("ssh_verifications", "public_key_id"),
    ("ssh_verifications", "issued_by"),
    ("ssh_verifications", "prepared_at"),
    ("ssh_verifications", "proof_id"),
    ("ssh_verifications", "proof_hash"),
    ("ssh_verifications", "invalidated_at"),
    ("node_ssh_proof_keys", "approved_by"),
    ("ssh_config_snapshots", "restored_at"),
)

def literals(values: tuple[str, ...]) -> str:
    """Only compile fixed, source-code-owned SQL identifier literals."""
    if any(not re.fullmatch(r"[a-z][a-z0-9_]*", x) for x in values):
        raise ValueError("unsafe built-in SQL identifier")
    return ",".join("'" + x + "'" for x in values)

SCHEMA_SQL = "SELECT " + ", ".join([
    "(SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN (" +
    literals(REQUIRED_TABLES) + ")) AS table_count",
    "(SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (" +
    literals(REQUIRED_INDEXES) + ")) AS index_count",
] + [
    "(SELECT COUNT(*) FROM pragma_table_info('" + table + "') WHERE name='" +
    column + "') AS col_" + table + "_" + column
    for table, column in REQUIRED_COLUMNS
])

@dataclass(frozen=True)
class Check:
    key: str
    severity: str  # FAIL blocks release, WARN requires Owner review
    explanation: str
    source: str     # fixed FROM/WHERE expression yielding a count

CHECKS = (
    Check("root_pin_missing_audit", "FAIL", "Owner-pinned Root key lacks matching approval audit",
          "FROM node_ssh_proof_keys p WHERE NOT EXISTS "
          "(SELECT 1 FROM audit_logs a WHERE a.node_id=p.node_id "
          "AND a.actor_id=p.approved_by AND a.action='ssh.proof-key.pin' "
          "AND a.result='ok')"),
    Check("shared_root_proof_key", "FAIL", "Root proof key fingerprint reused across multiple VPS nodes",
          "FROM (SELECT fingerprint FROM node_ssh_proof_keys "
          "GROUP BY fingerprint HAVING COUNT(*)>1)"),
    Check("overlapping_operations", "FAIL", "VPS with more than one unresolved Agent operation",
          "FROM (SELECT node_id FROM operations WHERE status IN "
          "('CREATED','DISPATCHED','RUNNING') GROUP BY node_id HAVING COUNT(*)>1)"),
    Check("unknown_terminal_result", "FAIL", "Any DISPATCHED/RUNNING operation is unresolved; expiry never releases the VPS lock",
          "FROM operations WHERE status IN ('DISPATCHED','RUNNING')"),
    Check("terminal_missing_audit", "FAIL", "Terminal Agent result lacks matching durable audit",
          "FROM operations o WHERE o.status IN ('SUCCEEDED','FAILED') AND NOT EXISTS "
          "(SELECT 1 FROM audit_logs a WHERE a.operation_id=o.id "
          "AND a.node_id=o.node_id AND a.action=o.action AND a.result=o.status)"),
    Check("terminal_duplicate_audit", "FAIL", "Multiple terminal audit records for one Agent operation",
          "FROM (SELECT o.id FROM operations o JOIN audit_logs a "
          "ON a.operation_id=o.id AND a.action=o.action AND a.result=o.status "
          "WHERE o.status IN ('SUCCEEDED','FAILED') "
          "GROUP BY o.id HAVING COUNT(*)>1)"),
    Check("verified_incomplete_proof", "FAIL", "VERIFIED challenge missing signed evidence or preparation",
          "FROM ssh_verifications v WHERE v.status='VERIFIED' AND "
          "(v.prepared_at IS NULL OR v.verified_at IS NULL OR v.proof_id IS NULL "
          "OR v.proof_hash IS NULL OR v.public_key_id IS NULL)"),
    Check("verified_missing_audit", "FAIL", "VERIFIED challenge lacks original Root-proof attribution audit",
          "FROM ssh_verifications v WHERE v.status='VERIFIED' AND NOT EXISTS "
          "(SELECT 1 FROM audit_logs a WHERE a.id=v.proof_id "
          "AND a.node_id=v.node_id AND a.actor_id=v.issued_by "
          "AND a.action='ssh.verification.proof' AND a.result='VERIFIED')"),
    Check("verified_missing_installed_key", "FAIL", "VERIFIED challenge lacks matching verified daily key",
          "FROM ssh_verifications v WHERE v.status='VERIFIED' AND NOT EXISTS "
          "(SELECT 1 FROM node_keys nk WHERE nk.node_id=v.node_id "
          "AND nk.public_key_id=v.public_key_id AND nk.login_user=v.login_user "
          "AND nk.purpose='daily' AND nk.verified_at IS NOT NULL)"),
    Check("pending_inactive_daily_key", "FAIL", "PENDING challenge references inactive/stale daily key",
          "FROM ssh_verifications v WHERE v.status='PENDING' AND NOT EXISTS "
          "(SELECT 1 FROM public_keys k WHERE k.id=v.public_key_id "
          "AND k.purpose='daily' AND k.active=1)"),
    Check("pending_revision_mismatch", "FAIL", "PENDING challenge refers to superseded VPS configuration",
          "FROM ssh_verifications v JOIN nodes n ON n.id=v.node_id "
          "WHERE v.status='PENDING' AND "
          "(v.config_revision<>n.config_revision OR v.login_user<>n.login_user)"),
    Check("duplicate_key_version", "FAIL", "Public-key version reused within the same purpose",
          "FROM (SELECT purpose,version FROM public_keys "
          "GROUP BY purpose,version HAVING COUNT(*)>1)"),
    Check("unexpected_assertion_row", "FAIL", "Transaction-only SQLite assertion table is nonempty",
          "FROM manual_ssh_assertions"),
    Check("active_credential_missing_pair_audit", "FAIL", "Active Agent credential lacks matching one-time pairing attribution",
          "FROM agent_credentials c WHERE c.revoked_at IS NULL AND NOT EXISTS "
          "(SELECT 1 FROM pairing_tokens p JOIN audit_logs a "
          "ON a.node_id=p.node_id AND a.actor_id=p.created_by "
          "AND a.action='agent.pair' AND a.result='success' "
          "WHERE p.node_id=c.node_id AND p.used_at=c.paired_at)"),
    Check("expired_pending_challenge", "WARN", "Any PENDING challenge needs completion or manual review before release",
          "FROM ssh_verifications WHERE status='PENDING'"),
    Check("expired_undispatched_operation", "WARN", "Any CREATED operation remains queued and needs explicit review",
          "FROM operations WHERE status='CREATED'"),
)
CHECKS_SQL = " UNION ALL ".join(
    "SELECT '" + c.key + "' AS check_id, COUNT(*) AS n " + c.source
    for c in CHECKS
)

def assert_fixed_read_queries() -> None:
    for query in (SCHEMA_SQL, CHECKS_SQL):
        # No CLI input ever participates in either SQL statement.
        if not query.startswith("SELECT ") or ";" in query or "\x00" in query:
            raise ValueError("non-read-only built-in query")

def validate_schema(row: dict[str, Any]) -> bool:
    if type(row.get("table_count")) is not int or row["table_count"] != len(REQUIRED_TABLES):
        return False
    if type(row.get("index_count")) is not int or row["index_count"] != len(REQUIRED_INDEXES):
        return False
    return all(
        type(row.get("col_" + table + "_" + column)) is int
        and row["col_" + table + "_" + column] == 1
        for table, column in REQUIRED_COLUMNS
    )

def validate_count(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("invalid aggregate count")
    return value

def evaluate(query: Callable[[str], list[dict[str, Any]]],
             source_mode: str, reviewed_commit: str | None = None) -> tuple[dict[str, Any], int]:
    assert_fixed_read_queries()
    report: dict[str, Any] = {
        "schema": "ssh-manager-staging-d1-readonly-gate-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_mode": source_mode,
        "read_only": True,
        "network_calls": source_mode == "staging_remote_d1",
        "remote_deployment_performed": False,
        "ssh_configuration_modified": False,
        "reviewed_commit": reviewed_commit,
        "real_ssh_authentication_verified": False,
        "checks": [],
        "preflight_ready": False,
    }
    try:
        schema_rows = query(SCHEMA_SQL)
        if len(schema_rows) != 1 or not validate_schema(schema_rows[0]):
            report["checks"] = [{"id": "required_schema", "status": "FAIL",
                                  "detail": "Required migrated tables, indexes or columns are missing"}]
            report["fail_count"] = 1
            report["warn_count"] = 0
            return report, 2
        values = query(CHECKS_SQL)
        found: dict[str, int] = {}
        expected = {c.key for c in CHECKS}
        for item in values:
            key = item.get("check_id")
            if not isinstance(key, str) or key not in expected or key in found:
                raise ValueError("unrecognized or duplicate check")
            found[key] = validate_count(item.get("n"))
        if set(found) != expected:
            raise ValueError("missing aggregate check")
        checks = [{"id": "required_schema", "status": "PASS",
                   "detail": "Required migrated tables, indexes and columns present"}]
        for c in CHECKS:
            count = found[c.key]
            checks.append({
                "id": c.key, "status": c.severity if count else "PASS",
                "count": count, "detail": c.explanation,
            })
        report["checks"] = checks
        report["fail_count"] = sum(c["status"] == "FAIL" for c in checks)
        report["warn_count"] = sum(c["status"] == "WARN" for c in checks)
        report["preflight_ready"] = report["fail_count"] == 0 and report["warn_count"] == 0
        return report, 2 if report["fail_count"] else (3 if report["warn_count"] else 0)
    except (ValueError, sqlite3.Error, OSError, TimeoutError, subprocess.SubprocessError):
        # Never echo Wrangler stderr/stdout: they may contain configuration data.
        report["checks"] = [{"id": "query_execution", "status": "FAIL",
                              "detail": "Aggregate query failed or returned malformed data"}]
        report["fail_count"] = 1
        report["warn_count"] = 0
        return report, 2

def open_snapshot(file: Path) -> sqlite3.Connection:
    if file.is_symlink() or not file.is_file():
        raise ValueError("SQLite snapshot must be an existing regular file (not a symlink)")
    uri = file.resolve().as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection

def local_query(connection: sqlite3.Connection, sql: str) -> list[dict[str, Any]]:
    if sql not in (SCHEMA_SQL, CHECKS_SQL):
        raise ValueError("unapproved query")
    return [dict(row) for row in connection.execute(sql).fetchall()]

def verify_reviewed_checkout(expected_sha: str, runner: Callable[..., Any] = subprocess.run) -> None:
    """Refuse remote evidence from the wrong checkout or any dirty worktree."""
    if not COMMIT_SHA.fullmatch(expected_sha):
        raise ValueError("Review commit must be a full 40-character Git SHA")
    commands = (
        (["git", "rev-parse", "HEAD"], "sha"),
        (["git", "status", "--porcelain", "--untracked-files=normal"], "dirty"),
    )
    for argv, kind in commands:
        try:
            result = runner(argv, cwd=str(ROOT), capture_output=True, text=True,
                            check=False, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("Cannot verify reviewed Git checkout") from exc
        if result.returncode != 0:
            raise ValueError("Cannot verify reviewed Git checkout")
        if kind == "sha" and result.stdout.strip().lower() != expected_sha.lower():
            raise ValueError("Local HEAD differs from the approved Git commit")
        if kind == "dirty" and result.stdout.strip():
            raise ValueError("Git worktree is not clean; refusing remote D1 evidence")


def staging_config(config: Path, confirmed_id: str) -> Path:
    expected_config = ROOT / CONFIG_NAME
    if (config.name != CONFIG_NAME or config.is_symlink() or not config.is_file()
        or config.resolve() != expected_config.resolve()):
        raise ValueError("Only the existing repository-root single Staging config is allowed")
    if not DB_UUID.fullmatch(confirmed_id):
        raise ValueError("Invalid confirmed Staging D1 UUID")
    if stat.S_IMODE(config.stat().st_mode) & 0o022 and os.name != "nt":
        raise ValueError("Staging config is group/other writable")
    # Generated staging config is strict JSON, even though it uses .jsonc.
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError("Cannot safely parse generated Staging config") from exc
    if not isinstance(data, dict):
        raise ValueError("Invalid Staging config object")
    bindings = data.get("d1_databases")
    vars_ = data.get("vars")
    if (data.get("name") != DATABASE_NAME or data.get("workers_dev") is not False
        or data.get("preview_urls") is not False or "env" in data
        or not isinstance(vars_, dict)
        or vars_.get("MANUAL_SSH_ACTIONS_ENABLED") != "false"
        or not isinstance(bindings, list) or len(bindings) != 1):
        raise ValueError("Staging worker identity or safe SSH flag mismatch")
    binding = bindings[0]
    if (not isinstance(binding, dict) or binding.get("binding") != "DB"
        or binding.get("database_name") != DATABASE_NAME
        or not isinstance(binding.get("database_id"), str)
        or not DB_UUID.fullmatch(binding["database_id"])
        or binding["database_id"].lower() != confirmed_id.lower()):
        raise ValueError("Confirmed Staging database UUID does not match config")
    control_host = vars_.get("CONTROL_HOSTNAME")
    agent_host = vars_.get("AGENT_HOSTNAME")
    hostname = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    )
    if (not isinstance(control_host, str) or not isinstance(agent_host, str)
        or control_host == agent_host
        or not hostname.fullmatch(control_host) or not hostname.fullmatch(agent_host)
        or "staging" not in control_host.split(".")[0]
        or "staging" not in agent_host.split(".")[0]):
        raise ValueError("Distinct, valid Control/Agent Staging hostnames not confirmed")
    routes = data.get("routes")
    if (not isinstance(routes, list) or len(routes) != 2
        or any(not isinstance(route, dict) or route.get("custom_domain") is not True
               for route in routes)
        or {route.get("pattern") for route in routes} != {control_host, agent_host}):
        raise ValueError("Staging Worker routes do not match the confirmed hostnames")
    assets = data.get("assets")
    if not isinstance(assets, dict) or assets.get("run_worker_first") is not True:
        raise ValueError("Single Worker asset routing configuration is not confirmed")
    return config.resolve()

def parse_wrangler_json(raw: str) -> list[dict[str, Any]]:
    try:
        payload: Any = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Wrangler response was not JSON") from exc
    if isinstance(payload, list):
        if len(payload) != 1:
            raise ValueError("Expected exactly one Wrangler query")
        payload = payload[0]
    if (not isinstance(payload, dict) or payload.get("success") is not True
        or payload.get("errors")):
        raise ValueError("Wrangler reported an unsuccessful query")
    rows = payload.get("results")
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise ValueError("Wrangler omitted aggregate query results")
    return rows

def remote_query(config: Path, sql: str, runner: Callable[..., Any] = subprocess.run
                 ) -> list[dict[str, Any]]:
    if sql not in (SCHEMA_SQL, CHECKS_SQL):
        raise ValueError("unapproved query")
    wrangler = ROOT / "node_modules" / "wrangler" / "bin" / "wrangler.js"
    node = shutil.which("node")
    if not node or not wrangler.is_file():
        raise ValueError("Node.js and locally installed Wrangler are required")
    cmd = [
        node, str(wrangler), "d1", "execute", DATABASE_NAME,
        "--config", str(config), "--remote", "--json", "--command", sql,
    ]
    env = {**os.environ, "WRANGLER_SEND_METRICS": "false"}
    result = runner(cmd, cwd=str(ROOT), capture_output=True, text=True,
                    check=False, timeout=45, env=env)
    if result.returncode != 0 or len(result.stdout) > MAX_JSON_BYTES:
        raise ValueError("Wrangler aggregate query failed")
    return parse_wrangler_json(result.stdout)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging-only", action="store_true", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sqlite-snapshot", type=Path,
                      help="inspect a copied SQLite database snapshot without writing to it")
    mode.add_argument("--execute-remote", action="store_true",
                      help="opt in to READ-ONLY queries of the existing Staging D1")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--confirm-database-id")
    parser.add_argument("--reviewed-commit")
    args = parser.parse_args()
    if not args.execute_remote and not args.sqlite_snapshot:
        print(json.dumps({
            "schema": "ssh-manager-staging-d1-readonly-gate-v1",
            "mode": "PLAN_ONLY", "preflight_ready": False, "network_calls": False,
            "checks": [{"id": c.key, "severity": c.severity} for c in CHECKS],
        }, indent=2))
        return 4
    if args.execute_remote:
        if (not args.config or not args.confirm_database_id or
            not args.reviewed_commit or not COMMIT_SHA.fullmatch(args.reviewed_commit)):
            parser.error("remote mode requires --config, --confirm-database-id and 40-char --reviewed-commit")
        try:
            verify_reviewed_checkout(args.reviewed_commit)
            config = staging_config(args.config, args.confirm_database_id)
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
        report, code = evaluate(
            lambda sql: remote_query(config, sql), "staging_remote_d1",
            args.reviewed_commit.lower(),
        )
    else:
        if args.config or args.confirm_database_id or args.reviewed_commit:
            parser.error("remote-only configuration flags are not accepted with a local snapshot")
        try:
            connection = open_snapshot(args.sqlite_snapshot)
        except (sqlite3.Error, ValueError, OSError):
            print(json.dumps({"preflight_ready": False, "error": "SNAPSHOT_UNAVAILABLE"}))
            return 2
        try:
            report, code = evaluate(lambda sql: local_query(connection, sql),
                                    "immutable_local_snapshot")
        finally:
            connection.close()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code

if __name__ == "__main__":
    sys.exit(main())
