#!/usr/bin/env python3
"""SQLite smoke test for every versioned D1 migration (no external packages)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
MIGRATIONS = BASE / "packages" / "db" / "migrations"


def run() -> None:
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA foreign_keys=ON")
    scripts = sorted(MIGRATIONS.glob("*.sql"))
    assert scripts, "no SQL migrations found"
    for script in scripts:
        db.executescript(script.read_text(encoding="utf-8"))
        print(f"Applied: {script.name}")

    node = "00000000-0000-4000-8000-000000000001"
    key = "10000000-0000-4000-8000-000000000001"
    user = "20000000-0000-4000-8000-000000000001"
    db.execute(
        "INSERT INTO users(id,email,role,status,created_at) VALUES (?,?,?,?,?)",
        (user, "owner@example.com", "owner", "active", 1),
    )
    db.execute(
        "INSERT INTO nodes(id,name,ssh_host,login_user,created_at) VALUES (?,?,?,?,?)",
        (node, "test", "127.0.0.1", "root", 1),
    )
    db.execute(
        "INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,created_by,created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (key, "daily", "test", "ssh-ed25519", "ssh-ed25519 dummy", "SHA256:test", 1, user, 1),
    )
    # Mirrors the control API's verification challenge INSERT shape.
    sql = (
        "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,config_revision,nonce_hash,status,"
        "created_at,expires_at,public_key_id,issued_by) VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?)"
    )
    assert sql.count("?") == 10
    params = (
        "30000000-0000-4000-8000-000000000001",
        node, "SHA256:test", "root", "a" * 64, "hash-only", 1, 301, key, user,
    )
    db.execute(sql, params)
    try:
        db.execute(sql, ("30000000-0000-4000-8000-000000000002", *params[1:]))
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("two pending verification challenges for one node accepted")
    db.execute(
        "UPDATE ssh_verifications SET status='EXPIRED' WHERE node_id=? AND status='PENDING'",
        (node,),
    )
    db.execute(sql, ("30000000-0000-4000-8000-000000000002", *params[1:]))
    assert db.execute(
        "SELECT count(*) FROM ssh_verifications WHERE node_id=? AND status='PENDING'",
        (node,),
    ).fetchone()[0] == 1
    assert db.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='identity_link_tokens'"
    ).fetchone()[0] == 1
    # Owner-pinned root proof public key: Agent can never create this record.
    db.execute(
        "INSERT INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at)"
        " VALUES (?,?,?,?,?)",
        (node, "base64url-root-public", "SHA256:owner-confirmed", user, 90),
    )
    verification_id = "30000000-0000-4000-8000-000000000002"
    revision = "a" * 64
    db.execute(
        "UPDATE nodes SET config_revision=?, init_stage='WAITING_VERIFICATION' WHERE id=?",
        (revision, node),
    )
    db.execute(
        "UPDATE ssh_verifications SET prepared_at=? WHERE id=? AND status='PENDING'",
        (100, verification_id),
    )
    # Mirrors Gateway's guarded, single-use state transition. A second proof
    # MUST NOT update VERIFIED again, even with otherwise identical evidence.
    verification_sql = (
        "UPDATE ssh_verifications SET status='VERIFIED',verified_at=?,proof_id=?,proof_hash=? "
        "WHERE id=? AND node_id=? AND status='PENDING' AND prepared_at IS NOT NULL "
        "AND expires_at>? AND nonce_hash=? AND login_user=? AND key_fingerprint=? "
        "AND config_revision=? AND public_key_id=? "
        "AND EXISTS (SELECT 1 FROM nodes WHERE id=? AND login_user=? AND config_revision=? "
        "AND init_stage='WAITING_VERIFICATION') "
        "AND EXISTS (SELECT 1 FROM public_keys WHERE id=? AND purpose='daily' AND active=1)"
    )
    arguments = (
        150, "40000000-0000-4000-8000-000000000001", "proof-hash",
        verification_id, node, 150, "hash-only", "root", "SHA256:test",
        revision, key, node, "root", revision, key,
    )
    result = db.execute(verification_sql, arguments)
    assert result.rowcount == 1, "valid, prepared proof failed conditional verification"
    assert db.execute(verification_sql, arguments).rowcount == 0, "proof replay accepted"
    assert db.execute(
        "SELECT status,proof_id FROM ssh_verifications WHERE id=?", (verification_id,)
    ).fetchone() == ("VERIFIED", arguments[1])
    # Never count a stale key or an unprepared record as verified.
    db.execute(
        "UPDATE ssh_verifications SET status='PENDING',prepared_at=NULL,verified_at=NULL "
        "WHERE id=?", (verification_id,)
    )
    assert db.execute(verification_sql, arguments).rowcount == 0, "unprepared proof accepted"
    db.execute(
        "UPDATE ssh_verifications SET prepared_at=100 WHERE id=?", (verification_id,)
    )
    invalid_key = (*arguments[:-1], "wrong-daily-key")
    assert db.execute(verification_sql, invalid_key).rowcount == 0, "inactive daily key accepted"
    # Every node must have at most one unresolved signed operation even when
    # two operators race between the initial SELECT and D1 INSERT.
    insert_operation = (
        "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,"
        "expected_revision,command_json,signature,status,created_at,expires_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    )
    operation_a = "40000000-0000-4000-8000-000000000001"
    operation_b = "40000000-0000-4000-8000-000000000002"
    operation_c = "40000000-0000-4000-8000-000000000003"
    def values(operation_id: str, identifier: str, state: str, target: str = node):
        return (operation_id, target, "node.preflight", user, identifier, revision,
                "{}", "fixture-signature", state, 1, 300)
    db.execute(insert_operation, values(operation_a, "unique-a", "CREATED"))
    try:
        db.execute(insert_operation, values(operation_b, "unique-b", "CREATED"))
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("concurrent unresolved operations for same VPS were accepted")
    db.execute("UPDATE operations SET status='SUCCEEDED' WHERE id=?", (operation_a,))
    db.execute(insert_operation, values(operation_b, "unique-b", "DISPATCHED"))
    try:
        db.execute(insert_operation, values(operation_c, "unique-c", "RUNNING"))
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("another operation bypassed a DISPATCHED command")
    # One VPS does not lock all other VPSs.
    secondary_node = "00000000-0000-4000-8000-000000000002"
    db.execute(
        "INSERT INTO nodes(id,name,ssh_host,login_user,created_at) VALUES (?,?,?,?,?)",
        (secondary_node, "second", "127.0.0.2", "root", 1),
    )
    db.execute(insert_operation, values(operation_c, "unique-c", "CREATED", secondary_node))
    db.execute("UPDATE operations SET status='FAILED' WHERE id=?", (operation_b,))
    db.execute(insert_operation, values("40000000-0000-4000-8000-000000000004", "unique-d", "CREATED"))
    print("PASS: single unresolved operation per VPS, with independent nodes")

    print("PASS: migrations, guarded root proof, expired challenge and replay rejection")


if __name__ == "__main__":
    run()
