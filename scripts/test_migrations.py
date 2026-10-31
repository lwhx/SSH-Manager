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
    print("PASS: migrations, foreign keys, verification deduplication and expiry")


if __name__ == "__main__":
    run()
