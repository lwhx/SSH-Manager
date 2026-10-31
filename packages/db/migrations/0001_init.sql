PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('owner','admin','viewer')),
  status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_identities (
  subject TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), provider TEXT NOT NULL DEFAULT 'access', created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, ssh_host TEXT NOT NULL, ssh_port INTEGER NOT NULL DEFAULT 22,
  login_user TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unpaired', init_stage TEXT NOT NULL DEFAULT 'WAITING_PAIR',
  config_revision TEXT NOT NULL DEFAULT 'unverified', agent_version TEXT, os_id TEXT,
  last_seen_at INTEGER, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_credentials (
  node_id TEXT PRIMARY KEY REFERENCES nodes(id), public_key TEXT NOT NULL,
  paired_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS pairing_tokens (
  id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id),
  token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, used_at INTEGER, created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_nonces (
  node_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(node_id,nonce)
);
CREATE TABLE IF NOT EXISTS public_keys (
  id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('daily','rescue')),
  name TEXT NOT NULL, algorithm TEXT NOT NULL, public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL, version INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_key_active ON public_keys(purpose) WHERE active=1;
CREATE TABLE IF NOT EXISTS node_keys (
  id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id), public_key_id TEXT NOT NULL REFERENCES public_keys(id),
  login_user TEXT NOT NULL, purpose TEXT NOT NULL, state TEXT NOT NULL, expires_at INTEGER, verified_at INTEGER
);
CREATE TABLE IF NOT EXISTS ssh_verifications (
  id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id), key_fingerprint TEXT NOT NULL,
  login_user TEXT NOT NULL, config_revision TEXT NOT NULL, nonce_hash TEXT NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, verified_at INTEGER
);
CREATE TABLE IF NOT EXISTS ssh_config_snapshots (
  id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id), local_ref TEXT NOT NULL,
  config_hash TEXT NOT NULL, revision TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id), action TEXT NOT NULL,
  operator_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, expected_revision TEXT NOT NULL,
  command_json TEXT NOT NULL, signature TEXT NOT NULL, status TEXT NOT NULL,
  result_code TEXT, detail TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, finished_at INTEGER,
  UNIQUE(operator_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_operation_poll ON operations(node_id,status,expires_at);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, node_id TEXT, action TEXT NOT NULL,
  operation_id TEXT, result TEXT NOT NULL, reason TEXT, created_at INTEGER NOT NULL
);
