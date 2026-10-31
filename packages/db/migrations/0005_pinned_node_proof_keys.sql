-- Per-node Root Helper trust anchor. NEVER trust Agent device keys for SSH proof.
CREATE TABLE IF NOT EXISTS node_ssh_proof_keys(
 node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 public_key TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 approved_by TEXT NOT NULL REFERENCES users(id),
 created_at INTEGER NOT NULL
);
-- Retain non-secret proof attribution for audit and replay analysis.
ALTER TABLE ssh_verifications ADD COLUMN proof_id TEXT;
ALTER TABLE ssh_verifications ADD COLUMN proof_hash TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_verification_unique_proof_id
 ON ssh_verifications(proof_id) WHERE proof_id IS NOT NULL;
