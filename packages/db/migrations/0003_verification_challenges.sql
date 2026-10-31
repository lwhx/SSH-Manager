-- Per-node challenge state. No client-controlled callback can mark these VERIFIED.
ALTER TABLE ssh_verifications ADD COLUMN public_key_id TEXT REFERENCES public_keys(id);
ALTER TABLE ssh_verifications ADD COLUMN issued_by TEXT;
ALTER TABLE ssh_verifications ADD COLUMN invalidated_at INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_pending_verification_per_node
  ON ssh_verifications(node_id) WHERE status='PENDING';
CREATE INDEX IF NOT EXISTS idx_verification_node_status_expiry
  ON ssh_verifications(node_id, status, expires_at);
