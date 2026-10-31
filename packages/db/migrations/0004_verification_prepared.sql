-- A prepared challenge is NOT proof of SSH authentication.
-- Only the future root-observed, signed login evidence may mark VERIFIED.
ALTER TABLE ssh_verifications ADD COLUMN prepared_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_ssh_verifications_prepared
 ON ssh_verifications(node_id,status,prepared_at);
