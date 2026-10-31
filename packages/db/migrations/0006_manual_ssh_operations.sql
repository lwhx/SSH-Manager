-- P4/P5 scoped manual SSH operations: durable manager-owned snapshot lifecycle.
-- A snapshot is created ONLY after the Root Helper confirms success.
ALTER TABLE ssh_config_snapshots ADD COLUMN source_operation_id TEXT;
ALTER TABLE ssh_config_snapshots ADD COLUMN restored_at INTEGER;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_snapshot_ref_node
 ON ssh_config_snapshots(node_id,local_ref);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_rescue_per_node
 ON node_keys(node_id) WHERE purpose='rescue' AND state='installed';
CREATE INDEX IF NOT EXISTS idx_snapshot_active
 ON ssh_config_snapshots(node_id,restored_at,created_at);

-- A failed guard within D1 batch must ABORT, rolling back any preceding
-- operation-status update rather than returning a false-success 409 after commit.
CREATE TABLE IF NOT EXISTS manual_ssh_assertions (
 value INTEGER NOT NULL CHECK(value=1)
);
