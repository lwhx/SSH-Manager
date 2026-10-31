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
