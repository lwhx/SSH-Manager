-- One VPS may have at most one unresolved signed operation, including during
-- races between independent admins and Worker isolates. A SELECT check alone
-- cannot provide this guarantee; D1's unique index is the final arbiter.
--
-- Do NOT silently mark DISPATCHED/RUNNING operations completed or expire
-- unknown outcomes. If historical data already violates this constraint,
-- migration fails closed and requires a supervised Staging investigation.
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_unresolved_operation_per_node
 ON operations(node_id) WHERE status IN ('CREATED','DISPATCHED','RUNNING');
