/**
 * Present safety-critical API failures without inviting an unsafe retry.
 * Keep the stable server error code in the message for audit correlation.
 */
const messages:Record<string,string>={
 IDEMPOTENCY_SCOPE_CONFLICT:
  "同一幂等键不能用于不同 VPS、不同 SSH 操作或不同参数。请核对原任务及节点记录，不要重复下发（IDEMPOTENCY_SCOPE_CONFLICT）。",
 NODE_OPERATION_RESULT_UNKNOWN:
  "当前 VPS 上一次 SSH 操作结果未知，已禁止再次下发。请先通过 VPS 服务商控制台核查实际 SSH 状态，不要重复执行危险命令（NODE_OPERATION_RESULT_UNKNOWN）。",
 NODE_OPERATION_IN_PROGRESS:
  "当前 VPS 已有任务执行中，请等待 Agent 的真实回执；不要重复提交相同操作（NODE_OPERATION_IN_PROGRESS）。",
 NODE_SETTINGS_CONFLICT:
  "节点资料已被其他管理员修改，或 Agent 正在配对，修改已被拒绝（HTTP 409）。请刷新节点资料后核对，再重新编辑（NODE_SETTINGS_CONFLICT）。",
 VERIFICATION_ALREADY_PENDING:
  "该 VPS 已有待完成的 SSH 验证挑战；请先完成或手动取消原挑战（VERIFICATION_ALREADY_PENDING）。",
 NODE_OFFLINE:
  "当前 VPS 的 Agent 已离线或心跳超时，禁止下发 SSH 操作（NODE_OFFLINE）。",
 MANUAL_SSH_FEATURE_DISABLED:
  "当前环境已禁止高风险 SSH 修改，不能执行人工操作（MANUAL_SSH_FEATURE_DISABLED）。",
 INTERNAL_ERROR:
  "服务端处理异常。请先查询任务中心或审计记录，确认实际结果，不要立即重复提交危险操作（INTERNAL_ERROR）。"
};
export function presentConsoleError(value:unknown):string{
 if(typeof value!=="string"||!value.trim())return "REQUEST_FAILED";
 return messages[value]||value;
}
