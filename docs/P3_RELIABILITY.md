# P3.3 — Agent 断网恢复、证明死信队列与操作回执幂等

> 本功能只在 SSH Manager 开发分支实现。**尚未对真实 VPS 和 Cloudflare Staging 完成端到端验收**，不得以 CI 通过为由关闭密码认证或合并生产。

## 一、为什么需要两套不同的本地队列

一条 SSH 验证链路涉及两种对象：**Root Helper 签署的 SSH 认证证明**，以及 **Agent 执行完签名命令后的操作结果**。两者权限不同、生命周期不同，不能混用：

| 对象 | 持久化位置 | 所有者 | 内容 | 断网行为 |
| --- | --- | --- | --- | --- |
| Root 签名证明 | `/var/lib/ssh-manager-root/proof-outbox` | root，0700/0600 | 不含私钥的签名认证证据 | 保留、后续重传；绝不重新签署同一挑战 |
| Agent 操作回执 | `/var/lib/ssh-manager-agent/reports` | ssh-manager，0700/0600 | 已执行操作的结果代码、状态及受限详情 | 先落盘再上报，断网重试；绝不重新执行命令 |

Cloudflare 接受后，Agent 才向本机队列发送 ACK。若 ACK 丢失，同一份证明或同一份已保存的终态回执可以再次上报，Cloudflare 通过精确校验返回幂等确认，而不是重复修改配置或插入审计。

## 二、永久失败与暂时失败的区别

**Root 证明**只有收到 Cloudflare HTTP 409 并且错误码明确属于 `CHALLENGE_NOT_ACTIVE`、`CHALLENGE_CONTEXT_CHANGED` 或 `PROOF_ALREADY_USED_OR_CONTEXT_CHANGED`，才进入 `/var/lib/ssh-manager-root/proof-outbox/rejected`。原始签名 JSON 和受控的拒绝原因仍由 root 私有保存，下一份证明可以继续上报。

**Agent 操作回执**只有收到 HTTP 409 并且错误码属于 `VERIFICATION_PREPARATION_STALE`、`INVALID_PREPARATION_REPORT`、`INVALID_POLICY_REPORT`、`INSTALL_PROOF_MISSING` 或 `CONFLICTING_OPERATION_REPORT`，才保存在 `/var/lib/ssh-manager-agent/reports/rejected`，而非无限占据队列首位。错误操作结果不会被更改或重新执行。

所有其他情况，包括断网、DNS/TLS 故障、超时、401、403、429、5xx、未知错误码以及可能延迟的准备确认 `CHALLENGE_PREPARATION_UNCONFIRMED`，**都保留本地记录并等待下一次重试**。绝不把“Cloudflare 暂未收到准备回执”误判为 SSH 登录无效。

## 三、原始五分钟挑战期限不会延长

Root Helper 出具的签名证明包含可信 SSH 认证时间和观察时间。Agent 在挑战有效期内短暂断线（例如 90 秒）后，Cloudflare 仍可在**原五分钟期限内**核验其签名及全部上下文。断网不会使挑战自动续期。

超过挑战到期时间后，旧证明不能成为 VERIFIED。必须由管理员为**当前选中的单台 VPS**重新发起一次五分钟验证；不能绕过源认证、上传私钥、放宽 journal PID 校验或自动改用密码认证。

## 四、已覆盖的自动化测试

- 单台 Root Helper 的终态证明已失效时，签名证明被 root 私有隔离，但下一个合法证明仍可从队列取出。
- Root 归档目录、文件权限、允许的错误原因和签名原文保存均有测试；未知错误不允许归档。
- Agent 在 Cloudflare HTTP 503 后重启，已持久化的操作结果仍能继续发送，原签名命令不会被重新执行；重复写入不同操作结果会被拒绝。
- Agent 自有回执目录也测试了 symlink、世界可读权限、终态归档和后续回执恢复。
- Cloudflare 对相同终态操作报告返回幂等确认；修改状态、代码或详情的回执将被拒绝。
- 延迟的 Root 证明在原挑战五分钟内仍可成功，挑战已过期或证明伪造时间则拒绝。
- 保持原有 Go race/vet、Root Helper root-only 测试、TypeScript/Vitest、D1 SQL 和隔离 Ubuntu OpenSSH 集成测试。

## 五、剩余已知限制 / Staging 阻断项

- **本轮已新增 Root 日志读取恢复**：Helper 收到签名命令后先保存领取记录，执行结束后将准确结果写入 root-only 0600 文件并 fsync，再回复 Agent。Agent 重启可读取已持久化的结果，补发云端回执，不执行第二次 SSH 命令。若 Helper 在修改 SSH 文件后尚未完成结果落盘就崩溃，则只能人工核查。
- 需要真实 Staging VPS 核验 systemd 用户/组权限、Root 出站队列与 Agent 持久化目录、journald PID 来源，以及 Cloudflare Worker/DO/D1 的事务一致性。
- 与 SSH 登录证明有关的 `VERIFIED` D1 写入目前是一组原子事务。其他操作状态的后续元数据写入仍应在后续安全审查中逐项核验，不能据此宣称所有 P3 操作完全事务化。
- P4 关闭密码登录、救援公钥授权与手动回滚仍未开放。禁止自动回滚及跨 VPS 批量更改。

## 六、Root Helper 执行成功与 Agent 保存回执之间的异常恢复

恢复凭据分为三层：root 私有领取记录（只表示操作曾被领取）、root 私有终态结果文件（Root Helper 已执行并 fsync）、Agent 自有操作回执及结算标记。

Root 日志位于 /var/lib/ssh-manager-root/operations：operation UUID 对应的 .json 是领取记录，.result.json 是仅 root 可读取的不可覆盖终态记录，包含节点 ID、动作、UUID 和结果。Agent 的领取记录与终态回执分别存放在 /var/lib/ssh-manager-agent/operations 和 reports，使用所属服务账户独占权限。

Agent 发生重启或本机 IPC 响应丢失后，只通过 SO_PEERCRED 保护的 Root Helper Unix Socket 发出只读 operation.recover 请求；Helper 必须检查当前配置节点、操作 UUID 与动作完全匹配，不能重放过期签名命令，也不能查询跨 VPS 的 Root 结果。

| 状态 | 恢复动作 | 限制 |
| --- | --- | --- |
| RECORDED（已有可信终态结果） | Agent 读取原结果、先持久化回执、再上传 Cloudflare，收到确认后写入 .settled 标记 | 不重新修改 SSH |
| UNCONFIRMED（只有领取记录） | 不推断成功或失败；宽限期后写入 .review，交管理员核查 | 不允许自动重执行 |
| NOT_FOUND（无 Root 领取记录） | 不推断云端结果；宽限期后写入 .review | 不允许自动重执行 |
| 权限异常、符号链接或节点/动作不匹配 | 拒绝本地恢复 | 不伪造可信结果 |

仍存在不可自动消除的故障窗口：Root Helper 修改了 authorized_keys，随后在写入最终结果之前崩溃。在这种情况下，领取记录无法证明最终 SSH 状态，必须通过服务商控制台或独立 SSH 会话检查，绝不能自动重试修改、打开密码登录、恢复旧 SSH 配置或标记 VERIFIED。

当前 .review 仅是 Agent 私有目录中的本地人工核查标记，尚无云端 UI 审核操作。真实 VPS 的 SIGKILL、断电、journald 兼容性以及 Cloudflare Staging 全链路仍待验收。
