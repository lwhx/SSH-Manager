# SSH Manager V4 · 安全不变量与当前验收状态

> **状态更新（2026-11-01）**：P3 Root 独立签名证明、P4 手动密码策略变更、P5 救援公钥和单节点手动恢复相关代码与隔离 CI 已实现，PR #8 已合并到 `main`。**但真实 Cloudflare Staging、可销毁 VPS、Access/RBAC 与 P3.4 T01–T11 尚未获得独立实机验收。生产 VPS 禁止以“代码存在”为理由启用 SSH 高危写入。**

## 永远不得放宽的信任边界

1. **浏览器管理面**：Cloudflare Access JWT + D1 Owner/Admin/Viewer RBAC；没有独立密码登录。Agent hostname 不得暴露管理 API、HTML 或静态资源；管理 hostname 仅使用 hostname-based Access。
2. **Agent**：非 root、仅出站、Ed25519 设备身份、时钟与 nonce 重放校验；只接收 node_id、版本、有效期、签名和动作白名单一致的命令，**不得执行任意 Shell**。
3. **Root Helper**：本机 Unix Socket 与最小 root 权限；Root Proof 私钥仅存于当前 VPS，Owner 从可信渠道核对并固定相应公钥。Agent 设备签名和 HTTP 成功不等于 Root 可信证明。
4. **SSH 登录证明**：准备挑战或客户端 `ssh` 返回成功，都不能证明新登录安全可用；必须有匹配 node/user/key/revision/TTL 的可信 sshd journald + `/proc` 证据及 Root 签名，并成功更新 D1。
5. **公钥**：全局 daily/rescue 只存公钥，不自动安装到任何 VPS；用户的 daily/rescue 私钥不得上传。Root Helper 只操作精确选中的 VPS 和受管的文件/条目，不覆盖已有 authorized_keys。
6. **人工危险操作**：`MANUAL_SSH_ACTIONS_ENABLED` 和 Root 本机 `enable_*` 默认全部 false。关闭/恢复密码、快照回滚、救援启用/撤销必须由 Owner 选择单节点、输入完整 UUID、原因并满足安全证明要求。
7. **不确定结果**：DISPATCHED/RUNNING 过期是 `RESULT_UNKNOWN`，不能自动标记 FAILED/SUCCEEDED、解除操作锁、再次执行 Root SSH 写入或回滚。Agent 崩溃/失联后仅重发持久化结果。
8. **事务与审计**：身份变更、密钥固定/轮换、一次性挑战、敏感操作的节点/密钥/快照状态必须与必要审计一致；并发条件、唯一索引、事务内失败断言必须失败关闭，不能补造历史审计。
9. **安全文件系统**：严格检查所有权、文件权限、symlink/`O_NOFOLLOW`、OpenSSH `Include/Match`、系统权限与 journald 来源；不兼容环境返回拒绝，不静默降级。
10. **独立救援入口**：SSH Manager 不能替代 VPS 服务商 VNC、Serial、Rescue Console；任何真机实验必须保留现有连接和恢复路径。

## 已实现不代表发布批准

- **已实现 + 自动化测试覆盖**：Control/Agent API、同 Worker DO、Root Helper、日常/救援公钥受限操作、事务审计、并发回执、Staging D1 聚合只读预检。
- **仍需独立完成**：Staging 实际 D1 绑定核查与只读预检、管理域名 Access 和 RBAC 验证、真实可销毁 Linux VPS 的可信登录证据、单节点密码禁用后新 SSH 会话与手动恢复、独立安全 Review 和生产批准。
- **默认策略**：`MANUAL_SSH_ACTIONS_ENABLED=false`、Root `enable_*` 全 false。无授权不进行 Cloudflare D1 远端迁移或 VPS SSH 写入。

进一步阅读：[最新开发文档](DEVELOPMENT.md)、[P3 真实联调](P3_STAGING_LIVE_RUNBOOK.md)、[P4/P5 人工操作](P4_P5_MANUAL_OPERATIONS.md)、[P6 发布安全关卡](P6_RELEASE_AND_SECURITY_GATE.md)、[D1 只读预检](STAGING_D1_READONLY_PREFLIGHT.md)。
