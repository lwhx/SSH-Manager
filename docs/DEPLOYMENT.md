# Cloudflare 部署与安全检查

**本文件描述 V4 原型的配置前置，尚未完成真实生产部署验证。**

## 资源

- 两个 Worker：\`ssh-manager-control\`（需要 Access）；\`ssh-manager-agent-gateway\`（Agent 身份签名）。
- 一个 D1（生产/Staging 要隔离）。
- Durable Object \`NodeSession\` 注册在 Gateway；Control 使用跨 Worker DO binding。
- GitHub/Cloudflare Access 登录来源；\`BOOTSTRAP_OWNER_EMAIL\` 只用于明确的首位 Owner 引导。
- 命令 Ed25519 密钥对，仅 Control Worker 保存私钥。不要向 GitHub 提交任何 Secret、私钥、D1 令牌。
- Cloudflare 自定义域名：\`console.example.com\`、\`agent.example.com\`。

## 安装

1. 修改 wrangler 配置中的 \`REPLACE\` 占位符，并创建 Cloudflare D1。
2. 通过 \`wrangler secret put COMMAND_PRIVATE_KEY --config wrangler.control.jsonc\` 安全配置 Control 端签名密钥。
3. 在 Cloudflare Access 中开启 GitHub/Cloudflare 两种 IdP，并明确配置 Allow 策略、MFA 和应用 AUD。不要允许任意 Cloudflare 账号进入。
4. 设置 \`ACCESS_TEAM_DOMAIN\` 为实际 Access team domain，\`ACCESS_AUD\` 为应用 AUD，\`BOOTSTRAP_OWNER_EMAIL\` 为受信任 Owner 的完整邮箱。
5. 使用相应 Wrangler 命令运行 D1 migrations，先部署 Gateway，再部署 Control。
6. 在隔离 Staging 环境运行 JWT 伪造/过期、配对令牌重复、Agent 签名重放和 WebSocket 连通性测试。
7. 真实 VPS 验证之前，不要启用 SSH 写操作。

## 当前实现与不可跳过的安全验收

已实现 Agent 出站通信、Root Helper 限权 Unix Socket、指定 VPS 的日常公钥安装、Root 认证签名、Cloudflare 验签、防重放、D1 一次性状态更新、Agent/Root 持久化操作结果及断网恢复。Owner 为每台 VPS 人工固定 Root Helper 的独立证明公钥。

**真实 VPS + Cloudflare Staging 的端到端验收仍未完成。** GitHub CI 和本地 workerd 合约测试不能替代真实 SSHD journald 认证日志与 VPS 系统权限验证。

- P4 关闭密码登录、单节点救援公钥启用/撤销及 SSH 配置手动回滚：尚未开发，继续保持锁定。
- 可信登录的人工验收参见 [P3.3 证明指南](P3_PROOF_END_TO_END.md)。
- 隔离 VPS 权限、服务账户及预检参见 [Staging 清单](P3_STAGING_DEPLOY_CHECKLIST.md)。
- Root/Agent 断网与崩溃恢复参见 [P3.3 可靠性](P3_RELIABILITY.md)。

### 本地 Worker / D1 合约测试（不调用远程服务）

CI 额外运行：

```bash
node scripts/test_gateway_workerd.mjs --local-only
```

脚本使用 `wrangler dev --local`、临时 D1 `--persist-to` 状态目录和仅用于进程内测试的 Ed25519 公私钥，验证真实 Worker 设备认证、Root 证明签名、D1 状态转移、幂等与数据库故障注入。只监听 127.0.0.1，不操作云端数据库或 VPS。运行结束自动移除测试配置和临时目录。

## 紧急恢复

若 SSH 登录和 Agent 同时不可用，本项目无法自行恢复；请使用 VPS 提供商的 VNC、Web Console 或 Rescue Mode。

## Agent 配置文件权限（必检）

标准路径 `/etc/ssh-manager/agent.json` 的配对操作应先建立 `ssh-manager` 系统账户并由 root 执行。目录权限为 **`root:ssh-manager 0750`**，设备凭据文件权限必须是 **`ssh-manager:ssh-manager 0600`**。Agent 启动时会拒绝符号链接、组/全局可读权限及其他 UID 拥有的设备私钥。

Root Helper 的 `/etc/ssh-manager/helper.json` 保持 **`root:root 0600`**，不可与 Agent 设备私钥混放。Root 独立证明私钥在 `/var/lib/ssh-manager-root` 中，不上传云端。

Agent 的 systemd 状态目录为 **`StateDirectory=ssh-manager-agent`**，存储领取凭据、等待云端确认的回执、人工核查标记；Root Helper 使用 **`StateDirectory=ssh-manager-root`** 保存 root-only 执行日志与签名证明。任何操作的执行结果不确定时都禁止自动重执行 SSH 修改，也禁止自动回滚。

旧文档曾出现 `agent.json` 为 `root:ssh-manager 0640` 的建议；该权限与现行 Agent 运行时严格的同 UID、0600 检查不兼容，本版以这里的说明为准。

## P4/P5 手动 SSH 修改（部署前必须阅读）

只有完成 P3.4 T01–T11 真实 VPS + Cloudflare Staging 验收后才可进行独立审查。新版本加入 `0006_manual_ssh_operations.sql`，需要按序应用全部迁移后才能识别人工操作的快照与回执事务。

`MANUAL_SSH_ACTIONS_ENABLED` 在 Control 配置中默认 `false`。Root Helper 的 `enable_password_disable`、`enable_password_restore`、`enable_config_rollback`、`enable_rescue` 同样全部默认 `false`；仅允许独立测试 VPS 上管理员按操作窗口逐项开启，完成后关闭。

Root Helper 的 systemd 服务只允许对 `/etc/ssh/sshd_config.d` 开放必要写权限，不允许整个 `/etc` 可写。安装 P4 配置时要求主 `sshd_config` 的第一条有效配置是 Include `/etc/ssh/sshd_config.d/*.conf`，否则拒绝，不做自动修复。SSH Manager 只创建和删除自己的 drop-in，不执行通用 shell，也不覆盖别人的配置。

Root Helper 执行高危操作后，必须使用只在 root 私有目录存在的证明密钥对操作 ID、当前节点、动作、配置版本和完整结果 SHA256 签名。Agent 只是转发；Cloudflare 只有通过固定 Root 公钥验证后才以 D1 原子事务修改操作、节点、救援状态或快照。Root 回执无法保存、云端验签失败、状态不确定时只能人工核查，绝不重执行和自动回滚。

详细说明：[P4/P5 手动操作](P4_P5_MANUAL_OPERATIONS.md) 与 [P6 上线前门槛](P6_RELEASE_AND_SECURITY_GATE.md)。
