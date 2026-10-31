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

## 当前尚未完成

- Agent WSS 主动长连及切换重连完整状态机（目前 HTTPS 轮询可使用）。
- SSH 特权 Helper、快照、可信会话证明和 Linux 发行版兼容性测试。
- 前端完整的 Owner 二次确认、RBAC 管理和实时操作流。
- 密码登录恢复、救援公钥授权与撤销。
- 端到端 Cloudflare Staging 部署验收与 T01-T36 的实际测试。

## 紧急恢复

若 SSH 登录和 Agent 同时不可用，本项目无法自行恢复；请使用 VPS 提供商的 VNC、Web Console 或 Rescue Mode。

## Agent 配置文件权限（必检）

`-mode pair` 默认会创建由执行用户拥有、0600 权限的配置文件。若使用 `sudo` 配对，必须在启动非特权 Agent 服务前创建独立的 `ssh-manager` 用户/组，并将 `/etc/ssh-manager` 目录设为 `root:ssh-manager` 0750、`agent.json` 设为 `root:ssh-manager` 0640。Agent 只需读取设备私钥，不能拥有修改配置的能力。

Agent 使用 systemd `StateDirectory=ssh-manager` 保存本地操作收据；同一指令经 WSS 与 HTTPS 重复送达时只处理一次。操作未确认时不会自动回滚。

`agent/internal/sshkeys` 目前仅是**未接入网络/特权 Helper 的受测文件维护模块**；不得单独让 Web 请求触发修改系统 SSH。
