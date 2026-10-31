# SSH Manager V4

基于 Cloudflare Workers、D1、Durable Objects 和 Linux Go Agent 的多 VPS SSH 密钥管理系统。

**架构已调整为 1 个 Worker + 2 个自定义域名**。单 Worker 同时提供中文管理面板及 VPS Agent 通信，但二者通过精确 Host 隔离：

| 入口 | 业务 | 安全验证 |
|---|---|---|
| Control 域名，例如 console.example.com | 中文 React 管理面板、/api/* | hostname-based Cloudflare Access + Worker Access JWT 验签 |
| Agent 域名，例如 agent.example.com | 仅 /agent/v1/*（设备配对、WebSocket、命令和回执） | Agent Ed25519 设备签名 |
| 共用 Cloudflare Worker | 一份 D1 + 同 Worker NodeSession Durable Object | 不再使用跨 Worker DO binding |

两域名指向同一 Worker；管理域名不能访问 Agent API，Agent 域名不能访问管理 API 或任何 Web 静态文件。即便有人错配 Cloudflare Access，管理内容仍须通过 Worker 内置 JWT 校验。禁用 workers.dev、Preview URLs，设置 assets.run_worker_first=true，防止静态文件绕过路由。

**Access 只能保护管理 hostname，不能开启 Worker-level Access**，否则 VPS Agent 的 WebSocket 会被拦截。

> 项目尚未完成 Cloudflare Staging + 真实 VPS P3.4 T01–T11 联调。当前代码可部署测试环境，不可视为生产 SSH 管理已验收。

## 快捷部署（独立 Staging）

先在 Cloudflare Zero Trust 为 Control 域名配置 GitHub/Cloudflare 双身份、MFA 和 Owner Allow 策略，获取 Team Domain 与 Access Application AUD。准备两个当前 Cloudflare 账户管理的自定义域名。

~~~powershell
git clone https://github.com/lwhx/SSH-Manager.git
cd SSH-Manager
npm install
npx wrangler login
npm run cf:quick
~~~

首次按提示填写两个域名、Team Domain、AUD、Owner 邮箱并确认 SINGLE-STAGING。脚本配置一个 Staging D1、一套命令签名密钥、一个 Worker 的本地 Durable Object，上传 Secret，自动构建中文界面。后续在同一目录执行：

~~~powershell
git pull --ff-only
npm install
npm run cf:quick
~~~

不会自动重新生成密钥、自动开启救援或修改 VPS。

[单 Worker 快捷部署](docs/CLOUDFLARE_QUICK_DEPLOY.md) · [完整部署须知](docs/DEPLOYMENT.md) · [双 Worker 迁移指南](docs/MIGRATE_DUAL_TO_SINGLE.md) · [GitHub 自动部署（单 Worker）](docs/GITHUB_CLOUDFLARE_SINGLE_DEPLOY.md)

## 核心安全约束

1. 只保存日常公钥和救援公钥；用户的 SSH 私钥不上传 Cloudflare/GitHub/Agent。
2. VPS 上的 Go Agent 主动连接 Agent 域名，使用 Ed25519 身份签名，WebSocket 优先、HTTPS 备用。
3. 必须先安装日常公钥，再由管理员本地新 SSH 会话验证；可信服务端 SSHD/journald 证据由 Root Helper 签名，Cloudflare 验证后更新 D1 VERIFIED。
4. 只有管理员明确选择**单台 VPS**、输入完整 UUID 和原因，才能人工下发关闭密码登录、启用/撤销救援公钥、手动恢复和配置回滚命令。
5. **永不自动回滚，不自动恢复密码登录，不批量下发救援公钥。**

云端 MANUAL_SSH_ACTIONS_ENABLED=false、VPS Root Helper 的全部 SSH 写入开关均默认 false。真实 Staging E2E 未完成之前不要对生产 VPS 开启。

## 源代码目录

- apps/single-worker/：单 Worker 路由入口与 Host 分流
- apps/control-worker/：Access JWT、RBAC、管理 API
- apps/agent-gateway/：Agent 配对、通信、Root 验签及 NodeSession
- apps/console/：React 中文面板
- packages/db/migrations/：D1 数据迁移
- packages/protocol/：签名协议、可信证明
- agent/：Go Agent + Root Helper
- scripts/cloudflare_quick_deploy.mjs：单 Worker Staging 部署

## 本地测试

~~~bash
npm install
npm run check
npm run test
npm run test:cf:quick
npm run cf:quick:dry
npm run build:web
node scripts/test_gateway_workerd.mjs --local-only
cd agent && go test ./...
~~~

本地 CI 通过不等于云端 VPS 实机验收。相关文档：[P3.4 实机 Runbook](docs/P3_STAGING_LIVE_RUNBOOK.md)、[P4/P5 人工操作](docs/P4_P5_MANUAL_OPERATIONS.md)、[P6 上线门槛](docs/P6_RELEASE_AND_SECURITY_GATE.md)。

许可证由仓库所有者确定。
