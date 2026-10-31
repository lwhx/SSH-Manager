# SSH Manager V4 — Cloudflare 快捷部署（Staging）

> 只用于独立测试环境。不会连接生产 VPS，不会修改任何 SSH 密码认证、救援公钥或回滚开关。真实 Cloudflare + VPS 端到端验收尚未完成。

## 为什么不用官方 Deploy to Cloudflare 按钮

SSH Manager 是包含 Control Worker、Agent Gateway Worker、D1 和 Durable Objects 的多 Worker 项目。官方 Deploy Button 不能从同一个 monorepo 自动部署两套 Worker，本项目提供 Windows/macOS/Linux 通用的一条命令部署脚本。

## 第一次部署

首先在 Cloudflare Zero Trust 中配置 GitHub / Cloudflare 身份来源、MFA，以及只允许自己账号的登录策略。

为 Control 的预定 hostname 创建 Self-hosted Access Application，例如：

- ssh-manager-control-staging.你的账号.workers.dev
- 或者已经属于 Cloudflare 的测试域名，例如 console-staging.example.com

Control 必须由 Access 保护；Agent Gateway 不应被浏览器 Access 保护，否则 WebSocket 将返回 403。

你需要事先取得：
- Zero Trust Team Domain，示例：myteam.cloudflareaccess.com
- Control Access Application AUD（不是 Token，不是 Secret）
- 初始 Owner 的完整邮箱（与 Access 登录身份一致）

控制台部署前可根据 Cloudflare 账户的 Workers 子域名创建 hostname-based Access Application；也可以在 Worker 部署后开启 worker-level Access，但此时必须核对应用的实际 AUD。没有正确的 Access 应用及登录策略时，不能把这套测试系统当作正式管理面板使用。

Windows PowerShell：

~~~powershell
git clone https://github.com/lwhx/SSH-Manager.git
cd SSH-Manager
npm ci
npx wrangler login
npm run cf:quick
~~~

首次运行需要输入 Team Domain、Application AUD、Owner 邮箱，并输入 STAGING 确认只使用测试资源。

也支持在终端中提前设置非秘密配置：

~~~powershell
$env:SSH_MANAGER_ACCESS_TEAM_DOMAIN="myteam.cloudflareaccess.com"
$env:SSH_MANAGER_ACCESS_AUD="Control应用AUD"
$env:SSH_MANAGER_OWNER_EMAIL="owner@your-domain.com"
npm run cf:quick
~~~

## 自动执行内容

1. 检查 TypeScript 并构建 React 中文管理面板。
2. 检查当前 Cloudflare 账号是否已有 ssh-manager-staging D1；没有则创建；已有则要求明确输入数据库完整名称才能复用。
3. 将同一个 D1 UUID 写入两份 Staging Wrangler 本地配置（文件已加入 gitignore）。
4. 生成 Ed25519 签名密钥对。仅将公钥放入 Gateway 配置；将私钥的 PKCS#8 DER base64 直接通过 stdin 上传 Control Worker Secret，不保存到磁盘、Git 或普通配置。
5. 对 Staging D1 应用远端 migrations。
6. 先部署 ssh-manager-agent-gateway-staging，再部署 ssh-manager-control-staging。
7. 本地保存不含私钥的状态文件，用于下次更新保持 D1 和签名密钥稳定。

所有手动 SSH 高危操作开关保持 false，且从不触碰 production Wrangler 配置。

## 后续更新

同一台电脑保留初次部署的两份 Staging Wrangler 配置和 .ssh-manager-deploy/staging.json，执行：

~~~powershell
git pull --ff-only
npm ci
npm run cf:quick
~~~

脚本验证：当前登录 Cloudflare 账号内的 D1 UUID 与已配置的 Staging UUID 相同；Control Worker COMMAND_PRIVATE_KEY Secret 存在；Gateway 公钥、绑定名称和所有安全锁没有被改动。再自动迁移与部署两个 Worker，不产生新签名密钥，不修改任何 VPS。

## 部署后必须核验

Cloudflare Dashboard → Workers & Pages 中确认两个 Worker 均成功部署。Control 所有访问地址都应被 Access 保护，允许名单必须仅包含你的可信登录身份；Agent Gateway 应使用公开 HTTPS/WSS 设备身份签名，而不是浏览器 Access。

随后运行安全拓扑检查（必须提供真实 URL）：

~~~powershell
python scripts/staging_remote_probe.py --staging-only --control-url https://实际Control域名 --gateway-url https://实际AgentGateway域名
~~~

只有 Control Access 和 Agent Gateway 边界都 PASS，才可以在一台独立测试 VPS 上继续 P3.4 T01–T11 的真机验收。生产 VPS 不能使用当前版本执行高危 SSH 写入。

## 故障处理

首次初始化中断后，本地状态保持 bootstrapping。下次运行会检查 Control Secret：存在则安全恢复并继续部署；缺失就停止，不会擅自重新生成并覆盖已有 Gateway 公钥。不要删除本地状态强行初始化，以免破坏已配对的设备。

更换电脑时，请安全迁移两份本地 Staging Wrangler 配置和 .ssh-manager-deploy/staging.json（均不包含私钥），再在同一 Cloudflare 账号下执行快捷部署。不要对一个已有设备的部署重复初始化密钥。

预检查与本地测试：

~~~powershell
npm run test:cf:quick
npm run cf:quick:dry
~~~

这些测试不会连接 Cloudflare。完整验收依旧以 docs/P3_STAGING_LIVE_RUNBOOK.md 和 docs/P3_STAGING_E2E_ACCEPTANCE.md 为准。
