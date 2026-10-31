# SSH Manager Cloudflare 部署（简化版）

这是 **1 个 Cloudflare Worker + 2 个自定义域名 + 1 个 D1 + Worker 内部 Durable Object** 的架构。

**推荐直接通过 Cloudflare Dashboard → Workers & Pages → GitHub 导入仓库，不再要求你先用 Windows 终端部署。**

## 只做 3 步

1. **Cloudflare Zero Trust**：为管理域名（默认 ssh-staging.你的主域名）创建 hostname-based Access 应用，绑定 GitHub / Cloudflare IdP 和 Owner 邮箱、MFA，记录 Team Domain 与 AUD。
2. **Cloudflare Workers & Pages → GitHub**：选 lwhx/SSH-Manager、main、Worker 名 ssh-manager-staging。Root 目录为仓库根目录，Build command 留空，**Deploy command 写 npm run cf:deploy**，Preview command 写 npm run cf:preview:skip。
3. **只填 4 个 Build Variables 并 Save and Deploy**：
   - SSH_MANAGER_BASE_DOMAIN=你的 Cloudflare zone（例 whks.de）
   - SSH_MANAGER_ACCESS_TEAM_DOMAIN=你的 Access Team Domain
   - SSH_MANAGER_ACCESS_AUD=Control Access Application AUD
   - SSH_MANAGER_OWNER_EMAIL=你的管理员邮箱

**提醒：** Cloudflare 默认 Workers Builds Token 可能没有 D1 权限。首次部署应选择限定当前账户的 API Token，授予 Workers Scripts/Routes 和 D1 必要的 Read/Edit 权限。账户/Token 鉴权错误按日志修复，绝不把 Token 提交 GitHub。

首次云端构建会自动创建 Staging D1、完成迁移、生成短暂存在于构建进程内的 Ed25519 签名私钥并通过 stdin 存到 Worker Secret，再部署**一个** Worker 和两个 Custom Domains。部署后的 GitHub main 自动更新只会复用已有 D1、域名、DO、签名密钥。

如果想使用不同域名，可同时设置 SSH_MANAGER_CONTROL_HOSTNAME 和 SSH_MANAGER_AGENT_HOSTNAME 覆盖默认的 ssh-staging / agent-staging。

**管理 hostname 独占 Cloudflare Access**；不能对整个 Worker 开启 Access，否则 Agent WebSocket 失败。Worker 会再验证 JWT 且按 Host 拒绝其他服务的路径。必须保持 workers_dev=false、preview_urls=false 和 assets.run_worker_first=true。

## 不建议的事情

- 不要用两个 Worker 来部署当前代码。
- 不要使用带 REPLACE 占位符的示例 Wrangler 文件直接部署。
- 不要在 GitHub/Cloudflare Build Variables 存放 SSH 私钥、Root 证明私钥或 COMMAND_PRIVATE_KEY。
- 不要删除旧 D1 后重复初始化。私钥如果丢失或远端状态不完整，必须人工恢复。
- 不要把部署成功视为 P3.4 真机验收通过，也不允许直接对生产 VPS 开启 SSH 危险写入。

## 部署验证

访问管理域名应该先跳转 Cloudflare Access。Agent 域名 /agent/v1/health 直接返回设备认证 JSON；Agent 域名的 /、/api/v1/health 必须返回 404。

真实环境联调还应执行：

~~~bash
python scripts/staging_remote_probe.py --staging-only --control-url https://ssh-staging.你的主域名 --gateway-url https://agent-staging.你的主域名
~~~

进一步参阅 [3 步快捷部署指南](CLOUDFLARE_QUICK_DEPLOY.md) 和 [双 Worker 迁移](MIGRATE_DUAL_TO_SINGLE.md)。

## 备用本地部署方式

~~~powershell
git clone https://github.com/lwhx/SSH-Manager.git
cd SSH-Manager
npm install
npx wrangler login
npm run cf:quick
~~~

本地首次引导现在只需要一个 Control 域名，Agent 域名自动推导；后续使用同一条 npm run cf:quick 更新。Cloudflare Workers Builds / GitHub Actions / 本地更新应选一个作为主要部署渠道，避免并行部署冲突。
