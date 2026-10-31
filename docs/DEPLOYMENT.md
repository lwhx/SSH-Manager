# SSH Manager V4：Cloudflare 单 Worker + 双自定义域名部署

> **仅独立 Staging**。P3.4 真实测试 VPS、Windows 全链路验收未完成，禁止对生产 SSH 认证执行高危操作。

## 目标配置

- 唯一 Worker：ssh-manager-staging。
- 统一入口：apps/single-worker/src/index.ts。
- 两个 Custom Domains（均属当前 Cloudflare zone）：管理域名 + Agent 域名。
- 一个 D1：ssh-manager-staging，binding DB。
- 一个 SQLite Durable Object：本 Worker 导出的 NodeSession，binding NODE_SESSIONS，**无跨 Worker script_name**。
- ASSETS：apps/console/dist，必须 assets.run_worker_first=true。
- workers_dev=false、preview_urls=false，拒绝其它访问入口。
- 同一 Worker 中 COMMAND_PUBLIC_KEY 为公开配置，COMMAND_PRIVATE_KEY 为仅存在 Cloudflare 的 Secret。

**Access 只能保护 Control hostname，不能保护整个 Worker：** Cloudflare Zero Trust 需要为 Control 自定义域名创建 Self-hosted Access Application，配置 GitHub/Cloudflare IdP、MFA、精确 Owner Allow。Agent 自定义域名使用设备 Ed25519 验证，不允许浏览器 Access 阻断 WebSocket。Worker 内部所有管理页面和 API 均再次验签 Access JWT。

Control 与 Agent 域名必须不同，DNS/Custom Domain 不得与旧 Worker 或既存 CNAME 冲突。

## 快捷部署

先在 Cloudflare Zero Trust 创建 Control 域名的 Access Application，取得 Team Domain、Application AUD、Owner 邮箱。

~~~powershell
git clone https://github.com/lwhx/SSH-Manager.git
cd SSH-Manager
npm install
npx wrangler login
npm run cf:quick
~~~

首次引导输入两个域名、Access Team Domain、AUD、Owner 邮箱，并确认 SINGLE-STAGING。已存在 Staging D1 时必须输入 REUSE-SINGLE-D1，且不能把旧 D1 当作旧 Durable Object 自动迁移。

本地生成的 wrangler.single.staging.local.jsonc、.ssh-manager-deploy/single-staging.json 已在 gitignore 中；它们不保存私钥。快捷脚本按已绑定的 D1、公钥、域名和安全锁检查环境，绝不在更新时自动更换签名密钥。

后续更新：

~~~powershell
git pull --ff-only
npm install
npm run cf:quick
~~~

离线测试（绝不触及云端）：

~~~powershell
npm run test:cf:quick
npm run cf:quick:dry
~~~

## 手动 Wrangler 部署（不使用脚本）

复制 wrangler.single.staging.example.jsonc → wrangler.single.staging.local.jsonc。填入 Cloudflare D1 UUID、两域名（routes 及 CONTROL_HOSTNAME/AGENT_HOSTNAME）、Access Team Domain/AUD、Owner 邮箱与命令公钥。私钥 PKCS#8 DER Base64 只能安全上传为 Cloudflare Worker Secret，不提交到 GitHub/D1/Agent。

~~~bash
npm install
npm run check
npm run build:web
npx wrangler d1 migrations apply ssh-manager-staging --remote --config wrangler.single.staging.local.jsonc
npx wrangler deploy --config wrangler.single.staging.local.jsonc
npx wrangler secret put COMMAND_PRIVATE_KEY --config wrangler.single.staging.local.jsonc
~~~

已配置过 Cloudflare Secret 时不要覆盖旧私钥。所有危险操作开关默认 false。

## 必须完成的安全验收

~~~bash
python scripts/staging_remote_probe.py --staging-only --control-url https://console-staging.example.com --gateway-url https://agent-staging.example.com
~~~

Control 匿名 API 必须被 Access 拦截；Agent /agent/v1/health 正常返回设备签名认证 JSON；Agent /api/v1/health、/ 和 /index.html 必须返回 404。管理域名登录后访问 Agent API 也必须 404。

检查两个自定义域名确实指向同一个 Worker，且 workers.dev / Preview URLs 均关闭。只有安全拓扑通过才能继续单台 VPS 的 T01–T11 验收。

已有双 Worker Staging/生产实例必须先阅读 [人工迁移指南](MIGRATE_DUAL_TO_SINGLE.md)；快捷部署不会自动处理旧 DO 命名空间、Agent 连接、D1 与签名密钥。

紧急恢复必须使用云厂商 Console/VNC/Rescue。项目永不因 SSH 断开自动回滚或恢复密码登录。
