# Cloudflare 单 Worker 快捷部署（Staging）

**一个 Worker、两个 Custom Domain、一个 D1、一个 NodeSession Durable Object**。仅用于独立测试环境。

## 1. 首次准备

在你的 Cloudflare 账户内准备两个属于当前 zone 的自定义域名，例如：

| 用途 | 示例域名 | 身份保护 |
| --- | --- | --- |
| 管理面板/API | console-staging.example.com | hostname-based Cloudflare Access；GitHub/Cloudflare 登录、MFA、Owner Allow |
| Agent 通信 | agent-staging.example.com | 不使用浏览器 Access；Agent Ed25519 设备签名 |

还需记录 Access Team Domain（例如 myteam.cloudflareaccess.com）、Control Application AUD、Owner 完整邮箱。**千万别开启 Worker-level Access，它会连 Agent WebSocket 一起拦截。**

## 2. Windows PowerShell 一条命令

~~~powershell
git clone https://github.com/lwhx/SSH-Manager.git
cd SSH-Manager
npm install
npx wrangler login
npm run cf:quick
~~~

按提示填写两个域名、Team Domain、AUD、Owner 邮箱，输入 SINGLE-STAGING。

脚本执行 TypeScript 检查、React 构建、Staging D1 创建/复用与迁移，生成 Ed25519 公私钥（私钥仅短暂存在内存，并通过 stdin 导入 Cloudflare Secret），部署**单个** ssh-manager-staging Worker 和两个 Custom Domain。已有同名 D1 必须明确输入 REUSE-SINGLE-D1；不代表旧 DO 已迁移。

部署后 Worker 内置身份校验会阻止从 Agent 域名访问任何管理网页/API。运行时静态资源要求 run_worker_first=true；禁用 workers.dev 和 Preview URLs。

## 3. 后续自动更新

~~~powershell
git pull --ff-only
npm install
npm run cf:quick
~~~

复用原 D1 UUID、命令公钥、Worker Secret 和两个自定义域名，不自动轮换签名密钥，不修改任何 VPS。

必须保留本地文件 wrangler.single.staging.local.jsonc、.ssh-manager-deploy/single-staging.json（均加入 gitignore、不含私钥）。若更换电脑，需安全迁移环境状态；不得删除配置后对已有环境盲目重新初始化。

## 4. 验证

离线：
~~~bash
npm run test:cf:quick
npm run cf:quick:dry
~~~

Cloudflare 远程：
~~~bash
python scripts/staging_remote_probe.py --staging-only --control-url https://console-staging.example.com --gateway-url https://agent-staging.example.com
~~~

Control 匿名请求被 Access 拦截；Agent health 直接返回 JSON；Agent 管理 API/HTML/静态文件返回 404，所有检查通过后才能继续单 VPS 的 P3.4 T01–T11。

## 5. 兼容性与中断处理

旧双 Worker 本地配置或 .ssh-manager-deploy/staging.json 被发现时，单 Worker 快捷脚本**主动停止**以防静默替换现有命令密钥；参考 [双 Worker 迁移文档](MIGRATE_DUAL_TO_SINGLE.md)。

首次上传 COMMAND_PRIVATE_KEY 前若中断，脚本不会凭空重建另一把私钥。应检查 Cloudflare 环境并人工恢复，绝不通过删除状态文件绕过校验。

原始 wrangler.single.staging.example.jsonc 只是带占位符的模板，不可直接使用 GitHub 自动部署。后续如接入 GitHub/Cloudflare 自动发布，必须保留同一个 D1、Worker 名、命令签名密钥与 Access 策略，且不能将私钥保存到 GitHub。

当前生产环境没有完成真实 SSHD/journald/Root Helper 端到端安全验收。

## 6. GitHub 自动部署（可选）

单 Worker 版本另有按需启用的 GitHub Actions 工作流，可在首次 Wrangler 引导配置 Cloudflare Secret 后自动部署**一个** Worker。默认关闭，不会修改任何 VPS。详情见 [GitHub 自动部署设置](GITHUB_CLOUDFLARE_SINGLE_DEPLOY.md)。
