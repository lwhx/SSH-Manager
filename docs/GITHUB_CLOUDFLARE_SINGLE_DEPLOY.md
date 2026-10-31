# GitHub → Cloudflare 单 Worker 自动部署（Staging）

这是 **可选**部署方式。默认不执行任何云端发布。请先完成首次本机 npm run cf:quick，确认一个 Worker、两个域名、同一 D1 和已存在的 Cloudflare Secret；再启用 GitHub Actions。

## 为什么这样安排

- 旧版 GitHub 配置需要分别部署 Control 与 Gateway 两个 Worker；本版只用一个 ssh-manager-staging Worker。
- GitHub Actions **不会创建或重置 Ed25519 COMMAND_PRIVATE_KEY**。私钥始终只存在 Cloudflare Worker Secret。
- GitHub 只接收部署所需的 Cloudflare API Token、Account ID 和非秘密配置。不能将 Root Helper 私钥、SSH 登录私钥、设备密钥或 Worker COMMAND_PRIVATE_KEY 交给 GitHub。
- 部署仅针对独立 Staging。没有经过真实 VPS T01–T11 验收，不允许自动部署生产。

## 必须先完成的一次性操作

1. 按 [快捷部署指南](CLOUDFLARE_QUICK_DEPLOY.md) 运行 npm run cf:quick，首次创建 Cloudflare Staging Worker 和 D1；确认 COMMAND_PRIVATE_KEY 存在。
2. 在 Cloudflare Access 为 Control 自定义域名创建 Self-hosted App，仅允许你的 GitHub/Cloudflare 登录身份，通过 MFA。绝不能给整个 Worker 加 Access（否则 Agent WebSocket 403）。
3. 在 GitHub 仓库 Settings → Environments 创建 cloudflare-staging，建议配置审批人员。
4. 在 GitHub Settings → Secrets and variables → Actions 添加以下两项 Repository 或 Environment secrets：

| Secret | 作用 |
| --- | --- |
| CLOUDFLARE_API_TOKEN | 仅具有当前账户需要的 Workers/D1 部署权限的 Cloudflare API Token |
| CLOUDFLARE_ACCOUNT_ID | 当前 Cloudflare Account ID（也可作为普通变量管理，但流程使用 Secret） |

**不要在 GitHub 保存命令签名私钥。**

## GitHub Actions Variables

把首次部署的 D1 UUID、公开命令公钥和真实域名填为 Variables：

| Variable | 例子 / 说明 |
| --- | --- |
| SSH_MANAGER_STAGING_D1_UUID | 第一次快捷部署保存的 Staging D1 UUID |
| SSH_MANAGER_STAGING_COMMAND_PUBLIC_KEY | 同一 Staging Worker 的 32-byte Ed25519 原始公钥（base64url） |
| SSH_MANAGER_STAGING_CONTROL_HOSTNAME | console-staging.example.com |
| SSH_MANAGER_STAGING_AGENT_HOSTNAME | agent-staging.example.com |
| SSH_MANAGER_STAGING_ACCESS_TEAM_DOMAIN | myteam.cloudflareaccess.com |
| SSH_MANAGER_STAGING_ACCESS_AUD | 管理域名的 Access Application AUD |
| SSH_MANAGER_STAGING_OWNER_EMAIL | 首位 Owner 邮箱 |
| SSH_MANAGER_STAGING_AUTO_DEPLOY | 默认不设置；需要随 main 推送自动部署时明确设为 true |

项目会检查域名是两个不同的 Cloudflare Custom Domain，且不会开放 workers.dev/Preview URLs；管理面板静态文件必须经过 Worker 的 JWT 验签及 Host 路由。

## 执行

前往仓库 Actions → Deploy one Cloudflare Worker (Staging) → Run workflow。手动触发时可不启用 AUTO_DEPLOY 变量，但必须先配置上述 Secret/Variables 和 Staging Environment。

如果需要每次 main 代码变更时自动更新**同一个** Worker，可把 SSH_MANAGER_STAGING_AUTO_DEPLOY 设置为 true。触发范围仅包括 Worker 源码、协议、部署配置和当前工作流变化；不会因为 Agent 源码变化而自动修改 VPS。

工作流每次会：
1. 检查 TypeScript、运行测试并构建 React；
2. 从 GitHub Variables 安全生成被 gitignore 忽略的单 Worker Wrangler 配置；
3. 验证 Cloudflare 已有 COMMAND_PRIVATE_KEY Secret，缺失直接失败，不重生成；
4. 仅对已有 Staging D1 应用增量迁移；
5. 仅部署 ssh-manager-staging 一个 Worker；
6. 使用匿名请求复核 Control Access 和 Agent hostname 隔离；任何 /api/*、/index.html 从 Agent 访问不得返回 200。

**警告：** 当前仅核对 Cloudflare Secret 的存在，无法从 Cloudflare 读回私钥校验它是否与公开密钥匹配。因此首次引导和后续 GitHub Variables 都必须使用完全相同的公钥；修改公钥可能导致远程命令验签失败。不可擅自重置。

该工作流只更新 Worker，不会安装 Agent、修改 VPS SSH 密码登录、自动救援或回滚。实机安全验收仍需手动执行。
