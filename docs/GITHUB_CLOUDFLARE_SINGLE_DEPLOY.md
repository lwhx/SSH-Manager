# GitHub → Cloudflare：只维护一个 Worker

**首选：Cloudflare 原生 GitHub Integration（无需本地首次部署）**。

打开 Cloudflare → Workers & Pages → Create Application → GitHub：

| 配置项 | 填写 |
| --- | --- |
| Repository | lwhx/SSH-Manager |
| Branch | main |
| Worker name | ssh-manager-staging |
| Root directory | / |
| Build command | 留空 |
| Deploy command | npm run cf:deploy |
| Preview command | npm run cf:preview:skip |

Build variables 只要：
- SSH_MANAGER_BASE_DOMAIN
- SSH_MANAGER_ACCESS_TEAM_DOMAIN
- SSH_MANAGER_ACCESS_AUD
- SSH_MANAGER_OWNER_EMAIL

根据需要额外使用两个 hostname override 变量。Access Application 仅保护 ssh-staging.你的主域名，Agent 域名不通过浏览器 Access。

**第一次 Save and Deploy 即可由脚本自动创建 D1、签名密钥和单 Worker。以后推送 main 自动更新，不需要重复配置 D1 UUID 或公钥。** 自动化脚本只允许 Staging，不会对 VPS 下发 SSH 写入。

Cloudflare 默认 Build API Token 不一定具备 D1 Read/Edit，需要在 Builds 中选择权限合适、范围有限的 API Token。Workers Builds 若没有暴露 CLOUDFLARE_API_TOKEN 或 CLOUDFLARE_ACCOUNT_ID，按日志通过 Build secrets/variables 补充。禁止向代码仓库传入任何私钥。

完整操作见：[Cloudflare 3 步部署](CLOUDFLARE_QUICK_DEPLOY.md)。

## 如果原来已配置 GitHub Actions

仓库仍保留独立的 GitHub Actions Staging workflow 作为兼容备选。若使用 Cloudflare 原生 GitHub Integration，请**不要**将 GitHub Actions 变量 SSH_MANAGER_STAGING_AUTO_DEPLOY 设置为 true，否则可能有两个构建同时更新同一个 Worker。

如果需要沿用 GitHub Actions，仍可参考原有脚本 scripts/cloudflare_ci_config.mjs 及 .github/workflows/cloudflare-single-staging.yml，它需要提前初始化 D1/私钥与 GitHub 端的 Secrets/Variables，步骤较多，不是现在推荐的快捷流程。

安全要求始终不变：管理域名 Access 登录、Agent 设备签名、Root Helper 单节点操作和全局高危开关默认关闭。生产 SSH 相关动作必须等待真实 VPS Staging 验收。
