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

## Cloudflare 3 步部署（推荐，不需要本地命令）

1. Cloudflare Zero Trust → 为 ssh-staging.你的主域名创建 **Control 专属** Access Application，配置 GitHub / Cloudflare 登录、管理员 Allow/MFA，取得 Team Domain 和 Application AUD。
2. Cloudflare Workers & Pages → GitHub，选择 lwhx/SSH-Manager、main，Worker 名为 ssh-manager（D1 仍为 ssh-manager-staging）。**Build command 留空、Deploy command 填 npm run cf:deploy、Preview command 填 npm run cf:preview:skip。**
3. 添加四个 Build variables：SSH_MANAGER_BASE_DOMAIN（如 whks.de）、SSH_MANAGER_ACCESS_TEAM_DOMAIN、SSH_MANAGER_ACCESS_AUD、SSH_MANAGER_OWNER_EMAIL；点击 Save and Deploy。

第一次构建自动创建 Staging D1、命令签名密钥、一个 Worker 和两个 Custom Domains（ssh-staging / agent-staging），以后 GitHub main 自动更新并保留数据与密钥。若默认 Build API Token 缺乏 D1 权限，需要在 Cloudflare Builds 选择包含 Workers Scripts/Routes 与 D1 Read/Edit 的受限 API Token。

不需要在 Windows 安装 Wrangler，也不需要手动填 D1 UUID 或 Ed25519 公钥。**Access 只能保护管理域名，不得对 Worker 整体开启 Access。**

[Cloudflare 3 步快捷部署](docs/CLOUDFLARE_QUICK_DEPLOY.md) · [完整部署须知](docs/DEPLOYMENT.md) · [GitHub 自动部署](docs/GITHUB_CLOUDFLARE_SINGLE_DEPLOY.md) · [旧版迁移](docs/MIGRATE_DUAL_TO_SINGLE.md)

仍支持本地 PowerShell 备用方案：npm install → npx wrangler login → npm run cf:quick。

> Cloudflare Workers Builds 名称错位导致签名私钥上传到另一 Worker 时，请勿删除已创建的 D1。修复请查看 [签名密钥安全恢复指南](docs/CLOUDFLARE_SPLIT_SIGNER_RECOVERY.md)。


## 管理面板导航

新版管理面板参考 Komari 的信息层级，但不代替 Komari 的系统资源监控：

- **仪表盘**：节点数量、Agent 在线情况以及待初始化节点概览。
- **VPS 节点**：全宽服务器列表，支持名称/IP 搜索、在线状态、分组过滤、排序；添加 VPS 使用独立三步向导。
- **单节点详情**：概览、Agent 管理、SSH 安全、操作记录、节点设置，所有危险操作只针对当前节点。
- **双公钥管理**：保存日常/救援公钥，不会因此自动推送到任何 VPS。
- **任务中心**：只读展示最近 100 条操作，显示 RESULT_UNKNOWN（结果未知）并要求人工核查；不提供危险操作的自动重试。
- **操作审计**：Owner 可查看操作记录；**系统设置**显示现有的云端配置与安全开关。

节点详情使用 `#/nodes/<UUID>?tab=ssh` 等哈希地址；只包含节点标识及页签，不保存配对令牌或 SSH 私钥。编辑已配对节点时，SSH 主机、端口和登录用户在前后端均锁定；分组、备注和展示名称可编辑并记录审计。首次上线必须由 Staging D1 增量迁移应用 `0007_node_metadata.sql`，官方部署脚本先迁移再部署 Worker。

**管理台改版验收**：[VPS 节点列表、配对向导与任务中心 Staging 验收清单](docs/VPS_CONSOLE_STAGING_ACCEPTANCE.md)。所有真实 VPS 试验仍必须先经过安全关卡。

## Linux VPS Agent 安装与配对（Staging）

管理端部署成功不等于 VPS 已连接。**进入「VPS 节点」→「添加 VPS」→「基本信息」→「安装 Agent」→「确认连接」**，或从服务器列表打开已有节点的 **「Agent 管理」** 页签，面板会显示 **Agent 安装与配对** 向导：复制绑定了当前 Worker Git commit 的安装命令到 Debian/Ubuntu systemd 测试 VPS；安装器自动构建并启动非 root Agent，完成配对时从交互终端读取十分钟一次性令牌（不出现在命令行/日志）。Token 过期可以在同一节点点击「重新生成配对令牌」，无需删除节点。

本向导只完成 Agent 设备注册、心跳、WSS/HTTPS 通讯；Root Helper 的配置、SSH 公钥修改及可信认证证明仍按 [P3 实机 Runbook](docs/P3_STAGING_LIVE_RUNBOOK.md) **人工逐台验收**，不能用生产 VPS 直接测试。安装脚本需要 curl、tar、Go 1.23+。

[Staging 安装器详细说明](docs/AGENT_STAGING_INSTALL.md)

> **误删 Cloudflare Worker，但原 D1 仍在？** 使用 [Staging Worker 删除后的受控恢复指南](docs/CLOUDFLARE_DELETED_WORKER_RECOVERY.md)。不要删除 D1 试图绕过安全检查。

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
