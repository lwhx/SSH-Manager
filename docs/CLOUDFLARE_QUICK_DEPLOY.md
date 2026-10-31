# SSH Manager：Cloudflare 三步快捷部署（1 Worker + 双域名）

**推荐方式：只用 Cloudflare 控制台 + GitHub，不用在 Windows 本地安装 Node、Git 或 Wrangler。**

当前代码只自动部署独立的 **Staging 测试环境**，不会操作生产 VPS。生产 SSH 密码修改、救援密钥和回滚全部默认关闭。

## 第 1 步：在 Cloudflare Zero Trust 配置管理登录

假设你在 Cloudflare 中托管的主域名是 whks.de，部署后默认采用：

| 业务 | 自定义域名 | 登录 |
| --- | --- | --- |
| SSH Manager 中文管理面板 | ssh-staging.whks.de | Cloudflare Access（GitHub / Cloudflare IdP） |
| VPS Agent / WebSocket | agent-staging.whks.de | 设备 Ed25519 签名，不使用浏览器 Access |

把示例 whks.de 替换成你自己的 Cloudflare **Active zone**。

打开 Cloudflare → Zero Trust → Access → Applications，创建一个 **Self-hosted** 应用：

- Application Hostname：ssh-staging.你的主域名
- IdP：已在你的 Zero Trust 账户中配置好的 GitHub / Cloudflare 认证来源
- Access policy：仅允许你的管理员邮箱或专门的管理员组，启用 MFA
- 记录 Team Domain（例如 myteam.cloudflareaccess.com）和 Application AUD

**必须只保护管理 hostname**，不要开启 Worker-level Access，否则 Agent 的 WebSocket 会被拦截。Agent hostname 只能提供 /agent/v1/*。

## 第 2 步：Cloudflare 连接 GitHub 仓库

打开 Cloudflare Dashboard → Workers & Pages → Create Application → GitHub，授权并选择：

| 设置 | 内容 |
| --- | --- |
| GitHub 仓库 | lwhx/SSH-Manager |
| 分支 | main |
| Worker 名称 | **ssh-manager-staging**（必须精确一致） |
| Root directory | 仓库根目录 / |
| Build command | 留空 |
| Deploy command | **npm run cf:deploy** |
| Preview command | **npm run cf:preview:skip** |

Cloudflare 会运行 Wrangler 及内部的单 Worker 部署脚本。此脚本自行构建 React 中文面板，不需要手动填写 D1 UUID、命令公钥或上传私钥。

### 只需填写 4 项非秘密 Build Variables

在 Cloudflare Workers Builds 的 **Build variables and secrets** 中配置：

| 变量名 | 示例值 | 用途 |
| --- | --- | --- |
| SSH_MANAGER_BASE_DOMAIN | whks.de | 自动生成 ssh-staging 与 agent-staging 两个域名 |
| SSH_MANAGER_ACCESS_TEAM_DOMAIN | myteam.cloudflareaccess.com | Access Team Domain |
| SSH_MANAGER_ACCESS_AUD | 从管理 Access 应用复制 | JWT Audience |
| SSH_MANAGER_OWNER_EMAIL | 你的真实管理员邮箱 | 首位 Owner |

注意：这四项是**构建变量**，不是 SSH 密钥。管理账号密码不需要输入，密钥也不需要人工生成。

如果已经准备好别的子域名（例如 ssh.whks.de 和 agent.whks.de），可额外设置：
- SSH_MANAGER_CONTROL_HOSTNAME=ssh.whks.de
- SSH_MANAGER_AGENT_HOSTNAME=agent.whks.de

两项必须同时填写，而且都属于 SSH_MANAGER_BASE_DOMAIN 所指向的 Cloudflare zone。Access 应用的 hostname 也必须相应一致。

### Build API Token 权限

Cloudflare Workers Builds 会为连接的 GitHub 仓库提供部署 API Token，但默认 Token **不一定拥有 D1 创建和迁移权限**。首次部署需要在 Cloudflare 的 Builds 设置中选用权限仅限当前账户/相关 zone 的 API Token，至少允许：
- Workers Scripts（Read/Edit）
- Workers Routes（Edit，用于自定义域名）
- D1（Read/Edit，创建及迁移数据库）
- 当前账户的相关只读权限

如果日志提示缺失 CLOUDFLARE_API_TOKEN 或无法取得账号 ID，按错误提示在 **Cloudflare Builds secrets/variables** 中补充作用域受限的 CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID。**不要放到代码仓库、普通环境变量或 Worker runtime vars。**

## 第 3 步：Save and Deploy

首次构建自动：

1. 检查 GitHub 分支必须是 main，验证 Access 参数和域名
2. 仅在**确定为全新环境**时创建 ssh-manager-staging D1
3. 自动执行 D1 migrations
4. 生成一组 Ed25519 命令签名密钥；**私钥仅存在构建过程的内存中，然后通过 stdin 写入 Cloudflare Worker Secret COMMAND_PRIVATE_KEY**
5. 创建一个 Worker 并绑定两个 Custom Domains、一个 D1 和 Worker 内 NodeSession Durable Object
6. 保持 MANUAL_SSH_ACTIONS_ENABLED=false

以后 GitHub main 推送新版本，Cloudflare 会自动构建更新：
- 从 Cloudflare **已部署的 Worker bindings** 读取原域名、D1 UUID、Access 配置和命令公钥
- 验证 COMMAND_PRIVATE_KEY Secret 和 D1 仍存在
- 自动应用增量 migrations，只更新**原来的那一个 Worker**
- **不重置密钥，不删除 D1，不修改任何 VPS**

首次部署完成，Cloudflare Workers 只应有一个新应用 ssh-manager-staging。

## 必须做一次的安全检查

在浏览器：
- 访问 https://ssh-staging.你的主域名，应进入 Cloudflare Access 登录
- 访问 https://agent-staging.你的主域名/agent/v1/health，应返回 agent_auth=device-ed25519 的 JSON
- 访问 https://agent-staging.你的主域名/api/v1/health，必须是 404
- 访问 https://agent-staging.你的主域名/，必须是 404

此时只可使用测试节点，**不应开放真实生产 VPS 的关闭密码登录/救援/回滚功能**。更多 T01–T11 验收见 P3_STAGING_LIVE_RUNBOOK.md。

## 已有 Staging 的处理方式

如果你以前用 npm run cf:quick 成功部署过**同名**单 Worker + D1，云端 GitHub 构建会读取已存在的 Worker bindings；不会重新生成密钥。

如果 D1 存在但 Worker 状态不完整、Root/Agent 回执不明确、签名私钥丢失，脚本会**拒绝自动重建**，要求人工恢复。不要删除已有 D1 或强制重生成密钥，也不要把旧双 Worker 的 NodeSession 当成已自动迁移。

## 备用：PowerShell 一次性快捷部署

如果不想用 Cloudflare Git Integration，可在 Windows PowerShell 中运行：

~~~powershell
git clone https://github.com/lwhx/SSH-Manager.git
cd SSH-Manager
npm install
npx wrangler login
npm run cf:quick
~~~

现在只需输入一个管理域名（Agent 域名自动推导）、Access Team Domain、Application AUD 和 Owner 邮箱；本地一条命令处理 D1、密钥与一个 Worker。更新用 npm run cf:quick。

**两种部署模式只选一种进行日常自动更新**。不要同时开启 GitHub Actions 旧版部署和 Cloudflare Workers Builds。

### Cloudflare 自动检测说明

仓库根目录的 `wrangler.jsonc` 是一个**默认锁闭、不可访问的安全骨架**，用来让 Cloudflare GitHub 导入时识别项目，不会包含 D1、路由或签名密钥。**部署命令必须填写 `npm run cf:deploy`**，因为它会生成真正的单 Worker 配置；直接使用默认 `npx wrangler deploy` 只会部署未配置的锁闭版本。
