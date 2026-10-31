# SSH Manager

基于 **Cloudflare Workers + D1 + Durable Objects + Go Agent** 的多 VPS SSH 密钥管理与紧急救援平台。

> **开发状态：V4 P3.1 安全原型，尚未生产就绪。** 已具备 Cloudflare 管理平台、Agent WSS/HTTPS 通信、Root Helper 的只读配置检查与默认禁用的日常公钥安装路径。**尚未完成真实 VPS 端到端验收，不能用于生产 SSH 修改。** 可信登录证明、关闭密码登录和单节点救援仍然锁定。

## 产品约束

- 两把不同公钥：日常公钥与救援公钥，绝不上传私钥。
- Agent 首次连接后，必须先安装日常公钥并验证全新 SSH 公钥登录，才允许**人工**关闭密码登录。
- 保存救援公钥不授权任何节点；只能在特定 VPS 页面人工启用。
- 密码登录恢复、SSH 快照回滚都要求单节点、管理员手动发起。**永不自动回滚**。
- Agent 不提供任意 shell 或 Web SSH；默认只读。所有 SSH 写操作需要特权 Helper 和实际 E2E 验收。
- Agent 断线、重新上线或 SSH 登录失败，不执行过期危险操作。
- 无法通过 Cloudflare / Agent 救援时使用 VPS 服务商控制台。

## 当前实现

| 模块 | 状态 |
|---|---|
| Cloudflare Workers 控制端 | 初版代码 |
| Access JWT 校验、Owner 初始允许名单 | 初版代码，待真实 Access 验收 |
| 中文 Web 面板 | 初版代码 |
| D1 数据结构和版本化迁移 | 初版代码 |
| 全局两种公钥保存（不自动安装） | 初版代码 |
| Node 配对令牌与 Agent Ed25519 身份 | 初版代码 |
| Agent WSS 长连接 + HTTPS 备用轮询与签名报告 | 初版代码 |
| Durable Object WebSocket 投递 | 初版代码，Agent 已支持 WSS 与 HTTPS 双通道 |
| Agent 命令验签、过期与白名单 | 初版代码 |
| P3 安全 authorized_keys 本地模块 | **已接入可选 Root Helper，默认禁止写入，待 VPS 验收** |
| P3 SSH 有效配置规则解析 | **已接入 Root Helper，须提供明确 SSH 来源 IP** |
| Root-only Unix Socket Helper | **基础实现与单元测试，默认禁用日常公钥安装** |
| Agent 日常公钥真正安装 | **具备本地显式 opt-in 路径，尚未真实 VPS 验收** |
| 可信 SSH 登录证明 | **未实现，后端拒绝调用** |
| 关闭密码登录 | **锁定** |
| 单节点救援与手动回滚 | **锁定** |

### 代码结构

- `apps/console/` React 中文面板
- `apps/control-worker/` Access 认证与管理 API
- `apps/agent-gateway/` Agent 网关与 Durable Object
- `packages/db/migrations/` D1 迁移
- `packages/protocol/` 签名协议与安全校验
- `agent/` Go Agent（独立于 SSH daemon）
- `docs/` 部署安全说明
- `wrangler.*.jsonc` Cloudflare Worker 配置

## 本地开发与部署前置

依赖 Node.js 22+、Go 1.23+、Cloudflare 账户、Wrangler 权限、D1 与 Cloudflare Access 应用。云端资源、身份认证与密钥必须由部署者创建，不应写入仓库。

```bash
npm install
npm run check
npm run build:web
cd agent && go test ./...
```

### Cloudflare 安装概览

1. 创建一套 D1 数据库，分别在 `wrangler.control.jsonc` 和 `wrangler.gateway.jsonc` 填入真实 database_id。
2. 为控制台设置 Access 应用并配置 GitHub、Cloudflare 两种 IdP 的允许名单。
3. 创建**不同环境使用不同值**的命令 Ed25519 签名密钥对：控制 Worker 通过 Secret `COMMAND_PRIVATE_KEY` 使用 PKCS#8 DER base64；Gateway 的 `COMMAND_PUBLIC_KEY` 使用匹配的原始 32 字节 Ed25519 公钥 base64url。生产私钥绝不提交 Git。
4. 配置控制 Worker 的 `ACCESS_TEAM_DOMAIN`、`ACCESS_AUD`、`BOOTSTRAP_OWNER_EMAIL`。
5. `npm run db:migrate:remote`，之后按顺序部署 Gateway 和 Control Worker。
6. 将 Console 主机名绑定到 Access 保护范围，将 Agent 域名绑定到设备认证 Gateway。**Agent 网关必须不能被浏览器 Access 登录策略错误拦截。**
7. 先在独立 Staging 环境做端到端认证与通信测试，不要接入任何真实生产 VPS。

更多说明见 [部署须知](docs/DEPLOYMENT.md)。

## 单节点只读检查

在 VPS 详情页可人工点击 **SSH 只读环境检查**。Agent 返回 OS、sshd 文件存在性、Agent 状态；**该结果不等于 SSH 认证规则有效，也不能作为关闭密码登录的依据**。任务实际状态可在页面查询。

## Agent 配对

在 Web 面板中创建节点、获得 10 分钟的一次性配对令牌。构建 Agent：

```bash
cd agent
go build -o ssh-manager-agent .
```

在 VPS 上通过受信任渠道安装已校验的二进制。配对：

```bash
read -rs TOKEN
printf '%s\n' "$TOKEN" | sudo ./ssh-manager-agent -mode pair -gateway https://agent.example.com -node NODE_UUID -token-stdin -config /etc/ssh-manager/agent.json
unset TOKEN
```

配对令牌通过标准输入传递，避免出现在 Shell 历史和进程列表。配对结束后由管理员创建专门的 `ssh-manager` 服务用户/组，并将 `/etc/ssh-manager` 设置为 `root:ssh-manager`、`0750`，`agent.json` 设置为 `root:ssh-manager`、`0640`（允许 Agent 只读密钥，拒绝修改）。随后以该最小权限账户通过 systemd 运行 Agent（示例文件位于 `agent/ssh-manager-agent.service`；使用前调整权限和目录）。

**重要：** Root Helper 未配置时请求会失败；即使已配置，默认也会因为 `enable_daily_install=false` 而拒绝安装。只有在隔离测试 VPS 中经本机管理员显式开启、完成签名和配置版本检查后，才可能执行**追加日常公钥**，不会关闭密码登录。

## 开发路线

- P1：Cloudflare 基础、JWT 身份、D1、中文管理台
- P2：Agent、配对、加密、实时通信与命令安全
- P3.1：已实现独立 root-owned Helper、受控追加日常公钥及 SSH 生效配置检查；**待独立测试 VPS 真实验收**。P3.2/P3.3：补齐可信 SSH 新连接认证验证。
- P4：手动关闭密码认证及修改后验证
- P5：**只对选定 VPS** 启用/撤销救援公钥、手动恢复密码及快照
- P6：全兼容性测试、审计、升级与生产部署文档

所有高危步骤必须先通过隔离测试 VPS 的实际测试；未通过不得去掉安全锁。

## 安全提示

Cloudflare 控制面本身是高价值权限入口：需要 MFA、明确允许的管理员、分环境签名密钥。拥有签名密钥、修改 Worker 代码的权限相当于拥有远程节点管理能力。救援私钥应该离线保管。

许可证待仓库所有者确定。

## GitHub 与 Cloudflare Access 双身份绑定

默认 Owner 第一次登录时使用部署引导邮箱绑定一个**经过 Access JWT 验证的 subject**。后续即使新 GitHub / Cloudflare 身份具有同一邮箱也**不会自动合并权限**。

Owner 在「双公钥管理」页面生成 5 分钟的一次性身份绑定码；在另一个已通过 Cloudflare Access、尚未被 SSH Manager 授权的会话中粘贴该绑定码，系统校验相同邮箱、有效期及单次消费后绑定新身份。这样既支持两种登录方式，又防止仅凭邮箱提升权限。使用前需应用 `0002_identity_links.sql` 迁移。

## P3.1 特权 Helper

详情参阅 [P3 Helper 运行与安全验收指南](docs/P3_HELPER.md)。Root Helper 在 VPS 本地独立运行，重新验签并验证 Unix Socket UID，只接受 ssh.policy.inspect 及明确启用的 ssh.daily.install。默认禁用所有 SSH 写入操作，绝不自动修改密码登录方式。
