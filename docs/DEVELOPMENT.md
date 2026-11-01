# SSH Manager V4 · 当前开发文档（以 main 实际代码为准）

> 文档用途：后续开发、AI Coding Agent 接手、代码审查、Staging 验收及发布评审的**统一技术基线**。  
> 整理日期：2026-11-01。功能代码基线：`main` 合并提交 [`4b8939b542314eed46f5b9260fb8a02fffcfee48`](https://github.com/lwhx/SSH-Manager/commit/4b8939b542314eed46f5b9260fb8a02fffcfee48)，来源 PR [#8](https://github.com/lwhx/SSH-Manager/pull/8)，其被合并的开发提交为 `851ee52f69f2b4118a31c8558a24003fd7e24f92`。后续**仅文档提交**不改变该功能基线。实际开发前仍须执行 `git rev-parse HEAD` 并阅读最新源码。  
> **重要状态：功能代码已合并 main，自动化 CI 及隔离测试通过；Cloudflare 远端 Staging D1 预检、Access/RBAC 浏览器测试、真实可销毁 VPS T01–T11、P4/P5 真机闭环、独立安全 Review 尚未被认定通过。不能把“已合并 main / 可构建 / 已部署”理解为“生产 SSH 安全可用”。**

## 0. 阅读顺序与状态含义

本文取代早期讨论式的总体开发方案，作为**现状与下一步开发规范**；原有 `docs/superpowers/specs/2026-11-01-vps-console-design.md` 和 `docs/superpowers/plans/2026-11-01-vps-console.md` 保留作历史设计记录，历史任务框中的未勾选状态**不代表当前代码未实现**。

状态术语必须统一：

| 状态 | 含义 | 是否可以用于生产 |
| --- | --- | --- |
| 已实现 | 当前 main 源码中存在相关接口、页面、模块或逻辑 | **不等于**通过安全验收 |
| CI 已验证 | TypeScript、Vitest、SQLite、local workerd+D1、Go、隔离回环 SSH 等仓库测试通过 | **不等于**云端与真实 VPS 验收 |
| 远端 Staging 待验收 | 需操作者在隔离 Cloudflare 账户/D1/域名和可销毁 VPS 上收集证据 | 不得视为生产完成 |
| 生产未授权 | 没有真实 E2E 记录、独立审核和 Owner 明确批准 | 保持 SSH 高危写操作关闭 |

已合并的 PR #8 在合并前最后一次完整自动化验收为 [CI #638](https://github.com/lwhx/SSH-Manager/actions/runs/41287436656)、[隔离 SSH #191](https://github.com/lwhx/SSH-Manager/actions/runs/41287436694)、[Staging 二进制 #86](https://github.com/lwhx/SSH-Manager/actions/runs/41287436696)。这些是**源码 CI 证据**，不是远端部署证据。

## 1. 项目目标、范围与不可变原则

SSH Manager 为多台 Linux VPS 提供集中式清单、Agent 连接、SSH 公钥管理、可信 SSH 登录验证及**单节点手动**安全操作。前端信息层级参考 Komari，但**不是** Komari 资源监控产品。

核心产品要求：

1. 用户通过 Cloudflare Access 配置的 GitHub / Cloudflare IdP 登录；**SSH Manager 本身没有密码登录入口**。
2. 一个管理端统一查看多台 VPS，操作必须绑定**一台确定的 node UUID**。没有任何“保存全局密钥后立即推送所有 VPS”的动作。
3. 全局仅维护两种用途的 SSH **公钥**：`daily`（日常）与 `rescue`（救援）。**用户的 SSH 私钥保留在本地 SSH 客户端**，不上传 Cloudflare/D1/Agent。
4. 先安装 daily 公钥，再通过**新的、真实的 SSH 公钥连接**和可信服务器侧日志证明成功，才可能考虑手动关闭密码认证。
5. 手动关闭密码登录、手动恢复密码策略、快照回滚、救援公钥安装/撤销，必须单节点二次确认，不得由掉线、超时、定时任务或 SSH 失败自动触发。
6. Agent 是非 root 出站客户端；Root Helper 是本地 root 最小权限执行边界。不能让 Agent 设备签名替代 Root Helper 的独立证明。
7. 操作结果未知（`RESULT_UNKNOWN`）应阻止新的危险写入，不能因为命令 TTL 到期就认定“没有执行”或自行释放单节点锁。
8. 测试、部署和生产启用是**不同审批阶段**。新增功能必须默认失败关闭。

非目标：浏览器内任意 Shell/SSH 终端、VPS CPU/流量全功能监控、批量密钥推送、自动轮换所有机器的公钥、自动解锁/回滚、恢复用户 Linux 密码。

## 2. 技术架构

### 2.1 当前部署形态

```text
Windows / 浏览器
   │
   └── Cloudflare Access（GitHub / Cloudflare IdP；管理域名专属）
          │ Access JWT
          ▼
     Control Custom Domain ──┐
                              │ 单个 Cloudflare Worker
     Agent Custom Domain ─────┤ apps/single-worker
          ▲                   │ Host 精确分流，静态资源也先校验 Access
          │ Ed25519           ├── apps/control-worker（RBAC / 管理 API）
          │ 设备签名          ├── apps/agent-gateway（配对 / 心跳 / 回执 / Root 证据）
          │                   ├── D1（配置、任务、签名关联、审计）
    VPS Go Agent ─────────────└── NodeSession Durable Object（同 Worker WSS）
          │ Unix Socket（不得暴露外网端口）
          ▼
    Root Helper（root；独立 Ed25519 证明密钥）
          │
          ├── 只读 sshd 策略检查 + journald /proc 可信认证取证
          ├── 受限的 authorized_keys 日常 / 救援公钥操作
          └── 单节点、显式授权的 sshd drop-in / 快照手动操作
```

- **Worker 数量**：1。`apps/single-worker/src/index.ts` 导出同 Worker 的 `NodeSession` Durable Object；**不使用**跨 Worker Service Binding。
- **域名数量**：2。`CONTROL_HOSTNAME` 必须与 `AGENT_HOSTNAME` 不同；`classifyHostPath` 精确校验 hostname + 路径，不通过域名转发不属于该入口的功能。
- **管理域名**：所有管理 API、SPA、静态资源进入前需验证 `Cf-Access-Jwt-Assertion`，JWT 的签发者、audience、签名由 Worker 再校验。
- **Agent 域名**：仅 `/agent/v1/*`，不受浏览器 Access 认证保护，但其配对/设备消息按独立机制验证。不得在 Agent 域名暴露 SPA、`/api/v1/*`、管理健康检查。
- **静态资源**：`assets.run_worker_first=true`，以免 Cloudflare Assets 在管理 JWT 检查之前直接返回页面。
- **公网入口**：`workers_dev=false`、`preview_urls=false`；仅允许确认过的两个 Custom Domains。

### 2.2 主要技术栈

| 组件 | 技术 |
| --- | --- |
| 管理界面 | React 19、TypeScript、Vite 7、CSS、Vitest |
| Control / Agent API | Cloudflare Workers、TypeScript |
| 长连接 | 同 Worker 的 Durable Object `NodeSession` / WebSocket，HTTPS Poll 备用 |
| 持久化 | Cloudflare D1 / SQLite（版本化迁移） |
| 管理端身份 | Cloudflare Access JWT（`jose` 验证）；本地 D1 RBAC |
| 签名 | Ed25519：Cloudflare 命令签名、Agent 设备签名、Root 独立回执/证明 |
| VPS | Go 1.23+ Agent、独立 Root Helper、systemd、OpenSSH |
| 验证和发布 | GitHub Actions、Vitest、Python unittest、local workerd+D1、Go race/vet/integration |

## 3. 仓库目录与模块责任

```text
apps/
  single-worker/src/       Cloudflare 单入口与 Host/Assets 安全隔离
  control-worker/src/      Access JWT、身份、RBAC、节点、操作、密钥、审计
  agent-gateway/src/       Agent 配对、签名、nonce、心跳、回执、Root proof、DO
  console/src/             React 管理界面、分屏组件、样式及对应测试
packages/
  protocol/src/            共享签名协议、校验、SSH proof、manual outcome
  db/migrations/           0001 至 0008 的增量 D1 Schema
agent/
  main.go / ws.go          非 root Agent、命令验签与 Gateway 通信
  report_outbox.go         本地持久化回执，网络故障只重发不重执行
  recovery.go              结果不确定时的保守恢复/人工核查
  internal/sshhelper/      Root Helper、签名回执、受限操作和本地日志
  internal/sshkeys/        安全 authorized_keys 文件操作
  internal/sshprobe/       sshd 策略与有效配置检查
  internal/sshproof/       journald /proc SSH 认证证据
  internal/sshmanaged/     管理过的 SSH 配置片段、快照
  cmd/ssh-manager-helper/  Root Helper 可执行入口
  cmd/ssh-manager-prove/   本地认证证明工具
scripts/
  cloudflare_native_*      Cloudflare Builds / 单 Worker 自动部署
  cloudflare_quick_*       本地手动引导与部署
  install_agent_staging.sh 固定 Git SHA 的隔离 VPS 安装器
  staging_*                只读 Staging 预检与探测
  test_*                   SQL、Cloudflare、协议及安全回归
docs/                      验收、部署、恢复、历史设计及本主文档
.github/workflows/         CI、SSH 隔离集成、构建、Staging 部署
```

业务代码不得在 `Agent`、`Root Helper` 和 `Control` 三个信任层之间跳过验证。扩展功能应优先修改对应模块并新增同目录测试，而不是把所有逻辑堆入 `index.ts`。

## 4. 用户身份、RBAC 与密钥责任

### 4.1 浏览器身份

- 管理端不储存密码，也不实现独立账号密码登录。GitHub / Cloudflare 是 Cloudflare Zero Trust Access 的外部身份提供商，非 SSH Manager 自建 OAuth。
- `verifyControlAccess` 验证 Access issuer、audience、RS256 签名，并读取 `sub` 与规范化后的 `email`。
- 首个 Owner 的建立依赖 `BOOTSTRAP_OWNER_EMAIL`，相同邮箱但不同 Access `sub` **不能静默合并账号**。
- Owner 可创建五分钟有效的一次性身份关联 token；仅在匹配邮箱、活跃账号、token 未用且未过期时允许关联新的 Access subject。
- 角色：`viewer`（只读节点/任务等）、`admin`（节点创建编辑、配对、预检、验证准备）、`owner`（以上全部 + 全局公钥更新、Root 公钥固定、身份关联、审计、手动高危动作）。
- 非 GET 的管理请求要求同源 `Origin` 且 `Content-Type: application/json`；角色与目标节点校验均须**由服务端执行**，前端隐藏按钮不等于授权。

### 4.2 三种不同的私钥

| 密钥 | 私钥存放位置 | 用途 |
| --- | --- | --- |
| 用户 SSH `daily/rescue` 私钥 | **用户本地 SSH 客户端** | 真实 SSH 登录；服务器只接受相应公钥 |
| Cloudflare Command Ed25519 私钥 | Cloudflare Worker Secret（`COMMAND_PRIVATE_KEY`） | 签发限时、限节点、限动作的命令 |
| VPS Root Helper Ed25519 私钥 | **对应 VPS 的 root-only 存储** | 独立签发 SSH 登录证明和操作回执 |

另外每台 Agent 有独立设备 Ed25519 身份密钥（仅该 VPS 本地保存私钥），Gateway 的 `agent_credentials` 只持有设备公钥。**Agent 身份签名不能代替 Root 对 SSH 修改或真实登录的证明。**

### 4.3 全局 daily / rescue 公钥

- `GET /api/v1/keys` 列出当前活跃公钥；`PUT /api/v1/keys/daily` 与 `.../rescue` 由 Owner 写入。
- 轮换以 D1 `batch` 原子停用旧活跃键、插入新键、分配版本并写审计；daily 轮换同时将数据库中尚未完成的 PENDING 验证挑战失效。
- **“设置全局公钥”不意味着将其推送到任何 VPS**。`rescue` 只有选中节点、显式请求 `rescue/enable` 并通过独立 Root 回执后才视作安装。
- 每台 VPS 单独保存 `node_ssh_proof_keys` 的 Root Helper 公钥及 Owner 审计；必须从服务商控制台或受控本机途径独立核对 fingerprint，Agent 不能提交或替换自己的信任锚。

## 5. VPS 生命周期与状态机

### 5.1 从创建到验证的正确顺序

```text
创建 VPS → WAITING_PAIR
    ↓ 一次性配对 Token（10 分钟）
Agent 配对 / 心跳 → PREFLIGHT
    ↓ 节点预检、只读 SSH Policy Inspect
POLICY_INSPECTED
    ↓ Owner 已固定该节点 Root Proof 公钥；daily 公钥受控安装
WAITING_VERIFICATION
    ↓ 准备 5 分钟挑战；管理员从本地新建真实公钥 SSH 连接
    ↓ Root Helper 校验 journald + /proc，并独立签名
    ↓ Agent 转发；Gateway Root 公钥验签并更新 D1
KEY_VERIFIED（只有可信证明后）
    ↓ Owner 明确确认、云端及本机危险开关允许
PASSWORD_DISABLED（高危；仍需人工验证新的 SSH 连接）
    ↓ Owner 指定快照手动 restore / rollback
POLICY_INSPECTED（须重新完整验证）
```

配对成功**只证明设备通信**；`ssh.verification.prepare` 的 `prepared_at` **只证明挑战准备**；客户端执行了 `ssh -i` 或返回成功**不足以**标记为 VERIFIED。`ssh_verifications.status=VERIFIED` 必须来自有效 Root 签名的服务器侧证明路径。

验证 token 仅返回一次，D1 只保存 `nonce_hash`；验证挑战 TTL 为 300 秒。`PENDING` 过期、公钥轮换、配置变更、取消以及准备失败不能提升为 VERIFIED。

### 5.2 操作任务状态

- `CREATED`：命令已持久化但未派发；过期且**从未派发**的操作才可安全变为 `EXPIRED`。
- `DISPATCHED` / `RUNNING`：已可能在 VPS 执行，不因 TTL 超时而清除。
- `SUCCEEDED` / `FAILED`：只有已验证的终态回执及相关副作用/审计一致时才可提交。
- `RESULT_UNKNOWN`：对超时的 DISPATCHED/RUNNING 进行 UI 投影，**不是**真实完成状态，必须人工查 VPS；单节点锁仍被保留。
- D1 `0008_single_active_operation.sql` 使用唯一部分索引禁止同节点同时存在多条 CREATED/DISPATCHED/RUNNING；两个并发管理员也不能绕过这一约束。
- `Idempotency-Key`：管理端操作使用独立的幂等键；失败时只有完全相同的已持久化结果允许重新确认，**不自动重新执行 Root 写入**。

## 6. 主要 API（以源码为最终契约）

以下均为当前已编写的入口。管理 API 位于**Control hostname**，且在 Worker 路由前须通过 Access JWT。表中的 `:id` 是完整、有效的节点 UUID。

### 6.1 Control API

| 方法 | 路径 | 最低权限 / 作用 |
| --- | --- | --- |
| GET | `/api/v1/health` | Access 验证；状态与高危开关 |
| GET | `/api/v1/me` | 已绑定用户；角色、Agent 域名、功能开关 |
| POST | `/api/v1/identity/link-start` | Owner；签发 5 分钟一次性关联 token |
| POST | `/api/v1/identity/link-claim` | 已通过 Access 验证但允许尚未绑定；消费合法 token |
| GET / POST | `/api/v1/nodes` | 只读列表 / Admin 创建节点并签发 10 分钟配对 token |
| GET / PATCH | `/api/v1/nodes/:id` | 查看节点 / Admin 编辑受控元数据 |
| POST | `/api/v1/nodes/:id/pairing-token` | Admin；仅未配对节点重新生成 token |
| GET / POST | `/api/v1/nodes/:id/ssh-proof-key` | Admin 查看 / Owner 首次固定 Root 公钥 |
| POST | `/api/v1/nodes/:id/preflight` | Admin；入队 `node.preflight` |
| POST | `/api/v1/nodes/:id/ssh-policy/inspect` | Admin；只读有效 SSH 策略 |
| POST | `/api/v1/nodes/:id/daily-key/install` | Admin；要求节点 Root 信任锚和当前策略 |
| POST | `/api/v1/nodes/:id/ssh-verification/start` | Admin；创建挑战、签名准备任务和审计 |
| GET | `/api/v1/nodes/:id/ssh-verification/:verificationId` | Admin；只读投影验证状态 |
| POST | `/api/v1/nodes/:id/ssh-verification/:verificationId/cancel` | Admin；条件取消 PENDING |
| POST | `/api/v1/nodes/:id/ssh/password/disable` | Owner；手动关闭密码认证 |
| POST | `/api/v1/nodes/:id/ssh/password/restore` | Owner；手动恢复快照中的密码策略 |
| POST | `/api/v1/nodes/:id/ssh/config/rollback` | Owner；手动配置快照回滚 |
| POST | `/api/v1/nodes/:id/rescue/enable` | Owner；仅目标节点启用救援公钥 |
| POST | `/api/v1/nodes/:id/rescue/revoke` | Owner；仅目标节点撤销已安装的救援公钥 |
| GET | `/api/v1/nodes/:id/rescue/state` | Admin；救援密钥状态 |
| GET | `/api/v1/nodes/:id/snapshots` | Admin；Root 管理的配置快照记录 |
| GET / PUT | `/api/v1/keys`、`/api/v1/keys/daily`、`/api/v1/keys/rescue` | Admin 查看 / Owner 更新全局公钥；不推送 VPS |
| GET | `/api/v1/operations` 或 `?node_id=:id` | 已登录用户；最近 100 条任务 |
| GET | `/api/v1/operations/:id` | 已登录用户；任务详情/状态投影 |
| GET | `/api/v1/audit` | Owner；最近 100 条审计 |

**写操作的共同要求：** 同源 Origin、JSON、管理者角色、选中的 node UUID；入队动作要求有效 `Idempotency-Key`。P4/P5 还需 `confirm_node_id` 与**至少 12 字符且不超过 280 字符**的 `reason`；恢复/回滚额外需要 `snapshot_ref`。高危功能在 `MANUAL_SSH_ACTIONS_ENABLED=false` 时返回锁定错误。

**注意实际实现差异：** `GET /api/v1/operations/:id` 对过期 `CREATED` 存在条件性状态落库逻辑，不应笼统宣称“所有 GET 都完全只读”；验证状态的 GET 已改为只读投影。后续若统一 GET 语义，需要单独修改并加回归测试。

### 6.2 Agent Gateway（仅 Agent hostname）

| 入口 | 用途 |
| --- | --- |
| `GET /agent/v1/health` | 匿名的受限服务健康状态，不暴露管理 API |
| `POST /agent/v1/pair` | node_id + 一次性 token + Agent 设备公钥；签发命令公钥给 Agent |
| `POST /agent/v1/heartbeat` | 签名心跳、版本/OS 状态 |
| `POST /agent/v1/poll` | 获取经 Cloudflare 命令私钥签过名的待派发任务 |
| `POST /agent/v1/report` | Agent 上报 RUNNING/终态；危险任务还须 Root 独立签名回执 |
| `POST /agent/v1/ssh-proof` | 上传 Root 证明；严格校验节点、挑战、版本、签名和重放 |
| `GET /agent/v1/ws` | 通过 NodeSession DO 建立 WSS 连接；HTTPS Poll 备用 |

Agent 请求设备签名基于 `METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256(body)`；使用 `X-Node-Id`、`X-Device-Timestamp`、`X-Device-Nonce`、`X-Device-Signature`。服务端限制大致 ±60 秒时钟偏差、nonce 唯一性和签名；重放 nonce 存入 `device_nonces`。不要在未逐项对照当前代码时自行变更签名序列化格式。

## 7. 命令与 Root 回执的双签名链路

### 7.1 命令签发

Control 使用 `COMMAND_PRIVATE_KEY` 为包含 `v`、`id`、`node_id`、`action`、`actor`、`issued_at`、`expires_at`、`expected_revision`、`payload` 的固定格式命令签名。通常命令 TTL 45 秒。Agent 和 Root Helper 各自校验签名、时限、单节点 ID、当前 SSH 配置 revision、允许的动作类型；Agent 不能执行任意 Shell。

白名单动作：

`node.preflight`、`node.status`、`ssh.policy.inspect`、`ssh.daily.install`、`ssh.verification.prepare`、`ssh.password.disable`、`ssh.password.restore`、`ssh.config.rollback`、`ssh.rescue.enable`、`ssh.rescue.revoke`。

### 7.2 Root Helper 隔离

- Root Helper 在 VPS 本机通过 Unix Socket 与非 root Agent 通信，不提供公网管理 API；由 systemd 运行，执行前必须验证本地上下文与权限。
- `enable_daily_install`、`enable_ssh_proof`、`enable_password_disable`、`enable_password_restore`、`enable_config_rollback`、`enable_rescue` **默认全部 false**，且只对配置所在的 VPS 生效。
- Root 自己持有签名私钥，Cloudflare 只存对应**该节点**的 Owner 审核公钥。没有 Root 证明密钥、文件元数据不可信、journal/PID 来源无法证实时，返回失败或需要人工检查。
- Agent 使用本地可持久化 outbox 保存结果；断网、进程重启后**只重发持久化终态**。Root 执行后回执丢失或 journal fsync 失败，必须保留“不确定 / 人工核查”，不再执行一遍 SSH 写入。

### 7.3 D1 终态原子性

- 操作从 DISPATCHED/RUNNING 切换为 SUCCEEDED/FAILED，以及必要的节点、key、快照和 audit 更新，必须在**一个 D1 batch** 中。
- `apps/agent-gateway/src/index.ts` 使用 `manual_ssh_assertions` 的 CHECK 失败哨兵约束检查零行 CAS / 必要副作用，避免“操作已标成功但审计缺失”。
- 并发上传同一终态仅允许一个成功提交；丢失 ACK 后可以接受**完全一致的已持久化终态**作为幂等确认；不同 `status/result_code/detail` 必须冲突拒绝。
- 浏览器自己发送的 “verified=true”、Agent 自报成功、HTTP 200、准备任务成功均不能取代 Root 可信证明。

## 8. P3 / P4 / P5 受限操作细则

### P3：先安装日常公钥，再证明真实 SSH 登录

1. 创建并配对单节点 Agent，先通过只读 preflight 和 ssh policy inspect。
2. Owner 从**该 VPS 本机可信通道**确认并首次固定 Root Proof Ed25519 公钥；Cloudflare 保存 fingerprint、Owner 和审计。
3. Admin 请求 `ssh.daily.install`，Root Helper 必须允许该 VPS 本地的 daily install。写入 `authorized_keys` 时不覆盖用户现有内容。
4. 创建 300 秒挑战；准备任务只写 `prepared_at`，不写 VERIFIED。
5. 用户本地以 `BatchMode=yes`、禁密码/键盘交互、HostKeyChecking 严格校验的**新 SSH 会话**登录；Root Helper 从可信 journald 元数据及 `/proc` 进程链核验。
6. Root 独立签名 `ssh-proof`，经 Agent 设备签名上传，Gateway 用 Owner 已固定的 Root 公钥验签并更新 D1。成功后的节点状态为 `KEY_VERIFIED`。
7. 若证据不充分、过期、重放、错 VPS、错登录用户、错公钥或错 revision，拒绝更新 VERIFIED；不自动修改密码策略。

### P4：Owner 手动密码认证操作

前置项：可销毁测试 VPS 的 P3 已完整验收、最近 30 分钟存在同节点/用户/版本的 VERIFIED、Owner 输入完整 UUID + 原因、服务器端和 Root 本机对应开关开启。Root 只管理被允许的 OpenSSH drop-in，先写原始 root-only 快照与 Manifest，再校验 sshd、应用 reload。

`ssh.password.disable` 完成后**仍要人工检查新建立的 SSH 公钥会话**。如写入后出现 reload 或签名持久化异常，不能自行恢复或宣称失败时“没有写入”，需使用服务商 Console 核查。

`ssh.password.restore` 与 `ssh.config.rollback` 必须匹配未消费的当前 snapshot_ref、文件/配置 revision 与 Root 签名，只撤销 SSH Manager 自己的管理片段。不会重置用户 Linux 密码，也不保证原有账户必然可以通过密码登录。

### P5：Owner 手动单 VPS 救援密钥

- 全局保存 rescue 公钥仅为配置；不启用任何机器。
- `rescue/enable` 明确选择**一台 VPS**，Root 只加入受管理且带标记的救援 key，保留既有 authorized_keys。
- `rescue/revoke` 仅可精准移除当前节点上 SSH Manager 管理的指定 rescue 条目，不删除其他 key。
- 救援 key 不因任务 TTL 到期而自动撤销，也不自动广播到全部 VPS。
- “恢复密码登录”“救援安装/撤销”“快照回滚”全部**人工命令触发**；没有 SSH 掉线自动回滚逻辑。

## 9. 数据库与迁移规则

D1 Schema 为 **0001–0008 增量迁移**，已合并主分支。旧迁移**不可原地修改**；新增表、索引、约束必须追加 `0009_*.sql`（或最新连续编号），同时更新测试及 D1 只读预检的 schema 假设。

| 迁移 | 主要对象 |
| --- | --- |
| `0001_init.sql` | `users`、`user_identities`、`nodes`、`agent_credentials`、`pairing_tokens`、`device_nonces`、`public_keys`、`node_keys`、`ssh_verifications`、`ssh_config_snapshots`、`operations`、`audit_logs` |
| `0002_identity_links.sql` | `identity_link_tokens` |
| `0003_verification_challenges.sql` | 每节点单 PENDING 验证索引、关联 active public key、审计签发者 |
| `0004_verification_prepared.sql` | `prepared_at` |
| `0005_pinned_node_proof_keys.sql` | 每节点 `node_ssh_proof_keys`、`proof_id`、`proof_hash` 与唯一性 |
| `0006_manual_ssh_operations.sql` | 快照恢复状态、单节点 rescue 唯一索引、`manual_ssh_assertions` |
| `0007_node_metadata.sql` | `group_name`、`notes`、分组索引 |
| `0008_single_active_operation.sql` | 单节点最多 1 条 CREATED/DISPATCHED/RUNNING 的唯一部分索引 |

重要事务安全点：首次 Owner 建立、身份链接 token 签发/领取、节点创建与 pairing、全局密钥轮换、Root 公钥 pin、验证挑战创建/取消、终态回执等均须一并提交相关审计。并发控制不能只依赖前置 SELECT，必须使用 D1 唯一索引/CAS/必要的事务内 SQL 断言。**绝不能自动补写历史审计记录“让检查绿灯”。**

## 10. 管理界面 IA 与交互规范

当前前端不再是单一长页面，采用 React hash 路由，避免 Cloudflare SPA 路由回退问题：

| 路由 | 功能 |
| --- | --- |
| `#/dashboard` | 节点/待初始化/操作概览 |
| `#/nodes` | 全宽 VPS 清单：搜索、在线状态、分组、排序 |
| `#/nodes/:uuid` | 单节点概览 |
| `#/nodes/:uuid?tab=agent` | 安装/配对 Agent、配对状态 |
| `#/nodes/:uuid?tab=ssh` | Root key、预检、daily key、挑战与危险动作 |
| `#/nodes/:uuid?tab=history` | 此节点任务历史 |
| `#/nodes/:uuid?tab=settings` | 节点展示字段与受控编辑 |
| `#/keys` | 全局 daily/rescue 公钥；明确告知保存不等于推送 |
| `#/tasks` | 最近 100 条操作、过滤与结果未知警告 |
| `#/audit` | Owner 审计记录 |
| `#/settings` | Access 配置和开关状态等 |

- 新建 VPS 是“基本信息 → 安装 Agent → 确认连接”三步流程；pairing token 只能临时显示，不能进入 URL、本地持久化存储、日志。
- 已配对节点的 SSH host、port、login user 不允许被任意编辑来绕过信任锚；名称、分组和备注可按白名单更新并审计。
- `RESULT_UNKNOWN` 必须显著区别于 SUCCEEDED/FAILED；禁止一键重试未确定的危险操作。
- Owner-only 动作需要独立二次确认，且所有安全限制必须由后端重验。
- 搜索、筛选、排序、分页/刷新必须保持可访问、响应式，不把模拟数据冒充生产信息。

## 11. 环境配置与部署方式（务必分清是否会修改远端）

### 11.1 基础条件

- Node.js 22（仓库 GitHub Actions 使用版本）、npm、Python 3、Git。
- Go 1.23+；VPS Agent 及 Root Helper 的真实测试仅在 Debian/Ubuntu 等受支持的**可销毁测试系统**进行。
- 部署到 Cloudflare 前需要真实 Access Team Domain/AUD、Control 与 Agent Custom Domains、独立 Staging D1、命令签名密钥、匹配 Worker/DO 的配置。
- `COMMAND_PRIVATE_KEY` 必须是 Worker Secret，Root 证明私钥留在对应 VPS；不要上传、打印或提交。

### 11.2 本地安全开发命令

```bash
npm install
npm run check
npm run test
npm run test:cf:quick
npm run test:cf:native
npm run build:web
node scripts/test_gateway_workerd.mjs --local-only

python3 scripts/test_migrations.py
python3 -m unittest discover -s scripts -p 'test_*.py'

cd agent
go test -race ./...
go vet ./...
go build ./cmd/ssh-manager-helper
go build ./cmd/ssh-manager-prove
```

`npm run dev:web` 仅启动本地 Vite 开发预览；不要将前端 UI 可点视为后端/云端已经允许 SSH 操作。`npm run cf:quick:dry` 用于配置生成逻辑 dry-run。**不要把 `npm run cf:deploy`、`npm run cf:quick`、`npm run deploy:single`、`npm run db:migrate:remote` 作为普通测试命令**，这些可能连接/修改远程 Cloudflare。

### 11.3 Cloudflare 自动与手动部署渠道

1. **Cloudflare Workers Builds**：README / 部署文档提供 GitHub main 连接，Deploy command 为 `npm run cf:deploy`，Preview command 为 `npm run cf:preview:skip`；此渠道可能**在 main 更新时自动构建/部署**，即使只更新文档。每次更改 main 前先核对 Cloudflare 项目 Build/Deploy 触发配置。
2. **GitHub Actions Staging Workflow**：`.github/workflows/cloudflare-single-staging.yml` 配置为手动 `workflow_dispatch`，或 main push 触发且仓库变量 `SSH_MANAGER_STAGING_AUTO_DEPLOY=true` 时执行真正 deploy job。该任务会执行**远程 D1 迁移**及 Worker 部署，必须人工核对变量、Environment 和绑定后才开放。
3. **本地脚本**：`npm run cf:quick`、`npm run cf:deploy` 等是有副作用的部署工具，不要在代码/文档测试中无意运行。
4. **安全总则**：只使用一个选定的自动化部署渠道；不因合并到 main 就认为已允许生产高危写入。`MANUAL_SSH_ACTIONS_ENABLED` 默认 `false`，Root 本地 `enable_*` 默认均为 `false`。

Cloudflare Staging 的迁移与部署属于真实远端操作，不能用本地单测证明已完成。Worker 签名密钥、D1、Custom Domains、DO 绑定必须复用原来的已批准 Staging 资源，避免误建第二个 Worker/误换 signer。

### 11.4 Staging D1 聚合只读预检

入口：`scripts/staging_d1_readonly_preflight.py`，详见 [STAGING_D1_READONLY_PREFLIGHT.md](STAGING_D1_READONLY_PREFLIGHT.md)。

```bash
# 默认仅输出计划；不会查询数据库，退出码 4
python3 scripts/staging_d1_readonly_preflight.py --staging-only

# 只读已有且一致的本地 SQLite 快照
python3 scripts/staging_d1_readonly_preflight.py --staging-only \
  --sqlite-snapshot /path/to/safe-staging-snapshot.sqlite

# 经 Owner 允许、明确确认现有 Staging D1 UUID 后才执行
python3 scripts/staging_d1_readonly_preflight.py --staging-only --execute-remote \
  --config wrangler.single.staging.native.jsonc \
  --confirm-database-id "<VERIFIED_STAGING_D1_UUID>" \
  --reviewed-commit "<REVIEWED_40_CHARACTER_GIT_SHA>"
```

- 默认 PLAN_ONLY；远程运行前要求 Git HEAD/审核 SHA 一致、工作区干净、配置为仓库根目录的 `native` 或 `local` Staging 文件且 D1 UUID、双域名、Worker 路由与危险开关匹配。
- 检查 **15 张表、5 个唯一部分索引定义、10 个关键字段、17 项业务完整性聚合**；报告只返回检查 ID / 状态 / 数量，不输出节点或密钥明细。
- 退出码 `0`：本次数据检查 PASS，仍**不是**真实 SSH 安全审批；`2`：FAIL/执行异常必须阻断；`3`：WARN 需人工复核不得自动放行；`4`：只显示计划未执行。
- DISPATCHED/RUNNING 无论是否过期都阻断；任何 CREATED 或 PENDING 需要人工检查。只读工具**不会**清空任务、补审计、解除锁或替换公钥。
- **没有 Owner 的确认与真实 Staging 绑定核对，不得自行执行远端检查。**

## 12. 现有自动化测试与验收标准

| 级别 | 典型入口 | 能证明什么 | 不能证明什么 |
| --- | --- | --- | --- |
| TypeScript / Vitest | `npm run check`、`npm run test` | 类型、安全状态机与组件行为 | 真实 Cloudflare Access、SSH 登录 |
| SQLite / Python | `scripts/test_migrations.py`、`test_security_transactions.py`、`test_verification_lifecycle.py`、`test_terminal_report_races.py`、`test_staging_d1_readonly_preflight.py` | Schema 迁移、事务回滚、唯一性、并发模拟 | 真正 D1 远端历史数据 |
| Local workerd+D1 | `scripts/test_gateway_workerd.mjs --local-only` | Gateway 请求、认证结构和并发回执的隔离集成 | VPS 真机 SSH/PID 可信取证 |
| Go | `go test -race ./...`、`go vet ./...` | Agent/Root Helper、本地文件、回执 outbox | 云端真实网络 / 跨系统 SSH |
| 隔离 OpenSSH | `ssh-integration.yml` | 回环测试 SSH 公钥登录 | 公网 VPS 与真实 Cloudflare |
| 远端 Staging | P3 T01–T11、P4/P5 单节点 Runbook | 一台可销毁 VPS 上的可信端到端流程 | 自动等于生产可用 |

修改任何认证、签名协议、身份关联、D1 事务、单节点锁、SSH 配置文件操作时，必须同时新增**失败先行**回归：包括相同与冲突回执并发、nonce 重放、旧 revision、错节点/错用户、审计插入失败/忽略、Root journal 不可写、Agent 网络断线、命令已执行但 ACK 丢失等。测试必须能够明确区分“没有执行”“已执行”“结果未知”。

## 13. 仍未完成的发布门槛与优先级

### P0：先解决真实安全验收（阻断生产）

- [ ] 指定一名非原代码作者的独立 Reviewer，记录正式安全 Review；审阅 Access/Owner、单节点 Root trust pin、D1 并发 CAS、快照回滚。
- [ ] 确认 Cloudflare 的**真实** Staging Worker/Custom Domains/D1/DO、当前 main 构建版本、Access IdP/RBAC；执行受批准的 D1 只读预检并归档脱敏 JSON。
- [ ] 在**可销毁 VPS** 中按 [P3.4 T01–T11](P3_STAGING_E2E_ACCEPTANCE.md) 与 [真实操作 Runbook](P3_STAGING_LIVE_RUNBOOK.md) 验证 Root Helper、journald PID 与进程链、Windows 新 SSH 公钥连接。
- [ ] P4/P5 分别验证单节点密码禁用、独立再次登录、手动恢复、单节点救援 key 加/撤、D1 审计一致性以及服务商控制台救援；所有高危开关在测试完成后恢复 false。

### P1：可复现构建与运维质量

- [ ] 仓库目前没有提交 `package-lock.json`；在可信环境生成并审查 lockfile，逐步把 CI / Build 迁移到 `npm ci`，生成并验证依赖清单/SBOM。当前 `rollup: 4.66.0` override 只是临时限制，并**不等价于完整可复现构建**。
- [ ] 维护版本、Agent 更新机制和兼容性策略；现有安装脚本按固定 SHA 安装，**不应声称支持安全自动升级**。
- [ ] 对历史 D1 不一致状态提供**只读定位 + 人工决策**流程，严禁自动“修正”为成功或直接回写审计。
- [ ] 分离并审查复杂 `index.ts` 的事务逻辑；尤其检查“先 D1 batch 提交、后检查 `meta.changes`”的边界，同时将 API GET 的过期写入语义统一为明确的设计契约。
- [ ] 对 Cloudflare Workers Builds 及 GitHub Actions 自动部署通道做唯一性检查，防止 main docs-only push 产生意外部署或与生产 signer 竞争。

### P2：体验增强（不得削弱安全）

- [ ] 节点列表与任务中心的数据量、搜索/筛选性能、空状态、移动端可访问性完善。
- [ ] Agent 协议/Worker 配置的版本协商、手动升级和兼容性报错。
- [ ] 操作结果未知的只读诊断界面、人工核查记录与安全追踪，而非“重试执行”按钮。
- [ ] 经需求批准再增加配置导出/API 文档生成；必须**脱敏**并保持与代码一致。

## 14. 给后续 AI Coding Agent / 新开发者的执行规范

每次开始任务前按顺序执行：

1. 固定 `main` 当前 SHA，阅读本文件、`docs/SECURITY.md`、`P3_STAGING_LIVE_RUNBOOK.md`、`P4_P5_MANUAL_OPERATIONS.md`、`P6_RELEASE_AND_SECURITY_GATE.md`。历史方案只作参考，**以实际源码与测试为准**。
2. 提出变更范围：改哪些模块/API/表，涉及哪些信任边界；标出哪些是纯 UI、哪些会接触 Root/SSH/D1/Cloudflare 实际环境。
3. 先编写或更新测试，复现失败；再用最小补丁修复。修改 D1 结构只追加新迁移，不编辑旧迁移。
4. 涉及签名、密钥、证明、回执、失败后的写入等，按“同一节点、同一操作、同一审计、同一事务、失败关闭”原则审查。
5. 执行 TypeScript、Vitest、SQLite、workerd+D1、Go 及相应集成测试；提供**可追踪的 CI run URL 和 commit SHA**，不得凭空声称测试通过。
6. 将代码推送至开发分支、经 PR 审核再合并。对 `main` 的每次更新必须先确认 Cloudflare Builds 是否监听分支；未经授权**不部署、不执行远程 D1 迁移、不 SSH 到生产 VPS**。
7. 交付时说明：已实现功能、测试结果、明确未验收项、风险与后续建议。不要将“CI Green”描述成“生产已验证”。

**绝对禁止：** 私钥上传/硬编码/日志打印、Agent 任意 shell、设备签名假冒 Root proof、跨节点批量变更、自动恢复密码登录、任务超时自动解锁、Root 结果未知时重执行高危写操作、自动覆盖 authorized_keys / 其他 SSH 配置、自动补写审计，以及未经批准把 `MANUAL_SSH_ACTIONS_ENABLED` 或 Root `enable_*` 打开。

## 15. 其他权威文档与维护规则

- [安全不变量](SECURITY.md)
- [完整 Staging 部署](DEPLOYMENT.md)、[Cloudflare 3 步部署](CLOUDFLARE_QUICK_DEPLOY.md)
- [Staging D1 只读安全预检](STAGING_D1_READONLY_PREFLIGHT.md)
- [VPS 管理台验收清单](VPS_CONSOLE_STAGING_ACCEPTANCE.md)
- [P3 真实隔离联调](P3_STAGING_LIVE_RUNBOOK.md)、[P3.4 T01–T11 验收](P3_STAGING_E2E_ACCEPTANCE.md)
- [P4/P5 单 VPS 手动操作](P4_P5_MANUAL_OPERATIONS.md)
- [P6 发行与生产安全关卡](P6_RELEASE_AND_SECURITY_GATE.md)
- [Agent Staging 安装](AGENT_STAGING_INSTALL.md)
- [原始 VPS Console 设计](superpowers/specs/2026-11-01-vps-console-design.md)（历史）

文档维护要求：任何改变用户可见页面、API、签名格式、关键 D1 迁移、权限模型、危险开关或部署流程的代码 PR，应同步更新本开发文档及对应 Runbook，明确“实现 / 自动化测试 / 真实环境验收”三者差别。避免保留互相冲突的“原型未实现”“已上线生产”等过期表述。
