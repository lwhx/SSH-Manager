# SSH Manager — VPS 管理新版 Staging 验收清单

> 本文针对 PR #8 的 Komari 风格管理台重构。**只在 Cloudflare Staging 和可销毁测试 VPS 上执行**。CI 全绿不等于界面或 SSH 实机验收通过。不要绕过原有 P3.4 T01–T11 安全关卡。

## 0. 部署前隔离关卡（必须完成）

- [ ] 使用已审核的 PR commit SHA，确认 GitHub CI 中 TypeScript、Vitest、D1 迁移、local workerd、Go Agent/Root Helper 测试全部成功。
- [ ] PR **不得自动合并**。仅在 Owner 授权后才允许将审核过的 commit 部署到现有独立 Staging；不要创建新的 D1，也不要轮换签名密钥。
- [ ] 保留现有 Cloudflare Access：管理 hostname 只接受 GitHub/Cloudflare 身份，Agent hostname 保持设备 Ed25519 签名；不要对整个 Worker 强制浏览器 Access。
- [ ] Staging 的 `MANUAL_SSH_ACTIONS_ENABLED=false`，VPS Helper 的写操作开关继续全部禁用；生产 VPS 不参加验收。
- [ ] D1 迁移确认 `0007_node_metadata.sql` 已应用：`nodes.group_name`、`nodes.notes` 存在，原有节点、Agent 凭证和操作记录保留；运行脚本只迁移当前 Staging D1。

## 1. 导航、列表和响应式

- [ ] 登录后可分别打开仪表盘、VPS 节点、双公钥管理、任务中心、操作审计（仅 Owner）、系统设置。
- [ ] VPS 列表显示真实节点，支持名称/IP/用户名搜索、全部/在线/离线/未配对筛选、分组和最近添加/名称排序。
- [ ] 心跳超过 90 秒的节点不得展示为在线；未配对节点不能伪装为在线。
- [ ] 在不同页面之间切换、浏览器前进/后退、刷新后能保留正确的路由。无效 UUID 与错误 tab 必须回退到安全页面，不执行任何写请求。
- [ ] 逐个打开五个详情页签：概览、Agent 管理、SSH 安全、操作记录、节点设置。地址 `#/nodes/<UUID>?tab=ssh` 不包含配对令牌、私钥或任何证明 token。
- [ ] 桌面大宽度与 850px/540px 以下窄屏无关键按钮溢出。表格可横向滚动，表单可操作，弹窗可通过关闭按钮与 Esc 安全关闭。

## 2. 新增 VPS 与 Agent 配对（只用隔离测试机）

- [ ] 选择「添加 VPS」，确认三步流程：基本信息 → 安装 Agent → 确认连接。创建前没有后台 SSH 动作。
- [ ] 提交名称、主机、用户和端口后只创建当前节点的 D1 记录，不修改测试 VPS 的 sshd、密码、公钥或救援设置。
- [ ] 在安装器提示输入令牌时，再点击重新生成配对令牌；令牌有效期 10 分钟。更新令牌应立即使旧令牌失效。
- [ ] 安装命令固定到 Worker 所使用的 commit，不带令牌，不使用 `curl | bash`；令牌仅可在当前会话看到，不得写入 URL、日志或浏览器持久化存储。
- [ ] 真实配对与心跳只验证 Agent 通道，不把 Agent 在线当作 SSH 可信认证成功。
- [ ] 中途关闭弹窗并再次打开时，回到空白基本信息步骤；不能显示另一个节点的旧令牌。

## 3. 节点设置与权限边界

- [ ] 未配对节点允许管理员修改名称、分组、备注和未锁定的 SSH 主机/端口/登录用户。
- [ ] 已配对节点仅可修改名称、分组、备注。通过 DevTools 手工构造 PATCH 修改 SSH 主机/端口/用户必须被后端拒绝，不能依赖前端 disabled 属性。
- [ ] **并发测试**：在表单加载后让同一测试节点配对，旧表单的连接修改必须得到 `NODE_SETTINGS_CONFLICT`（HTTP 409），数据库中的地址保持不变。
- [ ] 两位管理员同时编辑过期的节点资料，后提交的旧快照不得覆盖先提交的新内容；同样返回 HTTP 409。
- [ ] 查看者（viewer）不可创建节点、保存设置、公钥或访问 Owner 审计；所有 API 继续使用 Access JWT/RBAC、同源 Origin 校验。
- [ ] 成功的资料修改要写入 audit_logs；拒绝修改不能伪装成成功。

## 4. 任务中心、未知结果与人工恢复

- [ ] 任务中心列出当前最多 100 条操作；节点详情仅显示当前节点的任务；支持状态筛选与刷新。
- [ ] `SUCCEEDED` 只能来自服务端接受的真实终态；已派发 `DISPATCHED` 或已开始 `RUNNING` 且过期无终态时，显示 `RESULT_UNKNOWN`，不得当作成功或普通“仍在执行”。
- [ ] 后端在同一 VPS 存在这种未知结果时，拒绝新下发操作与新的 SSH verification preparation，返回 `NODE_OPERATION_RESULT_UNKNOWN`（HTTP 409）；不能仅凭任务 TTL 到期就解锁。
- [ ] 只有有效的 Agent 终态回执（`SUCCEEDED` / `FAILED`）可以解除相应阻塞。**若回执永远丢失：停止面板下发，通过服务商 Serial/VNC/Rescue 控制台独立核查并使用经批准的人工恢复流程**；不要直接篡改 D1 状态或重复危险命令。
- [ ] 不能出现自动关闭密码登录、自动救援公钥安装、自动回滚或批量变更。
- [ ] 以上故障注入只用可销毁测试 VPS 或本地 D1/workerd；绝不能在生产 VPS 上模拟未知结果。

## 5. 上线证据与拒绝条件

每个用例记录测试日期、Git SHA、Staging 版本、测试节点 UUID、操作/挑战 ID、预期/实际结果及脱敏截图。禁止收集私钥、pairing token、challenge token、Cloudflare API token、Access Cookie 或完整敏感 SSH 配置。

**拒绝合并/部署的条件**：任何权限绕过；重放或错误节点操作；修改已配对节点连接；结果未知时再次下发；静态资源泄露至 Agent hostname；D1 迁移丢数据；配对令牌泄漏；自动回滚或自动修改密码认证。

全部条目检查完成后，再按 [P3 Staging 实机联调](P3_STAGING_LIVE_RUNBOOK.md) 和 [P6 安全发布门槛](P6_RELEASE_AND_SECURITY_GATE.md) 单独决定是否通过 SSH 安全验收。**验收单签字前保持 PR Draft、Staging 写开关关闭。**
