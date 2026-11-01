# SSH Manager — VPS 管理新版 Staging 验收清单

> 本文针对 PR #8 的 Komari 风格管理台重构。**只在 Cloudflare Staging 和可销毁测试 VPS 上执行**。CI 全绿不等于界面或 SSH 实机验收通过。不要绕过原有 P3.4 T01–T11 安全关卡。

## 0. 部署前隔离关卡（必须完成）

- [ ] 使用已审核的 PR commit SHA，确认 GitHub CI 中 TypeScript、Vitest、D1 迁移、local workerd、Go Agent/Root Helper 测试全部成功。
- [ ] PR **不得自动合并**。仅在 Owner 授权后才允许将审核过的 commit 部署到现有独立 Staging；不要创建新的 D1，也不要轮换签名密钥。
- [ ] 保留现有 Cloudflare Access：管理 hostname 只接受 GitHub/Cloudflare 身份，Agent hostname 保持设备 Ed25519 签名；不要对整个 Worker 强制浏览器 Access。
- [ ] Staging 的 `MANUAL_SSH_ACTIONS_ENABLED=false`，VPS Helper 的写操作开关继续全部禁用；生产 VPS 不参加验收。
- [ ] D1 迁移确认 `0007_node_metadata.sql` 已应用：`nodes.group_name`、`nodes.notes` 存在，原有节点、Agent 凭证和操作记录保留；运行脚本只迁移当前 Staging D1。

## 0.1 已部署 Staging D1 只读准入（禁止自动修复）

- [ ] Owner 从 Cloudflare Dashboard **独立**确认当前账户、`ssh-manager-staging` Worker、已有 D1 绑定的 UUID 与本地生成的 `wrangler.single.staging.local.jsonc` 完全一致；确认 SSH 写开关 `MANUAL_SSH_ACTIONS_ENABLED=false`。绝不能自动创建新 D1 或改用生产绑定。
- [ ] 在审核过的固定 Git SHA 上先运行 `scripts/staging_d1_readonly_preflight.py --staging-only` 检查 PLAN_ONLY；这是无网络预览，不算完成验收。
- [ ] 经 Owner 明确授权后，只在现有 Staging D1 执行 [只读汇总预检](STAGING_D1_READONLY_PREFLIGHT.md)。保存脱敏报告、审核 SHA、时间、退出码；要求 0 FAIL，所有 WARN 必须人工确认，不得据此解锁任何未知 Agent 任务。
- [ ] 同时核对历史 Root 绑定缺审计、VERIFIED 持久化证明和单节点操作锁。发现异常必须保持 Draft，不合并、不部署、不将记录强制标为 SUCCEEDED，也不执行 D1 更新来“修正”检查结果。
- [ ] 独立安全审查人员需检查代码与回归测试，记录审查结论。D1 检查绿色不是 Access/RBAC、Root Helper、真实 SSH 登录及人工恢复验收的替代品。

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

## 4.1 SSH 验证挑战的事务与并发验收

- [ ] **开始挑战**：在 Staging 对单个已完成公钥安装、已固定 Root 公钥并在线的测试节点发起挑战；确认 `ssh_verifications` PENDING、`operations` CREATED/DISPATCHED 与 `ssh.verification.start` 审计同一 D1 事务提交。响应中的原始 nonce 不得保存至数据库、日志或持久化浏览器存储。
- [ ] **审计中断**：仅用隔离 SQLite/local D1 触发器注入审计 INSERT 失败；验证挑战、准备操作与审计**全部回滚**，不可留下孤立 PENDING。不得在实际 Staging D1 上添加用于故障注入的触发器。
- [ ] **并发创建**：两个管理员同时开始同节点挑战时，只允许一个 PENDING；第二个必须拒绝且不派发另一份签名命令。如果已存在未结束的 DISPATCHED/RUNNING，仍应返回明确的操作阻塞信息，不得释放单节点操作锁。
- [ ] **配置变化**：在开始请求的预读与事务写入之间模拟节点 SSH 配置版本、活动 daily key、Agent 心跳状态发生变化；应拒绝创建新挑战及准备操作。不得使用过期公钥验证结果继续推进密码关闭流程。
- [ ] **挑战取消**：只允许当前节点、当前管理员角色授权且尚未到期的 PENDING 进入 CANCELLED；与 Root VERIFIED 并发时必须通过数据库条件更新解决竞争，后到请求返回 HTTP 409 而不是伪报“已取消”。
- [ ] **取消审计故障**：本地注入 `ssh.verification.cancel` 审计写入失败；必须回滚 CANCELLED，重试同一取消应遵守真实状态。跨节点或重复取消均不得产生虚假成功记录。
- [ ] **GET 只读**：重复读取过期、活动日常公钥已变化或配置版本不匹配的挑战，数据库原始记录与审计行数不变；响应只投影 EXPIRED/INVALIDATED。过期 PENDING 只能在受控写入路径安全清理。
- [ ] **取消不等于终止 Agent 执行**：取消挑战后，已经 DISPATCHED/RUNNING 且回执未知的准备任务仍保持操作锁，不能将取消当作 Root 未执行命令的证据，也不得自动重派或回滚。

## 4.2 Agent 终态回执与验证状态并发（必须先通过 local workerd + D1）

- [ ] **同一终态回执并发**：对同一隔离节点、同一已派发的测试操作同时提交至少 5 份各自有效签名的相同 Agent 终态回执；数据库仅允许一次 `DISPATCHED/RUNNING → SUCCEEDED/FAILED`、一次终态审计。其余请求只允许返回对**完全相同**持久结果的幂等确认，不得再次下发或重放 SSH 指令。
- [ ] **不同终态竞争**：同时上报不同 `result_code`、`detail` 或 `SUCCEEDED/FAILED`，只能有一个完整终态胜出。败方收到 `CONFLICTING_OPERATION_REPORT` 或不可重试的异常，不能写入额外审计或修改节点状态。
- [ ] **终态 CAS 0 行**：对同一操作重复执行更新，`changes()=0` 必须在同一个 D1 batch 内触发 SQL 断言失败，使后续副作用和审计一起回滚，不能依靠提交之后检查 `meta.changes`。
- [ ] **必要副作用缺失**：本地模拟签名验证准备 `prepared_at`、SSH policy 节点更新或日常公钥安装后节点阶段更新返回零行，整个 D1 batch 必须回滚；不可保留孤立 `SUCCEEDED`。
- [ ] **审计失败**：仅在隔离 local D1 注入终态 `audit_logs` INSERT 错误，验证操作仍处于 `DISPATCHED/RUNNING`，节点配置、密钥安装和验证标记均未部分提交。不要对远程 Staging D1 或真实 VPS 注入写故障。
- [ ] **取消后迟到的准备结果**：已取消/失效的 SSH 挑战不可凭迟到回执自动重新激活或变成 `VERIFIED`；若结果不可确认，保留单节点锁并走人工核查，不能自动解除阻塞。
- [ ] **高危操作证明**：日常公钥写入以及手动密码/救援 SSH 操作，不能只凭 Agent 设备签名结束任务；必须验证对应 VPS 固定的 Root 独立签名和结果语义，无法证实“未写入”的故障保持未知状态。

## 5. 上线证据与拒绝条件

每个用例记录测试日期、Git SHA、Staging 版本、测试节点 UUID、操作/挑战 ID、预期/实际结果及脱敏截图。禁止收集私钥、pairing token、challenge token、Cloudflare API token、Access Cookie 或完整敏感 SSH 配置。

**拒绝合并/部署的条件**：任何权限绕过；重放或错误节点操作；修改已配对节点连接；结果未知时再次下发；静态资源泄露至 Agent hostname；D1 迁移丢数据；配对令牌泄漏；自动回滚或自动修改密码认证。

全部条目检查完成后，再按 [P3 Staging 实机联调](P3_STAGING_LIVE_RUNBOOK.md) 和 [P6 安全发布门槛](P6_RELEASE_AND_SECURITY_GATE.md) 单独决定是否通过 SSH 安全验收。**验收单签字前保持 PR Draft、Staging 写开关关闭。**
