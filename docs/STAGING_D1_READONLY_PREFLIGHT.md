# SSH Manager · Staging D1 只读安全预检

> 适用于 PR #8 的**发布前只读数据完整性检查**。不是部署脚本、SSH 登录证明或生产安全放行。

## 安全边界

`scripts/staging_d1_readonly_preflight.py` 只使用 Python 标准库，SQL 在源码中预定义，只查询**汇总计数**。不输出 SSH 公钥、私钥、令牌、节点 UUID 或原始审计行；表结构缺失、查询结果异常、Wrangler 输出不完整都会失败关闭。

- 默认只打印检查计划，**不连接数据库或网络**，退出码 `4`（未验收）。
- `--sqlite-snapshot` 使用 `mode=ro&immutable=1` 与 `PRAGMA query_only=ON` 检查已准备好的**一致性本地快照**。不要直接复制仍在 WAL 写入中的在线数据库文件。
- 远程模式必须明确提供 `--staging-only --execute-remote --config --confirm-database-id --reviewed-commit`，校验现有生成配置的 Worker、D1 绑定 UUID、双 Staging 域名与 `MANUAL_SSH_ACTIONS_ENABLED=false`。
- 远程仅调用项目中安装的 Wrangler：`d1 execute ssh-manager-staging --config ... --remote --json --command <固定 SELECT>`。不接受用户 SQL，不执行迁移、部署、导出、SSH 写入、批量公钥设置或自动回滚。
- 远程模式还会用只读 Git 命令核对当前 `HEAD` 必须等于 `--reviewed-commit`，并拒绝整个 Git 工作区存在任何已跟踪改动或未忽略的新文件。实际操作前，Owner 必须从 Cloudflare 控制台**独立核对当前账户、Worker 的真实 D1 绑定和 Staging 数据库 UUID**；本脚本不能替代该核对，也不能证明远端 Worker 与本地配置一致。

Cloudflare 的 `d1 execute` 是通用 SQL 执行命令。即使本脚本固定只读 SELECT，仍建议操作账户使用能完成诊断的最小权限；不要因为预检失败就自动扩大权限。绝不把 Token 放进命令行或聊天消息。

## 执行示例

在已固定并审核 Git SHA 的仓库根目录，安装好 Python、Node.js 及项目依赖后运行。

**无网络计划：**

```bash
python3 scripts/staging_d1_readonly_preflight.py --staging-only
```

**本地不可变快照：**

```bash
python3 scripts/staging_d1_readonly_preflight.py --staging-only \
  --sqlite-snapshot /path/to/isolated-staging-snapshot.sqlite
```

**仅在 Owner 审批、核对现有 Staging 数据库 UUID 后执行远程只读检查：**

```bash
git rev-parse HEAD
python3 scripts/staging_d1_readonly_preflight.py --staging-only --execute-remote \
  --config wrangler.single.staging.local.jsonc \
  --confirm-database-id "<STAGING_D1_UUID>" \
  --reviewed-commit "<EXACT_REVIEWED_40_HEX_GIT_SHA>"
```

Windows PowerShell 请使用单行命令，`python3` 可替换成实际安装的 `python` 或 `py -3`。`wrangler.single.staging.local.jsonc` 必须是之前 Staging 部署生成的真实配置；脚本不会创建它，也不会使用生产配置兜底。审核 SHA 与实际 checkout 必须由操作者核对一致。

## 预检范围与解释

**结构检查：** 13 张必要表、5 个核心唯一部分索引与 10 个迁移字段；并核对每个索引的唯一性、列顺序和 WHERE 谓词，不能只凭同名索引存在就放行。缺失或定义不符均阻止继续读取业务检查。

**FAIL：** Root 公钥绑定缺审计或跨节点复用；同一节点多个未完成操作；任何 DISPATCHED/RUNNING 操作未结束；终态 Agent 回执缺审计或重复审计；VERIFIED 缺少 Root 证明/审计/已验证日常公钥；PENDING 引用失效公钥、旧配置或未安装的节点日常密钥；公钥版本重复；断言表非空；有效 Agent 配对记录缺少匹配 Owner、token 与时间戳的审计。

**WARN：** 任何 PENDING SSH 验证挑战或 CREATED 排队操作，即使尚未到期也不自动放行。任何 DISPATCHED/RUNNING 操作均为 FAIL；任务 TTL 到期绝不解除单节点操作锁。程序不自动清理或改变这些记录，必须由 Owner 单独审核。

报告只包含检查 ID、异常**数量**、状态、运行模式、时间和 Git SHA，不包含受影响节点明细。后续查明具体异常节点必须另行授权只读调查，禁止伪造审计、修改状态或解除操作锁。

| 退出码 | 含义 | 后续处理 |
| --- | --- | --- |
| `0` | 全部完整性检查 PASS | 仅允许进入后续人工审核 |
| `2` | FAIL、迁移缺失、查询失败或格式不符 | 阻断合并、部署和高危 SSH 写操作 |
| `3` | 存在 WARN | Owner 人工判断，不能自动放行 |
| `4` | PLAN_ONLY，未访问数据库 | 不构成 D1 验收证据 |

## 证据与独立 Review

人工留存：审核者、被审核的完整 commit SHA、Cloudflare 账户/Worker/D1 UUID 独立核对结果、执行时间、退出码和**脱敏 JSON**。不要留存 Cloudflare Token、Access Cookie、私钥、配对 token、SSH challenge token、Root 签名 payload、完整 SSH 配置、原始 Wrangler stderr/stdout 或数据库导出。

即使 D1 检查无异常，也不等于完成可信 Root 公钥来源确认、Cloudflare Access/RBAC 浏览器验收、隔离 VPS 新 SSH 连接、P3 T01–T11 及 P4/P5 人工恢复。上述独立安全 Review 和真实环境证据缺失时，PR 继续 Draft，不合并、不部署、不启用 `MANUAL_SSH_ACTIONS_ENABLED`。
