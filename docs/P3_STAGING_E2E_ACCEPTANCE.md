# SSH Manager V4.0 — P3.4 隔离 Staging 全链路验收清单

> **用途：只用于专用测试 VPS + 独立 Cloudflare Staging 环境。** 不能直接用于生产 VPS，不启用 P4 关闭密码登录、救援授权、自动回滚或批量操作。此文档可作为人工验收记录的模板，但不代表已经完成任何真实 Staging 验收。

## 1. 验收范围与结果定义

目标链路：管理员在当前选中的单台测试 VPS 创建挑战 → 设备身份认证 → Root Helper 准备挑战 → 由管理员本地私钥建立新的 SSH 公钥连接 → OpenSSH 留下可信服务端认证证据 → Root Helper 通过内核凭据及进程链核验 → Root Ed25519 签名 → Agent 可靠转发 → Cloudflare 验证固定公钥并一次性更新 D1 → 管理员在面板看到 `VERIFIED`。

必须明确区分四种状态：`PREPARED` 只证明挑战已经部署；`SSH_LOGIN_OBSERVED` 是服务器观察到的候选认证；`ROOT_SIGNED` 是 Root Helper 已完成独立校验并签发证据；**只有 D1 原子提交成功后，控制台才可显示 `VERIFIED`**。这些状态不可相互代替。

## 2. 严格前置条件

| 检查点 | 放行标准 | 未达标准时 |
| --- | --- | --- |
| 主机范围 | 专门创建、可随时销毁的测试 VPS；保留云服务商 VNC/串行控制台 | 停止验收 |
| 配对范围 | 每次测试只选择一个固定 node_id，不执行批量命令 | 停止验收 |
| Cloudflare | 与生产环境分开的单 Worker、两个自定义域名、同 Worker NodeSession DO、D1、Control-only Access audience、签名密钥 | 停止验收 |
| Agent | 非 root `ssh-manager` 运行；设备密钥仅自身可读 0600；只主动向外连接 | 停止验收 |
| Root Helper | root 私有配置与证明私钥，组受控 Unix Socket，不监听外网管理端口 | 停止验收 |
| 日常公钥 | 由本地管理员授权安装到该测试 VPS 的特定登录用户，不覆盖现有条目 | 停止验收 |
| 现有 SSH | 密码认证当前状态不改变；保存现有 SSH 会话和主机指纹 | 停止验收 |
| 可信日志 | journald 必须有可确认的 `_TRANSPORT`、`_EXE`、`_UID`、`_PID` 及 SSH 进程祖先；stdout 不可采用父进程 PID 代替子进程 | 状态 `UNVERIFIABLE`，不放行 |

## 3. 只读采证（新脚本）

在**隔离测试 VPS** 上，将仓库的 `scripts/staging_readiness.py` 放在受管理员控制的工作目录。运行：

```bash
sudo python3 scripts/staging_readiness.py \
  --staging-only \
  --login-user root \
  --node-id NODE_UUID_FROM_SELECTED_STAGING_VPS \
  --client-ip 203.0.113.10 \
  --local-ip 192.0.2.10 \
  --ssh-port 22
```

将这些**文档示例地址**替换成此次 Staging 环境中 `sshd` 实际看到的客户端 IP 和服务器本地监听 IP。脚本检查文件元数据、Socket 严格属组与 0660 权限、systemd 服务状态、`sshd -t/-T -C` 生效选项和最近两小时的 journald 认证记录；还会读取 **Root Helper 配置中的非敏感节点/登录上下文字段**进行单 VPS 匹配，但不会输出配置内容，也不会读取 Agent 设备私钥。脚本**不会读取 SSH 私钥内容、不会修改 authorized_keys、不会写 sshd_config、不会重启 systemd、不会访问网络**。

退出码 `0` 仅表示全部前置项为 `PASS`；退出码 `2` 表示有 `FAIL`，必须解决；退出码 `3` 表示只有 `WARN`，需要人工检查。关键文件和服务缺失会直接标记为 `FAIL`。无论退出码是什么，输出中的 `actual_ssh_login_proven=false` 与 `cloudflare_remote_e2e_verified=false` 都不会被自动改为 true。这个工具**不是服务器可信登录证明器**。

完整 P3.3 SSH 认证取证、Windows PowerShell 流程及原始密钥安全要求仍以 `docs/P3_PROOF_END_TO_END.md` 为准。本文件不替代 Root Helper 的既有 `scripts/staging_proof_preflight.py`，而是额外审查 systemd 运行账户、Socket 与状态目录权限。

## 4. 人工联调顺序及必须保留的证据

| 序号 | 操作 | 验收证据 | 失败处理 |
| --- | --- | --- | --- |
| T01 | 单 Worker + 双域名 Cloudflare Staging 部署、Access Host 隔离与 D1 迁移 | 不含任何 Secret 的迁移记录、Worker 版本、D1 环境标识 | 不进入 VPS 阶段 |
| T02 | 单节点 Agent 配对 | D1 节点 ID 与 Agent UID/服务状态，配对 token 已消费 | 只检查当前 VPS，不重用一次性 token |
| T03 | Root Helper 准备挑战 | Root 私有 challenge 记录及控制端 `prepared_at`，不得为 VERIFIED | 只读排查本机日志 |
| T04 | Windows PowerShell 新建纯公钥 SSH 连接 | `BatchMode=yes`、禁密码/键盘交互、HostKeyChecking=yes、连接不复用 | 禁止用密码或旧连接补齐证据 |
| T05 | Root 取证 | 相同会话/用户/日常密钥指纹的 journald + `/proc`，不得泄露完整 IP 或私钥 | 任何不确定均 `UNVERIFIABLE` |
| T06 | Root 签名上传 | proof_id、node_id、key_id、挑战版本、有效期、签名校验成功 | 不能由客户端自己提交 VERIFIED |
| T07 | D1 状态确认 | ssh_verifications=VERIFIED；nodes=KEY_VERIFIED；node_keys.verified_at 非空；audit_logs 可追溯签发人 | 事务异常不得显示成功 |
| T08 | 重放与篡改 | 过期 token、另节点 proof、错用户、签名篡改全部拒绝 | 无覆盖、无重试执行 SSH 修改 |
| T09 | 网络/Agent 重启 | Root 已持久化终态仅重发结果，不再次写 authorized_keys | 不可确认时标记人工核查 |
| T10 | Root 中间崩溃 | 有领取记录但无终态时停在人工核查，不自动执行、不自动回滚 | 通过服务商控制台确认 |
| T11 | 原始配置一致性 | sshd_config、既有 authorized_keys、密码认证方式保持原状态 | 立即停止后续测试 |

记录方式：保留时间、单节点 ID、测试操作 ID、匿名化的指纹后缀、Worker 部署版本、测试结果和必要的脱敏日志。**不得导出设备签名私钥、Root 证明私钥、SSH 私钥、配对 token、nonce 原文、Cloudflare API Token 或访问 Cookie。**

## 5. 禁止自动解除的上线关卡

- 只读脚本 PASS、单元测试 PASS、本地 workerd+D1 PASS，并不等同于 T01–T11 已全部通过。
- 真实 VPS 的 journald PID 与 shell 祖先关系无法证实，必须判定为不支持可信证明，不能添加强制放行按钮。
- Cloudflare D1 验证业务状态与人工审计没有完全一致前，不能允许任何声称“SSH 已验证”的 UI 状态。
- **P4 密码登录手动关闭、救援授权/撤销、SSH 配置手动恢复功能仍应锁定**；不得通过任何“测试通过”选项自动启用。
- 管理员继续只操作选中的单 VPS，不广播、不自动回滚、不自动修改现有密码认证。

## 6. 自动化测试与 CI 接入

对新增的只读采证器运行：

```bash
python3 -m unittest discover -s scripts -p 'test_staging_readiness.py' -v
```

如并入 GitHub Actions，可在现有 control job 中追加一条 Python 单元测试命令；不应将该采证器自动运行在 GitHub Runner 的生产网络环境，也不应由 CI 自动 SSH 登录生产 VPS。

## 当前状态

此文档仅为**待执行的 Staging 验收程序**，不是已完成的测试证明。真实测试 VPS、真实 Cloudflare Staging 和 Windows 私钥登录目前均未在本轮使用。


## 7. 真实联调执行入口

P3.4 现在增加两个仅用于隔离 Staging 的执行入口：

1. scripts/staging_remote_probe.py：从管理员机器匿名检查远端安全拓扑。Control 必须被 Cloudflare Access 拦截，Agent Gateway 必须直接返回设备认证 health JSON，不能被浏览器 Access 误拦截。
2. docs/P3_STAGING_LIVE_RUNBOOK.md：固定 Cloudflare Staging、单 VPS、Root Helper、Windows 新 SSH 会话和 D1 VERIFIED 的完整执行顺序。

这两个入口只让 T01–T11 可重复执行，不会把任何条目标记为已通过。真实环境没有留存证据前，本文件的当前状态仍是“待验收”。

## 单 Worker 双域名的特殊安全门槛

管理域名必须仅经过 hostname-based Access；不能对 Worker 整体配置 Access，否则 Agent WebSocket 会被阻断。Agent 域名不能路由到 /api/*、/、/index.html。Worker 静态资源必须 run_worker_first=true，禁用 workers.dev 和 preview URLs。单 Worker 上报本地 CI PASS 仍不等于云端路由隔离已验收。
