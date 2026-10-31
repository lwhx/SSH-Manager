# 已删除 Worker、保留 D1 的 Staging 受控恢复

适用：原来的 Cloudflare `ssh-manager` Worker 已删除，但原 `ssh-manager-staging` D1 数据库仍存在，且所有 VPS 节点仍处于 **unpaired + WAITING_PAIR**，从未发生 Agent 配对或 SSH 操作。

**不要删除 D1、Access 应用，也不要尝试复制旧 Worker 的签名密钥。** 删除 Worker 可能使 COMMAND_PRIVATE_KEY 无法取回，恢复脚本只在经远端 D1 验证没有任何已配对身份或操作历史时，生成新的命令签名身份。

## 在 Cloudflare 新建 Worker

1. Workers 和 Pages → Create application → GitHub → 选择 `lwhx/SSH-Manager`，生产分支 `main`。
2. Worker 名称：`ssh-manager`（原来的 D1 名称仍为 `ssh-manager-staging`）。
3. Build command：**留空**；Deploy command：`npm run cf:deploy`；Preview command：`npm run cf:preview:skip`；根目录：`/`。关闭 Preview 构建，不开启 Worker-level Cloudflare Access。
4. Build Variables 添加（取原 Access 实际值）：`SSH_MANAGER_BASE_DOMAIN=whks.de`、`SSH_MANAGER_ACCESS_TEAM_DOMAIN`、`SSH_MANAGER_ACCESS_AUD`、`SSH_MANAGER_OWNER_EMAIL`。
5. 另加 **一次性普通 Build Variable**：
   - `SSH_MANAGER_RECOVER_DELETED_WORKER`
   - `CONFIRM_UNPAIRED_STAGING_WORKER_RECREATE`

部署脚本在首次运行时只允许不存在或安全的空占位 Worker；会查找 **原 D1 UUID**，只执行只读检查，然后绑定回同一 D1。不会调用 `d1 create`、`d1 delete` 或自动清理原有节点。

## 自动拒绝条件

以下任何一项非零或无法查明时，脚本拒绝继续：未配对以外的节点、已配对设备、已使用配对令牌、**尚未过期的配对令牌**、设备 nonce、SSH 操作、node keys、认证验证、快照、Root 证明公钥。已存在的 **未配对** 节点和管理员身份可以保留。若因为现存有效令牌失败，令牌 10 分钟有效；让其自然过期后重试构建，不要修改数据库清除记录。

脚本在部署公钥后再次检查 D1，防止配对时序冲突，再把新的 `COMMAND_PRIVATE_KEY` Secret 上传到 **实际部署的 ssh-manager Worker**。全程禁止 SSH 高危操作。

成功日志：

```text
DELETED WORKER RECOVERY OK. Existing Staging D1 retained.
Remove SSH_MANAGER_RECOVER_DELETED_WORKER from Cloudflare Build variables NOW.
```

**看到成功后立即删除一次性 Build Variable** `SSH_MANAGER_RECOVER_DELETED_WORKER`，正常后续更新复用新密钥。若部署中断于创建新 Worker 后但 Secret 未上传，只有在同样的只读 D1 检查通过时，才允许使用该一次性变量恢复。不要反复无条件重试或开启 SSH 操作。

## 验收

- Workers & Pages → `ssh-manager` → Bindings：`DB` 仍指向原 `ssh-manager-staging` D1，`NODE_SESSIONS` 仍是同 Worker Durable Object。
- Variables & Secrets：存在 `COMMAND_PRIVATE_KEY`，`MANUAL_SSH_ACTIONS_ENABLED=false`。
- 控制端 `https://ssh-staging.whks.de` 应要求 Cloudflare Access 登录；Agent 的 `https://agent-staging.whks.de/agent/v1/health` 返回设备认证 JSON。
- Agent 域名上的 `/api/v1/health` 必须 404。
- 管理面板原未配对 VPS 节点仍在，随后只在**可销毁测试 VPS**上进行 Agent 配对验收。

若 D1 已有真实配对或已执行操作，必须停止自动恢复，另行评估原始签名身份和数据影响。
