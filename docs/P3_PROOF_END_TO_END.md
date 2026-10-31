# P3.3 — SSH 新连接可信认证：隔离 VPS 验收指南

> 开发版：**不可直接部署生产 VPS**。代码包含服务器端证明签名和 Cloudflare 一次性状态更新，但尚未做真实 VPS + Cloudflare Staging 端到端验收。

## 一、必须保持的安全边界

- 所有操作只针对当前选中的单台 VPS；全局救援公钥默认不生效。
- 日常私钥始终保存在管理员客户端，不上传 Workers、D1、Agent、Helper。
- SSH 配置回滚只允许管理员手动针对单节点触发；不会自动回滚。
- Root Helper 的 `enable_daily_install` 和 `enable_ssh_proof` 默认都是 `false`。
- **VERIFIED 只证明经服务器认证的日常 SSH 密钥登录。它不会自动关闭密码登录；P4 仍锁定。**

## 二、服务器信任链

1. 控制端针对单节点创建五分钟挑战：D1 和 VPS 仅保存 token 的 SHA256 摘要。
2. Root Helper 生成私有 Ed25519 证明密钥；**Owner 通过该 VPS 控制台独立读取公钥和 SHA256 指纹，在面板里单节点固定**。Agent 无权注册或改写。
3. Agent 只接收已签名的 `ssh.verification.prepare` 命令；Root Helper 重新验签并保存挑战元数据，不修改 sshd。
4. 管理员使用已校验的服务器 host key、日常私钥建立新的仅公钥 SSH 会话；token 通过加密 SSH 标准输入传给无特权 `ssh-manager-prove`。
5. 独立证明 Socket 从内核 `SO_PEERCRED` 获取客户端 PID 和 UID，Root Helper 验证本机 sshd 生效配置、journald 可信 `_EXE` / `_UID` / `_PID`、公钥指纹及连接时间。
6. 使用 Linux `/proc` 验证证明 CLI 进程的祖先链包含同一条认证日志对应的 sshd PID；完全不信任用户提供的 `SSH_CONNECTION` 或 `SSH_USER_AUTH` 文件。
7. Root Helper 本机一次性消费挑战并签署证明，保存于私有出站队列；Agent 只能转发，不能签名。
8. Cloudflare 校验该节点 Owner 固定的 Root 公钥、节点、用户、密钥、配置版本和到期时间，用 D1 条件 UPDATE **一次性**改为 VERIFIED。相同已签名证明重试仅允许幂等确认。

## 三、隔离 VPS 手动准备（不得用于生产）

- 确认能够通过云服务商控制台登录，并保留现有管理员 SSH 会话和配置快照。
- 在测试 VPS 上构建并安装 `agent/cmd/ssh-manager-helper` 和 `agent/cmd/ssh-manager-prove`。后者是普通用户可执行的本机 Unix Socket 客户端，不需要 sudo/setuid。
- Root 状态目录应是 `root:root`、0700：`sudo install -d -o root -g root -m 0700 /var/lib/ssh-manager-root`。
- **显式生成**本节点证明密钥：`sudo /usr/local/libexec/ssh-manager-helper --init-proof-key`。打印 base64url 公钥和 SHA256 指纹；私钥只存于 `/var/lib/ssh-manager-root/proof_ed25519`、0600，已有文件不可覆盖。
- 在 SSH Manager 当前 VPS 详情页，粘贴本机输出的公钥和另行人工核对的指纹。绑定只影响当前 VPS。
- `/etc/ssh-manager/helper.json` 保持 `root:root`、0600；在隔离 VPS 里显式将 `enable_ssh_proof` 设为 true，且日常公钥已经安装时继续保持 `enable_daily_install=false`。
- Helper 证明 Socket 为 `/run/ssh-manager-proof/proof.sock`，目录 0711、Socket 0660 归 Root 与目标 Linux 用户 GID，Helper 仍以 SO_PEERCRED 检查确切 UID 与进程祖先。
- Agent 继续使用普通 `ssh-manager` 账户，只能从本地受限控制 Socket 获取 Root 已签名证明，再通过现有 HTTPS Device Auth 向 Cloudflare 上报。
- OpenSSH 的 journald 记录必须带可信 `_EXE`、`_UID`、`_PID`，且 `_TRANSPORT` 为 `syslog` 或 `journal`。**拒绝 `stdout`/`stderr` 记录**：systemd 官方说明它们的 `_PID` 可能代表打开日志流的父进程，容易混淆不同 SSH 会话。参考 https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html 。若只有普通 auth.log、stdout 日志或 PID 关系不匹配，验证必须失败，不得人工强行通过。
- 应完整应用 D1 迁移，包含 `0005_pinned_node_proof_keys.sql`，再进行此测试。

## 四、Windows PowerShell 新建 SSH 验证连接示例

从面板复制本节点挑战 UUID 与 token，确认 VPS 状态已显示“本机挑战已准备”。根据实际测试 VPS 替换占位符，且预先通过可信渠道把 VPS 主机公钥加入 known_hosts。

```powershell
$challengeId = "来自面板的五分钟挑战 UUID"
$nonce = "来自面板的一次性 token"
$user = "root" # 改成目标 VPS 登录用户
$hostName = "你的隔离测试 VPS IP 或域名"
$port = 22
$identity = "$HOME\.ssh\id_ed25519"

$nonce | ssh -T -p $port -i $identity `
  -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none `
  -o PreferredAuthentications=publickey `
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no `
  -o ControlMaster=no -o ControlPath=none `
  -o StrictHostKeyChecking=yes `
  "$user@$hostName" "/usr/local/bin/ssh-manager-prove -id $challengeId"
```

CLI 输出“本地证明已排队”不代表 Cloudflare 已验收成功；必须等待面板出现 VERIFIED。

## 五、必须通过的反向用例

- 错误私钥、SSH 主机公钥未知、密码回退和旧连接复用。
- 错误 Linux 用户、另一台 VPS 的 challenge、错误密钥指纹、变更 SSH 配置版本、错误 token、过期挑战。
- 一条不同 SSH 会话的 sshd 日志 / PID、伪造 SSH_CONNECTION、客户端提交假 syslog 或缺失可信 journald 字段。
- 过期签名证明、Root 私钥与绑定公钥不匹配、重放已消费挑战、重复 Cloudflare 上报。
- Agent 被攻破但没有 Root 证明私钥；Root Helper 离线、Cloudflare 暂时不可用与证明过期。
- 最终确认没有写动 `sshd_config`、原有授权密钥，也没有改变密码认证状态。

## 六、实际完成程度

仓库已包含 Go Root proof 签名及一次性消费测试、TypeScript 验签和身份绑定测试、D1/SQLite 状态转移与重放测试、回环 sshd 真实公钥登录集成测试。

**尚未对真实 Ubuntu/Debian/AlmaLinux VPS 和 Cloudflare Staging 完成端到端：新 SSH 会话 → host journald → Root Socket → Root 签名 → Agent 转发 → D1 VERIFIED。** 某些 OpenSSH 版本的认证日志进程 PID 可能不在 shell 的祖先链；不兼容时必须安全失败。

在完成上述实机联调、权限审查、事故恢复演练之前，PR 保持 Draft，绝不解锁 P4 关闭密码登录或任何自动回滚。
