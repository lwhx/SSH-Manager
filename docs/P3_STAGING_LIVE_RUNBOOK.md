# SSH Manager V4.0 — P3.4 真实 Staging 联调 Runbook

> 只适用于专用、可销毁的测试 VPS 与独立 Cloudflare Staging。禁止把这里的步骤直接用于生产 VPS。P4 关闭密码登录、救援公钥、自动回滚和批量操作仍然锁定。

## 0. 本轮完成标准

P3.4 只有在 P3_STAGING_E2E_ACCEPTANCE.md 的 T01–T11 有真实证据后才算完成。任何本地 CI、只读检查或远端 health 探针都不能代替 VERIFIED。

本轮保持以下硬约束：

- Control 与 Agent Gateway 使用不同域名。
- Control 必须由 Cloudflare Access 保护，只允许 GitHub / Cloudflare 两种身份来源。
- Agent Gateway 不使用浏览器 Access；设备仍以自身 Ed25519 身份签名。
- 每次只操作一台明确选中的测试 VPS。
- 日常公钥安装前先做 SSH 有效策略检查；安装完成后立即重新关闭 Helper 的 daily-install 本地开关。
- 真实日常私钥只保留在管理员 Windows 客户端。
- 不改 PasswordAuthentication，不实现或调用任何 P4/P5 功能。

## 1. 固定本轮 Git 提交

Cloudflare Worker、VPS Agent、Root Helper 和 prove CLI 必须来自同一个 Git commit。

在部署机执行：

    git rev-parse HEAD

把该 SHA 记入本轮验收记录。后续 VPS 也必须 checkout 同一 SHA。

## 2. 单 Worker、双域名的 Cloudflare Staging

统一使用一个 ssh-manager-staging Worker，同时绑定两个自定义域名：

- console-staging.example.com：React 管理网页和 /api/*；由 hostname-based Cloudflare Access 保护
- agent-staging.example.com：只提供 /agent/v1/*；Agent 使用自己的 Ed25519 签名认证

Worker 共用一个 D1（ssh-manager-staging）和一个本地 NodeSession Durable Object；不再部署两个 Workers，也不使用跨 Worker Service binding。

    npm install
    npx wrangler login
    npm run cf:quick

首次填写 Control/Agent 域名、Access Team Domain/AUD/Owner，确认 SINGLE-STAGING。脚本创建/复用 Staging D1，运行迁移，生成签名密钥（私钥仅送入 Worker Secret）并部署一个 Worker。

**Cloudflare Access 只能保护管理 hostname，不能配置 Worker-level Access**，否则会拦截 Agent WebSocket。保持 workers_dev=false、preview_urls=false、assets.run_worker_first=true。已有双 Worker 运行实例必须先阅读 docs/MIGRATE_DUAL_TO_SINGLE.md。

## 3. 双域名安全边界

    python scripts/staging_remote_probe.py --staging-only --control-url https://console-staging.example.com --gateway-url https://agent-staging.example.com

通过条件：

- Control 未登录的 /api/v1/health 被 Cloudflare Access 重定向，不能直接公开。
- Agent /agent/v1/health 返回设备签名 JSON。
- Agent /api/v1/health、/ 和 /index.html 只能 404，绝不能泄漏管理 API 或 SPA。
- Control 域名带 Access Session 时也不能访问 /agent/v1/*。
- 未声明域名、workers.dev、preview URL 必须没有可用管理或 Agent 接口。

以上检查未通过，禁止在实际 VPS 上继续验收。

## 4. 准备一台可销毁的 Linux 测试 VPS

必须先确认云厂商 VNC / Serial / Rescue 可用，并保留现有 SSH 会话。

建议 Ubuntu 或 Debian 首轮验证。创建专用服务账户与目录：

    sudo getent group ssh-manager >/dev/null || sudo groupadd --system ssh-manager
    sudo id -u ssh-manager >/dev/null 2>&1 || sudo useradd --system --gid ssh-manager --home-dir /nonexistent --shell /usr/sbin/nologin ssh-manager
    sudo install -d -o root -g ssh-manager -m 0750 /etc/ssh-manager

在同一个 Git SHA 构建三项二进制：

    cd agent
    go build -o /tmp/ssh-manager-agent .
    go build -o /tmp/ssh-manager-helper ./cmd/ssh-manager-helper
    go build -o /tmp/ssh-manager-prove ./cmd/ssh-manager-prove

安装：

    sudo install -o root -g root -m 0755 /tmp/ssh-manager-agent /usr/local/bin/ssh-manager-agent
    sudo install -o root -g root -m 0755 /tmp/ssh-manager-prove /usr/local/bin/ssh-manager-prove
    sudo install -d -o root -g root -m 0755 /usr/local/libexec
    sudo install -o root -g root -m 0755 /tmp/ssh-manager-helper /usr/local/libexec/ssh-manager-helper
    sudo install -o root -g root -m 0644 ssh-manager-agent.service /etc/systemd/system/ssh-manager-agent.service
    sudo install -o root -g root -m 0644 ssh-manager-helper.service /etc/systemd/system/ssh-manager-helper.service

先把 helper.example.json 复制成 /etc/ssh-manager/helper.json，并只填当前这台 VPS 的：

- node_id
- command_public_key
- allowed_user
- client_address
- local_address
- ssh_port
- snapshot_root

初始必须：

- enable_daily_install=false
- enable_ssh_proof=false

配置文件最终要求 root:root 0600。

## 5. 在面板创建单节点并配对 Agent

通过 Control 的 GitHub 或 Cloudflare Access 登录，创建唯一测试节点，记录 node UUID 和十分钟一次性 pairing token。

在 VPS 上配对，token 只走 stdin：

    read -rs TOKEN
    printf '%s\n' "$TOKEN" | sudo /usr/local/bin/ssh-manager-agent -mode pair -gateway https://agent-staging.example.com -node NODE_UUID -token-stdin -config /etc/ssh-manager/agent.json
    unset TOKEN

检查：

    sudo stat -c '%U:%G %a %n' /etc/ssh-manager /etc/ssh-manager/agent.json /etc/ssh-manager/helper.json
    sudo systemctl daemon-reload
    sudo systemctl enable --now ssh-manager-helper.service
    sudo systemctl enable --now ssh-manager-agent.service
    sudo systemctl status --no-pager ssh-manager-helper.service ssh-manager-agent.service

Agent 必须是 ssh-manager 用户，不能以 root 运行。

## 6. 只读准入

把本轮真实客户端 IP、本机监听 IP 和 SSH 端口填入：

    sudo python3 scripts/staging_readiness.py --staging-only --login-user root --node-id NODE_UUID --client-ip CLIENT_IP_SEEN_BY_SSHD --local-ip VPS_LOCAL_IP --ssh-port 22

FAIL 必须全部解决。WARN 不能自动当作通过。

## 7. P3.4 唯一一次日常公钥安装窗口

在面板保存 Staging 日常公钥，然后先执行 SSH policy inspect。

只有 policy inspect 成功、config revision 固定后，才在 VPS 本机把 helper.json 的 enable_daily_install 临时改为 true，并重启 Helper。

在面板对当前这一个节点执行日常公钥安装。确认成功后，立即把 enable_daily_install 改回 false，再重启 Helper。

同时检查：

    sudo stat -c '%U:%G %a %n' /root/.ssh /root/.ssh/authorized_keys

并人工确认既有 authorized_keys 条目没有被覆盖，密码认证配置没有变化。

## 8. 初始化并固定 Root 证明密钥

在 VPS 本机控制台执行：

    sudo /usr/local/libexec/ssh-manager-helper --init-proof-key

把输出的公钥与 SHA256 指纹通过独立控制台人工核对后，只固定到当前 node UUID。

随后在 helper.json 中：

- enable_daily_install=false
- enable_ssh_proof=true

重启 Helper，再运行一次 staging_readiness.py。

## 9. 真实 Windows 新 SSH 会话

在面板创建五分钟 challenge，必须先看到 prepared_at 已写入且状态仍是 PENDING。

Windows PowerShell 使用日常私钥新建连接，禁止密码回退、Agent、连接复用：

    $challengeId = "面板中的 verification UUID"
    $nonce = "面板中的一次性 token"
    $user = "root"
    $hostName = "测试 VPS 主机名或 IP"
    $port = 22
    $identity = "$HOME\.ssh\id_ed25519"
    $nonce | ssh -T -p $port -i $identity -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=yes "$user@$hostName" "/usr/local/bin/ssh-manager-prove -id $challengeId"

本地显示证明已排队仍不等于成功。必须等待 Cloudflare D1 的 challenge 变成 VERIFIED。

## 10. T07 原子状态确认

在面板确认：

- ssh_verifications.status = VERIFIED
- nodes.init_stage = KEY_VERIFIED
- node_keys.verified_at 非空
- audit_logs 中 ssh.verification.proof 的 actor 是签发 challenge 的管理员

需要数据库复核时，只执行 SELECT，不修改 D1。

## 11. 负向与恢复测试

Happy path 完成后，再用新的 challenge 分别验证：

- 错误私钥不能登录。
- 错 token、过期 token、另一个 node 的 proof、错用户、篡改签名全部拒绝。
- Agent 在已持久化 Root 终态之后重启，只允许重发，不重新执行 SSH 修改。
- Root Helper 只有领取记录但没有终态时必须进入人工核查，不能自动执行、不能自动回滚。

每个故障用例都必须使用新的 challenge，不能复用已 VERIFIED 的 token。

## 12. 收尾

最终状态必须保持：

- enable_daily_install=false
- P4 关闭密码登录功能仍不可用
- 救援公钥未对任何节点自动生效
- 无自动回滚
- 原 PasswordAuthentication 状态保持原样
- PR 继续 Draft，直到 T01–T11 全部留有真实验收证据

证据只保存：Git SHA、Worker 部署版本、node UUID、operation/challenge ID、匿名化指纹后缀、时间与脱敏日志。禁止保存私钥、pairing token、challenge token、Cloudflare API Token、Access Cookie 或完整敏感配置。
