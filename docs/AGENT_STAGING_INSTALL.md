# Staging VPS Agent 安装与配对

> **仅供可销毁的 Debian/Ubuntu systemd 测试 VPS。** 不要直接用于生产 VPS。安装器不会修改 sshd、authorized_keys、密码登录、救援公钥或自动回滚策略。

## 前提条件

- 先在 Cloudflare SSH Manager 面板中创建 VPS，选中节点。
- 测试 VPS 有出站 HTTPS 网络，支持 amd64/arm64；可连接 GitHub 和 Go modules。
- 已安装 curl、tar、Go 1.23 或以上（例如从 https://go.dev/dl/ 安装），以及基本 Linux 用户管理命令。
- 始终保留已有 SSH 会话，以及云服务商 VNC/Serial/Rescue 控制台。

## 管理面板安装入口

进入「VPS 节点」→「添加 VPS」→「基本信息」→「安装 Agent」；已有 WAITING_PAIR 节点则从服务器列表点击「查看详情」→「Agent 管理」。复制命令到该测试 VPS 的终端。命令指向 **管理面板自身所部署的 Git SHA**，避免使用移动的 main 分支造成 Agent/Worker 协议不一致。

安装器执行以下安全流程：

1. 检查支持的系统、Go 版本、systemd 及目标 Node ID/HTTPS Agent 域名。
2. 从 GitHub 下载固定 SHA 的源码，并在 VPS 编译三个二进制。
3. 创建无登录权限的 ssh-manager 系统账户；只安装 Agent 和 inactive Root Helper 的文件及 systemd unit。
4. **安装二进制之后**提示从面板生成最新的 10 分钟一次性令牌（这样不会因编译过程耗时而失效）；token 通过 /dev/tty 静默输入，使用 stdin 传给配对 CLI。
5. Agent 以非 root 用户启动，主动向 Agent Gateway 发送签名心跳与 WSS/HTTPS 连接。

**Agent 初次在线只表示设备通信就绪。** Root Helper 尚未配置和启动，不能据此认定 SSH 公钥已安装或登录已验证。接下来的 Helper 配置、只读预检和可信证明，严格遵循 [真实 Staging 联调 Runbook](P3_STAGING_LIVE_RUNBOOK.md)。

## 排错

~~~bash
sudo systemctl status --no-pager ssh-manager-agent.service
sudo journalctl -u ssh-manager-agent.service -n 80 --no-pager
sudo stat -c '%U:%G %a %n' /etc/ssh-manager/agent.json
~~~

- VPS 仍 WAITING_PAIR：检查新的 token 是否超过 10 分钟；点击面板“重新生成配对令牌”。
- 面板显示 paired 但离线：检查公网出站 443、Agent Gateway hostname、Agent 服务日志和 VPS 时间。
- Agent 已在线但 Root Helper 操作失败：Root Helper **默认不运行**；按 P3 Runbook 配置，不要直接开启 SSH 写入开关。
- 安装器遇到同名文件会拒绝覆盖，避免误重置设备密钥或破坏现有 Agent。
- 若 Cloudflare 已部署新 commit，旧 Agent 的身份配置不会自动更新；升级必须有独立、可验签的升级机制，本安装器不会自动升级或重配现有节点。

## 安全警告

配对令牌不应出现在终端命令行参数、浏览器复制安装命令、日志或 GitHub 仓库中。不要执行来自未知站点的 curl | bash。安装时先下载固定 Git SHA 的脚本，审阅后以 sudo 显式执行。
