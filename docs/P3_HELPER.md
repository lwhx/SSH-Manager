# P3.1 Linux Root Helper 运行与隔离测试指南

**当前是开发版本。禁止直接使用生产 VPS 验收。**

## 组件职责

1. Cloudflare 控制端以 Ed25519 私钥签名指令。
2. 非特权 Agent 仅通过 WSS/HTTPS 接收指令，再将原始签名指令传给本机 Unix Socket。
3. Root Helper 通过 SO_PEERCRED 检查本机进程 UID，重新校验签名、节点 ID、有效期、用户及配置版本。
4. Helper 通过固定路径运行 sshd -t 和 sshd -T -C，对指定来源 IP 的规则进行只读检查。
5. Helper 仅允许 ssh.policy.inspect；安装日常密钥的 ssh.daily.install 默认被 enable_daily_install=false 禁止。
6. 任何时候都不会自动关闭或恢复密码认证、添加救援公钥，也不执行任意 Shell 命令。

## 隔离测试 VPS 的配置约束

- 仅支持 Linux 与 systemd，默认 OpenSSH 可执行路径 /usr/sbin/sshd。
- Agent 独立服务用户 ssh-manager，Root Helper 独立 systemd 服务。
- Agent 配置文件 /etc/ssh-manager/agent.json 推荐 root:ssh-manager、权限 0640。
- Helper 配置 /etc/ssh-manager/helper.json **必须** root:root、权限 0600。
- Helper Socket 路径为 /run/ssh-manager/helper.sock，只允许 ssh-manager 用户通过 SO_PEERCRED 检查。
- Root Helper 操作记录位于 /var/lib/ssh-manager-root/operations，Agent 操作记录位于 /var/lib/ssh-manager-agent/operations，目录必须分离。
- Helper 配置需填入正确节点 UUID、命令签名公钥、唯一允许操作的 Linux 用户、客户端来源 IP、VPS 本地 IP、SSH 端口。
- 快照目录仅允许 /var/lib/ssh-manager-root/snapshots/ 下的私有路径。
- Agent 配置显式增加 helper_socket 为 /run/ssh-manager/helper.sock。
- 首次配置始终保持 enable_daily_install=false。

## 手动操作顺序

1. 先在隔离 VPS 上部署 Root Helper，检查 systemd 服务状态、Socket 权限和 SSH 只读检查。
2. 进入指定 VPS 的 Web 页面，点击检查 SSH 实际生效配置（Helper）。该操作只读取配置，不改变登录方式。
3. 检查面板返回的有效配置 revision，确认公钥认证允许、AuthorizedKeysFile 路径符合保守约束。
4. 只有在隔离测试 VPS 上，拥有独立救援控制台并完成权限审查后，才可由本机管理员显式开启日常公钥安装权限。
5. 安装后验证新增公钥存在、原有 authorized_keys 未丢失、快照存在，密码认证状态未改变。
6. **不能在此阶段关闭密码登录**。仍需要 P3.3 服务器可信新建 SSH 连接认证验证。

## 必须拒绝的输入

- 未签名或签名篡改的指令；非本机节点；过期命令；重复命令。
- 错误的 Linux 用户、错误公钥指纹、错误配置版本。
- sshd 语法无效、有效配置不支持公钥认证。
- 非默认 AuthorizedKeysFile、额外认证条件、不允许的 root SSH 策略。
- 用户家目录路径含不安全目录或符号链接；authorized_keys 所有权或权限不安全。
- Helper 未安装、配置异常、执行时不是 root、Unix peer UID 不匹配。

## 测试

在 agent 目录执行 go test -race ./... 、go vet ./... 和 go build ./cmd/ssh-manager-helper。以上仅证明代码级行为；真实发行版兼容性、SELinux、VPS 主机网络和 SSH 登录仍需要独立实机验收。
