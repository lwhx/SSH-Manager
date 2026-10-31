# P3.3 隔离 Staging 部署前检查清单

> 本清单只适用于独立测试 VPS。禁止直接运行于生产主机；未经专门验收，不得关闭密码登录、自动回滚或批量激活救援公钥。

## Agent 配对与本机权限

原原型配对文件未保存 helper_socket 和 state_dir，导致配对成功后 Agent 无法使用 Root Helper。现已修复：新配对文件保存固定 Socket 路径 /run/ssh-manager/helper.sock，以及 systemd 持久化目录 /var/lib/ssh-manager-agent。旧文件缺少字段时按相同安全默认值加载。非标准 Socket、相对状态目录、非法 Gateway 及不安全私钥权限均拒绝。

- 隔离 VPS 应先建立无登录权限的 ssh-manager 系统账户。
- 标准配对文件位于 /etc/ssh-manager/agent.json，由 ssh-manager:ssh-manager 持有，权限 0600。
- 配对文件父目录 /etc/ssh-manager 由 root:ssh-manager 持有，权限 0750；该组绝不能拥有目录写权限。
- Root Helper 配置 /etc/ssh-manager/helper.json 继续是 root:root 0600。独立证明私钥保存在 root 私有目录，绝不上传 Agent 或 Cloudflare。
- 在独立 VPS 上以 root 执行标准路径配对，使用 -token-stdin 读取一次性配对令牌。程序在消费令牌之前检查目标文件不存在、Linux 服务账户可用和目录安全性。
- 可以只读检查文件所有权：sudo stat -c '%U:%G %a %n' /etc/ssh-manager /etc/ssh-manager/agent.json /etc/ssh-manager/helper.json
- Agent 的去重收据在 /var/lib/ssh-manager-agent/operations 下，systemd StateDirectory 会为专用服务账户创建目录。

## 隔离 Staging 端到端验收顺序

1. 先确保服务商串行/VNC 控制台和原有 SSH 会话可用，明确这台 VPS 与生产环境完全隔离。
2. 安装三个 Go 程序：SSH Manager Agent、Root Helper、普通用户可执行的 ssh-manager-prove。保持关闭密码登录功能禁用。
3. 只读执行：sudo python3 scripts/staging_proof_preflight.py --staging-only。出现 FAIL 直接阻断；WARN 要人工确认，不能当作验证成功。
4. 在单台 VPS 手动安装日常公钥，使用匹配的私钥建立新的 SSH 连接，确认服务器主机公钥已校验，禁止密码回退及旧连接复用。
5. Root Helper 独立生成证明密钥；Owner 通过 VPS 控制台单独核对并为本节点固定其公钥及 SHA256 指纹。
6. 创建五分钟挑战，等到本机准备完成，再通过加密 SSH 标准输入调用 ssh-manager-prove。
7. Root Helper 必须观察到可信 journald syslog/journal 认证事件、匹配的 SSH 连接和 Linux 进程祖先链。stdout、错误 PID、其他 Linux 用户、错误指纹、过期挑战一律拒绝。
8. Cloudflare 使用 Owner 固定的本机公钥验签，然后在一个 D1 事务里同时更新挑战 VERIFIED、节点 KEY_VERIFIED、日常密钥 verified_at、审计日志。审计 Actor 是签发挑战的实际管理员，不是 Agent 或 challenge UUID。
9. 模拟审计写入失败，确保验证状态、节点阶段、密钥时间和审计结果同时回滚。重复签名证明只允许幂等确认，不得重复执行。
10. 最后检查整个过程中 sshd_config、authorized_keys 的既有条目以及 PasswordAuthentication 均未发生意外变化。

## 当前已完成的 CI 与尚未完成的验收

| 测试项目 | 当前状态 |
| --- | --- |
| 真正的新 SSH 公钥登录、错误私钥失败、校验主机公钥 | 隔离 Ubuntu CI 通过 |
| 新 SSH 会话的 Linux 进程祖先链 | 隔离 Ubuntu CI 通过 |
| Root Ed25519 签名、nonce、防重放、Unix Socket 的内核 UID/PID | Go 测试通过 |
| Agent 配对文件、状态目录、权限及安全路径 | Go 测试覆盖 |
| D1 事务更新、审计归属、故障回滚与重复上报 | SQLite 测试覆盖 |
| 真实 Ubuntu/Debian VPS 的 journald 认证事件 PID 归属 | 尚未实机验收 |
| 真实 Cloudflare Worker/DO/D1 全链路 | 尚未联调 |
| Windows PowerShell 到隔离 VPS 的完整 SSH 证明 | 尚未验收 |
| P4 手动关闭密码登录、救援、公钥撤销、手动回滚 | 尚未开发，继续锁定 |

当前 PR 保持 Draft，主分支不合并，绝不在未经授权的生产 VPS 上执行命令。
