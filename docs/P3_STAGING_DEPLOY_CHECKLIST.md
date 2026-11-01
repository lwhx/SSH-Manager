# P3.3 隔离 Staging 部署前检查清单

> 本清单只适用于独立测试 VPS。禁止直接运行于生产主机；未经专门验收，不得关闭密码登录、自动回滚或批量激活救援公钥。

## Agent 配对与本机权限

早期原型配对文件未保存 helper_socket 和 state_dir，导致配对成功后 Agent 无法使用 Root Helper。现已修复：新配对文件保存固定 Socket 路径 /run/ssh-manager/helper.sock，以及 systemd 持久化目录 /var/lib/ssh-manager-agent。旧文件缺少字段时按相同安全默认值加载。非标准 Socket、相对状态目录、非法 Gateway 及不安全私钥权限均拒绝。

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
4. **先固定 Root 身份，再安装日常公钥**：Root Helper 在隔离 VPS 本机生成独立 Ed25519 证明密钥；Owner 通过服务商控制台独立核对，并在 SSH Manager 为这台 VPS 固定其公钥与 SHA256 指纹。Root 私钥只存放在 VPS 的 root 私有目录，不上传 Agent 或 Cloudflare。缺少固定公钥时，服务端拒绝下发 `ssh.daily.install`。
5. 在当前选中的单台 VPS 手动安装日常公钥。Root Helper 必须先确认能签发结果回执，完成后签名证明密钥指纹、操作 UUID、命令版本及结果；Agent 仅负责转发。随后使用匹配的私钥建立新的 SSH 连接，确认服务器主机公钥已校验，禁止密码回退及旧连接复用。**写入或同步结果不确定时，不得将 FAILED 当作未执行，必须保持单节点操作锁并人工核查。**
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
| **真实本地 workerd + D1**：Agent 设备签名、Root 签名、重放、VERIFIED、审计故障回滚 | **CI 已通过（仅本地）** |
| 真实 Ubuntu/Debian VPS 的 journald 认证事件 PID 归属 | 尚未实机验收 |
| 真实 Cloudflare Worker/DO/D1 全链路 | 尚未联调 |
| Windows PowerShell 到隔离 VPS 的完整 SSH 证明 | 尚未验收 |
| P4 手动关闭密码登录、救援、公钥撤销、手动回滚 | 尚未开发，继续锁定 |

## 本地 Worker + D1 验收复现

在仓库根目录安装 Node.js 与依赖后，只允许使用本地开关运行：

```bash
npm install
node scripts/test_gateway_workerd.mjs --local-only
```

测试脚本通过 Wrangler 临时配置、独立 D1、仅在进程内存在的测试设备/Root Ed25519 私钥，启动监听 127.0.0.1 的真实 Worker。使用数据库故障注入验证事务回滚，然后清理临时状态。不会接触生产 D1 或 VPS。

**尚未覆盖：** 真实 Cloudflare 远端 Worker/DO/D1、不同 Linux 发行版的可信 journald PID 和进程链、Windows PowerShell 完整 SSH 新连接、真实断电和云端超时恢复。未完成这些验收不得开放 P4。

当前 PR 保持 Draft，主分支不合并，绝不在未经授权的生产 VPS 上执行命令。
