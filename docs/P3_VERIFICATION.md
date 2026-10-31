# P3.3 — 日常 SSH 密钥真实登录验证：状态与安全边界

**当前仅实现挑战签发、查询和撤销；尚不具备服务器可信认证证明。绝不能据此解锁关闭密码登录。**

## 安全目标

只在真实观察到指定 VPS、指定 Linux 用户和指定日常 SSH 公钥完成全新公钥认证时，才允许把验证标记为成功。

每个挑战绑定以下信息：

- node_id：当前手动选择的 VPS；不得跨节点使用
- public_key_id / SHA256 指纹：当前有效日常公钥
- login_user：节点绑定的 Linux 登录用户
- config_revision：本机 Root Helper 检查的 SSH 生效配置版本，必须与安装日常公钥时一致
- nonce：256 位一次性随机挑战，D1 仅保存 SHA-256 哈希，明文仅首次返回浏览器
- expires_at：签发 300 秒后过期；一个 VPS 同时只允许一个 PENDING 挑战

## 当前已经实现的管理 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | /api/v1/nodes/{node_id}/ssh-verification/start | 检查 Agent 在线、安装记录、公钥版本、Linux 用户和配置版本，签发一次性挑战 |
| GET | /api/v1/nodes/{node_id}/ssh-verification/{verification_id} | 仅返回挑战的非机密状态，不泄漏原始 token 或存储的 nonce_hash |
| POST | /api/v1/nodes/{node_id}/ssh-verification/{verification_id}/cancel | 管理员撤销本节点待验证挑战 |

当前可能返回 PENDING、CANCELLED、EXPIRED、INVALIDATED。没有任何客户端、Agent 或管理员 API 可以将其直接变为 VERIFIED。

当全局日常密钥更新、目标节点重新安装日常公钥、SSH 生效配置版本改变时，正在等待的挑战失效。

## 可信 SSH 登录验证：待实现的严格条件

1. 本地 SSH 客户端使用日常私钥建立**新连接**，明确使用公钥认证，禁止密码/keyboard-interactive 回退与旧连接复用。
2. **不得关闭 SSH 主机公钥校验**；用户需正确核验目标 VPS 的 host key。
3. 验证依据必须来自服务器侧 sshd 实际完成的认证事件（用户、指纹、方法、连接时间与端点），不能仅根据客户端声称登录成功。
4. 可评估 OpenSSH ExposeAuthInfo，但单独相信用户提供的 SSH_USER_AUTH 路径或文件内容**不安全**；需验证真实会话来源和可信进程/sshd 认证证据。
5. 服务器 Root Helper 将可信证据绑定 challenge ID、nonce、节点 ID、用户、公钥指纹和配置版本，经过严格认证后一次性提交 Cloudflare。
6. Cloudflare 只能接受通过受信任 Helper 和服务器可信来源验证的证明；过期、重复、错误来源和错误用户一律拒绝。
7. 所有关键步骤需经过实际 Linux、Windows SSH 客户端和 Cloudflare Staging 测试，才能开发 VERIFIED 状态转移。

**本次未实现上述第 3–7 步，P4 手动关闭密码登录保持锁定。**

## P3.2 已有独立测试

GitHub Actions 的 Isolated SSH integration 工作流在临时 Ubuntu Runner 上安装 openssh-server、启动仅监听 127.0.0.1 的 sshd，并实际测试：

- 未安装公钥前无法登录
- 安装后使用匹配 ED25519 私钥成功 SSH 登录
- 错误私钥被拒绝
- SSH 密码认证配置仍为原值（未修改）

该测试证明了基础 SSH 文件变更及登录行为，不等于真实 VPS 网络、root 用户、Cloudflare Access 或服务器可信验证链已验收。

## 不变原则

救援公钥只在平台保存，不会因为日常公钥安装或验证挑战而全局生效；任何救援或 SSH 配置回滚仍必须针对指定 VPS、由管理员手动触发，且绝不自动回滚。
