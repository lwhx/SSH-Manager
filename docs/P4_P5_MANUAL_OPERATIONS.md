# SSH Manager V4 — P4/P5 单 VPS 手动 SSH 安全操作

> 开发代码与隔离 CI 已覆盖关键路径，但 P3.4 真实 Cloudflare Staging + VPS 尚未验收。**禁止把本文操作直接用于生产 VPS。** 本文不是上线批准。

## 一、权限、指令与信任边界

操作顺序：

1. Owner 使用经 Cloudflare Access JWT 校验的 GitHub 或 Cloudflare 身份登录，选择唯一 VPS。
2. 输入当前节点完整 UUID、至少 12 字符的操作原因并二次确认；请求带随机 Idempotency-Key。
3. Control 必须设置 MANUAL_SSH_ACTIONS_ENABLED=true，才会针对当前节点签发有效期 45 秒的 Ed25519 指令。此开关默认 false。
4. Agent 验签、核对节点和时效，持久化领取记录，再原样转交 Root Helper。
5. Root Helper 再次验签、核对唯一目标用户、当前 sshd -t/-T -C 修订版本，以及对应的 *本地* enable_* 开关。
6. Root Helper 拒绝没有独立 Root Ed25519 签名私钥的高危操作；成功后对结果的 SHA256、操作 ID、节点、动作、预期版本和执行时间签名。
7. Agent 先持久化回执，重启后只重发，绝不重执行。Gateway 以 Owner 针对本节点固定的 Root 公钥验签，并以一个 D1 batch 事务更新操作、快照/密钥、节点状态及人工审计。
8. Cloudflare 被拒绝或离线时 Root 结果保留在本地；云端不把设备自称成功视为成功。

没有任何 SSH 状态变化会由告警、失败探测、Agent 掉线、定时器或批量菜单触发。

## 二、P4 手动关闭密码登录

前置条件全部必须具备：

- 已通过 P3.4 真实 VPS E2E，测试对象不承载生产应用，服务商 VNC/Serial/Rescue Console 可用。
- 当前节点状态 KEY_VERIFIED，30 分钟内有 Root 可信证明 VERIFIED，证明绑定当前 login_user、当前日常公钥与 config_revision。
- 按单节点实际 IP/端口核对 sshd 策略：公钥认证生效，默认 AuthorizedKeysFile，Match 规则没有让检查路径失效。
- Root Helper enable_password_disable=true，Root 独立签名私钥已固定。其他 enable_* 不因本次操作自动打开。
- 主 sshd_config 第一条有效配置必须是 Include /etc/ssh/sshd_config.d/*.conf；没有该精确 Include 不得自动修改原配置来适配。
- /etc/ssh/sshd_config.d 是 root 控制的不可被普通用户写入的真实目录；SSH Manager 的 00-ssh-manager.conf 不得已被管理员创建或修改。

Root Manager 执行：先以 root-only 的不可覆盖 Manifest 保存初始 sshd_config 哈希、SSH 有效策略版本、禁用后文件 SHA256 和一次性 snapshot_ref；再原子创建自己管理的 drop-in，仅设置 PasswordAuthentication no、KbdInteractiveAuthentication no；验证 sshd -t/-T -C 的真实有效设置均为 no 且公钥仍允许，最后请求 systemd reload ssh/sshd。

如果文件写入后校验或 reload 失败，**不得隐式删除 drop-in 或自动回滚**。返回 MANUAL_REVIEW，管理员必须用服务商控制台和对应快照人工核查。Cloudflare 只能在取得成功 Root 签名回执时进入 PASSWORD_DISABLED，并记录有效配置新 revision 和快照。这个状态不等于新 SSH 连接已再次实测，仍需后续人工验证。

## 三、P5 单 VPS 救援公钥

- Owner 在全局配置中保存救援公钥只会存储公钥，**所有 VPS 均不受影响**。
- 面板选择一台 VPS、输入其 UUID 和原因，才能下发 ssh.rescue.enable。Root Helper enable_rescue 默认 false，需要本机明确打开。
- Root 只追加一条带 ssh-manager-rescue 精确标签的 Ed25519 公钥，不覆盖授权文件已有条目，先留不可覆盖的 root-only 快照。
- 如果该公钥本来就在 authorized_keys 但不是 SSH Manager 自己加的标签，视为 UNMANAGED，不得在云端声称安装成功。
- 救援公钥不会自动设置失效时间或定时撤销。它在手动撤销前持续有效，面板必须提示管理员撤销，不能把云端任务 TTL 误当公钥到期。
- ssh.rescue.revoke 只允许撤销当前 VPS 上实际登记的那一把救援密钥，必须精确匹配 ssh-manager-rescue 行；原有其他公钥和注释保留。先快照后同目录原子替换，拒绝任意文件写入。

## 四、手动恢复密码与快照回滚

ssh.password.restore / ssh.config.rollback 使用同一个经过 Root 管理的原始快照逻辑：

- 只在 PASSWORD_DISABLED 且节点当前 revision 与未使用的 snapshot 记录完全一致时放行。
- Owner 再次输入完整节点 UUID、原因、对应 snapshot_ref。
- Root 读取受限的原始 Manifest；同时匹配 node_id、login_user、主配置文件哈希、SSH Manager drop-in 完整哈希。
- 任一值不一致，拒绝覆盖管理员之后的配置编辑。
- **只移除 SSH Manager 自己创建的 drop-in**，验证原有密码/键盘交互策略恢复，然后 reload。不会改写其他 sshd_config 文件、用户密码、PAM 或 PermitRootLogin。
- 云端验证 Root 签名回执并以同一个 D1 事务记录 restored_at，将节点改为 POLICY_INSPECTED。原 VERIFIED 不再授权再次关闭密码；必须重新进行完整登录验证。

注意：恢复原密码策略 **不保证** Linux 用户拥有可登录密码，也不保证 PermitRootLogin 允许 root 密码登录。控制台仍须保留服务商救援入口。

## 五、危险开关

| 配置位置 | 配置项 | 默认值 |
| --- | --- | --- |
| Control Worker | MANUAL_SSH_ACTIONS_ENABLED | false |
| Root Helper | enable_password_disable | false |
| Root Helper | enable_password_restore | false |
| Root Helper | enable_config_rollback | false |
| Root Helper | enable_rescue | false |
| Root Helper | enable_ssh_proof | false |

实际测试顺序应是 P3.4 全部验收后，先在**单台可销毁 Staging VPS**中开启相应本机操作开关，再为 Staging Control 显式启用 MANUAL_SSH_ACTIONS_ENABLED。测试结束全部恢复 false，不可在生产直接统一开启。

## 六、P4/P5 验收要求

1. 匿名、viewer/admin、错误 Owner 节点确认、缺失原因、过期签名、错节点、错 revision 均被拒绝。
2. 未通过 KEY_VERIFIED 或真实 Root 可信证明不能进入密码禁用。
3. 根目录/配置文件 symlink、未按优先级 Include、冲突的 sshd Match 策略不得修改密码认证。
4. Root 证明私钥缺失或 Helper enable_* 为 false 时不能成功。
5. Agent 伪造 SUCCEEDED、修改 Root 回执、换动作/节点/操作 ID/结果摘要必须拒绝，D1 不变。
6. 快照不存在、已消费、主配置哈希变化、管理片段被人手工修改时回滚必须拒绝。
7. 救援启用只影响选中 VPS；原 authorized_keys 不得丢失；不同 VPS 的救援公钥默认不生效。
8. Root 已执行但 Agent 断网、崩溃或云端 D1/审计写入失败：必须保留人工核查证据、仅重发 Root 终态、不得自动重执行 SSH 写入或回滚。
9. OpenSSH 当前配置修改后新 SSH 公钥登录仍可用，原账号密码策略和管理快照元数据与控制端一致。
10. 仅有独立 Staging 的全链路记录后，才能评估生产支持；没有任何自动解锁开关。

与 P3.4 T01–T11 联调矩阵一同验收，不能以本地 workerd CI 取代真正的 Linux journald + Cloudflare E2E。
