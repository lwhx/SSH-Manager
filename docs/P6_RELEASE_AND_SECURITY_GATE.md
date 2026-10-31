# SSH Manager V4 — P6 安全测试、发行与生产准入门槛

> P6 不等于自动开通生产 SSH 写入。此文档给出发布工作流和无法绕过的实机安全门槛。

## 1. 源代码与受信任构建

- 固定单个 Git commit SHA，统一 Cloudflare Worker、Linux Agent、Root Helper、prove CLI 必须统一来源。
- GitHub Actions 的常规 CI 必须通过：Go go test -race ./...、go vet、Root Helper 测试、TS check、Vitest、SQLite migrations、local workerd + D1、隔离 OpenSSH 回环新连接。
- 手动 `workflow_dispatch` 的打包工作流仅生成 Linux amd64/arm64 二进制与 SHA256SUMS，不部署 VPS、Cloudflare 或自动发布生产版本。
- 产物校验通过哈希和可信 GitHub Actions 运行来源，不将 SHA256SUMS 误称为数字签名。正式版本还需要组织批准的签名与可重复构建策略。

## 2. 发行版兼容性矩阵

| 系统 | 前置检查 | 预期 |
| --- | --- | --- |
| Ubuntu LTS（独立测试 VPS） | systemd、OpenSSH、/usr/sbin/sshd、journald trusted syslog/journal、Include 优先级 | 必须完成真实全链路 |
| Debian stable（独立测试 VPS） | 相同条件，验证 ssh.service、journald PID 归属 | 必须完成真实全链路 |
| AlmaLinux/Rocky（独立测试 VPS） | sshd.service、selinux、sshd_config.d、journald PID 归属 | 未验收前标为不兼容 |
| 其他 Linux/容器 | /proc、systemd、sshd -T -C、UID/PID 可信取证、固定路径 | 默认不支持，不允许绕过安全检查 |
| Windows | 仅作为管理员 SSH 客户端，不安装 Linux Agent/Root Helper | 需要真实 PowerShell 端到端验证 |

只接受 Root Helper 真正可核验的 journald trusted _TRANSPORT=syslog/journal、_EXE、_UID、_PID 及 /proc SSH 会话祖先；stdout/stderr 或仅有 auth.log 一律判定不兼容，绝不退化成客户端自报“验证成功”。

## 3. 真实 Staging 发布关卡

- 独立 Control hostname Access、一个 Worker、两个 Custom Domains、同 Worker NodeSession Durable Object、D1、命令签名密钥、DNS；绝不复用生产实例。
- P3.4 T01–T11 完整真实 VPS 记录：通过前不开放任何生产 P4/P5 操作。
- P4 实测：公钥 VERIFIED、手动关闭密码、sshd -T -C、生效后新连接仍可用、手动恢复；失败场景绝不自动回滚。
- P5 实测：单节点救援安装、另一节点不受影响、单节点精准撤销，人工快照回滚，验证故障时 Cloudflare D1 事务原子一致。
- 验证 Agent 和 Root Helper 权限、systemd沙箱、SO_PEERCRED、root 私钥0600、文件安全打开、非 root Agent、失败状态人工核查。
- 渗透/故障注入：错角色、跨节点、重放、过期签名、Root 回执篡改、网络断开、Cloudflare 5xx、Root journaling fsync 失败、D1 audit abort、配置 symlink、用户UID变更。
- 最后由 Owner 人工批准具体节点可执行操作范围；不得一键对所有 VPS 启用密钥或救援。

## 4. 发布方式

先在手动 GitHub Actions 选择 staging build，把 SHA256SUMS 与源码 commit SHA 一起归档，管理员自行校验。

Cloudflare Staging 手动部署参考 docs/P3_STAGING_LIVE_RUNBOOK.md。独立 VPS 安装、手动操作及救援见 docs/P4_P5_MANUAL_OPERATIONS.md。即使所有自动化 CI 为绿色，也不将仓库自动合并 main，更不能自动部署生产节点。

## 5. 尚未通过的真实验收（不能省略）

- Cloudflare 远端 Access/DO/D1 与真实 Linux VPS Agent、journald PID/进程链、Windows 客户端完整闭环。
- P4 的真实 SSH 服务 reload、密码策略变更与二次连接能力。
- P5 的真实 authorized_keys 修改、单节点撤销与手动恢复/回滚。
- Ubuntu/Debian/AlmaLinux 的真实系统差异和中断恢复。

未完成上述验收时，状态是 **功能已写、部署未验、生产未授权**，不是生产可用。
