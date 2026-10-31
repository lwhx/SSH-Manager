# SSH Manager：双 Worker → 单 Worker 人工迁移

**重要：已有双 Worker 实例不会自动安全迁移。** 新架构的一个 Worker 有自己的 NodeSession Durable Object 命名空间；类名相同不等于把旧 Gateway Worker 的 DO 数据与连接迁入新 Worker。

旧版：Control Worker + Agent Gateway Worker，后者持有 DO，Control 通过跨 Worker binding 使用它。

新版：ssh-manager-staging 单 Worker，两个精确自定义域名、一个 D1、一个本地 NodeSession DO binding。

## 迁移要求

1. 固定旧 Git SHA、两个 Worker 的部署版本、D1 UUID、Access AUD、命令签名公钥与各 VPS Root 证明公钥；备份 D1、审计与必要的恢复信息。
2. 云端与各 VPS Root Helper 危险写入开关保持关闭。保留云厂商 Console/Rescue。
3. 排空或人工核查所有未完成操作、回执队列、DLQ、RESULT_UNKNOWN 和挑战；不能重新执行未知结果的 SSH 修改。
4. **优先新建完全独立的 Staging D1 和两个测试域名**，验收新 Worker 的 Access、路由隔离、DO、Agent WSS/HTTPS 重连与 Windows 新 SSH 会话证明。
5. 若要沿用旧 D1/签名密钥，必须人工规划数据与密钥连续性、旧 DO 的影响，不允许仅凭同名 D1 自动复用并宣称迁移成功。
6. 在可销毁的测试 VPS 上切换 Agent gateway URL 并验收，明确没有丢失的操作/签名挑战后，才可评估正式 VPS 切换。
7. 旧 Worker 不可在存在旧 Agent 连接或未确认回执时删除。退役应在所有对应节点复核后进行。

新 npm run cf:quick 检测到旧本地配置或旧 staging 状态时直接停止。需要管理员明确迁移，而不是删除状态文件强行重生成密钥。

**禁止** SSH 失败自动恢复、批量救援公钥、未验证密钥登录就关闭密码认证、覆盖其他管理员修改的 sshd 配置。
