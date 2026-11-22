# Hy2 Brutal 控制器候选

此目录保存固定 ngtcp2 1.25.0 的实验源码和验证夹具。后续生产接线及当前验收状态以 [接续记录](../../docs/development/continuation-2026-11-11.md) 为准；本 README 的历史结果不等于当前生产图验证。参照本地 sing-quic `7e0a5869` 的 `hysteria/congestion/{brutal,pacer}.go`：5 个按秒取模的采样槽、少于 50 个样本不补偿、ACK 比率最低 0.8、2×速率×平滑 RTT 的窗口、令牌桶（至少 10 包或 4 ms 速率的突发，最小 1 ms 等待）。实验有意用整数和饱和运算，窗口至少一包；极端数值/浮点取整与参考实现不保证逐位相同。

`controller.h` 为定长核心；`controller_test.c` 独立验证阈值、失效、限幅、窗口、突发、等待和溢出。`ngtcp2-candidate.patch` **基于先应用项目 `pmtud-restart.patch` 的 1.25.0**，增加内部 union 中的控制器、ACK/loss/RTT 和 native 计时器路径；其副本保存在 `target/continuation-20261111/hy2-brutal-native/`。`native_probe.c` 使用构造的内部连接直接触发回调和计时器，仅用于确认候选接线，不能证明真实 QUIC 包、可靠性或吞吐。候选在当前固定 Linux 构建下编译，内部结构总大小及 CC、算法、server 四个值与原版一致；这不是完整 ABI 或可移植性证明。`hy2-brutal-*` 日志保存验证。

继续前需：

1. 构建隔离的完整候选图并用真实连接对照固定对端，确保不是仅替换单个 object 后使用不一致结构；加入启动后、认证成功后与活动 I/O 生命周期的安装和关闭顺序。
2. 在真实 ACK、丢包、重传、超时、拥塞及 PMTU 变化下确认窗口、样本、实际发送速率和突发，特别是 ACK-only 和本地 `EMSGSIZE` 的计费；比较参考 pacing，在多流及 QUIC DATAGRAM 下验证背压。
3. 继续验证切回正常控制器、路径重置、速度改变、极端时间与速率值；评估发送后回调与活动 packet ownership、异步事件唤醒及连接重试。候选新增原算法恢复入口，`cc_algo` 保留原算法以便恢复；不能用于生产。
4. 才将固定速率、客户端/服务端协商、配置范围及禁用补偿传到真实控制器，重新核验锁、补丁来源与关闭图；验证公平性、持续拥塞与资源限制。生产不允许仅加 socket 限速冒充 Brutal。

窄检查示例：`gcc -std=c17 -Wall -Wextra -Werror -fsanitize=undefined experiments/hy2-brutal/controller_test.c -o /tmp/nexus-brutal-test && /tmp/nexus-brutal-test`。native 检查需要固定版生成的 `config.h` 和候选源码，见 `docs/development/continuation-2026-11-11.md`；不要覆盖共享的 mcpp 源缓存。

## 真实连接验证（2026-11-12）

候选已在单独的 `target/continuation-20261111/hy2-brutal-workspace` 中作为独立 mcpp 源变体构建；不是替换一个现有 object。该副本的 `src/mcpp.toml` 同时引用原 PMTU 补丁和本候选补丁，原仓库的锁文件、依赖及代码均未切换。`fixture.patch` 在测试夹具的认证后、下次发送前安装控制器并输出内部指标；它还只为实验将期限扩为 25 秒。图生成后的 Ninja 目标 `bin/hy2-application-fixture` 构建成功，日志 `hy2-brutal-candidate-target-build{,-v2}.log`；第一次整个图主动中断，不能算完整图验收。候选补丁含测试统计入口，不能直接作为生产 ABI。

`network.py` 对同一候选的实际 TLS/HTTP3/Hy2 双端连接传输双向各 1 MiB 与 FIN，核验接收内容和 ACK/loss 统计。无丢包时 500 kB/s 约 2.13 秒、2 MB/s 约 0.53 秒（epoll/IPv4）；中继丢弃一定比例的短头 UDP 包时，epoll/IPv4 与 uring/IPv6 均完成，native 报告真实丢包并增加补偿率。每 4 个短头包丢 1 个的 IPv4 试验在原 8 秒夹具期限失败；扩到 25 秒后约 8.22 秒完成，双方 625 kB/s 命中补偿上限。它是刻意的中继丢包，不代表标准网络丢包模型或吞吐保证。单独 syscall 跟踪确认对应后端（`hy2-brutal-net-{epoll,uring}-syscalls.strace`）。

固定 sing-box 服务端使用现有夹具的目标端等待上传结束再回送（`singbox-fixture.patch`）；候选客户端 TCP 与 FIN 验证 `hy2-brutal-singbox-client-v3.log` 通过。原并行双向夹具 `hy2-brutal-singbox-epoll-v1.log` 失败、未启用控制器的对照通过；对端服务端的流包装没有 `CloseWrite`，sing-box 目标先 FIN 时会关闭流并取消读取。此限制不能解释成候选完整互通或自动排除其他缺陷。独立固定 quic-go 客户端实际发 FIN 的四种 pre-auth 场景作为服务端验证通过 `hy2-brutal-preauth-v1.json`，但不能代替 sing-box 客户端半关闭证据。测试二进制与对端摘要记录在 `hy2-brutal-fixture-sha256-v2.txt`。

下一步仍应接入正式协商，测试 DATAGRAM、真实 MTU 故障与更复杂 backpressure，以及公平性和拥塞资源；不能将这一候选发布或报告为完成。

## 运行中更新与恢复（2026-11-12）

候选新增仅在前一个 UDP 发送完成、没有未决 native 输出时可调用的速率更新和恢复入口；更新时间不能早于 native 已处理时间。更新保留已积累额度及采样历史，恢复按最初的 Reno/Cubic/BBR 初始化窗口与算法，保留在途字节和重传账本，不清空 RTB。它仍是实验接口，调用者必须保证 quiescent 边界和重新唤醒写入/计时任务。单位测试覆盖参数、额度、采样和截止时间；native 内部探针直接核对三个算法的恢复回调、未决输出拒绝和在途字节保持，分别见 `hy2-brutal-reconfigure-unit-v2.log`、`hy2-brutal-switch-native-probe-v3.log`。

`network.py --switch --delay-ms 15` 在真实连接的双方累计发出约 256 KiB 后将 500 kB/s 更新到 2 MB/s，在约 768 KiB 后恢复原 CC；两个操作都由同一 executor 的下次输出执行，并在操作前后直接检查 native bytes-in-flight 相同。epoll/IPv4 与 uring/IPv6 的双向各 1 MiB/FIN、带受控丢包通过；切换时均观察到在途数据，日志 `hy2-brutal-switch-{flight-epoll-v2,flight-uring-v1,loss-epoll-v1,loss-uring-v1}.log`。另外测试恢复 Reno（epoll/IPv4）和 BBR（uring/IPv6）下的延迟与丢包，`hy2-brutal-switch-{reno-epoll-v1,bbr-uring-v1}.log` 通过；其他组合、真实迁移、未决 I/O 竞态、连续切换及长期公平性尚未验收。最新夹具、补丁摘要为 `hy2-brutal-switch-sha256-v2.txt`；之前 SHA 对应旧二进制，不能当作新源码证据。
