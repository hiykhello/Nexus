# sing-box / sing-tun 性能设计提取

状态：源码分析，未运行性能实验。优化收益为机制推断，不能视为 Nexus 已获得的性能。

## 参考快照

日期：2026-10-27。sing-box 本地仓库 `/home/yk/Code/sing-box`，提交 `a6952ccf6907c18e18917fcb763a433e8e36937b`；sing-tun 为对应 Go 模块缓存版本 `v0.9.7-0.20261023115453-611d83b7a57b`。来源与架构分析见[前轮参考记录](sing-box.md)。以下路径分别相对这两个源码根目录。

## 数据路径

| 优化机制 | 源码依据 | 优点与条件 | Nexus 提取方式 |
| --- | --- | --- | --- |
| UDP 入口能力探测 | sing-box `common/listener/listener_udp.go` 的 `loopUDPIn`、`loopUDPInBatch` | 同时满足批处理 handler、批读取器及 OOB 条件才进入批路径 | 以能力契约选择批处理，保留普通数据报与控制消息语义 |
| UDP 出口就绪批量聚合 | 同文件 `loopUDPOut` | 等到首包后收集队列中已有包，不为凑满批次无限等待 | 批量有数量上限和时间预算，避免增加低负载尾延迟 |
| L3 预判与直接包转发 | `adapter/router.go`、`protocol/tun/inbound.go`；sing-tun `flow.go` | 支持包端口的出口可避免 L3→L4→L3 的完整转换 | 按出口能力选择 L3/L4 路径，规则信息不足时回到完整判定 |
| 平台 I/O 独立接口 | sing-tun `stack_go_io.go` | 包突发读取、批量写入、套接字事件与 offload 能力集中管理 | 平台设备层提供可验证能力，协议核心独立于具体系统调用 |
| UDP GSO 合并与失败降级 | `stack_go_io_linux.go` 的 `writePacketBatch` | 仅合并地址、端口、长度等条件兼容的帧；特定不支持错误会禁用对应优化并重试 | 报文边界保留，失败降级必须不丢包、不重复发送 |
| 包头与载荷分段传输 | 同文件的 segments、`transmitFrame`；`stack_go_splice.go` 的向量存储 | 可减少拼接临时缓冲，但不自动意味着完整零拷贝 | 包存储预留头尾空间，评估 scatter/gather，记录实际拷贝次数 |
| 转发路径集成计数与回收 | `stack_go_splice.go` 的 `SpliceOptions`、token 分配与 socket 事件分派 | 加速路径保留读写统计和关闭处理；token 带代次过滤部分过期事件 | 加速契约包含计数、取消、关闭及事件身份，设计代次回绕边界 |

`readBurst` 在所读 Linux 实现中循环执行 `read`，因此“批次处理”不能写成“所有包一次系统调用读入”。`stack_go_splice.go` 的 socket 接管/事件集成也不能仅凭名称认定为 Linux `splice(2)` 零拷贝。

## 调度、并发与唤醒

`stack_go.go` 为平台队列创建引擎；`stack_go_engine.go` 在多引擎时建立局部流表，以消息处理控制操作，减少直接跨线程修改状态的需求。该实现仍存在共享目录和同步设施，不能描述为完全无锁。

引擎处理突发数据时使用字节预算，事件循环兼顾控制消息、包、socket 事件和定时任务。`park` 根据下一定时截止时间和现有工作决定等待，避免为每条流固定频率轮询。

`stack_go_wheel.go` 提供两级时间轮及 overflow 存储，集中组织连接定时器。借鉴点是统一调度和取消，而非照搬槽数、时间精度或声称任意规模下恒定复杂度。

Nexus 应将这些职责接入 Corosio 的执行器、取消与完成模型，先验证单一状态归属和有界处理，再实验多队列；不直接复制 Go 的调度模型，也不另造与 Corosio 竞争读取同一描述符的事件循环。

## 内存与空闲开销

`stack_go_memory.go` 抽象 slab、读缓冲槽位和区域分配；`stack_go_engine.go` 的 `idleTimeout`、`releaseReadBuffers` 在空闲或内存压力下清理批次引用、释放读缓存并回收池资源。

优点是将“高负载复用”和“空闲后释放”同时纳入策略。Nexus 应为池设置容量、缓存时间和压力响应，不让线程数或历史峰值永久决定内存驻留。活跃包、内核发送、异步操作仍引用的存储不能提前归还池。

`goDropCounter` 累积丢弃数，并按时间间隔汇总日志。Nexus 可采用逐事件计数、限频输出，避免拥塞时逐包日志进一步放大负载。

## TCP 与 TLS 优化的边界

`stack_go_engine.go` 的 `updateLoad` 按繁忙比例及流数量决定 ACK 合并；`stack_go_tcp_ack.go`、`stack_go_tcp_cubic.go`、`stack_go_tcp_bbr.go` 将 ACK/丢包恢复和拥塞控制组织成独立实现。

可借鉴“反馈驱动策略与明确状态”，但不能直接移植阈值或依据文件名判断算法实现完整。Nexus 需要在丢包、乱序、RTT 变化及小包请求下验证吞吐与尾延迟，再决定算法和合并策略。

sing-box 的 `common/badtls/read_wait.go` 有 `go1.25 && badlinkname` 条件，且依赖 TLS 内部适配；`common/ktls` 也有平台、版本和场景限制。前轮源码还明确提示部分 kTLS 用法会降低性能。因此不将 TLS 内部访问或 kTLS 设为必然更快的默认路径。

Nexus 自研 TLS 可以从接口设计阶段允许受控的缓冲借用，但需明确密文、明文、记录边界及密钥生命周期；密码依赖遵守[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)的 libcrypto 与 libssl 边界。

## 优先提取项

优先在设计中保留能力探测、普通路径、缓冲所有权、批处理预算、空闲回收和统一计数。多队列、offload、ACK 自适应及平台加速在测量后逐项启用。

详细的跨项目取舍与验收见[Nexus 性能设计](../architecture/performance.md)及[性能验证计划](../planning/performance-validation.md)。本轮没有构建、运行或重新测量 sing-box/sing-tun。

Linux 内核分流与系统部署的进一步分析见[nftables / systemd 专项](sing-box-linux.md)。
