# 第 96 批实现蓝图 · 下一代性能引擎

更新：2026-11-20。承接第 90 批同机性能基线（常规复制 CPU 373.3/346.7 ms/GiB、Splice 73.3/80.0 ms/GiB）以及自研 TUN 栈源码审计，规划高收益性能切片。

## 96A · TCP 转发与 Splice 快路径重构

### 1. 常规用户态复制路径（目标：`373 → ~100–130 ms/GiB`）
基于 `src/proxy/session.cpp#L146-L170` 与 `src/net/stream_relay.cppm#L45-L113` 的热点定位：
1. **消除每 16 KiB `write_all` 子协程分配**：改造 `DirectRelayAdapter` 直接走 `socket_output = true`（内联 `co_await destination().write_some(...)`），立即省去每 GiB 65,536 次 `capy::task<bool>` 协程帧堆分配与调度。
2. **两档自适应缓冲池**：
   - 初始短流保持 8–16 KiB 栈/小缓冲（保住 2,048 并发时 ~16 MiB 低 RSS）；
   - 同一方向连续满读超过 64 KiB 后，从 per-worker 缓冲池租借 **64–128 KiB** 缓冲（上限受内存预算控制），空闲或流关闭时归还。
3. **非阻塞 fast-path 批处理 + 批量记账**：
   - 就绪后尝试非阻塞 `::recv`/`::send` 连续批循环（burst 上限 256–512 KiB），仅在 `EAGAIN` 时才 `co_await` 挂起；
   - `session.touched = Clock::now()` 与 `session.count_traffic(...)` 移出单次 chunk 循环，在 burst 结束或遇 `EAGAIN` 时批量更新一次（将每 GiB 13 万次时钟与统计更新压降 50 倍以上）。

### 2. Splice 零拷贝快路径（目标：`73–80 → ~40–50 ms/GiB`）
基于 `src/proxy/session_splice.cpp#L71-L129` 的热点定位：
1. **独立读写等待槽消除背压退化**：在 Corosio（或 Linux socket 轻量就绪适配层）拆分独立的 `wait_read` 与 `wait_write` 槽位（`epoll` 同 fd 分派 `EPOLLIN`/`EPOLLOUT`，`io_uring` 发独立 `IORING_OP_POLL_ADD(POLLOUT)`）。输出 `EAGAIN` 时直接 `co_await output.wait_write()` 继续纯内核 `splice`，`drain_splice_pipe` 仅用于 `EINVAL/ENOSYS` 不可用兜底。
2. **零定时器公平让出**：删去 `co_await io::delay(20us)`（每 GiB 1,024 次定时器），改为仅在 executor 就绪队列非空时 `post` 一次无定时器让出，顺带消除 splice 下的 TCP 接入 P95 抬升。
3. **Per-worker 256 KiB Pipe 池 + 热流自动晋升**：
   - 将 `splice_pipes` 从纯计数信号量升级为真正的 per-worker pipe fd 缓存池（带空闲定时回收，保住空闲 FD 不涨）；
   - 创建 pipe 时调用 `fcntl(fd, F_SETPIPE_SZ, 256 * 1024)`，单次 `chunk` 升至 256 KiB（`splice` syscall 次数降 75%）；
   - 常规直连流单向累计超过阈值（如 256 KiB）后自动尝试租 pipe 晋升至零拷贝，小短流不占 pipe FD。

## 96B · Linux kTLS 零拷贝（TLS 1.3 加密流卸载）

严格遵循 [ktls.md](../architecture/ktls.md) 安全不变量：
1. **交接前条件**：自研 TLS 1.3 握手完成、校验通过、用户态记录层无残留未读/未写字节、提取精确的 TX/RX 密钥、IV、cipher（AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305）与下一条记录序列号。
2. **内核设置与分方向回退**：`setsockopt(SOL_TCP, TCP_ULP, "tls")` + `SOL_TLS` `TLS_TX` / `TLS_RX` 分开启用；前置探测失败无副作用回退用户态 TLS；单方向半成功时明确追踪每方向所有权，绝不复用旧密钥/nonce。
3. **控制消息与 KeyUpdate**：接收端使用 `recvmsg` 读取 `TLS_GET_RECORD_TYPE` 控制消息，正确处理 `alert`、`close_notify` 与 TLS 1.3 `KeyUpdate` 密钥轮换；与 `splice` 协同仅在已验证可安全交付控制消息的流方向启用。
4. **独立构建特性 `ktls`**：关闭图零影响；针对真实 TLS 对端验证 KeyUpdate、alert、半关闭、慢读者与加密长流 CPU 对比。

## 96C · io_uring 下一代 I/O 机制

针对 `io_uring` 后端探索并验证：
1. **Provided Buffer Ring（`io_uring_register_buf_ring`）**：per-worker 固定内存池注册给内核，减少用户态读缓冲预分配与提交准备开销。
2. **Multishot Recv（`IORING_OP_RECV` + `IOSQE_BUFFER_SELECT` + `IORING_RECV_MULTISHOT`）**：在短流高并发与 UDP/DNS 接收路径降低 `io_uring_enter` 提交频率；注意正确处理 `IORING_CQE_F_MORE` 标志失效重挂与 `ENOBUFS` 背压回退，严格受既有内存预算约束。

## 96D · 自研 TUN 栈性能与协议升级

基于 `src/tcp/{send,table}.cpp`、`src/packet/fd.cpp` 与 `src/tools/tun_host.cpp` 审计结果：

| 阶段 | 改造项 | 解决的问题 |
| --- | --- | --- |
| **P0** | `SendBuffer` / 接收队列替换为 `containers::ByteRing` | 消灭 `std::deque<uint8_t>` 逐字节 `pop_front()` 与发送切片 `std::vector` 拷贝 |
| **P0** | 协商 **TCP Window Scale（RFC 7323）**，放开 `table.cpp` 65535 窗口硬上限（支持 256 KiB–4 MiB，受内存预算约束） | 解除单流 64 KiB 窗口天花板（50ms RTT 下单流突破 10 Mbps 锁死） |
| **P0** | `ConnectionTable` / `ConnectionTable6` 与 UDP 流表由 `std::list`/`std::vector` 线性扫描升级为**哈希索引（四元组 + ConnectionId）** | 消除千流并发时的 $O(N^2)$ 查表退化 |
| **P0** | 补 **SRTT/RTTVAR 动态 RTO 估计 + 3-DupACK 快速重传** | 消除弱网/背压丢单包硬等 1000ms 超时 |
| **P1** | `FdPump` / `MemorySwitch` 改为批量包收发（32–64 包/轮）+ 接入 Linux TUN **`IFF_VNET_HDR`（GSO/GRO）** 与 **`IFF_MULTI_QUEUE`** | 单次 TUN syscall 搬运 64 KiB 大聚合 TCP 段，将 TUN 吞吐推向多 Gbit/s |
| **P2** | 补 **TCP SACK（RFC 2018）**、**TCP Timestamps**、基础拥塞控制（NewReno/CUBIC），接入 **ICMP Echo 转发** 与 **动态 PMTU（ICMP PTB）** | 补齐真实复杂网络下的丢包恢复与 ping/MTU 完整度 |

## 96E · 大容量缓存淘汰算法升级（`CLOCK` / `S3-FIFO` 与侵入式下标链表）

针对 DNS 地址/消息/响应缓存及未来大容量规则/状态缓存从 256 槽向数千–数万条扩展的需求，拒绝传统 `std::unordered_map + std::list`（节点堆分配碎、读命中改指针伤并发）：
1. **并发读多写少缓存（共享 DNS 地址缓存）**：引入 **`CLOCK`（Second-Chance）或 `S3-FIFO`**——平坦定长槽位数组 + 每槽 1 字节 `std::atomic<std::uint8_t>` 访问位，读命中仅在 `0 → 1` 时写一次（热点已为 1 时零写、不脏缓存行），在保持无锁读的同时抗单次扫描污染，消除全表线性找最早过期的 $O(N)$ 开销。
2. **单执行器独占缓存（`MessageCache` / `ResponseCache`）**：在扩容至千级以上时，采用**连续数组 + 侵入式 `uint32_t` 下标双向链表 + 平坦哈希索引**，实现零节点堆分配的 $O(1)$ 查找、淘汰与 TTL/字节双上限管理；磁盘缓存 `lookup()` 依然保持只读，不因命中触发同步落盘。

