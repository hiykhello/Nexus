# Nexus Core 硬上限解除与高性能重构方案

本文档对应内核规模化演进专项：在**零性能回退、零热路径额外堆分配**的前提下，系统性解除 Nexus Core 中全部人为业务与运行时硬上限，以高性能数据结构（平铺开放寻址哈希、动态 Slab + 侵入式 LRU、零拷贝 mmap、透明 `string_view` 索引）替代固定小数组与线性扫描；同时明确划定必须保留的 RFC 线规、OS ABI 与反 DoS 安全边界。

---

## 1. 并行实施矩阵（4 条无交集轨道）

为支持 4 名工程执行者在不冲突文件集合上并行推进，全部改造按目录与模块职责划分为 4 条严格无交集轨道：

| 轨道 | 核心目标 | 独占修改文件范围 | 高性能目标结构 |
| --- | --- | --- | --- |
| **Track 1** | 出站、策略组、多用户入站与配置上限 | `src/config/*`、`src/relay/*_api.cpp`、`src/relay/relay.cpp`、`src/relay/mesh_outbound.cpp`、`src/relay/mux_*.cpp`、`src/relay/session_splice_*.cpp`、`src/provider/workspace_emit.cpp`、`src/tailscale/packet_filter.{cppm,cpp}` | `uint32_t` 索引 + 动态 `std::vector` + O(1) 透明 `string_view` 平铺哈希 / 有序表 |
| **Track 2** | 规则引擎与零拷贝 NXMM 规模上限 | `src/rules/rules.cppm`、`src/rules/mmap_ruleset.cpp`、`src/rules/matcher_eval.cpp`、`src/rules/program.cpp`、`src/rules/convert_*.cpp`、`src/rules/srs_*.cppm`、`src/tools/route_files.cpp`、`src/relay/routing_context.cpp` | 高默认/可配零拷贝 mmap 预算（默认 4M 规则 / 256 MiB）+ 无界零分配视图遍历 |
| **Track 3** | UDP 流表与数据面槽位硬上限 | `src/relay/session_udp_types.cppm`、`src/relay/session_udp_alias_tunnel.cppm`、`src/relay/session_udp_tunnel.cpp`、`src/relay/tproxy_udp.cpp`、`src/net/stream_datagrams.cppm` | 动态 Slab 池 + 侵入式双向 LRU + 平铺开放寻址哈希 + 可配软上限（默认 `4096`） |
| **Track 4** | DNS、系统网络状态、FakeIP WAL 与 Tailscale 队列 | `src/dns/cache.cpp`、`src/dns/cache_snapshot.cppm`、`src/dns/quic_query_runtime.cppm`、`src/platform/network_state.cpp`、`src/state/fakeip_disk.cppm`、`src/state/fakeip_wal.cpp`、`src/tailscale/multi_worker.cppm` | 可配高水位池 + O(1) 哈希索引 + 随池规模缩放的 WAL/队列预算 |

---

## 2. Track 1 — 出站、策略组、多用户入站与配置上限

### 2.1 出站与策略组 `256` 数量上限解除

- **现状瓶颈**：`src/relay/relay.cpp`（`outbounds.size() >= 256`）、`src/relay/*_api.cpp`、`src/relay/mesh_outbound.cpp`、`src/config/providers.cpp` 及 `src/config/config_types*` 使用人为 `256` 上限或窄整型索引，且多处按标签线性扫描查找出站与策略组。
- **高性能改造**：
  - 将出站与策略组索引统一升级为 `std::uint32_t` + 动态 `std::vector`，移除 `256` 人为上限（仅保留防止畸形输入的合理高安全护栏，如 `65535` 或受内存预算约束）。
  - 在配置装载与运行时路由表构建期建立 O(1) 透明 `string_view` 哈希索引（`tag -> uint32_t index`），彻底消除热路径和重载路径上的 O(N) 标签线性扫描。

### 2.2 多用户入站 `32` / `64` 上限解除

- **现状瓶颈**：`src/config/inbound.cpp`、`src/config/protocols_ext_inbounds.cpp` 与中继入站认证器对多用户账号硬编码 `32` / `64` 人为上限，大租户或订阅分发场景受阻。
- **高性能改造**：
  - 移除 `32` / `64` 人为上限，改用动态容器存储用户表。
  - 构建只读平铺哈希表或透明 `string_view`（及定长密钥字节视图）O(1) 认证索引，确保单包/单连接认证路径**零堆分配、常数时间查找**，并维持定长敏感字段的常量时间比对语义。

### 2.3 人为配置条目上限批量解除

| 配置项 | 原上限 | 涉及模块 | 目标设计 |
| --- | --- | --- | --- |
| `http-clients` | `16` | `src/config/http_clients.cpp` | 动态列表 + O(1) 具名索引 |
| 自定义 `headers` | `16` | `src/config/http_clients.cpp` / 传输配置 | 动态数组，保留总字节反 DoS 护栏 |
| `use_providers` | `64` | `src/config/groups.cpp` | 动态去重集合（O(1) 去重） |
| 策略组 `arguments` / `concurrency` | `16` | `src/config/groups.cpp` | 解除 `16` 限制，受 CPU/合理安全上限约束 |
| 订阅 `include/exclude-regex` / `tag-prefix` | `256` / `32` | `src/config/providers.cpp` | 动态规则列表 + 预编译正则缓存 |
| `cors-allow-origin` | `32` | `src/config/` / `src/control_api/http_server.cpp` | 动态数组/集合，保留精确匹配与通配匹配语义 |
| `mux max-connections` | `64` | `src/config/mux.cpp`、`src/relay/mux_outbound.cpp`、`src/provider/workspace_emit.cpp` | 移除 `64` 硬顶，支持高并发连接池配置 |
| `tcp-splice-pipes` | `256` | `src/config/reload.cpp`、`src/relay/session_splice_linux.cpp` | 提升/按需动态扩展管道池容量 |
| WebSocket 批处理条目 | `16` | `src/control_api/http_ws.cppm` | 动态批量拉取/写出（配合单帧字节预算） |
| Tailscale `advertise-routes` | `64` | `src/config/`、`src/tailscale/` | 动态前缀列表，零固定 64 上限 |
| Tailscale ACL `packet_filter` | `inplace_vector<Raw, 512>` | `src/tailscale/packet_filter.{cppm,cpp}` | 迁移至动态 `std::vector` + 排序平铺表（支持 >512 条规则与二分/前缀匹配） |

---

## 3. Track 2 — 规则引擎与零拷贝 NXMM 规模扩展

### 3.1 规则条目数与输入字节上限提升

- **现状瓶颈**：`src/rules/rules.cppm` 硬编码 `max_rules = 262144` 与 `max_input_bytes = 33554432`（32 MiB），在 `src/rules/mmap_ruleset.cpp`、`src/tools/route_files.cpp`、`src/relay/routing_context.cpp`、`src/rules/convert_*.cpp` 与 `src/rules/srs_*.cppm` 拦截大型全球 IP/域名规则集。
- **高性能改造**：
  - 将默认上限提升至高规模水平（默认 `4,000,000` 条规则与 `256 MiB` 零拷贝 mmap 预算），并支持按配置显式覆写预算上限。
  - 全链路维持 NXMM 零拷贝 `mmap` 映射与二进制索引二分/基数查表，不因规则规模扩大而引入整文件内存拷贝。
  - **严格保留防 DoS 护栏**：保留 `max_rule_depth = 32`、JSON 嵌套深度 `64`、正则状态机/步数上限与 SRS 解压炸弹膨胀比检查。

### 3.2 查询上下文 `64` / `256` 截断消除

- **现状瓶颈**：`src/rules/matcher_eval.cpp:126-140` 与 `src/rules/program.cpp:12` 对查询上下文中可评估条目数设置了 `64` / `256` 硬截断。
- **高性能改造**：改为基于 `std::span` / 索引范围的动态遍历，完整评估全部上下文条目，且热路径保持**零额外堆分配**。

---

## 4. Track 3 — 高性能 UDP 流表与数据面槽位

- **现状瓶颈**：
  - `src/relay/session_udp_types.cppm` 硬编码编译期常量 `routed_udp_slots = 128` 与 `fixed_udp_slots = 16`（`std::array` 定长槽位），限制单会话并发 UDP 目的端数量。
  - `src/relay/tproxy_udp.cpp` 硬编码 `flow_limit = 128`。
  - `src/relay/session_udp_alias_tunnel.cppm` 与 `src/net/stream_datagrams.cppm` 存在固定 `16` 槽位与线性扫描逻辑。
- **高性能改造**：
  - 以**动态 Slab 对象池 + 侵入式双向链表 LRU + 平铺开放寻址哈希表**替代固定 `std::array` 与线性扫描：
    - **查找**：透明五元组/对端键平铺哈希，严格 **O(1)**，零临时对象构造。
    - **活跃续期与淘汰**：侵入式双向链表头插与尾淘汰，严格 **O(1)**，单包收发零堆分配。
    - **内存局部性**：连续 Slab 槽位数组按需倍增至可配置软上限（默认提高至 **`4096`**，支持通过配置按主机内存覆写），淘汰后槽位经空闲链表 O(1) 复用。
  - `tproxy_udp.cpp` 与 `session_udp_alias_tunnel.cppm` / `session_udp_tunnel.cpp` 统一复用同一套高性能 UDP 流表抽象，消除分散的 `128` / `16` 魔法数字。

---

## 5. Track 4 — DNS、系统网络状态、FakeIP WAL 与 Tailscale 队列

| 子系统 | 原上限与位置 | 高性能改造方案 |
| --- | --- | --- |
| **DNS 在途并发请求** | `pending_.size() == 4096`（`src/dns/cache.cpp:155,182`、`src/dns/cache_snapshot.cppm:374,395`） | 改为可配置软上限（高默认值，如 `32768`），基于开放寻址/预保留哈希表保证 O(1) 合并查询（singleflight）且避免突发高峰误返 `query_limit` |
| **DNS 缓存快照条目** | 快照硬限 `256`（`src/dns/cache_snapshot.cppm`） | 解除 `256` 硬限，改为按配置容量动态序列化/导出，避免大规模缓存被截断 |
| **DoQ / DoH3 连接池** | 固定 `16` 条连接（`src/dns/quic_query_runtime.cppm`） | 改为动态/可配连接池（高默认上限 + O(1) 键查找 + 空闲 LRU 回收），支撑多上游与高并发 QUIC DNS |
| **系统邻居表抓取** | `neighbor_limit = 4096`（`src/platform/network_state.cpp:26,140`） | 改为动态增长配合高安全护栏/可配上限，避免大二层企业网下静默截断 ARP/NDP 邻居快照 |
| **FakeIP WAL 压缩阈值** | `fakeip_wal_limit = 2 MiB`（`src/state/fakeip_disk.cppm`、`src/state/fakeip_wal.cpp`） | 改为可配置阈值并随 FakeIP 地址池规模自适应缩放，减少大池场景下频繁重写 WAL 带来的写放大 |
| **Tailscale 多 Worker 队列** | 固定小队列上限（`src/tailscale/multi_worker.cppm`） | 改为可配置容量的无锁/低竞争环形缓冲区，防止多核突发包丢弃同时保持有界内存背压 |

---

## 6. 明确非目标（必须保留的硬边界）

以下上限源自国际协议线规、操作系统 ABI 或基础安全防护，**严禁移除或放宽**：

| 类别 | 保留上限 | 依据说明 |
| --- | --- | --- |
| **RFC 协议线规** | DNS 域名 `253B` / 标签 `63B` / 报文 `65535B`；WebSocket Close 载荷 `123B`；TLS ECH `65531B`；REALITY `short-id` `8B` | RFC 1035 / RFC 6455 / RFC 9849 等协议线规硬性字段宽度 |
| **OS ABI 边界** | `IFNAMSIZ = 16`、`PATH_MAX = 4096`、`sockaddr_un::sun_path`（104/108B） | 内核系统调用结构体定长 ABI 约束 |
| **反 DoS 与栈安全** | 规则嵌套深度 `max_rule_depth = 32`、JSON 解析深度 `64`、正则状态/步数上限、SRS 解压炸弹膨胀比保护 | 防止恶意输入引发栈溢出、指数回溯或 OOM 放大攻击 |

---

## 7. 性能红线与验收基线

1. **热路径零回退**：数据面查找与淘汰全部保持 **O(1)**，稳态转发路径**零逐包堆分配**；现有性能基准（吞吐、P99 延迟、RSS）无退化。
2. **文件行数与模块规范**：每个新建/修改文件严格 `<= 500L`（`./scripts/check-source-lines.sh` 0 FAIL / 0 EXEMPT），严禁 `#ifdef` 内 `import` 或触碰不可变锁文件/补丁。
3. **分轨道规模回归测试**：
   - **Track 1**：构造 `>= 512` 出站与策略组、`>= 128` 多用户入站、`> 64` `use_providers` 与 `> 512` 条 Tailscale `packet_filter` 规则，验证加载、O(1) 查找、认证与热重载全部通过。
   - **Track 2**：构造超 `262144` 条规则（或大尺寸 NXMM 映射）及 `> 256` 查询上下文条目，验证零拷贝加载与精确匹配。
   - **Track 3**：环回压测 `>= 512` 并发不同目的端 UDP 流（覆盖普通 UDP、`tproxy_udp` 与固定隧道槽位），验证无早丢包且达软上限时按 O(1) LRU 精确淘汰最久未用流。
   - **Track 4**：压测 `> 4096` 并发 DNS `pending_`、大快照导出、QUIC 连接池复用与大 FakeIP WAL 轮转恢复，全部通过。
