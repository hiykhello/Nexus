# 第 95 批实现蓝图 · 出站组增强、TPROXY 缓存与可观测性/控制面

更新：2026-11-21。本蓝图将第 95 批（95A–95C）精确映射到源码模块、安全与性能边界以及双后端验收标准。

## 95A · `url-test` / `fallback` 出站组增强

### 1. 探测状态码严格校验
- **现状核查**：`src/tools/proxy_group_health.hpp` 发送 `HEAD <path> HTTP/1.1` 并仅检查是否收到有效 HTTP 响应，未按期望状态码校验（遇到透明代理/CDN 返回 `403`/`502`/`503` 时可能误判 `up`）。
- **源码改造点**：
  - `src/config/`、`src/tools/proxy_group_health.hpp`、`src/proxy/dial.cpp`（或 probe 响应解析处）：
    - `probe` 配置新增可选 `expected-status`（支持单值如 `204`、区间如 `200..299` 或列表，默认 `200..399` 或按 `204` 等显式指定；严格拒绝 `4xx`/`5xx`）；
    - 解析响应首行状态码，非期望状态码一律记为 `down` 并记录观测原因（不回退为 `up`）。
- **验收**：本地 HTTP stub 分别返回 `204`/`200`/`403`/`500`/`502` 与截断垃圾响应，验证 `403`/`5xx` 精准判 `down` 并触发切换。

### 2. `url-test` 临时手动覆盖与重置
- **源码改造点**：
  - `src/tools/proxy_group_health.hpp`、`src/tools/proxy_control_operations.hpp`、`src/tools/proxy_selector_state.hpp`、`src/state/`：
    - 为 `url-test` 组增加可选的临时手动覆盖槽（`manual_override` + 可选 TTL / 直到显式重置），支持通过本地控制面 `control select <group> <member>` 临时锁定成员，以及 `control select <group> --auto`（或 `reset`）恢复自动按延迟优选；
    - 锁定期间仍可后台更新观测延迟（不强行覆盖手动选择），但当手动锁定成员明确探测 `down` 且配置允许故障转移时可按策略处理（默认严格尊重显式覆盖并在观测输出中标明 `override` 状态）。
- **验收**：双后端控制面实测 `url-test` 自动选优 → 手动覆盖指定慢节点 → 探测刷新不冲掉覆盖 → 重置回自动优选；验证重启持久化语义清晰。

### 3. 可选 HTTP/2 PING 探测
- **源码改造点**：
  - `src/tools/proxy_group_health.hpp`、`src/http2/`、`src/config/`：支持 `probe` 配置 `mode "h2-ping"`（对 TLS+H2 节点通过已有 H2 连接发送标准 RFC 9113 `PING` 帧并测量 `PING ACK` RTT，省去每次探测重建 TCP+TLS 握手开销）。
- **验收**：本地 H2 服务端实测 `PING` 帧 RTT 测量、超时判 `down` 与断连重建。

---

## 95B · Linux TPROXY UDP `netns` 回写 Socket 缓存

- **问题根因**：`src/proxy/tproxy_udp.cpp` 当前对每个入站 UDP 流或不同回写目标频繁创建 `IP_TRANSPARENT` 绑定回写 socket（`socket()` + 多次 `setsockopt()` + `bind()` + `close()`），在跨 `netns`/高并发多目标 UDP（如 QUIC/DNS/游戏流）下产生大量内核 syscall 与端口锁竞争。
- **源码改造点**：
  - `src/proxy/tproxy_udp.cpp`（拆出独立小文件 `tproxy_reply_cache.hpp`，≤300 行、无虚函数）：
    - 增加有界 `TproxyReplySocketCache`（按 `(family, source_addr, source_port, netns_id, so_mark)` 索引，固定最大 FD 预算 + 空闲 TTL + LRU/CLOCK 淘汰）；
    - 对同源回写复用已绑定的 `IP_TRANSPARENT` socket，大幅降低 `socket`/`setsockopt`/`bind`/`close` 系统调用频次；
    - 遇 `ENOBUFS`/`EINVAL`/网络代次变更时自动淘汰失效项并安全重建；服务关闭或重载时一次性释放所有缓存 FD。
- **验收**：隔离 netns 双栈 TPROXY UDP 压力对照：验证回写源地址/端口 100% 精确伪装、FD 严格受预算约束、高频多流下 `socket`/`bind` syscall 数量显著下降且无泄漏。

---

## 95C · 低基数 OpenMetrics 指标与 BEVE/HTTP `/v1` 控制面（可选特性，`#1564`）

严格遵循既有架构文档 [control-api.md](../architecture/control-api.md)，全部以**无 `nexus` 前缀新模块**（`control_api.*` / `metrics.*`）与可选 `mcpp` 特性（`control-http` / `metrics-openmetrics`）落地，关闭时零代码体积与零运行时开销：

1. **低基数 OpenMetrics 指标导出（`/metrics`）**：
   - 仅暴露固定、有界、低基数标签（如 `inbound`、`outbound`、`protocol`、`family`、`outcome`），**严禁把域名、客户端 IP、URL、端口或用户自由文本放进 label**（防内存无限膨胀）；
   - 覆盖核心运维指标：活跃 TCP/UDP 会话数、累计上/下行字节、连接建立耗时分桶、DNS 缓存命中/缺失/刷新/失败计数、FakeIP 使用率、规则重载代次、`logging` 丢弃计数、`state` 写入/提交状态与各出站组探测状态。
2. **HTTP `/v1` + 本地 UDS BEVE 控制面**：
   - 复用既有 `http` 零分配解析器与 `logging` / `state` 能力，提供只读与读写分离接口：
     - `GET /v1/health`、`GET /v1/status`、`GET /v1/outbounds`、`GET /v1/dns/cache`、`GET /v1/connections`（分页/硬上限）；
     - `PUT /v1/groups/{tag}`（切换/覆盖出站组）、`POST /v1/log-level`、`POST /v1/reload`、`POST /v1/state/clear-cache`；
     - 可选流式日志/流量快照推送（带单连接出队缓冲硬上限，慢消费者超时即断开保护主数据面）。
   - **安全硬边界**：
     - TCP 监听默认仅限回环（`127.0.0.1` / `::1`），非回环地址必须显式配置强 `bearer-token`（常量时间比较 `crypto::constant_time_equal`）；
     - 本地 UDS 继续沿用 `SO_PEERCRED` UID 权限分离；
     - 严格请求体/头长度上限与最大并发控制面连接数预算。
3. **验收**：
   - 启闭图（`control-http` / `metrics-openmetrics` 开/关）双后端构建与 ELF 边界核查；
   - 实测 Bearer token 鉴权拒绝与常量时间校验、慢消费者断连不阻塞代理数据面、OpenMetrics 文本格式合法且无高基数标签泄露、热重载与动态切组端到端通过。
