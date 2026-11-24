# Hysteria 2 与 QUIC 承载设计

状态：Hysteria 2 入站与出站已接入生产双后端，最新实测与边界见 [项目进度](../../progress.md) 与 [支持矩阵](../../planning/proxy-kernel-support-matrix.md)。协议依据为 [Hysteria 2 规范](https://v2.hysteria.network/docs/developers/Protocol/)、[QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)、[QUIC TLS RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) 和 [QUIC DATAGRAM RFC 9221](https://www.rfc-editor.org/rfc/rfc9221)。Hysteria 2 不是 Hysteria 1；不能只自写特定 UDP 包格式，就声称兼容 QUIC。

## QUIC 技术路线

选择**用户态、无 I/O 的通用 QUIC 核心**作为实现路线，而不是另写仅够 Hysteria 使用的 QUIC 状态机。首选验证候选为 `libngtcp2` + `libnghttp3` 的核心库；由 Nexus 负责 UDP I/O、定时器、HTTP/3 与 Hysteria 编解码，并将自研 TLS 1.3 以 QUIC TLS 接口接入。`libngtcp2` 上游说明核心库本身不依赖外部库，其现成 crypto helper 则依赖各自的 TLS 后端；Nexus **不链接任何第三方 libssl 或该类现成 TLS helper**，密码原语继续使用已选 BoringSSL libcrypto。[ngtcp2 上游](https://github.com/ngtcp2/ngtcp2)，[nghttp3 上游](https://github.com/ngtcp2/nghttp3)。

ngtcp2/nghttp3 已按固定 release 加入正式包、锁和无文本包含的命名模块，具体来源和边界见[QUIC 依赖](../../build/quic-dependencies.md)。自研 TLS 必须补齐握手字节、各加密级别 secret、QUIC transport parameters、证书验证、密钥更新和失败事件，不能把 TCP TLS record 或 Linux kTLS 直接套在 UDP QUIC 上。还需实现/验证 QUIC Initial 密钥、头保护、AEAD、重传和数据所有权，核对 libcrypto 所需原语及 provider 回调。`nghttp3` 是否能与 Hysteria 认证后 `0x401` 非标准请求流正确分流，必须做实验；若需要补丁，应明确维护边界。上述适配失败时不允许悄悄引入 libssl，也不宣称 Hysteria 2 可用。

`lsquic`/`msquic` 可在调研中对照，但其 TLS provider、平台支持、HTTP/3 与拥塞控制的可插拔性需要同样验证，不因名字轻量就默认满足约束。当前命名模块为 `ngtcp2`、`nghttp3` 和项目内 `quic` / `hysteria2`；按[第三方模块封装](../../build/third-party-modules.md)和依赖锁定要求接入。

## 会话与线格式

使用标准 QUIC、TLS 1.3 和 HTTP/3：连接建立并验证证书/服务器名称，协商 `h3` 与 DATAGRAM 能力；认证完成之前不能处理代理业务。client 用 HTTP/3 `POST /auth`、authority `hysteria`，发送 `Hysteria-Auth`、`Hysteria-CC-RX` 和可选 `Hysteria-Padding`；服务端认证成功回状态 233，并返回 `Hysteria-UDP`、`Hysteria-CC-RX` 等。认证失败则按配置返回普通 HTTP/3 内容或转发伪装站，不能泄露错误细节；client 收到非 233 则视为失败。

每个 TCP 代理请求使用新的双向 QUIC stream：依次为 QUIC varint `0x401`、地址字符串长度、`host:port` 字节、填充长度与随机填充；服务端回单字节状态、消息长度/消息和填充长度/填充。成功后再双向转发字节，失败则关闭该 stream。地址、消息、填充、活跃流及握手耗时均须有上限；varint 支持分片到达且拒绝溢出。

UDP 通过 QUIC DATAGRAM 双向承载，报文依次为大端 session ID（32 位）、packet ID（16 位）、fragment ID（8 位）、fragment count（8 位）、varint 地址长度、地址及 payload。无分片时 count 为 1；分片按同 session/packet、地址和方向有界重组，乱序可以接受，缺片超时整体丢弃，限制总字节、并发数和生存期。服务端需给会话可靠地区分回包，空闲时回收资源；重新收到已过期 session ID 视为新会话。不能把 QUIC 自身 DATAGRAM 能力与自定义 UDP 分片混淆。

客户端最多保留八个完成的数据报：首个缓冲随连接内联，其余缓冲按实际包长分配、增长，并在队列非空时复用；队列排空或连接关闭时释放。空包不需要额外缓冲。所有 Hy2 入站和出站共享 32 MiB 动态数据报载荷额度，覆盖已保留分片及额外完成包缓冲，增长期间同时计入新旧缓冲。队列满、额度耗尽或分配失败时丢弃新数据报；现有数据报及已接收分片保持有效。内联缓冲、固定对象、分配器开销和原生 QUIC 内存不计入此额度，因此它不是进程内存总账。

构建启用 `quic-resumption` 时，每个具名出站的执行器保留最多八张单次提取的 TLS 票据。票据匹配实际 peer 地址和端口、证书信任、身份和 ALPN。静态或解析取得的 ECH 仍做完整握手。Hy2 在 TLS 完成后发送 `POST /auth`，每次连接重新认证，所有请求均使用 1-RTT。

## Brutal 拥塞控制与公平性

协议认证时交换的 `Hysteria-CC-RX` 是**字节/秒**；client 发 0 表示未知自身接收速率，server 发送侧必须改用常规拥塞控制；server 回 `auto` 时 client 发送侧同样必须使用常规控制；server 回 0 表示对其接收速率不设限制。双方发送速率取本端配置及对端实际通告可用值的组合，不能把 0 与普通数值混用。是否采用 Brutal 是本地传输控制决策，不是包内附加字段。

作为复现目标，Hysteria 当前 [Brutal 实现](https://github.com/HyNetworks/hysteria/blob/master/core/internal/congestion/brutal/brutal.go)按近期约 5 秒 ACK/loss **包数**采样；样本少于 50 时 `ack_rate = 1`，否则将 `acked / (acked + lost)` 下限钳至 0.8，关闭补偿时为 1。目标速率 `R`（字节/秒）经 token bucket pacing 以约 `R / ack_rate` 发送，已有平滑 RTT 时 `cwnd = max(max_datagram_size, 2 * R * smoothed_rtt_seconds / ack_rate)`；无 RTT 时该实现暂用 10240 字节。实际突发预算、ACK 回调与整数/时钟边界以锁定实现和测试为准。这是拥塞控制实现细节，不是 Hysteria 线协议保证，也不是无条件恒速。

当前 [ngtcp2 公开头](https://github.com/ngtcp2/ngtcp2/blob/main/lib/includes/ngtcp2/ngtcp2.h)中的 `cc_algo` 列举 Reno、Cubic、BBR，尚未证实存在通用外部控制器接口。要支持上述 Brutal，需要验证可维护的补丁或其他明确集成方式，包括丢包统计、pacer、cwnd 和运行时切换；单纯在 socket 外限速不能替代 QUIC 内部拥塞窗口。先以标准算法完成互操作，Brutal 独立标记待验证，不能声称已支持。设置目标带宽和总预算，测量公平性及持续拥塞，提供关闭补偿与切回常规控制的策略。

## 跳端口与伪装

客户端跳端口只在显式配置服务端可达的端口/范围时启用，使用有界随机选择和时间间隔；服务端通过多端口监听或网络转发将报文送至同一 QUIC endpoint。切换前保留旧路径并处理回包重叠、路径验证、NAT 重绑定、CID、PMTU 和丢包；服务端不支持的迁移或超时应可回退/重连，不承诺所有中间网络都无损。端口范围的本机转发规则不得误拦截服务器自身的出站 UDP，生命周期须纳入网络回滚。[上游端口跳跃说明](https://v2.hysteria.network/docs/advanced/Port-Hopping/)。

认证头及请求流的 padding 是协议内可选字段，须有最大长度、随机源及输入预算；它不保证不可识别。可选 Salamander 是在每个 QUIC 数据报外加 8 字节随机 salt，以 `BLAKE2b-256(key || salt)` 的 32 字节结果循环 XOR 数据；双方需一致配置，接收后再交给 QUIC 做认证。它是混淆而非独立认证或保密机制，缩短有效 MTU；不能随机改写标准 QUIC 数据报充当兼容伪装。新增的 Gecko 变体按选定上游版本另行实现和有界重组，不默认声称支持。

## 验收

先验证 TLS/QUIC 标准向量、HTTP/3 认证和真实 Hysteria 2 客户端/服务端互操作，再测 TCP 半关闭、UDP 会话/分片、背压、拥塞控制及端口切换。覆盖证书失败、认证失败时伪装、varint 截断/超限、DATAGRAM 未协商、迁移失败、网络变更、MTU、内存与计时器边界。记录实际依赖图及最终链接，证明没有引入 libssl、其他 TLS 库或上游示例的事件循环。未经完整验证不得承诺 P1 已可用。

