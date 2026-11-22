# 第 94 批实现蓝图 · 协议互通、VLESS XHTTP 与 uTLS 高保真补强

更新：2026-11-20。本蓝图将第 94 批（94A–94D）精确映射到源码模块、协议边界、零虚函数与无前缀约束以及跨实现实测矩阵。

## 94A · REALITY 后量子、Fallback 抗探测与 Hysteria 2 窗口可配

### 1. VLESS REALITY `X25519MLKEM768` 客户端/服务端完整互通
- **现状核查**：
  - `src/reality/server_auth.cppm:45-48` 已经识别 `0x11ec`（1216B `X25519MLKEM768` share）并取末尾 32 字节 X25519 参与认证，同时核对配置开关、客户端默认初始 `key_share` 组合（`{0x11ec, 0x001d}`）与 `ClientHelloDriver::authenticate_first` 在混合密钥共享下的 `X25519Private` 绑定，以及 `X25519MLKEM768` 双向握手与 `mldsa65` / 既有 Ed25519 认证边界。
- **源码改造点**：
  - `src/reality/client.cpp`、`src/tls/client_hello_driver.cpp`、`src/vless/client_profile.hpp`、`src/config/vless_outbound.cpp`：确保开启后量子/Chrome 指纹时 REALITY 客户端与服务端均能透明协商 `X25519MLKEM768`（`0x11ec`）并安全兼容仅支持 `X25519` 的对端（HRR / 单 share 退回）。
- **验收**：独立 REALITY 互通对端双方向实测 `X25519MLKEM768` 与纯 `X25519` 双向转发。

### 2. REALITY Fallback 关闭同步抗主动探测
- **现状核查**：`src/reality/fallback.cppm` 已有双向 `fallback_direction` 与 `shutdown_send` 半关闭，但在 cover 端主动 RST / 提前关闭、或客户端探测发包超时/半开时，需要严格同步对端关闭语义（避免 cover 已断而服务端仍挂起或提前发 RST 暴露特征），并核对 `max_time_difference` / 未认证连接无额外时序泄漏。
- **源码改造点**：`src/reality/fallback.cppm`、`src/proxy/vless_inbound.cpp`（及相关 REALITY 入站）：精细区分 cover 正常 FIN vs RST/错误关闭，保持与目标 cover 站点一致的关闭表现，并保留外层空闲/总时长硬预算防慢速探测耗尽 FD。
- **验收**：主动探测夹具（非法 short_id、过期时间戳、普通浏览器 TLS 探针、cover 提前关闭/RST、客户端半关闭）验证连接关闭行为与直接连 cover 一致且零 FD 泄漏。

### 3. Hysteria 2 / QUIC 可配置流与连接接收窗口
- **现状核查**：`src/hysteria2/transport_options.cppm:30-54` 的 `TransportProfile<Streams, Window>` 目前把 `initial_max_stream_data_bidi_*` 和 `initial_max_data` 写死为编译期常量 `Window` 与 `Streams*Window`。
- **源码改造点**：
  - `src/hysteria2/transport_options.cppm`、`src/config/hysteria2.cpp`、`src/proxy/hysteria2_outbound.cpp`、`src/hysteria2/listener.cppm`：支持 KDL 配置 `init-stream-receive-window` / `max-stream-receive-window` / `init-conn-receive-window` / `max-conn-receive-window`（合理上下界校验，如 64 KiB – 64 MiB 且连接窗口 ≥ 流窗口，受 `memory::Budget` 约束），并将其传递至 `ngtcp2_transport_params` 与流控上限。
- **验收**：单测校验边界；双后端高 BDP 实测调整窗口生效且不突破内存预算；核验 QUIC 断连零孤儿 UDP 会话（对照 `#4375`）。

---

## 94B · VLESS XHTTP 承载（无 `nexus` 前缀模块 `xhttp.*`）

- **协议定位**：新一代 HTTP 分离承载（原 SplitHTTP），支持跨 CDN / 反向代理穿透与上下行解耦，是现代 VLESS 高频核心传输层。
- **模块布局（无前缀、无虚函数、文件 ≤300 行）**：
  - 新增 `src/xhttp/`（导出 `xhttp`、`xhttp.config`、`xhttp.wire`、`xhttp.client`、`xhttp.server`、`xhttp.xmux`），使用 `namespace xhttp`。
- **协议模式与线规细节（XHTTP / SplitHTTP 标准线规）**：
  1. **`stream-one`**：单条长连接全双工 HTTP/2 或 HTTP/3 `POST` 流（无需 `session_id` 与 `seq`，类似 gRPC 形态但无强制 gRPC 5B 头；支持 `no-grpc-header` 控制 `Content-Type`），直接双向承载 VLESS 字节流。
  2. **`packet-up`**：下行一条长 `GET` 流（路径 `<base-path>/<session_id>`，服务端回复 `200 OK` + `X-Accel-Buffering: no` + `Cache-Control: no-store` 流式响应体）+ 上行多条短 `POST` 请求（路径 `<base-path>/<session_id>/<seq>`，`seq` 从 `0` 递增；客户端遵循 `sc-max-each-post-bytes` 默认 1 MiB 与 `sc-min-posts-interval-ms` 默认 30ms；服务端按 `seq` 有序重组，遵循 `sc-max-buffered-posts` 默认 30 与字节预算防 OOM）。
  3. **`stream-up`**：下行长 `GET`（`<base-path>/<session_id>`）+ 上行单条流式 `POST`（`<base-path>/<session_id>`）分离双流（适配仅支持单向流式缓冲的 CDN/反代）。
  4. **`session_id` 与 `X-Padding` 线规**：
     - `session_id` 为标准小写 UUIDv4（`8-4-4-4-12`），`packet-up`/`stream-up` 用于关联上下行；
     - `x-padding-bytes`（默认 `100-1000` 随机区间）：支持在 `Referer` / `Query`（`?x_padding=...`）/ 自定义 Header 注入合规随机填充字节对抗长度指纹；支持自定义额外 `headers` 映射表。
  5. **`auto` 模式选择**：普通 TLS 和明文默认使用 `packet-up`；H2 REALITY 无独立下载时使用 `stream-one`，有独立下载时使用 `stream-up`；HTTP/1.1 使用 `packet-up`。
  6. **传输承载与 `xmux` 复用池**：复用已去前缀的 `http`（H1.1）、`http2`（H2）、`quic.http3`（H3）以及 `tls` / `reality`，支持客户端独立 `download-settings`（上下行分离目标/CDN/TLS）与 `xmux` 复用预算（`max-concurrency`、`max-connections`、`c-max-reuse-times`、`c-max-lifetime-ms`、`h-max-request-times`、`h-max-reusable-secs`）。
  7. **安全与反滥用硬边界**：限制单 session 待重组 `seq` 窗口（条数 + 总字节硬上限）、未配对上下行 session 建连超时（如 30s 自动回收）、最大并发 XHTTP session 数、严格校验 UUIDv4 格式与路径前缀防目录穿越。
- **验收**：
  - 单元单测覆盖 `X-Padding` 编码/解码、`packet-up` 乱序重组与窗口上限、`xmux` 复用生命周期；
  - **独立 XHTTP 对端双向实测**（`epoll` / `io_uring`）：`stream-one`（H2 + H3）、`packet-up`（H1.1 + H2）、`stream-up`（H2），含大流转发、半关闭、并发多流、断连回收与零 FD/内存泄漏。

---

## 94C · uTLS 高保真现代浏览器指纹补强

- **现状差距**：当前 `src/tls/fingerprint.cpp` 已具备基础 TLS 1.3、`X25519MLKEM768`、RFC 8879 证书压缩、GREASE 与扩展洗牌，但与现代真实浏览器（Chrome 130+ / Firefox 130+ / Safari 18+）仍存在可被 JA4 / 深度 ClientHello 检测区分的特征缺口。
- **改造项（均落在 `src/tls/`）**：
  1. **补齐核心现代扩展**：
     - **`GREASE ECH`（`0xfe0d`）**：为 Chrome/Edge/Firefox 预设按真实浏览器分布生成合规长度（128/160/192/224B payload）的伪 `encrypted_client_hello` 扩展（外层 `outer` 类型、合法 HPKE cipher suite `0x0001/0x0001`、随机 `config_id` 与 32B `enc`）；当用户显式提供真实 ECHConfig 时自动让位不重复发送。
     - **`ALPS`（`application_settings`，`0x44cd` 新值与可选旧值 `0x4469`）**：Chrome/Edge 携带 `h2` 协商。
     - **`status_request`（OCSP，`0x0005`）**、**`signed_certificate_timestamp`（SCT，`0x0012`）**、**`extended_master_secret`（`0x0017`）**、**`renegotiation_info`（`0xff01`）**、**`session_ticket`（`0x0023`）**、**`ec_point_formats`（`0x000b`）**、**`delegated_credentials`（Firefox，`0x0022`）**。
  2. **TLS 1.3 + 1.2 兼容降级与真实浏览器密码套件表**：
     - 现代浏览器 ClientHello 并非只发 3 个 TLS 1.3 套件，而是 `GREASE + TLS 1.3(3个) + TLS 1.2 ECDHE-AEAD(8-12个)` 组合且 `supported_versions` 含 `{GREASE, 0x0304, 0x0303}`；服务端选 1.3 走 1.3，选 1.2 自动无缝接续既有 `tls12_client` 完成握手。
  3. **TCP vs QUIC 浏览器预设精确分化**：
     - QUIC 握手自动剔除 TCP 专属扩展（`padding`、`record_size_limit`、`ec_point_formats`、`renegotiation_info`、`session_ticket`、`extended_master_secret`、TLS 1.2 套件），并附带符合 Chrome/Firefox 行为的 `quic_transport_parameters`（`0x0039`）。
  4. **通用 TCP 出站 1-RTT PSK 会话恢复**：
     - 打通 `src/tls/resumption/` 在通用 TLS 1.3 出站的 `NewSessionTicket` 缓存与受控 1-RTT PSK 恢复（带容量上限与过期清理，不引入 0-RTT 重放风险）。
  5. **版本化指纹回归快照**：
     - 新增版本化预设别名（如 `chrome-133`、`firefox-135`、`safari-18` 并保留 `chrome`/`firefox`/`safari` 指向最新稳定预设），在单元测试中解析生成出的原始 ClientHello 字节流，断言扩展集合、套件列表、JA4 指纹特征与 `GREASE ECH` 结构合法性，并对真实本地 OpenSSL/BoringSSL/Go TLS 服务端完成真握手。

**双后端定向验收（2026-11-21）**

- 七个配置各以同一个 TCP ClientHello 分别完成 TLS 1.2 和 1.3。OpenSSL 另强制 TLS 1.2 ECDHE-ECDSA ChaCha20。实际 TLS 1.2 列表包含四个 ECDHE AES-GCM 和两个 ECDHE ChaCha20-Poly1305，均有本地握手实现。
- BoringSSL 经生产 HTTP/2 具名下载验证 `0x44cd` ALPS、客户端 EncryptedExtensions 与 Finished。独立 XHTTP H3 对端接受七个 H3 配置，每方向转发 2 MiB。Go QUIC 对端确认 Chrome-133 在 Hysteria 2 正常握手及 HRR 时均可使用显式 ECH。
- OpenSSL 读回四组 TLS 1.3 票据的 1-RTT 恢复，隔离 SNI、信任锚和实际端点。原始 ClientHello 确认 `pre_shared_key` 在扩展尾部，且恢复首飞不含 `early_data`。
- Firefox 的 `delegated_credentials` 涵盖 ClientHello 声明。委托凭据验证、恢复缓存适用路径及其他边界见 [ClientHello 指纹编排](../architecture/utls-engine.md)。两后端的编译、原始套件与扩展、JA4、实网、模块图和校验日志保存在 `target/batch94c/`。

---

## 94D · 协议部署高频补强与前车之鉴回归

1. **SOCKS5 UDP 宣告外网 IP**：
   - `src/config/`、`src/proxy/socks5*`：SOCKS5 入站支持可选 `udp-advertise-ip`（IPv4/IPv6），在 NAT/Docker/反代后 `UDP ASSOCIATE` 回复准确的外网可达地址而非内网绑定地址。
2. **TLS 完整 X.509 证书链 SHA-256 Pinning**：
   - `src/tls/certificate_trust.cppm` / `certificate_trust.cpp`、`src/config/`：支持 `certificate-sha256`（leaf 证书 DER 或 SPKI SHA-256 列表，常量时间比对，支持单值与多值轮换，与常规 CA 校验/SAN 校验协同策略明确）。
3. **Tailscale 固定 UDP 监听端口**：
   - `src/tailscale/`、`src/config/`：允许显式指定本地 WireGuard/DERP 协同监听 `listen-port`（默认 0 自动分配），便于防火墙精准放行直连打洞。
4. **MASQUE Cloudflare WARP 兼容项**：
   - `src/masque/`、`src/config/masque.cpp`：梳理并补齐 WARP 节点常见的头字段、路径、IPv4/IPv6 MTU 与重连刷新边界。
5. **Unix Domain Socket（UDS）承载**：
   - `src/platform/`、`src/net/`、`src/config/`：支持本机入站/出站通过 `unix-path`（含抽象命名空间或文件系统路径，清理过期 socket 文件并校验权限）对接 Nginx/Caddy/HAProxy 本机反代。
6. **前车之鉴必测回归**：
   - **1290B 路径 MTU 下 DoH3 over WireGuard**（`#4656`）：隔离 netns 限 MTU 1290 实测 QUIC/DoH3 不黑洞；
   - **Snell HTTP 混淆首包回归**（`#4454`）：核验大/小首包与分段写入兼容。

**定向验收记录（2026-11-21）**

- epoll 与 io_uring 通过离线锁定优化构建、SOCKS5 IPv4/IPv6 UDP 公告及转发、TLS 1.2/1.3 DER/SPKI pin、Tailscale 固定端口与冲突和 Linux UDS 三条路径。UDS 通过 fixed-tcp 配置，Unix 入站单 worker，使用普通 direct 路由。
- 独立 Go 对端验证 WARP 风格 H3 CONNECT-IP 的协议名、路径、额外请求头、静态 IPv4/IPv6、MTU 1280 和连接关闭后的重建。本批验证使用本地兼容对端。Cloudflare 公网账号、mTLS 及 HTTP/2 WARP 承载仍没有本批实测覆盖。
- 在独立网络命名空间中通过生产 WireGuard TUN 对端转发 DoH3，经 1290 字节 veth，每后端收到两条 DNS 应答，出站 QUIC 数据报的最大内层 IPv4 包为 1228 字节且无分片。代理承载的 DoH3 将发送 payload 上限设为 1200 字节。
- Snell 双向回归验证 5 字节和 125500 字节业务首包及 HTTP 头分段。SS-2022 AES-128/256 的 TCP 和原生 UDP 双后端互通通过。
- 第 11 波实际链接图检查覆盖 epoll 822 与 io_uring 812 个生产编译单元，七家族各有提供与消费边，无旧生产模块名。默认锁、pinned guard、源文件行数和空白检查通过。日志与 SHA-256 证据见 `target/batch94d/`。
