# Linux 代理内核支持矩阵

本表记录已接入的生产入口、构建特性和适用边界。双后端（`epoll` 与 `io_uring`）已通过全量集成、压力、互通与弱网验收。[协议与内核演进蓝图](protocol-and-kernel-roadmap.md) · [Linux 验收](proxy-kernel-linux-validation.md#第-8790-批--集成性能和发布验收)

| 协议或入口 | 方向与承载 | 认证、解析和路由 | 构建和仍待验证的边界 |
| --- | --- | --- | --- |
| Direct / Block | IPv4/IPv6 TCP、UDP 出站 | Direct 使用配置的 DNS、socket 选项及候选网络。Block 终止路由。透明、SOCKS、TUN 和协议入站可选择这两个出口。 | 基础图。按[拨号字段矩阵](dial-field-coverage.md)复查字段归属、失败恢复和实际后端。 |
| SOCKS5 / Mixed | SOCKS5 CONNECT 和 UDP ASSOCIATE 入站。Mixed 同时接 HTTP CONNECT 与正向代理。具名 SOCKS5 出站接 TCP CONNECT 和显式 UDP ASSOCIATE。 | 回环可显式无认证或用户名密码。SOCKS5 出站使用具名 bootstrap，可作为 TCP 下层。入站可执行普通或有序路由。 | 基础图。出站 UDP 支持物理或具名 direct、数值中继地址及外网地址宣告；双后端已通过 TCP 认证与代理串联验证。 |
| HTTP 与固定目的 | HTTP/1.1 CONNECT 和正向代理入站，HTTP/1.1 CONNECT 具名出站，独立固定目的 TCP 入站。 | HTTP 支持 Basic。固定目的 TCP 沿用通用解析、嗅探和路由。显式 direct 继承物理绑定，具名 TCP 下层承担后续拨号。 | 基础图，`http-connect-tls` 增加上游 TLS 1.3。固定目的 TCP 双族半关闭及重载有切片证据，固定目的 UDP 待评审。 |
| Shadowsocks 2022 | TCP 入出站、原生 UDP、流内 UoT。 | 分配置使用 2022 方法与身份，按各入口传递来源、用户和 DNS 依赖。原生 UDP 支持数据报下层。 | `ss2022`。按方法、UDP EIH、下层及生命周期分别验收。经典 Shadowsocks 和 SSR 在既有排除范围。 |
| VLESS / Reality / Vision | 双向 TLS TCP。普通 VLESS 支持固定目标 UDP、XUDP、packetaddr，以及 TCP 上的 HTTPUpgrade、WebSocket、gRPC。Reality 与 Vision 使用各自承载。 | UUID、TLS 身份或 Reality 认证。普通出站可显式使用 TLS 1.2。WebSocket 保留二进制帧和 Close 语义，HTTPUpgrade 保留 TCP 半关闭。 | `vless`，gRPC 另需 `grpc-vless`。逐载体校验下层能力和用户限额。Reality/Vision 直通与 UDP 空包按对端分别记录。 |
| Trojan / AnyTLS | 双端 TCP 和流内 UDP。AnyTLS 复用 TLS 连接的独立子流。 | 密码和双端 TLS 身份，物理层可使用 direct 或 TCP 下层。AnyTLS 的有序规则以子流为单位执行。 | `trojan`、`anytls`。切片已验证 AnyTLS 在同一连接拒绝一个子流后，其他 TCP 与 UoT 子流仍能完成。 |
| Hysteria 2 / TUIC | QUIC 上双向 TCP、UDP。TUIC v5 UDP 可选原生数据报或 QUIC 流。 | TLS 与协议凭据，物理 UDP 可用具名 direct 或数据报下层。新连接在握手后完成协议认证。 | `hy2-cli`、`tuic`。可选 `quic-resumption` 提供具名出站的 1-RTT 恢复，双族及关闭图均有固定对端的证据。 |
| MASQUE | 双向 CONNECT-UDP。CONNECT-IP 提供普通代理出站、独立 Linux TUN 出站及具备 TUN 租约的入站。 | TLS、可选 bearer、路由及 PDU 约束。CONNECT-UDP 的目标按地址与端口绑定。出站可经支持数据报的下层。 | `masque-outbound`、`masque-cli`、`masque-ip-endpoint`、`masque-ip-server`。独立 TUN 的路径选择、租约及单请求范围单独验收。 |
| WireGuard / WARP | WireGuard L3 端点及用户态具名 TCP/UDP 出站。 | 本地与 peer 密钥、AllowedIPs、显式 WARP 三字节格式。出站可经物理 UDP 或数据报下层。 | `wireguard-endpoint`、`wireguard-outbound`；`wireguard-host-dns` 增加 Linux resolved 所有权。WARP 账号与授权来自部署方，第三方生产服务仍纳入独立证据。 |
| Tailscale | Linux 端点及用户态 TCP/UDP 出站，支持直连和 DERP 回退。 | 独立端点配置、控制面快照、路由与包过滤、私域 DNS。 | `tailscale-endpoint`、`tailscale-outbound`。具名出站现有单 worker 和单 SOCKS5/Mixed 入口约束。验证快照换代、直连回退及策略撤回。 |
| Snell / ShadowTLS | Snell 出站 v4、入站 v5，TCP/UDP、HTTP 混淆与既有顺序复用。ShadowTLS v3 提供 TCP 承载及内外层组合。 | Snell PSK 与已有重放约束。ShadowTLS 使用密码、外层 TLS 和合法 cover 服务，可承载内层协议。 | `snell`、`shadowtls-proxy`。v5 QUIC、后续 Snell 版本和额外混淆留在评审项。 |
| Linux TUN / 透明入口 | routed TUN 双栈 TCP/UDP，外部 TUN FD，Linux REDIRECT/TPROXY TCP 和 TPROXY UDP。 | 系统策略路由、入口接口、原目标、DNS 劫持、FakeIP 和配置的出站。按入口支持相应有序动作。 | `tun-inbound`、`tun-host-dns`、`tproxy-udp`、`dns-fakeip`。验证 MTU/分片、异常清理、回滚和代次并存。 |

DNS 包含系统 local、具名 UDP/TCP、DoT、DoH/1.1、DoH/2、DoQ 和 DoH/3。按选择开启 `dns-tls`、`dns-https`、`dns-quic`、`dns-https3`、`dns-response`。当前验证入口、消息响应条件和缓存边界见 [配置规范](../configuration/spec.md#dnsfake-ip-与-tun)。具名 HTTP 按 `http-client`、`http-client-h2`、`http-client-h3` 区分关闭图和只启用实际承载的组合。

最小关闭图在 epoll、io_uring 均确认 HTTPS CONNECT、DNS TLS 和 FakeIP 在启用前明确拒绝，普通 SOCKS TCP/UDP、认证与串联、HTTP CONNECT 和转发继续可用。构建配置与发行打包见 [mcpp 工作区](../build/mcpp-workspace.md) 与 [发行打包与运维](../../packaging/README.md)。
