# 代理内核支持矩阵

本表记录 Nexus 当前已接入的生产协议、入口、特性开关与适用边界。Linux 双后端（`epoll` 与 `io_uring`）已通过全量集成、压力、互通与弱网验收，详见 [协议与内核演进蓝图](protocol-and-kernel-roadmap.md) 与 [验证体系与实机基线](validation.md)。

| 协议或入口 | 方向与承载 | 认证、解析与路由 | 构建特性与适用边界 |
| --- | --- | --- | --- |
| Direct / Block | IPv4/IPv6 TCP、UDP 出站 | Direct 支持接口绑定、双栈源地址、mark、`netns`、`protect-path`、TFO、MPTCP 及候选网络回退；Block 终止路由。 | 基础图。完整拨号字段语义见 [配置规范](../configuration/spec.md)。 |
| SOCKS / Mixed | SOCKS4/4a/5 TCP 与 SOCKS5 UDP ASSOCIATE 入出站；Mixed 同时处理 SOCKS5 与 HTTP。 | 回环可显式无认证或用户名密码；出站支持具名 bootstrap 与 TCP/UDP detour。 | 基础图。 |
| HTTP / 固定目的 | HTTP/1.1 CONNECT 与正向代理入出站（含上游 TLS 与 H2/H3 代理）；固定目的 TCP/UDP 入站。 | 支持 Basic 认证、16 KiB 头上限（`431`）与有序路由。 | 基础图，`http-connect-tls` 开启上游 TLS；现代 H2/H3 代理与 `naive` 见下。 |
| NaiveProxy / SSH | NaiveProxy 双向 H2/H3 `CONNECT`（含双向 padding）；SSHv2 `direct-tcpip` 多路复用出站。 | Naive 复用自研 TLS/uTLS 与 `nghttp2`/`nghttp3`；SSH 支持 `curve25519-sha256`、AEAD 与严格 HostKey 校验。 | `naive`、`ssh`。 |
| Shadowsocks 2022 | TCP 入出站、原生 UDP、流内 UoT。 | 2022 方法、抗重放状态、UDP EIH 与数据报下层。 | `ss2022`。经典 Shadowsocks 与 SSR 在排除范围。 |
| VLESS / REALITY / Vision | 双向 TLS TCP、Vision、REALITY、XUDP、`packetaddr`、WS、HTTPUpgrade、gRPC、XHTTP（H1/H2/H3）。 | UUID、TLS/REALITY 认证与 uTLS 指纹（Chrome 158 / Edge 158 / Firefox 161 / Safari 26.3 / iOS 26.3 / Android 16）。 | `vless`、`grpc-vless`、`xhttp-vless`。 |
| Trojan / AnyTLS | 双向 TCP 与流内 UDP（叠加 WS / HTTPUpgrade / gRPC）；AnyTLS 支持单 TLS 连接子流复用。 | 密码认证、双端 TLS、按子流执行有序规则。 | `trojan`、`anytls`。 |
| Hysteria 2 / TUIC | QUIC 双向 TCP/UDP；Hy2 支持 Salamander 混淆、Brutal 拥塞控制与端口跳跃；TUIC v5 支持原生数据报或流。 | 凭据认证、QUIC 1-RTT 恢复（`quic-resumption`）、数据报 detour。 | `hy2-cli`、`tuic`。 |
| MASQUE | 双向 `CONNECT-UDP` 与 `CONNECT-IP`（普通出站、独立 TUN 端点及带租约入站）。 | TLS、可选 bearer、路由与 PDU 约束。 | `masque-outbound`、`masque-cli`、`masque-ip-endpoint`、`masque-ip-server`。 |
| WireGuard / WARP / Tailscale | L3 TUN 端点与用户态 TCP/UDP 出站；Tailscale 支持直连与 DERP 回退及独立 DERP 中继服务。 | 本地/peer 密钥、WARP reserved、控制面快照、策略过滤与私域 DNS。 | `wireguard-endpoint`、`wireguard-outbound`、`wireguard-host-dns`、`tailscale-*`、`derp-server`。 |
| Snell / ShadowTLS | Snell 出站 v4 / 入站 v5（TCP/UDP、HTTP 混淆）；ShadowTLS v3 TCP 承载与 cover 服务。 | Snell PSK 与重放约束；ShadowTLS 外层 TLS + 内层协议组合。 | `snell`、`shadowtls-proxy`。 |
| 企业 VPN 与特殊隧道 | OpenVPN（TLS 控制 + AEAD 数据）、OpenConnect（HTTPS/CSTP + DTLS）、反向穿透、L3 桥接、外接 Tor 封装。 | 支持 `detour`、证书/口令认证及自动回退。 | `openvpn`、`openconnect`、`reverse-tunnel`、`bridge`、`tor`。 |
| Linux TUN / 透明入口 | routed TUN（双栈 TCP/UDP、外部 FD、`auto-redirect`）、Linux `redirect` TCP 与 `tproxy` TCP/UDP。 | nftables 策略路由、FakeIP 与 DNS 53 优先劫持、`systemd-resolved`（含关闭 DoT）与防环回。 | `tun-inbound`、`tun-host-dns`、`tproxy-udp`、`dns-fakeip`。 |
| 运维与基础服务 | ACME 自动证书、L4 SNI 无解密分流、SS-2022 多用户管理（`ssmapi`）、SNTPv4 时钟校准、内存看门狗与控制面 HTTP/OpenMetrics。 | `/v1/*` 控制面、`/metrics`、`log-ring`、只读 `dashboard-root` 静态托管与本地 UDS。 | `acme`、`sni-demux`、`ssmapi`、`ntp`、`memory-budget`、`control-http`、`metrics-openmetrics`。 |

- **DNS 体系**：支持 `local`、UDP/TCP、DoT（`dns-tls`）、DoH 1.1/2（`dns-https`）、DoQ（`dns-quic`）、DoH/3（`dns-https3`）、FakeIP（`dns-fakeip`）、`predefined`、`resolved`、`dhcp`（`dns-dhcp`）、`mdns`（`dns-mdns`）、消息响应条件（`dns-response`）及持久化乐观缓存。
- **具名 HTTP 客户端**：按 `http-client`、`http-client-h2`、`http-client-h3` 分级裁剪，支撑托管规则集与 ACME。
- **四层发布 Profile**：`profile-embedded`（精简客户端）→ `profile-sidecar`（跨端非 root 客户端）→ `profile-linux-epoll` → `profile-linux-uring`（旗舰配置），详见 [mcpp 工作区](../build/mcpp-workspace.md) 与 [发行打包](../../packaging/README.md)。
