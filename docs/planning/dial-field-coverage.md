# 第 71A 批 · 拨号字段作用层

更新：2026-11-20。这里记录工作树的接线与已知缺口。逐字段验证继续使用真实 socket、包源地址和固定对端。TCP 与 UDP 指代理节点的物理载体，业务 UDP 可以经 TCP 封装。

| 出站或用途 | 配置来源与物理执行点 | 作用范围及缺口 |
| --- | --- | --- |
| Direct TCP | `direct_tcp_options` 经 `proxy/dial.cpp` 进入 `net/tcp_connect.cppm` | TCP 源地址、接口、mark、复用、保活、无端口绑定和 MPTCP。TFO 在首写适配层。UDP 专用字段处于独立契约。 |
| Direct UDP | 直连配置经 `net/udp_dial.cpp` 被 SOCKS、透明入口、TUN、SS 入站和多种封装入口复用 | 绑定地址/接口、mark、复用、固定源端口和 DF 在 datagram FD 上执行。配置单一族地址与固定端口时，两个族应各自拥有该端口。第 70 批产物复现第二族绑定失败，修订后两种首包顺序在 epoll/io_uring 均通过。 |
| VLESS、SS-2022、Trojan、AnyTLS、Snell | 具名出站经各自物理 TCP connector 使用 `TcpSocketOptions`。显式 direct 下层传直连配置 | Vision、XUDP、当前 SS UoT、Trojan/AnyTLS 数据报与 Snell 当前承载使用 TCP 物理拨号。原生 SS-2022 UDP 出站列于 72。各协议的 TFO/MPTCP 复验列于 71C。 |
| SOCKS5 / HTTP CONNECT | 具名出站使用通用 TCP 拨号，显式 direct 继承直连选项。HTTPS CONNECT 使用已选 TCP、Fast Open 或代理下层完成验证。 | SOCKS5 UDP ASSOCIATE 使用 TCP 成功选择的接口与数值中继。本地 UDP 专用字段作用于中继 socket。物理与显式 direct 提供 UDP，具名 TCP detour 用于 CONNECT。 |
| ShadowTLS | `StlsTunnel` 创建物理 TCP socket，代理下层经 `LowerConnector` | 自身配置进入 `prepare_tcp_socket`。显式 direct 传同一组物理参数；双后端互通测试均观察到配置的 `127.0.0.2` 源地址。物理 TFO 通过相同 connector 提交认证 ClientHello，显式 direct 继承物理配置。 |
| Hy2、TUIC、MASQUE | 客户端物理 UDP 经 `net/udp_connect.cppm` | 自身物理 UDP 或显式 direct 使用实际绑定。代理下层承载复用其 packet tunnel。TCP 专用拨号选项由配置检查拒绝。 |
| WireGuard/WARP | 具名出站经 `wireguard_outbound.cpp` 的 `SocketBinder` 与 `Port::open`。独立端点使用其 listen 地址和 `endpoint/owner.cppm` | 物理 UDP 绑定、mark、源端口及 DF。端点独占 socket，端点复用契约有单独约束。代理下层使用 packet tunnel。 |
| Tailscale | 具名出站读取独立 endpoint 文件，复用该端点的 transport | 普通出站拨号字段没有入口。物理 socket 保持端点所有权，后续按 81 延伸配置和网络换代。 |
| DNS 与具名 HTTP | 当前数值 DNS 的 UDP 与 DoQ 使用 `net/udp_connect.cppm`，TCP/DoT/DoH 走 TCP。规则下载 H3 的物理路径走 MASQUE 客户端 UDP 准备 | 具名加密 DNS detour、业务/引导传输能力和完整 HTTP client 拨号矩阵分别在 75、77 收敛。 |

第 71B 的 `netns` 与 `protect-path` 已接到物理 TCP、普通 UDP、QUIC UDP 和具名 WireGuard 外层的创建准备，两个后端已验证 SOCKS TCP/UDP、双族、broker 接收实际目标命名空间的 FD、拒绝/超时/恢复，及 Hy2 自带和继承 direct 两种双族物理 UDP。第 71C 已双后端验证双栈 TCP 的接口候选时限和回退、IPv6 UDP 的首包同步错误回退、旧流保留、protect 缩短到配置期限、direct/Trojan MPTCP，以及 TCP Fast Open 已提交与未提交两种路径。剩余协议与资源范围随对应批次验收。代理链由实际创建物理 socket 的下层负责，检查不能只看末端出站支持的业务网络。
