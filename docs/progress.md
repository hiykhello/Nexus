# 项目进度与交付基线

更新：2026-11-22。本文记录 Nexus 当前已验证交付基线（第 91–152 批）与后续工作约束。功能目标以 [功能完整度清单](planning/feature-completion.md)、[支持矩阵](planning/proxy-kernel-support-matrix.md) 和 [协议与内核演进蓝图](planning/protocol-and-kernel-roadmap.md) 为准，编码与工程规范遵循 [C++ 编码规范](development/cpp-guidelines.md) 与 [文件行数规范](development/file-sizes.md)。

---

## 当前交付状态（第 91–152 批全部已完成并验收）

### 1. 第 147–152 批 · 生产配置闭环、P1 协议、Capy/Corosio 升级收敛、OS 模块拆分与四端 GUI 联动
详细规划见 [next-batches-147-152.md](planning/next-batches-147-152.md)。

- **Batch 147（生产配置闭环、`dns.reverse-mapping`、三级 `http-clients`、托管规则集与 `-D`/`-C`）**：
  - 打通纯内存零 I/O 被动 `dns.reverse-mapping`（严守零隐式 DNS 原则）、顶层 `http-clients` + `route.default-http-client` + 单规则集覆盖、`inline`/`local`/`remote` 规则集（持久化缓存 + `ETag 304` + 原子快照热切换）、全场景持久 DNS 缓存、`HTTPS`/`SVCB` 空应答及 `-D <dir>`/`-C <dir>` 部署目录解耦；`batch147-unit` 与 `batch147_live_integration.py` 全绿。
- **Batch 148（`log-ring`、弱网多接口 `fallback`、TUN/精细 `reject`、`tls-record-fragment`、SNTPv4 与三端可观测对齐）**：
  - 落地有界 `log-ring`（`GET /v1/logs` 快照/SSE 流/`nexus control logs` 与 `GET /v1/connections/{id}`）、多接口 `fallback` + `500ms` 延迟 + `15s` 回退、Linux `exclude-mptcp`/`multi-queue`、精细 `reject` `method`/`no-drop`、`tls-record-fragment`、`tcp-prefix`、全协议 `certificate-sha256`、`ntp` SNTPv4；三端 GUI 统一对齐 `/v1/logs`、`/v1/connections/{id}` 与 KDL 2.0；`batch148-unit` 与 `batch148_live_integration.py` 全绿。
- **Batch 149（SOCKS4/4a、`fixed-udp`、Trojan/AnyTLS 传输、Snell v5 出站、Hy2 端口跳跃、Web 控制台与四端 GUI 深化）**：
  - 补齐 SOCKS4/4a、`fixed-udp`、Trojan/AnyTLS over WS/HTTPUpgrade/gRPC、Snell v5 出站、Hy2 随机端口跳跃、`route-options` 协议感知 UDP NAT 自适应超时、`rule explain` 一体化断言及只读安全沙箱 `dashboard-root`（托管 `web/` Vite 8 + Lit + `@elelcode/lit-router` 静态产物）；`batch149-unit` 与 `batch149_live_integration.py` 全绿。
- **Batch 150（SSHv2 隧道出站 + Phase A 核心 OS 原语）**：
  - 新增独立特性 `ssh`（RFC 4251–4254 `curve25519-sha256`、`aes128/256-gcm@openssh.com`、`chacha20-poly1305@openssh.com`、`ssh-ed25519`/ECDSA/密码认证、HostKey 指纹校验与 `direct-tcpip` 多路复用池），并补齐 `src/{logging,state,control_api}` Win32/Darwin 原语及三端 `ssh://` 导入；`batch150-unit` 与真实 `sshd` 端到端集成全绿。
- **Batch 151（H2/H3 HTTP 代理、NaiveProxy 双向与三端 GUI 体验收口）**：
  - 升级 HTTP 代理 H2 `CONNECT`/H3 `CONNECT` + `CONNECT-UDP`，落地零重型外部依赖的独立特性 `naive`（H2/H3 + 双向 `padding` + 伪装 HTML 回落）；收口 Desktop 系统托盘、Apple 自适应入口/`NetworkPathWatcher` 与 Android `TileService`/`ScreenStateMonitor`；`batch151-unit` 与 5 组实机套件全绿。
- **Batch 152（Capy `0.2.8`/Corosio `0.3.12` 升级、`[target.'cfg(...)'.build]` 模块拆分、三产物收敛与终审）**：
  - 升级 Capy 至 `0.2.8`（`6a956906`）与 Corosio 至 `0.3.12`（`2d246de8`），撤销 6 项 OOM/非模块化补丁，仅保留 3 项最小补丁（`cpo_modules.patch`、`thread_local_modules.patch`、`empty_datagram.patch`）；`nexus.proxy-fault-tests`（`root-launch` 两个启动分配故障 + `reconfigure` + `vless-accept`）、`nexus.thirdparty-tests` 与 `batch123-tcp-udp-datapath-unit` / `socket-binding-{tcp,udp}` 全绿。
  - 利用 `mcpp 2026.11.21.1` `[target.'cfg(...)'.build]` 完成 `src/{logging,state,control_api,dns,platform}/` 跨平台模块拆分（全仓 `src/` 零残留 `*_windows.hpp` 与 `http_socket.hpp`）；同步修复 `src/control_api/http_server.cpp` 控制面空闲连接超时 `kPeerTimeout = 2s`（SSE 保持 `30s`）。
  - 离线锁定重建 `target/batch152/{android-profile,epoll,uring}-cli`（`134 MiB` / `138 MiB` / `138 MiB`），全量通过 `low-memory-client.kdl`、ELF 符号隔离审计（`android-profile-cli` 零 `io_uring_setup`/`sd_journal`/`KtlsSession`/`tproxy_udp`/`liburing`/`libsystemd`）、三产物 Batch 129–131（`android-profile-cli` FDs `16→16 (Δ0)` / VmRSS `14.45→16.24 MiB`、`epoll-cli` FDs `15→16 (Δ1)` / VmRSS `14.49→16.55 MiB`、`uring-cli` FDs `14→14 (Δ0)` / VmRSS `15.18→17.07 MiB`）、三产物 Batch 147–151 + `trojan_network` + `batch95a` + `batch95c` 全绿、双后端 Batch 132/133（96/96 场景双向互通）+ `httpupgrade_cli_network`（workers=1/2）全绿、`web/dist`（`185ms`）构建与 Desktop C++26 三产物 CTest（均 **0.55s**）及全仓守护终审。

### 2. 第 141–146 批 · `mcpp 2026.11` 工作区现代化与历史包袱清理
详细规划见 [next-batches-141-146.md](planning/next-batches-141-146.md)。

- **Batch 141（历史迁移动态壳子与 `.gitignore` 清理）**：
  - 彻底移除 `mcpp/` 下 65 个前工作区历史迁移壳子（回收 30+ GiB 陈旧缓存与漂移清单），仅保留 5 个有效入口：`mcpp/{epoll,android-arm64,darwin-arm64,windows-x64,host-consumer}`；`mcpp/epoll/mcpp.lock` SHA-256 零变动；同步精简 `.gitignore` 23 行历史特化项。
- **Batch 142（`[workspace.dependencies]`、聚合 Profile Feature 与 `--strict` 规范对齐）**：
  - 根 `mcpp.toml` 升级 `[workspace.package] mcpp = ">=2026.11.20.1"`，新增 `[workspace.dependencies]` 统一 11 个内部测试/实验成员依赖版本；修复 `[workspace.profile.release]` `opt-level = 3` → `opt = 3`，新增 `[build] target_budget = "24GiB"` 与 `[pack] include = ["docs/**", "packaging/**"]`。
  - 新增 `profile-sidecar`、`profile-linux-epoll`、`profile-linux-uring` 三组聚合特性，三端清单从 28 行重复特性收口为单行 `features = ["profile-sidecar"]` 并对齐 `aarch64-macos` / `x86_64-windows-msvc` 三元组；全工作区与外部消费端 6 组 `--strict --configure-only --offline --locked` 零警告。
- **Batch 143 & 144（跨平台 `[target.'cfg(...)'.build] sources` 拆分与 `module :private;` 独立单元化）**：
  - 拆分 `src/platform/socket_namespace_{linux,darwin,windows}.cpp` 与 `src/proxy/{socket_uid,process_owner,session_splice}_{linux,stub}.cpp`，交由 `src/platform/mcpp.toml` 与 `src/proxy/mcpp.toml` 按目标操作系统自动路由编译。
  - 将高扇入模块 `src/http/header.cppm`（35 导入）、`src/tls/profiles.cppm`（34 导入）与 `src/sniff/quic.cppm` 的非 inline 实现体迁入 `module :private;`，利用 `mcpp 2026.11.17.2+` 自动分片减少级联重编。
- **Batch 145 & 146（`profile.ci` 测试、`release -O3 -flto` 打包、聚合三产物全矩阵回归与终审）**：
  - 根 `mcpp.toml` 添加 `[target.'cfg(not(os = "linux"))'.test]` 裁剪 Linux 专属单测；`mcpp test --strict --offline --locked --profile ci`（`http_header`/`dns_local_config`/`tcp_socket_options`）与 `batch135-138-unit`/`batch96b-ktls-unit`/`quic-sniff` 全部通过；将 `src/tools/proxy_dns_reload.hpp` 匿名 lambda 改为具名仿函数 `DnsRuleSource` 消除 GCC 16 `-O3 -flto` mangling ICE，`mcpp pack --offline --locked --pkg-format dir` 成功产出 `target/dist/batch145-pack`（含 `bin/nexus`、`docs/`、`packaging/{systemd,openwrt,completions}`）。
  - 使用全新聚合特性离线锁定重建 `target/batch146/{android-profile,epoll,uring}-cli`，通过 ELF 符号隔离审计、三产物 `low-memory-client.kdl` 校验、三产物 Batch 129–131（`android-profile` `15→16 / 13.77 MiB`、`epoll` `16→16 (Δ0) / 14.02 MiB`、`io_uring` `14→14 (Δ0) / 14.07 MiB`）、三产物 Trojan/控制面/策略组、双后端 96/96 多实现双向互通矩阵 + 多跳互通 + HTTPUpgrade、Desktop C++26 三产物 CTest（均 **0.51s**）及全仓守护审计。

### 3. 第 135–140 批 · 跨平台内核硬化与生产边缘场景深挖
详细规划见 [next-batches-135-140.md](planning/next-batches-135-140.md)。

- **Batch 135 & 136（三端套接字绑定抽象、宿主原语清障与平台安全默认值）**：
  - 新增 `src/platform/platform_defaults.cppm`：固化 Apple NetworkExtension 安全 MTU（`4064 = 4096 - UTUN_IF_HEADROOM_SIZE`）、Android `9000` MTU（防 `ENOBUFS`）、Linux TUN GSO `< 49152` 护栏、Darwin `pcblist_n` 8 字节对齐步长（`>=22: 408B / <22: 384B`）、Windows 特殊伪 PID `0/4`、Android `uid % 100000` AppID 归一化与 `/system/bin/app_process*` Zygote 噪声过滤、Windows `fec0::/10` 伪 IPv6 DNS 判定与 `IP_UNICAST_IF` 网络序 / `IPV6_UNICAST_IF` 主机序字节序辅助。
  - 解除 `src/platform/socket_options.cppm` 顶部 Linux 编译阻断，在 `socket_options.cppm` / `socket_namespace.cpp` 补齐 Linux / Darwin（`IP_BOUND_IF`/`IPV6_BOUND_IF`/`SO_NOSIGPIPE`）与 Windows（`IP_UNICAST_IF`/`IPV6_UNICAST_IF`/`SIO_UDP_CONNRESET`）分支，同时完整保留 Linux LP64 `static_assert`。
  - 移除 `src/proxy/socket_uid.cpp` 的 `<arpa/inet.h>`（全仓 `src/` `<arpa/inet.h>` 降至 **仅 1 处**：`src/proxy/tproxy_udp.cpp`），并对 `src/proxy/process_owner.cpp`（叠加 Android Zygote 过滤）、`src/proxy/session_splice.cpp` 及 `src/dns/local_config.cpp`（Darwin `st_mtimespec`/`st_ctimespec`）完成非 Linux 便携化守卫。
- **Batch 137 & 138（RFC 8305 双栈 Happy Eyeballs、`fec0::/10` DNS 过滤、kTLS 内核矩阵与 QUIC `0x1c` 嗅探）**：
  - 新增 `src/net/happy_eyeballs.cppm` 并在 `src/proxy/dial.cpp`（保持状态化 `condition` 游标与 DNS 首选地址族严格一致）及 `src/net/tcp_connect.cppm` 落地双栈地址族交错与 `300ms` 快速回落窗口；`src/dns/local_config.{cppm,cpp}` 新增 `is_usable_system_dns_server` 过滤 Windows `fec0::/10` 伪 IPv6 DNS 服务器。
  - `src/tls/ktls/ktls.{cppm,cpp}` 新增 `KtlsKernelSupport` / `parse_linux_kernel_release` / `probe_ktls_kernel_support`（`5.1` AES-GCM/RX、`5.11` ChaCha20、`5.19` `TLS_TX_ZEROCOPY_RO`、`6.0` `TLS_RX_EXPECT_NO_PAD`、`6.14` KeyUpdate），在旧内核提取用户态密钥前提前无损降级；`src/sniff/quic.cppm` 支持跳过 RFC 9000 Initial 包中的 `CONNECTION_CLOSE (0x1c)` 帧并拒绝截断载荷。
- **Batch 139 & 140（端侧 MTU 护栏同步、专项单测、三产物重建与全量终审）**：
  - 同步 Apple `NexusPacketTunnelProvider.swift` 与 `TunnelSettingsBuilder.swift` 默认与钳制 `maxSafeMtu = 4064`（对齐 Android `ProfileRepository.kt` `coerceIn(1280, 9000)`）；新增 `tests/batch135_138_cross_platform_edge_cases_unit.cpp`，与 `batch96b-ktls-unit`、`quic-sniff` 同步全绿。
  - 离线锁定重建 `target/batch140/{android-profile,epoll,uring}-cli`，通过 ELF 符号隔离、三产物 `low-memory-client.kdl` 校验、三产物 Batch 129–131（三产物均达到 **FDs Δ0**：`android-profile` `16→16 / 13.32 MiB`、`epoll` `16→16 / 13.82 MiB`、`io_uring` `14→14 / 13.48 MiB`）、三产物 `trojan_network.py`、双后端 96/96 多实现双向互通矩阵、控制面/策略组/HTTPUpgrade/Desktop 三产物 CTest（均 **0.51s**）及全仓守护审计。

### 4. 第 129–134 批 · 黑盒一致性/对抗测试套、多实现双向实机互通与兼容性修复
详细规划见 [next-batches-129-134.md](planning/next-batches-129-134.md)。

- **Batch 129–131（离线黑盒一致性、DNS/Sniffer 对抗与零泄漏压测）**：
  - 新增 `tests/batch129_stream_boundary_conformance.py`（1-byte 分片 SOCKS5/HTTP CONNECT、Mixed Content-Length/Chunked、双向独立 FIN 半关闭、39 组畸形包 Fuzz + 30 路 RST 风暴）、`tests/batch130_dns_sniffer_adversarial.py`（3-byte TLS SNI / 4-byte HTTP Host 端口剥离分片嗅探重放与阻断、HTTP CONNECT 预读 `403`、DNS 畸形包/TXID 伪造过滤/`TC=1` 回退 TCP/16 路慢上游并发竞速）与 `tests/batch131_concurrency_reload_leak_stress.py`（96 TCP + 24 多目标 UDP NAT 并发风暴中叠加 4 轮在线重载、切网、清缓存与 16 路一键断流）。
  - 三产物实机全绿，压力收尾 FD 与内存：`android-profile` FDs `16→16 (Δ0)` / `13.22 MiB`、`epoll` FDs `15→16 (Δ1)` / `13.89 MiB`、`io_uring` FDs `14→14 (Δ0)` / `14.04 MiB`。
- **Batch 132 & 133（多实现双向全协议实机互通与真实缺陷修复）**：
  - 通过独立代理实现 A（18 组双向矩阵：`tests/batch132_peer_a_interop.py`）与独立代理实现 B（30 组双向矩阵含全部 14 组 XHTTP H1/H2/H3 与后量子 REALITY `X25519MLKEM768`：`tests/batch133_peer_b_interop.py`）实机对拍，定位并修复 **3 处真实服务端兼容缺陷**：
    1. `src/xudp/server_sessions.cppm`：放行非零 8 字节 `GlobalID` 作为本地流会话，彻底打通主流客户端 VLESS(+Vision/REALITY/WS/gRPC) UDP；同步更新 `tests/protocol/xudp_server_sessions.cpp`。
    2. `src/grpc/headers.cppm`：TLS gRPC 服务端兼容 `:scheme: http` 与省略 `te` 头的轻量客户端（保留非法或重复 `te` 严格拒绝）；同步扩展 `tests/grpc_headers.cpp`。
    3. `src/httpupgrade/httpupgrade.cppm`：HTTPUpgrade 服务端放行客户端浏览器伪装 `Sec-WebSocket-*` 请求头，同时客户端响应侧仍严格拒绝 `Sec-WebSocket-Accept` 防止帧错配；同步更新 `tests/httpupgrade.cpp` 与 `tests/httpupgrade{_cli,}_network.py`。
- **Batch 134（三产物重建、全量复验与终审）**：
  - 离线锁定重建 `target/batch134/{android-profile,epoll,uring}-cli`，通过 ELF 符号隔离、3 组更新 C++26 单元单测、三产物 Batch 129–131、双后端 18+30=48 组多实现双向矩阵（共 96/96 实机场景全绿）、原有控制面/策略组/Trojan/HTTPUpgrade/多跳互通回归、Desktop C++26 三产物 CTest（均 **0.51s**）及全仓守护审计。

### 5. 第 123–128 批 · 数据面深度提速、kTLS 接入、低内存抗泄漏加固与超大规则集 $O(\log N)$ 索引
详细规划见 [next-batches-123-128.md](planning/next-batches-123-128.md)。

- **Batch 123（TCP/UDP 底层热路径提速与半关闭防泄漏）**：
  - `src/platform/socket_options.cppm` 与 `src/platform/socket_namespace.cpp` 新增 `tune_tcp_low_latency(fd, 20000ms)`（`TCP_NODELAY` + Linux `TCP_USER_TIMEOUT` 并附 `static_assert` 核验常量），接入 `net/tcp_connect.cppm`、`proxy/tcp_listener.cpp` 与 `proxy/session_direct_relay.hpp`；`session_interface.hpp` 与 `server_runtime.cpp` 新增 15s 独立半关闭空闲超时（活跃单向下载不受影响，静默僵尸连接快速回收）。
  - 新增 `src/platform/udp_batch.{cppm,cpp}`（零分配 Linux `recvmmsg`/`sendmmsg` 32 包批量收发与 `UdpGsoSender` `UDP_SEGMENT` 自动无损回退）并升级 `src/udp-runtime/listener_receive.hpp` 每次事件唤醒排空多包；`tests/batch123_tcp_udp_datapath_unit.cpp` 全绿。
- **Batch 124（Linux `kTLS` 接入 TLS 代理热路径）**：
  - 新增 M1 兼容空桩 `src/tls/ktls/ktls_disabled.cppm`，在 `src/tls/corosio_application.cppm` 与 `src/tls/byte_stream.cppm` 基于 `NEXUS_ENABLE_KTLS` 接入 `KtlsSession`（握手后零残留卸载、自动无损用户态降级、KeyUpdate 与 `close_notify` 协调），并接入 `src/proxy/trojan.cpp` 与 `src/proxy/tcp_proxy_impl.hpp`；ELF 核验 `android-profile` 零 `KtlsSession` 符号、`epoll`/`io_uring` 完整包含，`trojan_network.py` 双后端 workers=1/2 全绿。
- **Batch 125（H2/XHTTP 低内存护栏与 QUIC 断链孤儿清零）**：
  - `src/http2/{server,session_core}.cppm` 显式钳制并通告 RFC 9113 `SETTINGS_MAX_FRAME_SIZE`（默认 16 KiB，钳制区间 `[16 KiB, 16 MiB-1]`）；新增面向 50 MiB 移动端扩展与 128 MiB OpenWrt 路由器的 [low-memory-client.kdl](configuration/examples/low-memory-client.kdl) 并通过三产物 `check`。
  - `src/hysteria2/client.cppm`、`src/tuic/client.cppm` 与 `src/masque/client_session.cppm` 加固断链与停机级联回收，立即释放 UDP NAT 映射与收发队列并唤醒读协程；`tests/batch125_quic_udp_teardown_unit.cpp` 全绿。
- **Batch 126（超大 `rule-set` $O(\log N)$ 索引与 DNS 慢上游实机验证）**：
  - 新增 `src/rules/any_index.hpp` 并接入 `src/rules/{rules.cppm,matcher.cpp}`：对大型复合 `any` 规则集（`>= 16` 子节点）编译合并去重有序 IPv4/IPv6 CIDR 区间二分表与排序域名/后缀表，保持严格三态语义与拷贝安全；`tests/batch126_large_ruleset_bench.cpp`（16,001 条复合规则集）实测 **50,000 次查询 9,382 us（均摊 0.188 us/次 ≈ 533 万次/秒）**；`dns_evaluate_failure_network.py` 与 `dns_batch93c_network.py` 三产物全绿。
- **Batch 127（`io_uring` Buffer Ring 接入与 TUN 防环回加固）**：
  - `src/proxy/mcpp.toml` 补齐 `io-uring` 特性传播；`src/net/udp_dial.cppm` 新增 `local_endpoints()`，`src/tools/tun_udp.hpp` 落地源/目与本地绑定端点自环回熔断计数器（`udp_self_loop_drops`）及 `kMaxDirectUdpFlows = 4096` 上限；`tests/batch127_uring_and_tun_loop_unit.cpp`（TUN 自环回熔断 + `io_uring` Buffer Ring 4096 字节收发 0 泄漏槽位）全绿。
- **Batch 128（三产物终审、全量回归与实机吞吐/RSS 基准）**：
  - 离线锁定构建 `target/batch128/{android-profile,epoll,uring}-cli`，通过 ELF 符号隔离、三产物核心/DNS 回归、双后端 Trojan/SOCKS5 UDP NAT/Hy2/TUIC 双向互通回归、Desktop C++26 三产物 CTest（均 **0.51s**）及全仓守护审计。
  - 同机 512 MiB 回环 SOCKS5+`splice` 实测：`android-profile` **93.50 Gbps / 11.03 MiB RSS**、`epoll` **92.44 Gbps / 11.55 MiB RSS**、`io_uring` **91.99 Gbps / 11.51 MiB RSS**。

### 6. 第 117–122 批 · 控制面批断流/按需测速/诊断 API、EWMA 可观测、桌面系统护栏与发行打包
详细规划见 [next-batches-117-122.md](planning/next-batches-117-122.md)。

- **Batch 117（控制面批断流、按需测速与诊断/事件 API）**：
  - `src/tools/proxy_control.hpp`、`src/tools/proxy_control_operations.hpp` 与 `src/control_api/http_server.cpp` 新增 `DELETE /v1/connections`（`NEXUS/1 close-all`）、`POST /v1/groups/{name}/probe`（`NEXUS/1 probe <group>`，202 接受 / 409 非探活组 / 404 未知组）、`GET /v1/diagnostics` 与 `GET /v1/events`；`src/tools/control.cpp` 补齐 CLI 帮助与非 Linux POSIX/Darwin 客户端 UDS 兼容。
  - `tests/batch95c_control_http_metrics_network.py` 扩展双活跃 SOCKS5 会话一键批量断流 EOF、按需测速与诊断/事件实机校验，三产物全绿。
- **Batch 118（EWMA 与断路器状态可观测升级）**：
  - `src/tools/proxy_group_health.hpp` 新增 `trigger_probe(group)`（立即清零断路器并重排探测），在 `Observation`、`group-health` 与 `GET /v1/outbounds` JSON 中向上兼容透出 `ewma_ms` 与 `breaker_open`；`tests/batch112_group_health_unit.cpp` 全绿。
- **Batch 119（Desktop 系统代理原子快照、诊断护栏与防火墙模块）**：
  - `desktop/src/system_proxy.{cppm,cpp}` 支持 Linux `gsettings` 启用前原子快照与精确还原、静默无桌面降级与 `diagnostic_mode` 宿主机防篡改护栏；新增 `desktop/src/firewall_helper.{cppm,cpp}`（剥离 Windows `\\?\` / `\\?\UNC\` 前缀与回环防火墙规则幂等安装）；`desktop.http_control` 与 Slint UI 接入“断开全部”与“立即测速”；CMake 4.5 + GCC 16 `ctest` 针对 `target/batch122/{android-profile,epoll,uring}-cli` 全部 **0.51s** 通过。
- **Batch 120（Android 与 Apple 全端批断流/测速/诊断对齐）**：
  - Android（`NexusControlClient.kt`、`ConnectionsScreen.kt`、`GroupsScreen.kt`、`MainActivity.kt`、`CoreProtocolTest.kt`）与 Apple（`HttpControlClient.swift`、`ConnectionsView.swift`、`DashboardView.swift`、`NexusApp.swift`、`NexusCoreBridgeTests.swift`）同步接入批断流、按需测速、`DiagnosticsSnapshot` 及 `ewma_ms`/`breaker_open` 模型。
- **Batch 121 & 122（发行自动化打包与全量终审）**：
  - 同步 Bash/Zsh/Fish 补全脚本，新增 [packaging/README.md](../packaging/README.md) 与 `scripts/package-linux-release.sh`；离线锁定构建 `target/batch122/{android-profile,epoll,uring}-cli` 并实机产出 `epoll`/`uring` 发行压缩包（`sha256sum -c` 通过），全套回归与全仓守护审计 100% 通过。

### 7. 第 111–116 批 · 控制面断流/切网闭环、EWMA 防抖选路、全端打通与发行打包
详细规划见 [next-batches-111-116.md](planning/next-batches-111-116.md)。

- **Batch 111（控制面断流与切网事件闭环）**：
  - `src/tools/proxy_control_operations.hpp`、`src/tools/proxy_control.hpp` 与 `src/control_api/http_server.cpp` 新增 `DELETE /v1/connections/{id}`（`NEXUS/1 close-any <id>` 跨监听器关闭活跃连接，未知返回 `404`、非法返回 `400`）与 `POST /v1/network-change`（`NEXUS/1 network-change`，推进代次并立即触发出站组重探）。
  - `tests/batch95c_control_http_metrics_network.py` 实机覆盖活跃 SOCKS5 会话断开 EOF 与切网事件，三产物全绿。
- **Batch 112（`url-test` EWMA 平滑与断路器防抖）**：
  - `src/tools/proxy_group_health.hpp` 引入 EWMA 平滑（`alpha=0.3`）、连续 3 次失败断路器冷却（`>= 5000ms`，探测恢复或切网立即清零）与 `invalidate_network()` 重置钩子。
  - 新增 `tests/batch112_group_health_unit.cpp`（GCC 16 C++26 单测直接包含生产头验证尖峰抗抖、滞后切换、断路器隔离恢复与切网重置）全绿，双后端与 `android-profile` 实机 `batch95a` / `outbound_group_health_network` 全绿。
- **Batch 113（`<arpa/inet.h>` 进一步清零与 OS 边界硬化）**：
  - `src/tools/tun_host.cpp` 与 `src/tools/tun_udp.hpp` 迁至零 libc `platform.ip_address`，全仓 `src/` `<arpa/inet.h>` 降至仅 **2 处**底层 Linux 文件（`socket_uid.cpp`、`tproxy_udp.cpp`）；补齐 `src/state/file.cppm` `<fcntl.h>` 使 macOS `F_FULLFSYNC` 生效；`tests/batch99a_cross_platform.cpp` 56 解析 + 25 格式化对等单测全绿。
- **Batch 114（三端客户端断流与切网事件全打通）**：
  - **Android**：`NexusControlClient.kt` 新增 `closeConnection` / `notifyNetworkChange`，`ConnectionsScreen.kt` + `MainActivity.kt` 接入一键断流，`NexusVpnService.kt` 接入 `DefaultNetworkMonitor` 自动切网推送（断网传空数组防环回），扩展 `CoreProtocolTest.kt`。
  - **Desktop**：`desktop.http_control`、`connections_panel.slint`、`app_window.slint`、`desktop/src/main.cpp` 与 `desktop/tests/bridge_test.cpp` 全量打通；CMake 4.5 + GCC 16 `ctest` 针对 `target/batch116/{android-profile,epoll,uring}-cli` 全部 **0.43s** 实机通过。
  - **Apple**：`HttpControlClient.swift`、`ConnectionsView.swift`、`DashboardView.swift`、`NexusApp.swift`、`NexusPacketTunnelProvider.swift`（切网改走轻量 `notifyNetworkChange`）与 `NexusCoreBridgeTests.swift` 完整对齐。
- **Batch 115（Linux systemd / OpenWrt 打包与 Shell 补全工程）**：
  - 新增 `packaging/systemd/{nexus.service,nexus@.service}`（`DynamicUser`、`StateDirectory`、`CapabilityBoundingSet` 与 `ExecReload` `nexus check` 预校验）、`packaging/openwrt/{nexus.init,Makefile}`（`procd` 自愈与 SquashFS `/tmp` 布局）与 `packaging/completions/{nexus.bash,_nexus,nexus.fish}`；`bash -n`、`sh -n` 与 `nexus check --config` 干跑正反校验全绿。
- **Batch 116（三产物终审与全量回归）**：
  - 离线锁定构建 `target/batch116/{android-profile,epoll,uring}-cli`，通过 ELF 符号隔离审计、`batch95c`、`batch95a`、双向互通压测、`selector_state_network`、Desktop 三产物 CTest 与全仓守护检查。

### 8. 第 105–110 批 · 控制面闭环、OS 抽象层、四端 CI/CD 与生产级客户端
详细规划见 [next-batches-105-110.md](planning/next-batches-105-110.md)。

- **Batch 105 & 106（HTTP `/v1` 清缓存闭环 + 跨平台 OS 抽象层）**：
  - `src/control_api/http_server.cpp` 补齐 `POST /v1/state/clear-cache`（支持 `all`/`dns`/`rulesets` 与非法 target `400` 拒绝）并接入 `src/tools/proxy_control.hpp`；移除 Linux 专属 `accept4`、`explicit_bzero` 与 `MSG_NOSIGNAL`。
  - `src/tools/proxy_run.cppm` 移除 `<arpa/inet.h>`（全仓 `src/` 仅余 **3 处** Linux 宿主文件：`socket_uid.cpp`、`tproxy_udp.cpp`、`tun_host.cpp`）。
  - `src/logging/{fd.cppm,sink.cpp}`、`src/state/file.cppm`、`src/platform/unix_socket_impl.hpp` 与 `src/tools/control.cpp` 补齐 POSIX/Darwin 兼容原语（`sigwait`、非 `O_PATH` 目录打开、`F_FULLFSYNC`、`getpeereid`、`arc4random_buf`、无 `/proc/self/fd` 与 `accept` 回退）。
  - 离线锁定构建 `target/batch105/{android-profile,epoll,uring}-cli`，三产物 ELF 审计、`batch95c_control_http_metrics_network.py` 与 `selector_state_network.py` 全绿。
- **Batch 107（四端 Profile 与 CI/CD）**：
  - 新增 `mcpp/darwin-arm64/mcpp.toml`（`kqueue`）与 `mcpp/windows-x64/mcpp.toml`（`iocp`），与 `mcpp/android-arm64/mcpp.toml` 组成四端构建清单；落地 `.github/workflows/ci-cross-platform.yml` 及 `scripts/build-{android-arm64,desktop,apple}.sh`。
- **Batch 108（Android 生产级完善）**：
  - 新增 `ProfileRepository.kt`（多配置档案、HTTPS/Base64 订阅导入与 `0600` 密钥隔离）、`ConnectionsScreen.kt`、`ConfigScreen.kt`、完整 `res/` 资源与 `CoreProtocolTest.kt` 订阅隔离测试。
- **Batch 109（Desktop Slint v1.19 + C++26 生产级完善）**：
  - 新增 `desktop.profile_store`、`parse_connections_json`、`connections_panel.slint` / `profiles_panel.slint` 并接入 `app_window.slint` 与 `desktop/src/main.cpp`；CMake 4.5 + GCC 16 (`import std;`) `ctest` 针对 `target/batch105/{android-profile,epoll,uring}-cli` 全部 **0.39s** 实机通过。
- **Batch 110（Apple Swift 6 `NEPacketTunnelProvider` 与终审）**：
  - 新增 `KeychainTokenStore.swift`、`NexusPacketTunnelProvider.swift`、`ConnectionsView.swift`，`HttpControlClient.swift` 补齐 `/v1/connections` 解码与 `clearCache(target:)`，扩展 `NexusCoreBridgeTests.swift`。

### 9. 第 99–104 批 · 跨平台内核解耦与全端客户端基座
详细规划见 [next-batches-99-104.md](planning/next-batches-99-104.md)。

- **内核解耦与 ARM64 移植（Batch 99–101）**：纯 C++26 零 libc `constexpr` IPv4/IPv6 解析与严格 RFC 5952 格式化器（`src/platform/ip_address.cppm`，56 例 `inet_pton` + 25 例 `inet_ntop` 对等单测全绿）；修复 `aarch64` `O_NOFOLLOW=32768` 并放宽 6 处 LP64 守卫；`src/state/` 全面改用 BoringSSL `crypto::random_bytes`；新增 `nexus check [--config] <config.kdl>` 干跑校验；落地 `mcpp/android-arm64/mcpp.toml` 与 [跨平台 OS 边界矩阵](platform/cross-platform-os-boundaries.md)。
- **三端基座（Batch 102–104）**：完成 Android（`ShareLinkParser.kt`、`GroupsScreen.kt`、`SplitTunnelScreen.kt`、自适应 `NavigationBar`/`NavigationRail`、`:bg` `NexusVpnService`）、Desktop（`desktop.http_control`、实时 `/metrics`、分享链接 `0600` 密钥导入）与 Apple（Swift 6 `actor` `HttpControlClient.swift`、`GroupsPane`）并完成三端 `/v1` JSON 线协议统一对齐。

### 10. 第 91–98 批 · Linux x86-64 双后端正式收官基线
详细规划见 [next-batches-91-96.md](planning/next-batches-91-96.md)，完整验收汇总见 `target/batch98/summary.md`。

- **Batch 91（异步日志）**：`logging` 模块族、无锁每生产者环形槽 + 单 writer `writev`、轮转/reopen、`Redacted<T>` 脱敏与可选 `log-journald`。
- **Batch 92（四层持久化）**：`state` 模块族、NXST01/BLAKE3 selector、FakeIP 256 地址段预留 + WAL、NXDN03 多视图 DNS 缓存、NXRS01 规则集缓存与故障恢复验收。
- **Batch 93（路由与 DNS 增强）**：有序 `route-only`、逻辑 `rule-set`、`tls-ech`、routed TUN DSCP/MAC/mark、出站 `domain-resolver` 具名 DNS 视图、响应压缩与原生 nftables `auto-redirect`。
- **Batch 94（现代协议与 uTLS）**：REALITY `X25519MLKEM768` + fallback、VLESS XHTTP（H1/H2/H3/xmux）、现代浏览器 TLS 指纹与 1-RTT PSK 恢复、全仓生产模块零旧前缀迁移。
- **Batch 95（策略组、TPROXY 与控制面）**：严格 `probe-expected-status`、`url-test` 手动覆盖/`--auto`、HTTP/2 `PING` 探活、64-FD 有界 `TproxyReplySocketCache`、HTTP `/v1/*`（常量时间 Bearer 鉴权）与低基数 OpenMetrics `/metrics`。
- **Batch 96（下一代性能引擎）**：per-worker `DirectBufferPool`/`SplicePipePool`、零定时器 `YieldToExecutor`、256 KiB splice 自动晋升、可选 Linux kTLS（`tls.ktls`）、`io_uring` Provided Buffer Ring + Multishot Recv（`platform.uring_buf_ring`）、自研 TUN 栈 RFC 6298/7323 + SACK/PMTU + 32 包批量泵及 `containers.cache_index`（CLOCK + 侵入式 LRU）。
- **Batch 97 & 98（全矩阵互通、弱网拷打与发布验收）**：双后端 46/46 互通 + `tc netem` 弱网/丢包/乱序/MTU 黑洞压测通过；42/42 集成/长稳/故障/热重载通过；同机基准 `epoll + splice` **46.7 ms/GiB / 19.2–19.6 Gbps / 11.16 ms P95 / 13.2 MiB RSS / 143 FDs**，`io_uring + splice` **53.3 ms/GiB / 19.4–20.2 Gbps / 10.78 ms P95 / 13.8 MiB RSS / 141 FDs**。

---

## 仓库守护与硬约束

- 默认 `mcpp/epoll/mcpp.lock` SHA-256 锁定为 `91580f265b74fafc8fe626e128401535fc0a61e8a70757f3264b2e14757d06ac`。
- 生产 `src/` 严禁 `nexus.` / `nexus::` 模块前缀，不新增虚函数，保持 `scripts/mcpp-generate-pinned-guard.py --check`、`scripts/check-source-lines.sh` 与 `git diff --check` 全绿。
- 仅在用户明确指示时执行 `git commit` / `git push`。
