# 协议矩阵补齐与内核能力演进蓝图

更新：2026-11-22。本文在既有架构决策（见 [ADR 0008](../decisions/0008-protocol-priorities-and-vmess-deprecation.md)）与当前生产支持矩阵（见 [proxy-kernel-support-matrix.md](proxy-kernel-support-matrix.md)）基础上，系统沉淀 Nexus 下一阶段的协议矩阵补齐顺序、明确排除范围，以及结合双端真实生产部署架构与现代代理内核实践提炼的十二项内核增强能力。

---

## 1. 当前协议基线与排除边界

### 1.1 已完成生产覆盖

- **核心与透明入口**：`direct`、`block`、`dns`、`socks`（SOCKS5 TCP/UDP）、`http`（HTTP/1.1 CONNECT + 正向代理 + 上游 TLS）、`mixed`、`fixed-tcp`、`redirect`（Linux TCP）、`tproxy`（Linux TCP/UDP）、`tun`（routed + 外部 FD + 严格路由 + `auto-redirect`）。
- **现代代理与隧道协议**：`shadowsocks`（SS-2022 TCP/UDP/UoT）、`vless`（TLS / REALITY / Vision / XUDP / WS / gRPC / HTTPUpgrade / XHTTP H1/H2/H3）、`trojan`、`anytls`、`hysteria2`（Salamander / Brutal）、`tuic`（v5）、`masque`（CONNECT-UDP + CONNECT-IP L3 双向）、`wireguard`（+WARP）、`tailscale`（+DERP）、`snell`（出站 v4 / 入站 v5）、`shadowtls`（v3）、`group`（selector / url-test / fallback）。
- **DNS 与规则引擎**：`local`、`udp`、`tcp`、`tls`（DoT）、`https`（DoH H1/H2）、`h3`（DoH3）、`quic`（DoQ）、`fakeip`、`predefined`、`resolved`、乐观缓存、并发竞速（`evaluate`/`race`/`speculative`）及超大规则集 $O(\log N)$ 索引。

### 1.2 明确排除范围（保持架构克制）

1. **过时或弱安全协议**：VMess、经典 Shadowsocks AEAD/旧流加密与 SSR、旧版插件接口与明文混淆（`sip003`/`simple-obfs`）、Hysteria v1、已废弃的旧版 QUIC/仅 H2 私有传输。
2. **已有原生替代或非核心杂项**：第三方兼容控制面 API（Nexus 统一使用原生 `/v1/*` + OpenMetrics `/metrics` + 本地 UDS）、与代理转发无关的外设/AI 凭据代理服务。

---

## 2. 协议矩阵分梯队补齐清单

| 梯队 | 协议 / 能力 | 方向与核心特性 | 复用与设计边界 |
| --- | --- | --- | --- |
| **P1 · 立即推进** | **既有协议小缺口收口** | ① SOCKS4 / SOCKS4a 入出站兼容<br>② 固定目的 UDP 入站（`fixed-udp`）<br>③ Trojan / AnyTLS 叠加 WS / HTTPUpgrade / gRPC 传输<br>④ Snell v5 出站（含可选 v5 QUIC 评估） | 复用既有传输与转发层，改动小、覆盖高频边缘与 CDN 反代场景 |
| **P1 · 立即推进** | **SSH 隧道（`ssh`）** | 出站；SSHv2 传输层、`curve25519-sha256`、`aes-gcm`/`chacha20-poly1305`、`ed25519`/ECDSA/密码认证、严格 HostKey 指纹校验、`direct-tcpip` 多路复用 | 完全基于既有 BoringSSL `libcrypto` 自研精简实现，零新增第三方密码/网络库 |
| **P1 · 立即推进** | **现代 HTTP 代理（H2/H3）与 NaiveProxy（`naive`）** | 出站 + 入站；HTTP/2 & HTTP/3 `CONNECT` 多路复用（H2 自动回落 H1.1）、HTTP/3 `CONNECT-UDP`、双向 `padding` 抗流量分析填充 | 基于既有 BoringSSL + uTLS 拟态指纹 + `nghttp2`/`nghttp3` 原生实现，避免引入重型浏览器网络栈依赖 |
| **P2 · 服务端与局域网体验** | **ACME 自动证书（`acme`）与 L4 SNI 分流** | HTTP-01 / TLS-ALPN-01 / DNS-01 自动签发续签 + 无解密四层 SNI 同端口多路复用分发 | 复用既有具名 HTTP 客户端与 BoringSSL X.509/CSR，小内存 VPS 可单进程承载同端口代理与合规 HTTPS 服务 |
| **P2 · 服务端与局域网体验** | **DNS 传输补齐（`dhcp` / `mdns`）** | `dhcp` 动态发现上游 DNS；`mdns` 解析局域网 `.local` 服务与主机名 | 显著提升桌面端、移动端与 OpenWrt 路由器的切网与内网体验 |
| **P2 · 服务端与局域网体验** | **服务端运维与内存守护** | ① 独立 **DERP 中继服务（`derp`）**<br>② **SS-2022 多用户管理接口（`ssmapi`）**<br>③ **低内存水位自保看门狗** | 形成自建 Mesh 服务端闭环；支持动态用户与计量；护航 iOS 50 MiB 扩展与低配路由器 |
| **P3 · 企业 VPN 与专用隧道** | **OpenVPN（`openvpn`）** | Endpoint / Client（后续可选 Server）；TLS 控制通道 + AEAD 数据通道 | 直接复用 Nexus L3 TUN Endpoint 抽象与 BoringSSL |
| **P3 · 企业 VPN 与专用隧道** | **OpenConnect（`openconnect`）** | Endpoint；HTTPS/TLS 认证 + CSTP / DTLS 数据隧道 | 覆盖主流企业 SSL VPN 接入场景 |
| **P3 · 企业 VPN 与专用隧道** | **反向穿透入站 & L3 物理桥接（`bridge`）** | 无公网 IP 边缘隧道反向接入；虚拟流量透明桥接至物理二/三层接口 | 按网关与边缘穿透场景按需启用独立编译特性 |
| **P4 · 可选轻量外接** | **Tor 匿名分流出站** | 对接外部本地匿名路由进程的轻量封装（SOCKS/Control 桥接） | 不内嵌重型匿名网络核心库，保持主二进制体积与审计面收敛 |

---

## 3. 从真实双端部署与现代架构提炼的十二项内核增强点

结合真实桌面端（Linux 透明 TUN + 严格路由 + 双栈/纯 IPv4 混合多级出口 + 本地/远程规则集 + Web 控制台）、移动端（免 Root VPN + 弱网多网卡切换 + 离线规则缓存 + 射频续航调优）与小内存 VPS 服务端（443 同端口多路复用 + 平滑硬排空重载 + 无感诊断排障）的一线工程实践，提炼以下 12 项核心增强能力：

> **核心不变量约束（零隐式 DNS 活动）**：无论新增何种规则集、IP 条件或 `dns.reverse-mapping`，流量路由匹配阶段始终严格坚持“**除非显式配置 `action = "resolve"`，否则绝不隐式发起任何 DNS 网络查询**”（详见 [routing-dns-and-state.md](../design-principles/routing-dns-and-state.md)）。`dns.reverse-mapping` 严格限于纯内存零 I/O 被动查表；缺失 IP 的域名目标在遇到 `ip_cidr` / GeoIP 规则时按三态逻辑静默跳过，绝不阻塞或泄漏本地 DNS 查询。

| 编号 | 领域 | 增强项 | 工程动机与设计要点 |
| --- | --- | --- | --- |
| **K1** | **DNS / 路由** | **打通 `dns.reverse-mapping` 被动反向域名映射** | `src/dns/reverse.cppm` 与 `OrderedTcpDomain::reverse_dns` 骨架已就绪但配置层尚未放开；打通后仅在纯内存零 I/O 被动索引既有 DNS 应答，在纯透明 TUN（不依赖 FakeIP）场景下即可直接按真实域名命中路由规则，绝不主动发查 |
| **K2** | **规则集与三级 HTTP 客户端** | **三级 `http-clients` 架构 + 托管式 `inline`/`local`/`remote` 规则集（离线常驻 + `ETag 304`）** | 确立“顶层 `http-clients` 实体池 → `route.default-http-client`（默认推荐直连根除冷启动互锁）→ 单规则集微观覆盖”三级模型；在 `nexus run` 内托管远程规则集持久化缓存、后台 `ETag 304` 零流量比对与原子路由快照热切换 |
| **K3** | **可观测与排障** | **常驻内存环形日志缓冲（`log-ring`）与单连接全链路详情查询** | 生产配置常驻 `level = "warn"` 时，内核仍在有界内存 FIFO 环形缓冲区保留 `trace`/`debug` 级 SNI 嗅探、规则命中与 DNS 解析元数据；控制面提供 `/v1/logs`（支持一次性回溯快照导出、`-f` 实时流、`--level` 过滤与 `--search` 检索）及 `/v1/connections/{id}` 全链路详情，彻底告别重启复现与粗粒度系统日志 |
| **K4** | **部署与 CLI 运维** | **工作根目录 `-D <dir>` 原生相对路径、`-C <dir>` 目录加载与重载硬排空护栏** | 支持 `-D <dir>` 对齐 systemd `StateDirectory`，使本地规则集/缓存/静态面板天然使用相对路径消除跨用户权限陷阱；支持 `-C <dir>`（严格仅加载 `*.kdl` 忽略 `.bak`，重名精确报源文件）；校验重载硬排空上限防止长连接 `tcp-keep-alive` 滞留旧代次；扩展 `nexus rule explain` 支持 DNS+路由一体化交互断言 |
| **K5** | **移动弱网与多接口容灾** | **多接口并行容灾拨号（`fallback` + `500ms` 延迟 + `15s` 快速回退窗口）与移动续航护栏** | 单接口在线时零开销直通；WiFi 假死或蜂窝切换时在延迟窗口后并行拨号备用接口并维持 15s 快速回退记忆；支持按出站差异化 `tcp-keep-alive`（降基带唤醒）、跨洋 `connect-timeout` 推荐基线（覆盖 TCP SYN `0→1→3→7s` 重传）、Android `exclude-package`（放行 Captive Portal）并明确校验移动端不得误配 `strict-route` |
| **K6** | **TUN / nftables** | **Linux TUN `exclude-mptcp` 与配置化 `multi-queue`** | 在 Linux `auto-redirect` nftables 规则中放行 MPTCP 子流避免透明劫持异常；将 `src/packet/tun_linux.cpp` 已有的 `IFF_MULTI_QUEUE` 配置化暴露以释放多 Worker 吞吐 |
| **K7** | **路由 `reject` 策略** | **精细 `reject` 模式（`default` 0ms RST/ICMP vs `drop`）与 `no-drop` 防风暴限流** | 面向纯 IPv4 出口与直连场景，对 `ip_version=6` 瞬时回发 TCP RST / ICMP Unreachable 迫使客户端 0ms 回退 IPv4 Happy Eyeballs；默认开启 30s 内 50 次触发自动切 `drop` 防风暴保护，显式 `no-drop` 保持秒拒 |
| **K8** | **DNS 缓存与记录过滤** | **全场景持久化 DNS 缓存（有界写缓冲）+ `AAAA`/`HTTPS`/`SVCB` 空 `NOERROR` 快捷过滤** | 解除 `message-cache-directory` 仅限直连数值上游与内联规则的限制并增加写缓冲减少闪存磨损；支持 `query-type` 符号名（含 `HTTPS(65)`/`SVCB(64)`）与零记录 `predefined rcode="NOERROR"`，源头阻断 CNAME 跟随与 `ipv6hint` 泄漏 |
| **K9** | **抗干扰数据面** | **`route-options` 轻量 TLS Record 分片（`tls-record-fragment`）、TCP 分段与 `tcp-prefix`** | 在自研 TLS 写入层对 ClientHello 执行可配置 Record 分片，零外部依赖应对基础明文 SNI 过滤 |
| **K10** | **TLS 信任与同端口复用** | **全协议 `certificate-sha256` 固定、顶层 `certificate` 信任库热重载与 L4 SNI 无解密分流** | 将证书 SHA-256 固定推广至全部 TLS/QUIC 协议并统一 CA 根库热更新；服务端提供轻量无解密 L4 SNI 分流能力（搭配 P2 ACME 与只读静态托管），大幅降低单机多服务内存开销 |
| **K11** | **时钟健壮性** | **内置轻量 SNTPv4 时钟偏移校准服务（`ntp`）** | 极简 UDP SNTPv4 维护单调偏移量，保护无 RTC 路由器与时钟漂移环境下的 SS-2022（30s 时间窗）与 TLS 有效期校验 |
| **K12** | **资源、网关与弱网优化** | **协议感知 UDP NAT 自适应超时、Endpoint `on-demand`、Hy2 端口跳跃、网关规则与 `dashboard-root`** | `dns`/`ntp`/`stun` 10s、`quic`/`dtls` 30s 降低 NAT 内存峰值；Endpoint 空闲自动休眠省电；Hy2 周期随机端口跳跃抗限速；网关 `source-mac-address`/声明式 `network-namespaces` 及控制面只读 `dashboard-root` 静态目录托管 |

---

## 4. 跨平台内核原语与四端 GUI 同步演进矩阵

为避免“内核能力超前、桌面与移动外壳脱节”，第 148–155 批同步推进跨平台 OS 原语与四端 GUI（全部复用统一 `/v1/*` HTTP 控制面、`/metrics` 与本地 IPC，严格维持外壳与 C++26 内核进程隔离）：

| 端侧 / 层次 | 载体与工程目录 | 第一阶段融合目标（第 148–152 批） | 第二阶段深化目标（第 153–155 批） |
| --- | --- | --- | --- |
| **Desktop GUI（Linux / Windows）** | `desktop/`（Slint v1.19 + C++26 `import std;` + CMake 4.5） | ① 接入 `GET /v1/logs`（`log-ring` 回溯、级别/域/关键词过滤、导出）与 `GET /v1/connections/{id}` 详情抽屉；② 概览实时上下行速率/折线、`Rule Explain` 交互测试台；③ `CoreSupervisor` 注入 `-D <data-dir>` 与原生系统托盘快捷菜单；④ 修复并扩展 `ShareLinkParser` 支持全部 P1 新协议与 KDL 2.0 语法。 | Windows Wintun / 系统服务安装器、Linux `systemd --user` 联动、可视化规则集与 DNS 规则编辑器、安装包签名与自动更新框架。 |
| **Android GUI & Bridge** | `android/`（Kotlin 2.4 + Jetpack Compose Material3 + `:core-bridge`，零 JNI） | ① 修复 `AndroidKdlBuilder` 与 `NexusVpnService`（对齐 KDL 2.0 字段、统一 `noBackupFilesDir` UDS、默认放行 Captive Portal、去重桥接类）；② Compose 接入 `/v1/logs` 回溯检索、连接详情（联动 `ConnectionOwnerResolver` 包名/SNI/规则）与平板/折叠屏自适应 Edge-to-Edge 布局；③ `TileService` + `ScreenStateMonitor` 续航联动与 `ShareLinkParser` 同步。 | `aarch64-linux-musl` 产物自动化 APK 打包校验、离线规则集状态卡片、低电/计费网策略切换面板。 |
| **Apple GUI & Bridge（macOS / iOS）** | `apple/`（Swift 6 + SwiftUI + `NexusCoreBridge` + `NEPacketTunnelProvider`） | ① `HttpControlClient` 接入 `/v1/logs` 与 `/v1/connections/{id}`；② 补齐 macOS `LogsPane` 与连接详情视图，并抽取 `NexusSharedUI` 提供 iOS/iPadOS 自适应 `TabView`/`NavigationSplitView` 入口；③ App Group `-D` 目录、`< 50 MiB` 扩展内存水位指示、`NetworkPathWatcher` 联动 `/v1/network-change` 与 `ShareLinkParser` 同步。 | Darwin `utun` 原生直通联调、Xcode Network Extension 签名工程模板、macOS `SMAppService` 后台守护一键管理。 |
| **通用 Web Dashboard** | `web/`（pnpm + Node + Vite 8 + Lit + `@elelcode/lit-router`，静态构建产物接入 `dashboard-root`） | 极简原生 Web Components 单页控制台（概览、策略组切换/测速、连接列表与详情、内存环形日志检索、只读诊断），编译后由 `control-http` 静态沙箱托管，供 OpenWrt / Linux 路由器 / 无头 VPS 浏览器零运行时依赖直管。 | 规则命中实时流视图、ACME 证书有效期与 `ssmapi` 多用户计量只读面板。 |
| **跨平台核心 OS 原语** | `src/{logging,state,control_api,packet,platform}/`（`[target.'cfg(...)'.build] sources`） | 第 150 批补齐 Win32 日志/状态文件原语（`CreateFileW`/`WriteFile`/`LockFileEx`/`MoveFileExW`）、Darwin `F_FULLFSYNC`、WinSock2 控制面 HTTP 与 Named Pipe 桥接。 | Windows Wintun (`tun_windows.cpp`)、Darwin `utun` (`tun_darwin.cpp`) 原生 L3 适配器与跨平台 CI 交叉编译矩阵验证。 |

---

## 5. 批次切分总览

- **第一阶段（第 147–152 批，详见 [next-batches-147-152.md](next-batches-147-152.md)）**：同步落地 **K1–K11 核心项 + K12 轻量项**、全部 **P1 协议**（小缺口收口、`ssh` 出站、现代 H2/H3 HTTP 代理与 `naive` 双向）、**Windows/Darwin 日志/状态/控制面核心 OS 原语（含基于 `mcpp` `[target.'cfg(...)'.build]` 的模块拆分与 Capy `0.2.8` / Corosio `0.3.12` 收敛）**以及 **四端 GUI（Desktop Slint / Android Compose / Apple SwiftUI / Web Dashboard）深度联动**。
- **第二至四阶段（第 153–158 批，已完成，详见 [next-batches-153-158.md](next-batches-153-158.md)）**：第 **153** 批完成全端统一 **Clang (`llvm@23.1.3`) + C++26（零 `-freflection`，`libc++` 静态链接）**、多平台新版 CI（`ubuntu-latest` / `windows-latest` / `macos-latest`，`actions/*@v6-@v7`）、跨平台 OS 原语 Phase B 与 `mcpp 2026.11.21.1` 工程化；第 **154–156** 批落地 **P2 能力**（`acme` + L4 SNI 无解密分流、DNS `dhcp`/`mdns`、独立 `derp-server` 中继、`ssmapi`、`memory.watchdog`）、**K12 剩余项**（Endpoint `on-demand`、`source-mac-address` ARP 邻居查询、声明式 `network-namespaces`）与四端 GUI 进阶面板；第 **157–158** 批落地 **P3 企业 VPN（`openvpn`、`openconnect`、`reverse-tunnel`、`bridge`）**、**P4 外接 Tor 封装（`tor`）**、全协议基准及基于 `mcpp fetch` 的离线发行流水线。
- **第五阶段（第 159–166 批，详见 [next-batches-159-162.md](next-batches-159-162.md) 与 [next-batches-163-166.md](next-batches-163-166.md)）**：第 **159–162** 批完成 XHTTP H1/H2/H3 HTTP 状态检查、MASQUE 证书指纹透传、三端分享链接修正、拆除 `nexus.compat` 消除代码侧 `nexus::` / `thirdparty.*` / `test.*` 前缀与工作区清理；第 **163–166** 批进一步移除 `thirdparty.`/`nex::`/工作区内部 `namespace = "nexus"` 与 `deps-tests`，推进 `mcpp-index` 多平台化、BLAKE3 ARM64 NEON 与 BoringSSL 无 `--noexecstack` 适配、Apple（macOS + iOS `XCFramework`）双形态 C ABI 交付与 Release/CI 对齐。
