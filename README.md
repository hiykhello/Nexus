# Nexus

Nexus 是采用 **C++26 Modules** 从零打造的现代通用代理平台（同时支持 `client` 与 `server`），内置高性能自研 TLS/uTLS、用户态 TUN/TCP/IP 协议栈、有序路由与 DNS/FakeIP 引擎、`epoll` / `io_uring` 双事件引擎与原生 HTTP/UDS 控制面，并提供面向 **Android**、**Windows / Linux Desktop** 与 **macOS / iOS** 的轻量原生客户端外壳。

---

## 核心技术特性

| 领域 | 选型与实现 |
| --- | --- |
| 语言与模块 | Clang（`llvm@23.1.6`）+ C++26 Modules（显式 `this`、concepts、尾置返回类型、零 `-freflection` 静态表分发与独立 `containers`/`functional`/`utility` 叶子基础包，`libc++` 静态链接），尽量无异常（`std::expected` / `std::optional`） |
| 异步与 I/O 引擎 | [cppalliance/corosio](https://github.com/cppalliance/corosio) + [ngcpp/proxy](https://github.com/ngcpp/proxy)，支持 Linux `epoll` 与 `io_uring`（含 Provided Buffer Ring + Multishot Recv）及 `splice(2)` / Linux kTLS 快速路径 |
| 协议与承载 | Direct / Block、SOCKS4/4a/5 / Mixed、HTTP/HTTPS CONNECT（H1/H2/H3）、NaiveProxy（H2/H3 + padding）、SSHv2 隧道、SS-2022（TCP / 原生 UDP / UoT + `ssmapi`）、VLESS（TLS 1.2/1.3 / REALITY `X25519MLKEM768` / Vision / WS / HTTPUpgrade / gRPC / XHTTP / XUDP / packetaddr）、Trojan、AnyTLS、Hysteria 2、TUIC v5、MASQUE（`CONNECT-UDP` / `CONNECT-IP`）、WireGuard / WARP（含 `on-demand`）、Tailscale（+ 独立 DERP 中继）、Snell v5、ShadowTLS v3、OpenVPN、OpenConnect、反向穿透、`bridge` 与外接 Tor 桥接 |
| 网络栈与透明代理 | 自研用户态 TUN（TCP/IP/UDP 栈、RFC 6298/7323、SACK/PMTU、`IFF_VNET_HDR` / 多队列）、原生 nftables `auto-redirect`、Linux REDIRECT / TPROXY TCP & UDP |
| TLS 与密码学 | 自研 TLS 1.2/1.3 与现代浏览器指纹编排（含 1-RTT PSK 恢复与 ECH）；密码原语统一采用静态 BoringSSL `libcrypto`，不引入第三方 `libssl` |
| HTTP 与 DNS | 自研 HTTP/1.1 + `nghttp2`（HTTP/2）+ `ngtcp2`/`nghttp3`（HTTP/3）具名客户端；多视图 DNS（UDP/TCP/DoT/DoH/DoQ/DoH3/`dhcp`/`mdns`）、乐观缓存、FakeIP 与嗅探 |
| 配置与规则集 | KDL 2.0（[glaze-kdl](https://github.com/hiykhello/glaze-kdl)，`GLZ_REFLECTION26 = 0` 标准反射路径），支持 KDL/BEVE 双向转换、SRS 子集导入与远程热更新 |
| 持久化与日志 | 四层崩溃安全状态存储（selector、FakeIP 段预留 + WAL、DNS 与规则集内容寻址缓存）；无锁异步日志管线（text/JSONL/轮转/journald）与低内存看门狗 |
| 控制面与观测 | 本地 `NEXUS/1` UDS / Windows Named Pipe、Loopback HTTP `/v1/*`（Bearer 常量时间鉴权、策略组切换/`--auto`、断流、切网重探、日志级别、热重载、清缓存、`acme`、L4 SNI 分流、`ssmapi`）与低基数 OpenMetrics `/metrics` |
| 全平台与运维 | **Android**（Kotlin 2.x + Jetpack Compose + `VpnService`）、**Desktop**（Slint v1.19 + C++26 `import std;`）、**Apple**（Swift 6 + SwiftUI + `NEPacketTunnelProvider`）、**Web**（Vite 8 + Lit），附 `packaging/` systemd / OpenWrt / Shell 补全 |

> 同机压测基线（Linux x86-64）：`epoll + splice` 吞吐 **19.2–19.6 Gbps**、CPU **46.7 ms/GiB**、**13.2 MiB RSS**、`io_uring + splice` 吞吐 **19.4–20.2 Gbps**。

---

## 快速开始

```bash
# 1. 干跑校验 KDL 2.0 配置
./nexus check --config docs/configuration/examples/socks5.kdl

# 2. 启动代理核心
./nexus run --config docs/configuration/examples/socks5.kdl

# 3. 构建并运行 Desktop C++26 Bridge 实机联调测试
NEXUS_CORE_BIN=./nexus ./scripts/build-desktop.sh
```

完整构建与运行包说明见 [mcpp 工作区构建](docs/build/mcpp-workspace.md) 与 [Linux 运行包说明](docs/build/runtime-package.md)。

---

## 文档导航

完整目录见 **[文档总导航](docs/README.md)**：

- **项目与原则**：[项目定位](docs/project/overview.md) · [核心架构原则](docs/design-principles/core-architecture.md) · [性能与数据面原则](docs/design-principles/performance-and-datapath.md) · [路由/DNS/状态原则](docs/design-principles/routing-dns-and-state.md) · [协议与策略组原则](docs/design-principles/protocols-and-groups.md) · [多平台运维原则](docs/design-principles/platform-and-operations.md)
- **核心架构**：[总体架构](docs/architecture/overview.md) · [协议解耦](docs/architecture/protocols.md) · [自研 TUN](docs/architecture/tun.md) · [自研 TLS 与指纹](docs/architecture/tls.md) · [路由引擎](docs/architecture/routing-engine.md) · [DNS 与乐观缓存](docs/architecture/dns.md) · [状态与缓存](docs/architecture/state-and-cache.md) · [控制面与 IPC](docs/architecture/control-api.md)
- **多端客户端**：[Android 外壳](android/README.md) · [Desktop (Slint + C++26)](desktop/README.md) · [Apple (Swift 6 + SwiftUI)](apple/README.md) · [发行打包与运维](packaging/README.md) · [跨平台 OS 边界矩阵](docs/platform/cross-platform-os-boundaries.md)
- **配置与开发**：[KDL 配置规范](docs/configuration/spec.md) · [规则集格式](docs/configuration/rule-sets.md) · [配置示例](docs/configuration/examples/README.md) · [C++ 编码规范](docs/development/cpp-guidelines.md) · [项目进度](docs/progress.md)
