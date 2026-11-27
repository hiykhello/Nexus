# Nexus 文档导航

本目录保存 Nexus 的项目定位、工程设计原则、核心架构规范、跨平台方案、配置参考、技术决策与演进规划。

---

## 1. 项目定位与当前状态

| 文档 | 内容 |
| --- | --- |
| [项目定位](project/overview.md) | 平台目标、client/server 角色定义与技术约束 |
| [Linux 代理内核支持矩阵](planning/proxy-kernel-support-matrix.md) | 已接入协议、入口、特性开关与适用边界 |
| [依赖与选型](technology/dependencies.md) | 核心依赖职责、BoringSSL `libcrypto` 底座与边界约束 |

---

## 2. 工程设计原则

| 文档 | 内容 |
| --- | --- |
| [核心架构原则](design-principles/core-architecture.md) | 类型注册分离、分阶段生命周期、协议与转发解耦、窄平台 Facade |
| [性能与数据面原则](design-principles/performance-and-datapath.md) | 转发公平性、可证明加速切换（`splice`/kTLS）、内存回收、UDP 批处理与基准纪律 |
| [路由、DNS 与状态原则](design-principles/routing-dns-and-state.md) | 首命中与三态逻辑、多维 DNS 缓存键与乐观刷新、原子落盘与 FakeIP 段预留 |
| [协议与出站策略组原则](design-principles/protocols-and-groups.md) | 协议线规边界、HTTP 连接池租约、EWMA/断路器/滞后选路状态机 |
| [多平台集成与运维原则](design-principles/platform-and-operations.md) | Linux nftables/systemd、Android 免 Root VPN、macOS 验签、Windows 代理/防火墙与 OpenWrt |
| [GUI 设计系统与交互原则](design-principles/gui-design-system.md) | CLI/GUI 产品边界、桌面零滚动 4 行 Bento 控制台、哑光视觉与 GPU/内存红线、四端统一基线 |
| [GUI 旗舰设计与逐界面规范](design-principles/gui-flagship-spec.md) | 四档仪器主题与 WCAG AA 基准、实时链路拓扑仪、全局命令与内联域名诊断、遥测微可视化与四端逐界面验收 |

---

## 3. 核心架构与协议设计

| 分类 | 文档 | 内容 |
| --- | --- | --- |
| 总体 | [总体架构](architecture/overview.md) | 分层、数据路径与生命周期 |
| 总体 | [组件模型](architecture/component-model.md) | 注册、路由上下文、生命周期与装配 |
| 总体 | [C++ Modules](architecture/modules.md) · [源码目录规划](architecture/source-tree.md) | 模块组织、依赖方向与工作区布局 |
| 总体 | [并发与多线程](architecture/concurrency.md) · [性能与资源设计](architecture/performance.md) | worker 所有权、批处理、加速通道与资源预算 |
| 协议 | [入站、出站与协议解耦](architecture/protocols.md) | 协议家族、承载组合、数据面契约与编译裁剪 |
| 协议 | [SOCKS5 / Mixed](architecture/protocols/socks5-mixed.md) · [VLESS / Trojan / SS-2022](architecture/protocols/vless-trojan-ss.md) · [REALITY](architecture/protocols/reality.md) | 经典与现代代理协议边界、流控与抗重放 |
| 协议 | [SS-2022 重放状态](architecture/protocols/ss2022-replay-state.md) · [WireGuard / WARP](architecture/protocols/wireguard.md) · [Hysteria 2 / QUIC](architecture/protocols/hysteria2.md) | 数据报隧道、抗重放与 QUIC 承载 |
| TLS/HTTP | [自研 TLS](architecture/tls.md) · [uTLS 指纹引擎](architecture/utls-engine.md) · [TLS/QUIC 恢复](architecture/tls-resumption.md) · [QUIC 1-RTT](architecture/quic-resumption.md) | 握手引擎、现代浏览器指纹、PSK 与 ECH |
| TLS/HTTP | [BoringSSL libcrypto](architecture/boringssl-libcrypto.md) · [Linux kTLS](architecture/ktls.md) | 密码原语底座与内核 TLS 零拷贝卸载 |
| TLS/HTTP | [HTTP/HTTPS/H2](architecture/http.md) · [具名 HTTP 客户端](architecture/http-clients.md) · [HTTP 代理线规](architecture/http-proxy-spec.md) | 自研 HTTP/1.1、`nghttp2`/`nghttp3` 与 MASQUE |
| 网络栈 | [自研 TUN 栈](architecture/tun.md) | 设备接入、用户态 TCP/IP/UDP 与资源配额 |
| 路由/DNS | [路由匹配与热重载](architecture/routing-engine.md) · [路由元数据与嗅探](architecture/routing-metadata.md) | 有序规则、索引、借用周期、嗅探与反查 |
| 路由/DNS | [DNS 与乐观缓存](architecture/dns.md) · [Fake-IP 与嗅探](architecture/dns-fakeip-engine.md) | 解析视图、TTL、负缓存、乐观刷新与双向映射 |
| 存储/运维 | [缓存与持久状态](architecture/state-and-cache.md) · [持久状态清单](architecture/persistence-inventory.md) · [四支柱配置边界](architecture/config-boundary.md) | Core 无数据库持久化（KDL/BEVE/原子快照/WAL）与客户端配置边界 |
| 存储/运维 | [规则集二进制格式](architecture/rule-set-format.md) · [BEVE 状态模型](architecture/beve-schemas.md) | BEVE 封装、索引边界与逻辑结构 |
| 存储/运维 | [原生控制面与 IPC](architecture/control-api.md) · [日志系统](architecture/logging.md) | HTTP `/v1/*`、OpenMetrics `/metrics`、本地 UDS 与异步日志 |

---

## 4. 多平台架构与客户端工程

| 文档 | 内容 |
| --- | --- |
| [跨平台 OS 边界矩阵](platform/cross-platform-os-boundaries.md) | Linux / Android / Windows / Apple OS 原语与移植对照 |
| [跨平台前序解耦路线](platform/cross-platform-prep.md) | POSIX 头文件清理与跨端演进步骤 |
| [平台抽象与宿主集成](platform/abstraction.md) · [跨平台 TUN 防环回](platform/tun-routing-and-loopback.md) | 窄平台能力、句柄所有权与路由防环策略 |
| [Linux 网络集成](platform/linux/networking.md) · [Linux 服务运维](operations/linux-service.md) · [发行打包与补全](../packaging/README.md) | nftables、策略路由、systemd 单元、OpenWrt `procd` 与 Shell 补全 |
| [Android 免 Root 指南](platform/android/non-root-integration-guide.md) · [ARM64 ABI 核查清单](platform/android/kernel-aarch64-checklist.md) | `VpnService`、`DnsResolver`、UDS `SCM_RIGHTS` 与 `aarch64-linux-musl` 适配 |
| [Windows 与 macOS 架构蓝图](platform/desktop-windows-macos-design.md) | Slint v1.19 C++26 桌面端、Swift 6 / SwiftUI 与 `NetworkExtension` |

---

## 5. 配置、构建与开发规范

| 分类 | 文档 | 内容 |
| --- | --- | --- |
| 配置 | [KDL 2.0 设计](configuration/kdl.md) · [配置规范](configuration/spec.md) · [规则集互转](configuration/rule-sets.md) · [配置示例](configuration/examples/README.md) | KDL 语法、完整配置字段、规则集与成对示例 |
| 构建 | [mcpp 工作区](build/mcpp-workspace.md) · [第三方模块封装](build/third-party-modules.md) · [QUIC 依赖](build/quic-dependencies.md) | 构建入口、离线锁与第三方模块边界 |
| 开发 | [C++ 编码规范](development/cpp-guidelines.md) · [C++26 数据结构](development/cpp26-data-structures.md) · [文件行数规范](development/file-sizes.md) · [模块与特性策略](development/module-feature-policy.md) | 错误处理约定、基础容器选型、300/500 行规范与模块边界 |
| 开发 | [Socket 绑定](development/socket-binding.md) · [TCP Fast Open](development/tcp-fast-open.md) · [上游问题跟踪](development/upstream-issues.md) | 底层网络细节与工具链/上游补丁边界 |

---

## 6. 架构决策记录（ADR）

| 编号 | 决策文档 | 核心结论 |
| --- | --- | --- |
| 0001 | [初始技术基线](decisions/0001-platform-baseline.md) | 平台定位、C++ Modules、KDL 2.0 与异步栈基线 |
| 0002 | [自研网络栈与 TLS](decisions/0002-self-developed-network-stack.md) | 自研 TUN TCP/IP 栈与自研 TLS/指纹引擎 |
| 0003 | [C++ 错误处理](decisions/0003-cpp-error-handling.md) | 尽量无异常，优先 `std::expected` / `std::optional` |
| 0004 | [现代 C++ 能力](decisions/0004-modern-cpp.md) | Clang `llvm@23.1.6` + C++26 Modules、显式 `this`、concepts、尾置返回与零 `-freflection` |
| 0005 | [HTTP 实现方向](decisions/0005-http-stack.md) | 自研 HTTP/1.1 + 无 I/O `nghttp2`/`nghttp3` |
| 0006 | [规则集格式与互转](decisions/0006-rule-set-formats.md) | KDL 2.0 与 BEVE 可逆语义转换 |
| 0007 | [BoringSSL 底座与 kTLS](decisions/0007-boringssl-libcrypto-and-ktls.md) | 静态 `libcrypto` 密码底座（无第三方 `libssl`）与 kTLS 卸载 |
| 0008 | [协议优先级与旧协议排除](decisions/0008-protocol-priorities-and-vmess-deprecation.md) | 聚焦现代安全协议，明确排除 VMess 与经典 SS AEAD |

---

## 7. 路线图与验证计划

| 文档 | 内容 |
| --- | --- |
| [实施路线](planning/roadmap.md) · [协议与内核演进蓝图](planning/protocol-and-kernel-roadmap.md) · [功能完整度清单](planning/feature-completion.md) · [拨号字段覆盖](planning/dial-field-coverage.md) | 总体演进路径、协议矩阵补齐顺序、内核增强与能力覆盖清单 |
| [网络栈验证](planning/network-validation.md) · [性能验证](planning/performance-validation.md) · [Linux 集成验证](planning/linux-validation.md) · [Linux 内核验收](planning/proxy-kernel-linux-validation.md) · [DNS 与状态验证](planning/dns-state-validation.md) | 各子系统测试策略与实机验收基线 |
| [内核审计缺陷与修复跟踪](planning/kernel-audit-findings.md) | 基线 `d10c429` / `0e52ae8` 及 Round 3–4 四轮内核专项审计发现（`13 P1 + 17 P2 + 1 P3`，共 31 项）根因、修复设计与回归验收清单 |
