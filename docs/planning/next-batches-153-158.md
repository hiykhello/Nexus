# 第 153–158 批 · GCC 16 统一反射与多平台 CI 闭环、以及 P2/P3/P4 演进规划

更新：2026-11-22。本规划承接 [protocol-and-kernel-roadmap.md](protocol-and-kernel-roadmap.md) 与 [next-batches-147-152.md](next-batches-147-152.md)，在第 152 批完成 Capy `0.2.8` / Corosio `0.3.12` 升级收敛及基于 `mcpp` `[target.'cfg(...)'.build]` 的跨平台模块拆分后，统筹推进活跃端 GCC 16 + `-freflection` 多平台 CI 闭环（Linux / Android / OpenWrt / Windows MinGW；macOS/iOS 内核构建暂缓待反射策略单独讨论）、P2 服务端与局域网能力，以及 P3/P4 企业级隧道扩展。

---

## 编译期策略：活跃端统一 GCC 16 + C++26 `-freflection`（macOS/iOS 内核构建暂缓）

1. **活跃内核目标统一采用 GCC 16 + `-freflection`**：Linux（`x86_64` / `aarch64`）、Android 免 Root sidecar（`aarch64-linux-musl`）、OpenWrt（`*-linux-musl`）与 Windows（`x86_64-windows-gnu` MinGW/GCC 16）全部原生使用 **GCC 16 + `-freflection`**，让 CLI（`src/tools/main.cpp` 等）与 `glaze-kdl` 持续享受完整 C++26 P2996 反射能力，**不为非 GCC 编译器引入任何反射降级分叉或适配包装模块**。
2. **优先通过 CI 多平台原生/系统工具链矩阵构建**：跨平台内核与客户端验证优先依托 `.github/workflows/ci-cross-platform.yml` 原生 Runner 与系统/CI 工具链完成，不强制依赖 `mcpp` 托管交叉工具包（后者仅作可选本地途径）。
3. **macOS / iOS 内核构建暂缓、后续单独讨论**：由于 Apple 生态当前主线工具链尚未原生具备完整 C++26 反射能力，暂缓 `aarch64-macos`/iOS C++26 内核构建与相关反射妥协，绝不因此令其他活跃端构建拐弯；`apple/` Swift 6 GUI 与 `NexusCoreBridge` 外壳测试保持独立演进。

---

## 批次规划表（第 153–158 批）

| 批次 | 主题 | 核心交付切片 | 验收标准 | 状态 |
| --- | --- | --- | --- | --- |
| **153** | **GCC 16 多平台 CI 闭环、跨平台 OS 原语 Phase B 与 `mcpp 2026.11.21.1` 工程化** | A. **GCC 16 统一多平台内核基线**：保持根工作区与活跃端 `dialect_cxxflags = ["-freflection"]` 零妥协；将 `mcpp/windows-x64/mcpp.toml` 对齐 `x86_64-windows-gnu`（MinGW/GCC 16 + WinSock2/IOCP），在 `mcpp/darwin-arm64/mcpp.toml` 标注 macOS/iOS 内核构建暂缓待反射策略单独讨论。<br>B. **`mcpp-index` 与多平台 CI 矩阵打通**：补齐 `3rdparty/mcpp-index/pkgs/n/*.lua` 多平台描述（`nexus.boringssl-crypto-source.lua` 解除 `archs = { "x86_64" }` 并补 `aarch64`/Windows 汇编或 `OPENSSL_NO_ASM` 回退、`nexus.corosio-source.lua` 按 Windows 条件改用 WinSock 系统库）；在 `.github/workflows/ci-cross-platform.yml` 完善 Linux（GCC 16）、Windows（MinGW/GCC 16 + Desktop CTest）、Android（`aarch64-linux-musl` + APK）CI 矩阵（不强制下载 `mcpp` 托管交叉工具链；macOS/iOS 暂仅运行 Apple Swift 6 GUI 桥接测试）。<br>C. **跨平台核心 OS 原语 Phase B**：将 `src/state/{snapshot,ruleset_*,fakeip_*}.cpp` 迁至 `state.file` + `platform.os_fs`（打通 Win32 全链路编译）；补齐 Windows Wintun（`tun_windows.cpp`）与 Windows 进程归属（IP Helper Table），以及 `src/rulefile/posix.cpp` / `src/packet/fd.cppm` 的 `cfg` 拆分（保留 Darwin 骨架文件不破坏结构，不阻塞其他端）。<br>D. **`mcpp 2026.11.21.1` 工程化落地**：全仓升级 `mcpp >= 2026.11.21.1`，配置 `[build] memory_threshold` 与 `[xlings] archives`；将 `mcpp why features --format json` 接入 CI 守卫（锁死 `profile-sidecar` 不含 `io-uring`/`ktls`/`log-journald`/`tproxy-udp`）；定期 `mcpp clean --stale` 控制 `target/` 体积并评估 `desktop/`（Slint 1.19.0）`mcpp pack` 接入。 | Linux（GCC 16）、Android `aarch64-linux-musl`（`profile-sidecar`）与 Windows `x86_64-windows-gnu`（MinGW/GCC 16）CI/实机全链路构建与单测通过；全活跃端保持 GCC 16 + `-freflection` 零回退分支；`mcpp why features` 侧车隔离守卫与 Phase B 原语单测全绿。 | 待开始 |
| **154** | **服务端同端口闭环：`acme` 自动证书与无解密 L4 SNI 分流** | A. 新增独立编译特性 `acme`：复用具名 HTTP 客户端与 BoringSSL X.509/CSR 实现 HTTP-01 / TLS-ALPN-01 / DNS-01 自动签发、续期与原子证书热替换。<br>B. 新增无解密四层 SNI 同端口多路复用分发，支持单进程在 443 端口共存承载代理入站、合规 HTTPS 与只读 Web 控制台。 | 本地模拟 ACME 目录/挑战服务端完整走通 HTTP-01/ALPN-01/DNS-01 签发续期热替换；443 单端口 SNI 多路复用并发与误报回落验证全绿。 | 待开始 |
| **155** | **局域网 DNS（`dhcp` / `mdns`）、独立 `derp` 中继、`ssmapi` 与低内存自保** | A. 新增 DNS `dhcp` 上游自动发现与 `mdns`（`.local` 主机与服务解析）。<br>B. 落地独立 `derp` 中继服务特性、SS-2022 多用户动态管理与计量接口（`ssmapi`），以及低内存水位自保看门狗（护航 iOS 50 MiB NE 扩展与 128 MiB 路由器）。 | `dhcp`/`mdns` 协议解析与本地网络集成、独立 `derp` 握手转发、`ssmapi` 动态增删/限额与低内存阈值触发回收测试全绿。 | 待开始 |
| **156** | **K12 剩余高级路由项与四端 GUI 进阶管理面板** | A. 内核补齐 Endpoint `on-demand` 空闲休眠、网关 `source-mac-address` 匹配与声明式 `network-namespaces`。<br>B. 四端 GUI 进阶：Desktop Windows Wintun/系统服务安装器 + `systemd --user` + 可视化规则/DNS 编辑器 + 打包签名；Android `aarch64-linux-musl` APK 一键产物校验与离线规则集卡片；Apple `utun` 原生直通联调与 `SMAppService`；Web 控制台实时规则命中流与 ACME/`ssmapi` 只读面板。 | Endpoint 休眠唤醒与网关规则单测实测通过；Desktop CTest / Slint UI、Android Gradle/APK、Apple Swift 6 Test 与 Web 构建静态联调全绿。 | 待开始 |
| **157** | **P3 企业 VPN 与专用隧道：`openvpn`、`openconnect`、`bridge` 与反向穿透** | A. 基于现有 L3 TUN Endpoint 与 BoringSSL 新增独立特性 `openvpn`（TLS 控制 + AEAD 数据通道）与 `openconnect`（HTTPS/TLS 认证 + CSTP/DTLS 数据隧道）。<br>B. 新增反向穿透入站与 L3 物理桥接（`bridge`）。 | 本地独立对端下 `openvpn`/`openconnect`/反向穿透/`bridge` 数据转发、重连、半关闭与隔离 feature 构建测试全绿。 | 待开始 |
| **158** | **P4 外接 Tor 封装、全协议长稳基准与 `mcpp fetch` 离线发布流水线** | A. 新增轻量外接 `tor` 出站封装（仅通过外部进程 SOCKS/Control 桥接，零重型库内嵌）。<br>B. 建立全协议吞吐/RSS 长稳回归基准与基于 `mcpp fetch --to/--from` 的全平台冷缓存离线打包发布流水线，执行全仓终审。 | `tor` 外接链路测试、全协议基准门禁、`mcpp fetch --to/--from` 冷缓存全平台打包及仓库全量审计 100% 通过。 | 待开始 |
