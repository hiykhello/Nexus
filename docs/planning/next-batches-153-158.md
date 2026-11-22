# 第 153–158 批 · 全端统一 Clang + C++26（无 `-freflection`）、新版多平台 CI 闭环与 P2/P3/P4 演进规划

更新：2026-11-22。本规划承接 [protocol-and-kernel-roadmap.md](protocol-and-kernel-roadmap.md) 与 [next-batches-147-152.md](next-batches-147-152.md)，在第 152 批完成 Capy `0.2.8` / Corosio `0.3.12` 升级收敛及基于 `mcpp` `[target.'cfg(...)'.build]` 的跨平台模块拆分后，统筹推进 **方案 A（全端统一 Clang + C++26，移除 `-freflection`）** 与新版跨平台 CI 闭环、P2 服务端与局域网能力、以及 P3/P4 企业级隧道扩展。

---

## 编译期策略：方案 A（全端统一 Clang + C++26，移除 `-freflection` / `<meta>`）

1. **全端统一采用 Clang + `-std=c++26`（零 `-freflection` 依赖）**：Linux（`x86_64` / `aarch64`）、Android 免 Root sidecar（`aarch64-linux-musl`）、OpenWrt（`*-linux-musl`）、Windows 与后续 Apple 端统一收敛至主流 **Clang + C++26**，移除 `dialect_cxxflags = ["-freflection"]`，跨平台标准库差异通过静态链接解决。
2. **仅移除 `<meta>` 反射，零重写 C++26 库基础设施**：
   - **CLI（[src/tools/main.cpp](../../src/tools/main.cpp)）**：移除仅此 1 处的 `#include <meta>` / `std::meta::*`，改为等价的零开销 `constexpr` 静态命令分发表；
   - **`glaze-kdl` 序列化**：直接运行于标准反射路径（`GLZ_REFLECTION26 = 0`），完全满足当前及后续结构体规模；
   - **零改动保留 C++26 核心库类型**：保留仓内已稳定运行的 `std::inplace_vector`（32 文件）、`std::function_ref`（32 文件）、`std::copyable_function`（3 文件）及 `#embed` 守护，避免无谓大面积重构，各端通过静态链接完整标准库实现零缺口落地。
3. **优先通过新版 CI 多平台原生矩阵构建**：依托 `.github/workflows/ci-cross-platform.yml`（`ubuntu-latest` / `windows-latest` / `macos-latest` 与最新版 Actions `checkout@v7` / `setup-java@v6` / `upload-artifact@v7` / `setup-node@v7` / `pnpm/action-setup@v6` / `cache@v6`），不强制依赖 `mcpp` 托管交叉工具包。

---

## 批次规划表（第 153–158 批）

| 批次 | 主题 | 核心交付切片 | 验收标准 | 状态 |
| --- | --- | --- | --- | --- |
| **153** | **方案 A（Clang + C++26 无 `-freflection`）迁移、新版多平台 CI 闭环与 OS 原语 Phase B** | A. **Clang + C++26 无 `-freflection` 迁移**：在工作区与 `mcpp/*` 移除 `-freflection` 并优先选用 Clang（保持 `standard = "c++26"` 与 `desktop/CMakeLists.txt` `cxx_std_26`）；仅将 `src/tools/main.cpp` `<meta>` 替换为零开销 `constexpr` 静态命令表，**零重写**保留全部 `std::inplace_vector` / `std::function_ref` / `std::copyable_function` / `#embed`，`glaze-kdl` 自动运行于 `GLZ_REFLECTION26 = 0`，跨平台产物通过静态链接标准库打包。<br>B. **新版 CI 修复与全端矩阵落地**：升级 `.github/workflows/ci-cross-platform.yml` Runner 至 `ubuntu-latest` / `windows-latest` / `macos-latest`，Actions 升至 `checkout@v7` / `setup-java@v6` / `upload-artifact@v7` / `setup-node@v7` / `pnpm/action-setup@v6` / `cache@v6`；修复 `Repo Audits` 离线缓存脚本（CI 无 `.tar.gz` 时按模式运行检查）、移除已废弃 `setup-android@v3`（直接复用预装 Android SDK）、初始化 MSVC 环境修复 `desktop-windows` 并纳入 Linux Clang C++26 + Web 构建校验；补齐 `3rdparty/mcpp-index/pkgs/n/*.lua` 多平台描述。<br>C. **跨平台核心 OS 原语 Phase B**：将 `src/state/{snapshot,ruleset_*,fakeip_*}.cpp` 迁至 `state.file` + `platform.os_fs`（打通 Win32 全链路编译）；补齐 Windows Wintun（`tun_windows.cpp`）、Darwin `utun`（`tun_darwin.cpp`）、Windows/Darwin 进程归属，以及 `src/rulefile/posix.cpp` / `src/packet/fd.cppm` 的 `cfg` 拆分。<br>D. **`mcpp 2026.11.21.1` 工程化落地**：全仓升级 `mcpp >= 2026.11.21.1`，配置 `[build] memory_threshold` 与 `[xlings] archives`；将 `mcpp why features --format json` 接入 CI 守卫（锁死 `profile-sidecar` 不含 `io-uring`/`ktls`/`log-journald`/`tproxy-udp`）；清理陈旧 `target/` 缓存并评估 `desktop/`（Slint 1.19.0）`mcpp pack` 接入。 | 本地 Clang + C++26（无 `-freflection`）全工作区构建与核心单测/实机回归全绿；GitHub Actions `Nexus Cross-Platform CI` 全部作业（`Repo Audits`、`Linux`、`Android APK`、`Desktop Windows`、`Apple Swift 6`、`Web`）100% 变绿；`mcpp why features` 侧车隔离守卫与 Phase B 原语单测全绿。 | 待开始 |
| **154** | **服务端同端口闭环：`acme` 自动证书与无解密 L4 SNI 分流** | A. 新增独立编译特性 `acme`：复用具名 HTTP 客户端与 BoringSSL X.509/CSR 实现 HTTP-01 / TLS-ALPN-01 / DNS-01 自动签发、续期与原子证书热替换。<br>B. 新增无解密四层 SNI 同端口多路复用分发，支持单进程在 443 端口共存承载代理入站、合规 HTTPS 与只读 Web 控制台。 | 本地模拟 ACME 目录/挑战服务端完整走通 HTTP-01/ALPN-01/DNS-01 签发续期热替换；443 单端口 SNI 多路复用并发与误报回落验证全绿。 | 待开始 |
| **155** | **局域网 DNS（`dhcp` / `mdns`）、独立 `derp` 中继、`ssmapi` 与低内存自保** | A. 新增 DNS `dhcp` 上游自动发现与 `mdns`（`.local` 主机与服务解析）。<br>B. 落地独立 `derp` 中继服务特性、SS-2022 多用户动态管理与计量接口（`ssmapi`），以及低内存水位自保看门狗（护航 iOS 50 MiB NE 扩展与 128 MiB 路由器）。 | `dhcp`/`mdns` 协议解析与本地网络集成、独立 `derp` 握手转发、`ssmapi` 动态增删/限额与低内存阈值触发回收测试全绿。 | 待开始 |
| **156** | **K12 剩余高级路由项与四端 GUI 进阶管理面板** | A. 内核补齐 Endpoint `on-demand` 空闲休眠、网关 `source-mac-address` 匹配与声明式 `network-namespaces`。<br>B. 四端 GUI 进阶：Desktop Windows Wintun/系统服务安装器 + `systemd --user` + 可视化规则/DNS 编辑器 + 打包签名；Android `aarch64-linux-musl` APK 一键产物校验与离线规则集卡片；Apple `utun` 原生直通联调与 `SMAppService`；Web 控制台实时规则命中流与 ACME/`ssmapi` 只读面板。 | Endpoint 休眠唤醒与网关规则单测实测通过；Desktop CTest / Slint UI、Android Gradle/APK、Apple Swift 6 Test 与 Web 构建静态联调全绿。 | 待开始 |
| **157** | **P3 企业 VPN 与专用隧道：`openvpn`、`openconnect`、`bridge` 与反向穿透** | A. 基于现有 L3 TUN Endpoint 与 BoringSSL 新增独立特性 `openvpn`（TLS 控制 + AEAD 数据通道）与 `openconnect`（HTTPS/TLS 认证 + CSTP/DTLS 数据隧道）。<br>B. 新增反向穿透入站与 L3 物理桥接（`bridge`）。 | 本地独立对端下 `openvpn`/`openconnect`/反向穿透/`bridge` 数据转发、重连、半关闭与隔离 feature 构建测试全绿。 | 待开始 |
| **158** | **P4 外接 Tor 封装、全协议长稳基准与 `mcpp fetch` 离线发布流水线** | A. 新增轻量外接 `tor` 出站封装（仅通过外部进程 SOCKS/Control 桥接，零重型库内嵌）。<br>B. 建立全协议吞吐/RSS 长稳回归基准与基于 `mcpp fetch --to/--from` 的全平台冷缓存离线打包发布流水线，执行全仓终审。 | `tor` 外接链路测试、全协议基准门禁、`mcpp fetch --to/--from` 冷缓存全平台打包及仓库全量审计 100% 通过。 | 待开始 |
