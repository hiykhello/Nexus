# 跨平台前序解耦清单与移植路线

更新：2026-11-20。本清单基于全仓源码扫描（48 个含 Linux/POSIX 系统头文件的文件与协议导入关系），为第 98 批收官后启动 Windows / macOS 跨平台移植提前扫清耦合边界。

## 1. 跨平台前可顺手清掉的 4 处耦合尾巴（随第 91–98 批去前缀捎带完成）

1. **统一随机数入口，消除 `linux_random` 泄露**：
   - `src/wireguard/port.cppm`、`src/anytls/auth.cppm`、`src/relay/wireguard_outbound.cpp`、`src/tools/tun_host.cpp` 当前直接导入 `nexus.platform.linux_random`。
   - 改为统一走 `crypto::random_bytes`（底层 BoringSSL `RAND_bytes` 原生跨 Linux/Windows/macOS）或抽象 `platform.random`。
2. **拆分 `src/platform/` 为跨平台通用与 Linux 专属**：
   - 通用：`ip_address`、`network_selection`、`network_state`（接口值类型）、`socket_options`（通用结构体，按 OS 分实现单元）。
   - Linux 专属：`netlink_*`、`ipv4_reverse_path`、`routing_rule`、`socket_namespace`、`resolved_*`、`sd_bus_abi`。
3. **清理散落在可跨平台目录中的零散 POSIX 头文件**：
   - 仅用 `<arpa/inet.h>` 做 IP 文本/字节转换的文件（`src/http/connect.cpp`、`src/config/{dependencies,dns}.cpp`、`src/rules/{validate,matcher,srs_payload}.cpp*`、`src/masque/{target,connect_ip}.cpp*`）统一改用 `platform.ip_address`（纯标准 C++，零 OS 头文件）。
   - `src/tls/certificate_trust.cpp`、`src/dns/local_config.cpp`、`src/dns/fakeip_history_store.cpp`、`src/rulefile/posix.cpp` 统一收口到 `platform.fs` / `state` 原子文件边界。
4. **消除协议目录反向依赖**：
   - 梳理 `src/masque/listener.cppm` 对 `relay` / `session_quota` 的反向依赖，改由 `relay` 适配层注入窄回调/facade；
   - 评估将 `src/relay/relay.cppm`（原 `src/proxy/proxy.cppm` 1,046 行、129 处 `#ifdef NEXUS_ENABLE_*`）按协议注册表拆细，降低跨平台裁剪维护成本。

## 2. 跨平台移植路线（第 98 批后启动，Android 优先）

### 阶段 1（首站）：Android（`aarch64-linux-musl` 静态 Sidecar + 最新 Kotlin / Gradle 外壳）
- **为何优先 Android**：底层仍是 Linux 内核，Corosio `epoll` 后端、自研 TUN 协议栈、`state` 原子持久化与 `logging` 95%+ 原生复用；且 Nexus 已提前具备免 Root `VpnService` 最关键的两个钩子：`LinuxTun::attach(fd, borrow/adopt)`（`device-fd`）与 `platform::protect_socket(fd, protect_path, deadline)`（Unix Socket `SCM_RIGHTS`）。
- **内核编译形态（避开 NDK Clang 与 C++26 `-freflection` 冲突）**：
  - 首期采用 **GCC 16 交叉编译 `aarch64-linux-musl` 静态可执行文件**（顺带产出 Linux ARM64 静态单文件发行版），按 Android 10+ SELinux `W^X` 规范命名为 `libnexus.so` 打包进 APK `jniLibs/arm64-v8a/`，由独立 `:bg` VPN 进程中的 `VpnService` 通过 `ProcessBuilder` 拉起，以 `device-fd` + `protect_path` + 本地控制面协作；
  - 100% 保留 GCC 16 + `-freflection` + `import std;` + `libstdc++`（`musl` 同样提供 `__errno_location()`），且天然进程隔离；
  - 远期在 Clang/NDK 原生支持 C++26 `-freflection` + `import std;` 后，再评估进程内 JNI `.so` 嵌入式第二形态。
- **内核侧最小改动项**：
  1. 将 `src/platform/` 与 `src/packet/fd.cppm` 中的 `__x86_64__` 宏守卫放宽至 `__aarch64__`，逐项核验 `aarch64` Linux 常量（尤其 `<fcntl.h>` 中 `O_DIRECTORY`/`O_NOFOLLOW` 等架构差异值）与结构体 ABI `static_assert`；
  2. 新增 Android 沙箱构建 Profile：强制 `epoll` 后端（规避 Android 12–15 `untrusted_app` seccomp 拦截 `io_uring_setup`），关闭 `tun-host-dns`、`log-journald`、`tproxy` 与 `tun_network_owner`（同步避开 glibc 专属 `posix_spawn_file_actions_addclosefrom_np`）；
  3. 宿主事件喂入：由 Android 侧 `ConnectivityManager.NetworkCallback` 监听 Wi-Fi/5G 切换与系统 DNS 变更，经控制面/热重载推送给 Nexus（Android 11+ 普通 App 无法读 `/etc/resolv.conf` 与 `RTM_GETNEIGH`）。
- **Android 外壳技术栈（纯官方现代标准）**：
  - **语言与 UI**：最新版 **Kotlin 2.x** + Jetpack Compose + Coroutines，独立 `:bg` 进程运行 `VpnService` 与 `protect_path` Unix Socket 服务端（通过 `LocalServerSocket` / `ParcelFileDescriptor` 接收内核发来的 `SCM_RIGHTS` fd 并调用 `VpnService.protect(fd)`）；
  - **构建系统**：直接使用 **Gradle 官方脚本控制三件套**——**Gradle Wrapper（`./gradlew` + `gradle/wrapper/gradle-wrapper.properties` 锁定版本，不依赖宿主机全局 Gradle）** + **Kotlin DSL（`settings.gradle.kts` / `build.gradle.kts`）** + **Version Catalog（`gradle/libs.versions.toml`）**，通过自定义 Gradle Task 将 `mcpp` 产出的 `aarch64-linux-musl` 静态内核复制并校验 SHA-256 到 `jniLibs/arm64-v8a/libnexus.so`。
- **详细系统交互与 DNS 落地指南**：见 [Android 免 Root 系统交互指南](android/non-root-integration-guide.md)。

### 阶段 2：Windows / macOS 工具链探测与全协议 CLI / TUN 移植

详细分层架构、WFP 防漏、Wintun/utun/NetworkExtension 选型与原生外壳设计见 [Windows 与 macOS 架构设计蓝图](desktop-windows-macos-design.md)。

#### 第 0 关：工具链与 C++26 Modules 最小可行探测（最高风险前置）
- 在目标平台（Windows x86-64/arm64、macOS arm64）先验证单文件到最小代理目标的编译链路：
  - C++26 `-fmodules` + `-freflection` 编译器支持（Windows: MinGW-GCC 16 / Clang / MSVC；macOS: Homebrew GCC 16 / Clang）；
  - `mcpp` 离线锁定构建与 BoringSSL / ngtcp2 / nghttp3 / nghttp2 / Glaze 跨平台打包；
  - Corosio 对应平台后端（Windows IOCP / macOS kqueue）基础连接、取消、超时与 DNS 回归。

#### 第一步：全协议代理 CLI 跨平台（90%+ 业务代码直接复用）
- 提供平台实现单元：
  - `platform.socket_options`（Windows `WSAIoctl`/bind/keepalive；macOS `IP_BOUND_IF`/`IPV6_BOUND_IF`/TFO）；
  - `platform.fs` / `state`（Windows `CreateFileW` + 私有 ACL + `FlushFileBuffers` + `MoveFileExW`/`ReplaceFileW` + 互斥锁；macOS `O_NOFOLLOW` + `fcntl(F_FULLFSYNC)` + `flock`）；
  - `logging` sink（Windows Console/Handle 写与轮转；macOS `stderr`/文件/可选 `os_log`）；
  - 本机控制面（Windows Named Pipe + DACL/Token 校验；macOS Unix Domain Socket + `LOCAL_PEERCRED`）。
- Linux 专属特性（`io-uring`、`splice`、`ktls`、`tproxy-udp`、`tun-host-dns`、`log-journald`）通过 `mcpp` target/platform 约束自动仅在 Linux 启用。

#### 第二步：桌面端 TUN 与系统网络接管
- **Windows**：Wintun 驱动适配（复用自研 TCP/IP 栈）+ IP Helper API（接口/默认路由监控、路由表防回环、`GetExtendedTcpTable` 进程归属、NRPT/接口 DNS 配置、原生 Windows Service Control Handler）。
- **macOS**：`utun` 设备适配 + BSD Routing Socket / `PF` / `scutil` DNS + `proc_pidinfo` 进程归属；面向桌面 GUI App 时直接复用已验证的 **`proxy.host` 嵌入接口 + 外部 TUN FD `borrow/adopt`** 对接 NetworkExtension。
