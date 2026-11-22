# Nexus Windows 与 macOS 架构设计蓝图

更新：2026-11-21。本文承接 [跨平台前序解耦与移植路线](cross-platform-prep.md) 与 [Android 免 Root 系统交互指南](android/non-root-integration-guide.md)，给出 **Windows** 与 **macOS** 桌面端从工具链、I/O 引擎、TUN/防回环、DNS 接管、进程归属、崩溃恢复到原生 GUI 外壳的完整分层设计。

---

## 1. 跨三端统一架构铁律

三端均坚持 **“核心独立原生进程（Sidecar / Service / Daemon）+ 平台原生极薄外壳”**，让 90%+ Sans-I/O C++26 协议与路由代码零改写复用：

| 维度 | Android（第 1 站） | Windows + Linux 桌面（第 2 站） | macOS / iOS（第 3 站） |
| --- | --- | --- | --- |
| **C++26 编译器** | GCC 16 交叉 `aarch64-linux-musl` | Linux GCC 16 / Windows GCC 16 (`x86_64-w64-mingw32` UCRT64) | Homebrew GCC 16 (`arm64-apple-darwin`) |
| **Corosio 异步后端** | `epoll` | Windows **IOCP** / Linux `epoll` / `io_uring` | **kqueue** |
| **原生外壳技术栈** | Kotlin 2.4 + Jetpack Compose + Gradle 9.9 | **Slint v1.19+ C++26**（独立 CMake 4.5+ `import std;` 子工程，Skia 渲染 + 原生 `SystemTrayIcon` + Fluent/Material 主题，零 C#/.NET/Electron） | **Swift 6 + SwiftUI**（`MenuBarExtra` + 设置，原生零额外运行时，顺带覆盖 iOS） |
| **内核托管形态** | `:bg` 进程 `VpnService` + `libnexus.so` | Windows：**Windows Service (`NexusService`, LocalSystem)**<br>Linux：`systemd` 服务 / 本机进程 | 阶段 A：`SMAppService.daemon` + `utun`<br>阶段 B：`NEPacketTunnelProvider` System Extension |
| **控制面 IPC** | 文件系统 UDS（`c.sock`, `<108B`） | Windows：**Named Pipe**（`\\.\pipe\nexus-control` + DACL）<br>Linux：文件系统 UDS（`SO_PEERCRED`） | 文件系统 UDS（`LOCAL_PEERCRED` / `getpeereid`, `<104B`） |
| **持久化落盘原语** | `openat(O_NOFOLLOW)` + `fsync` + `rename` | Windows：`CreateFileW` + 私有 DACL + `FlushFileBuffers` + `MoveFileExW`<br>Linux：`openat` + `fsync` + `rename` | `openat(O_NOFOLLOW)` + **`fcntl(F_FULLFSYNC)`** + `rename` |

> **关键共性**：
> 1. 因为 Nexus 核心启用了 C++26 `-freflection` 与 `import std;`，核心进程在三端均走 **GCC 16 原生编译链路**；
> 2. Windows + Linux 桌面 GUI 外壳作为独立 **CMake 4.5+ C++26（原生 `import std;`）** 子工程采用 **Slint v1.19+ 官方预编译 C++ SDK**（Ninja + GCC 16 / Clang / MSVC 均可），与 `nexus` 核心进程通过 Named Pipe / UDS 彻底进程隔离，既不引入 C#/.NET，也完全不污染主仓 `mcpp` 构建图。
> 3. Slint 桌面端遵循三许可制：开源分发可直接用 GPLv3；如需非 Copyleft 或商业分发桌面端，免费适用官方 **Royalty-Free Desktop License**（仅需在“关于”页展示 `AboutSlint` 署名）。

---

## 2. Windows 详细设计

### 2.1 双部署形态（无 UAC 轻量模式 + 零重复弹窗服务模式）
1. **用户态轻量代理模式（免管理员权限）**：
   - 普通权限直接拉起 `nexus.exe` 监听 `127.0.0.1` Mixed/SOCKS5；
   - 可选通过 WinINet `InternetSetOption(INTERNET_OPTION_PER_CONNECTION_OPTION)` 设置系统 HTTP 代理，退出时自动恢复原配置。
2. **全流量 TUN 模式（Windows Service，推荐主力）**：
   - 安装期一次性提权注册 `NexusService`（SCM 服务，运行于 `LocalSystem`），GUI 进程以普通用户权限常驻系统托盘，经 Named Pipe 控制服务启停与热重载，**日常开关 TUN 无需反复弹 UAC**；
   - **TUN 驱动**：直接接入 WireGuard 官方已 WHQL 签名的 **Wintun**（`wintun.dll`），零自签驱动门槛；Wintun 基于共享内存环形缓冲收发 IP 包，天然契合第 96D 批批量包处理改造，并复用 Nexus 自研 TCP/IP/UDP 栈。

### 2.2 防回环、路由与崩溃自愈
- **出站防回环（绝不仅靠 metric）**：
  - 通过 IP Helper API（`NotifyRouteChange2` / `NotifyIpInterfaceChange`）追踪真实默认物理出口网卡 `InterfaceIndex`（过滤 Wintun 自身 LUID）；
  - 所有 Nexus 物理出站 socket 在 `connect()` / `sendto()` 前显式绑定：
    - IPv4：`setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, &netOrderIfIndex, sizeof)`（**必须网络字节序 `htonl`**）；
    - IPv6：`setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF, &hostOrderIfIndex, sizeof)`（**主机字节序**）。
- **TUN 路由安装**：
  - 使用 `CreateIpForwardEntry2` 在 Wintun LUID 上安装默认路由（低 metric）并配合私有网段（RFC 1918 / 链路本地 / 局域网网关）排除；
  - **天然防残留**：Wintun 网卡生命周期绑定到内核句柄，一旦 `NexusService` 崩溃或被强杀，Windows 内核自动销毁 Wintun 适配器并连带清除其全部路由与接口 DNS；任何挂在物理网卡上的显式绕行路由记录在持久化事务文件中，下次启动幂等清理。

### 2.3 Windows DNS 接管与防 SMHNR 泄露
- **核心陷阱**：Windows 10/11 默认开启 **Smart Multi-Homed Name Resolution（SMHNR）**，系统 `Dnscache` 会向**所有在线网卡**并发发 UDP 53 查询并取最快结果，仅给 Wintun 设 DNS 仍会从物理网卡泄露 DNS！
- **三层防漏打磨**：
  1. 给 Wintun 设置哨兵 DNS（如 `172.19.0.2` / `fdfe:dcba:9876::2`）与最低 `InterfaceMetric`；
  2. **动态 WFP（Windows Filtering Platform）防漏规则（推荐）**：以 **`FWPM_SESSION_FLAG_DYNAMIC`** 创建 WFP 会话，仅放行 `NexusService` 进程自身（按 `FWPM_CONDITION_ALE_APP_ID`）及发往 Wintun 的 UDP/TCP 53，阻断其他进程直出物理网卡 53 端口；一旦服务进程崩溃或被强杀，**内核自动撤销动态 WFP 会话的所有规则，零残留不断网**；
  3. **物理网 `local` DNS**：经 `GetAdaptersAddresses` 采集非 Wintun 物理网卡的 `FirstDnsServerAddress` 与 `DnsSuffix`，通过绑定 `IP_UNICAST_IF` 的物理 socket 查询，兼容企业内网域与 Captive Portal。

### 2.4 进程归属、Named Pipe 安全、日志与 Slint v1.19+ 桌面外壳
- **进程归属匹配**：调用 `GetExtendedTcpTable` / `GetExtendedUdpTable`（`TCP_TABLE_OWNER_MODULE_ALL`）获取 PID 与服务名，通过 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` 取路径；遇到 `svchost.exe` 时按服务名查注册表 `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll` 精确识别系统服务。
- **控制面安全**：Named Pipe `\\.\pipe\nexus-control` 设置显式 DACL（仅允许 `SYSTEM`、Administrators 与当前交互用户组），复用既有 `NEXUS/1` 文本/BEVE 控制协议。
- **日志与状态**：`logging` 走 Windows Handle 文件写入与按大小轮转（可选 ETW/EventLog）；`state` 数据位于 `%ProgramData%\Nexus\lib` 与 `%ProgramData%\Nexus\cache`（私有 ACL 拒绝普通非授权账户篡改）。
- **Windows + Linux 桌面共享外壳（Slint v1.19+ C++）**：
  - 使用 `slint-project.json` + `edition = "1.19"` 与 **Skia 渲染后端**（保障中文字体回退、抗锯齿与 IME 体验）；
  - 直接复用 Slint 1.19 原生 `SystemTrayIcon`（支持可勾选菜单项与隐藏至托盘零刷新率空转省电），实现一键开关代理/TUN、切换出站组、实时流量/延迟卡片、动态调日志级别及“用系统编辑器打开 `config.kdl` + 热重载”；
  - 平台薄胶水仅保留少量原生 OS API（Windows：WinINet 系统代理、SCM `NexusService` 控制、Named Pipe 客户端；Linux：UDS `control.sock` 客户端与 `systemd`/桌面自启）。

---

## 3. macOS 详细设计

### 3.1 双形态演进路线（破解 Apple 签名门槛）
macOS 存在“开源免签名立即可用”与“正规 Apple 签名深度系统集成”两类需求，设计为共享同一套 C++26 内核与 SwiftUI 外壳的**双后端形态**：

1. **阶段 A · 开源特权 Daemon 形态（`utun` + `SMAppService.daemon`，零 Apple 付费账号门槛）**：
   - SwiftUI 菜单栏 App 通过 macOS 13+ 现代 API **`SMAppService.daemon`**（替代已废弃的 `SMJobBless`）注册本机特权守护进程运行 `nexus`；
   - `nexus` 通过 `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` 连接 `com.apple.net.utun_control` 直接创建 `utunX`（**注意 macOS `utun` 读写每包带有 4 字节网络序协议族头 `AF_INET`/`AF_INET6`**，在 `packet.tun_darwin` 薄适配层剥离/补全，上层 TCP/IP 栈零改动！）；
   - 通过 BSD Routing Socket（`PF_ROUTE`）管理路由，通过 `SystemConfiguration`（`SCDynamicStore`）备份原 DNS 并指向 TUN 哨兵 DNS，守护进程异常退出时由 `launchd` / 独立恢复逻辑还原。
2. **阶段 B · 正式签名 App 形态（`NEPacketTunnelProvider` System Extension）**：
   - 使用 Developer ID / App Store 签名的 System Extension 托管 `NEPacketTunnelProvider`；
   - 由系统通过 `NEPacketTunnelNetworkSettings` 声明地址、`includedRoutes`/`excludedRoutes` 与 `NEDNSSettings`（`matchDomains = [""]`），退出或崩溃时 **macOS 系统自动还原全部路由与 DNS，100% 零残留**；
   - 将 `utun` 文件描述符或包流直接交给 `nexus` 既有 `LinuxTun::attach` 同构接口（抽象为 `packet.tun_device`）。

### 3.2 防回环、网络监控与 DNS 打磨
- **默认网络监控**：使用 `SCDynamicStoreCreate` 监听 `State:/Network/Global/IPv4`、`State:/Network/Global/IPv6` 与 `State:/Network/Service/.*/DNS`（或 Swift 侧 `NWPathMonitor`），精准识别真实物理出口 `PrimaryInterface`（如 `en0`）并自动忽略自身 `utunX`。
- **出站防回环**：所有 Nexus 物理出站 socket 统一设置 **`IP_BOUND_IF`**（IPv4）与 **`IPV6_BOUND_IF`**（IPv6）绑定到当前物理接口 index，确保绝不回流进 `utunX`；切网（Wi-Fi ↔ 热点/以太网）时立即更新绑定接口并通知内核刷新连接与 `local` DNS。
- **DNS 与 mDNS / 局域网兼容**：
  - `utun` 模式下通过 `SCDynamicStore` 读取物理网原 DNS 与搜索域喂给 `local` 解析器；排除 `224.0.0.251`（mDNS/Bonjour）与局域网子网，避免破坏 AirDrop、隔空播放与打印机发现；
  - `NEPacketTunnelProvider` 模式下优先设 `matchDomains = [""]` 全局接管，并在配置允许时保留本地搜索域直连。

### 3.3 进程归属、持久化落盘与 IPC 安全
- **进程归属匹配**：通过 `sysctlbyname("net.inet.tcp.pcblist_n")` 与 `sysctlbyname("net.inet.udp.pcblist_n")` 按五元组反查 PID（按 `kern.osrelease` 兼容 macOS 13+ Ventura 408B 与旧版 384B `xinpcb_n` 结构体对齐），再用 `proc_pidpath(pid, ...)` 获取可执行路径并做缓存。
- **掉电安全持久化（`state`）**：macOS 普通 `fsync()` 只刷到磁盘缓存而不保证落物理介质，所有 `state` 原子提交（快照、FakeIP WAL、目录同步）在 macOS 实现单元中**强制使用 `fcntl(fd, F_FULLFSYNC)`**。
- **控制面 IPC**：使用文件系统 Unix Domain Socket + **`getpeereid()` / `LOCAL_PEERCRED`** 校验对端 UID；**注意 macOS `sockaddr_un.sun_path` 上限仅 104 字节**（比 Linux 108 字节更短），App Group 容器路径较长时务必用极短文件名（如 `c.sock`）或 `/var/run/nexus/c.sock`。
- **原生体验外壳**：纯 **Swift 6 + SwiftUI**，以 `MenuBarExtra` 菜单栏常驻为主界面（极低内存占用、无常驻重型 WebView），支持开机自启（`SMAppService.mainApp`）、代理模式一键切换、系统代理自动接管（`SCPreferences`）与实时流量/节点延迟面板。

---

## 4. 内核侧最小平台抽象边界（第 98 批后按此接口逐平台填实现）

为让 Windows 与 macOS 均以极小增量接入，在 `src/platform/` 收口为 6 个窄能力模块（全部无虚函数，按构建目标平台选编译单元）：

1. **`platform.socket_options`**：Linux (`SO_MARK`/`SO_BINDTOIFINDEX`) · Windows (`IP_UNICAST_IF`/`IPV6_UNICAST_IF`) · macOS (`IP_BOUND_IF`/`IPV6_BOUND_IF`)；
2. **`platform.network_state`**：Linux (`netlink`) · Windows (`IP Helper NotifyRouteChange2`) · macOS (`SCDynamicStore` / `PF_ROUTE`)；
3. **`platform.process_owner`**：Linux (`SO_PEERCRED`/`netlink inet_diag`) · Windows (`GetExtendedTcpTable` + `QueryFullProcessImageNameW`) · macOS (`pcblist_n` + `proc_pidpath`)；
4. **`platform.tun_device`**：Linux (`/dev/net/tun` & `attach`) · Windows (`Wintun` ring) · macOS (`utun` 4B PI header / `NEPacketTunnelProvider` fd)；
5. **`platform.fs`（支撑 `state` 与 `logging`）**：Linux (`openat`/`fsync`/`flock`) · Windows (`CreateFileW`/ACL/`FlushFileBuffers`/`MoveFileExW`) · macOS (`openat`/`F_FULLFSYNC`/`flock`)；
6. **`platform.control_ipc`**：Linux/macOS (`AF_UNIX` + `SO_PEERCRED`/`getpeereid`) · Windows (`Named Pipe` + DACL)。
