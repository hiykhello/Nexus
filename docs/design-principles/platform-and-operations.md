# 多平台系统集成与运维工程原则

本文汇总 Nexus 在 Linux 宿主集成、Android 免 Root VPN、Windows/Linux 桌面端、macOS/iOS 原生端及路由器部署中的关键工程经验与避坑清单。

## 1. Linux 宿主网络与服务集成

- **专属 `inet` nftables 表与防环回**：通过内核原生 Netlink 原子安装/撤回专属 `inet` 表，将包 `fwmark` 与 `conntrack` 标记协同保存/恢复，使已判定流跳过重复预判；协调策略路由表与出站 `fwmark`，彻底避免代理自身流量回环进入 TUN。
- **有界 NFQUEUE 预判与动态地址集**：对用户态预判队列设置长度与复制上限；监听系统网络地址变化动态更新本机排除集合，不依赖启动期静态快照。
- **外部防火墙共存与自愈**：将自身规则隔离在带实例标识的对象内，并支持外部防火墙（如容器网桥或路由器 `fw4`）重建后的事件驱动恢复；异常 `SIGKILL` 后由独立所有者快速回收专属表、路由与设备，绝不误删外部规则。
- **systemd 服务体验**：区分单实例与 `%i` 模板实例，隔离 `StateDirectory`；`SIGHUP` 热重载前先执行配置校验，失败保留旧实例继续服务；明确区分“使用系统 `systemd-resolved`”与“替代 `systemd-resolved`”两种运行角色。

## 2. Android 免 Root 系统集成

- **三层进程隔离**：UI 进程、`:bg` 守护进程（承载 `VpnService` 与 `specialUse` 前台服务）与原生 `libnexus.so`（`aarch64-linux-musl` + `epoll`，避免 seccomp 拦截 `io_uring_setup`）解耦；数据面 100% 留在原生侧零 JNI 拷贝。
- **私有 UDS 与 FD 泄漏防护**：`protect` 与控制 socket 置于 `noBackupFilesDir` 且路径远小于 108 字节，禁用 Abstract Namespace；Kotlin 侧收到 `SCM_RIGHTS` FD 并完成 `VpnService.protect(fd)` 后**必须立即关闭本进程副本**，防止 `RLIMIT_NOFILE` 耗尽。
- **DNS 与 Private DNS 打磨**：哨兵 DNS IP 落入 TUN 路由网段内；Android 10+ 经 `DnsResolver.rawQuery(underlyingNetwork, ...)` 透传原始 RFC 1035 报文以兼容 Captive Portal 与 DNS64；对发往哨兵 IP 的 TCP 853 快速返回 RST，让系统自动模式 1ms 内回退明文 53 而不卡顿。
- **切网与路由兼容**：仅监听 `NET_CAPABILITY_NOT_VPN` 物理网，去抖推送 `network-change`，断网时向 `setUnderlyingNetworks` 传空数组而非 `null`；Android 13+ 用原生 `excludeRoute`，Android 12 及以下先做用户态 CIDR 减法；分应用路由优先使用内核 `addDisallowedApplication` 零开销通道。
- **安全 MTU 与多用户进程归一化**：Android VpnService MTU 上限钳制在 `9000` 以规避部分厂商内核在超大 MTU 下的 `ENOBUFS` 丢包；进程归属路由对多用户/工作资料 UID 执行 `uid % 100000` AppID 归一化，并过滤 `/system/bin/app_process*`（Zygote）可执行路径噪声。
- **防假死断网与 APK 打包**：`useLegacyPackaging = true` 确保 `libnexus.so` 解压至可执行目录；守护进程监控子进程退出，限次指数退避重启，失败立即撤销 VPN 释放网络。

## 3. macOS / iOS 原生安全与网络扩展

- **特权 Daemon 纵深防御（macOS 阶段 A）**：
  - GUI 永不以 root 运行；受保护内核副本经 SHA-256 校验安装至 root 私有目录；
  - 控制 IPC 仅暴露窄动词，**严禁接受任意可执行文件路径**；
  - UDS 服务端校验对端 `getpeereid` UID、`LOCAL_PEERPID` 与内核 `csops`（`CS_VALID | CS_RUNTIME` + 20 字节 CDHash），并严格校验 macOS **104 字节** `sun_path` 上限；
  - 防 TOCTOU：配置文件核对属主与 `config_sha256`，热重载内容经控制器内联下发；提供不碰宿主机路由/DNS 的无副作用 `utun` 自测探针。
- **NetworkExtension 与 XNU 内核边界（阶段 B）**：基于 `NWPathMonitor` 监控物理网口并过滤自身 `utunX` 防自触发环路；`utun` 默认并钳制安全 MTU 为 **`4064`**（`4096 - UTUN_IF_HEADROOM_SIZE`），避免突破 4 KiB 页头引发吞吐断崖；路由排除私网及 `224.0.0.251/32`、`ff02::fb/128` 保持 AirDrop/Bonjour/mDNS 畅通；出站套接字绑定使用 `IP_BOUND_IF`/`IPV6_BOUND_IF` 与 `SO_NOSIGPIPE`，XNU `pcblist_n` 进程反查遵循 8 字节对齐步长（Darwin `>= 22`: `408B`，`< 22`: `384B`）；iOS 扩展严格遵循 `< 50 MiB` 内存红线并使用 App Group Keychain 保管控制面凭据。

## 4. Windows 与跨平台桌面客户端实践

- **Winsock2 套接字与系统 DNS 陷阱防护**：共享 UDP 套接字必须关闭 `SIO_UDP_CONNRESET`，防止对端返回 ICMP Port Unreachable 导致后续无关联 `recvfrom` 触发 `WSAECONNRESET` 误杀；出站网卡绑定区分 `IP_UNICAST_IF`（网络字节序大端）与 `IPV6_UNICAST_IF`（主机字节序）；系统 DNS 采集必须剔除已废弃的站点本地伪 IPv6 DNS（`fec0::/10`）；进程反查对伪 PID `0`（`:System Idle Process`）与 `4`（`:System`）做显式映射。
- **回环防火墙放行**：部分 Windows 环境会拦截未放行程序在 `127.0.0.1` 上的监听端口；按可执行文件绝对路径幂等添加防火墙规则（优先原生 COM `INetFwPolicy2`，若涉及命令行须剥离 `\\?\` 前缀并读取 `stdout` 报错）。
- **系统代理原子快照与优雅降级**：开启前完整快照 `ProxyEnable` / `ProxyServer` / `ProxyOverride`，同步清理残留 PAC 标志，退出时精确还原；无桌面环境（如无 `gsettings`）时优雅降级，不阻断代理核心启动。
- **单实例唤醒与托盘省电**：Windows 用命名 Mutex、Linux/macOS 用 `$XDG_RUNTIME_DIR` UDS 实现单实例互斥与二次启动唤醒前台；记录 UAC 取消状态避免反复弹窗，诊断模式禁止修改宿主机防火墙与系统代理；验证收进托盘后事件循环空闲 CPU 趋近于 0%。

## 5. 路由器与嵌入式打包

- 基于 `aarch64-linux-musl` / `x86_64-linux-musl` 纯静态构建，同时适配 `.apk`（OpenWrt 25+）与 `.ipk`（OpenWrt 24 及以下）打包；
- 配合 `procd` init 脚本提供崩溃自愈与 `SIGTERM` 优雅停机，并适配只读 SquashFS 根分区（临时状态与日志落入 `/tmp`）。
