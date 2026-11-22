# Linux ARM64（`aarch64-linux-musl`）内核适配与 ABI 核查清单

更新：2026-11-21。本清单基于对全仓 `src/platform/`、`src/packet/`、`src/state/`、`src/logging/` 及 `<arpa/inet.h>` 引用的静态审计，提前标注从 `x86_64-linux-gnu` 扩展至 **`aarch64-linux-musl`（Android Sidecar + Linux ARM64 静态发行版）** 时必须处理的架构差异与零遗漏改动点。

---

## 1. 高危架构常量陷阱（提前排雷）

### 1.1 `O_NOFOLLOW` / `O_DIRECTORY` 在 `x86_64` 与 `aarch64` 上数值不同
- **定位**：[netlink_abi.cppm](../../../src/platform/netlink_abi.cppm#L244-L247)
  - 当前硬编码 `inline constexpr int O_NOFOLLOW = 131072;`（`0400000` 八进制）。
  - 在 **Linux `aarch64`** 上：
    - `O_DIRECTORY = 16384`（`040000`，而 `x86_64` 为 `65536` / `0200000`）
    - `O_NOFOLLOW = 32768`（`0100000`，而 `x86_64` 为 `131072` / `0400000`）
    - `O_DIRECT = 65536`（`0200000`，而 `x86_64` 为 `16384` / `040000`）
    - `O_LARGEFILE = 131072`（`0400000`，而 `x86_64` 为 `32768` / `0100000`）
  - **风险**：若直接把 `x86_64` 的 `131072` 传给 `aarch64` `open()`，内核会按 `O_LARGEFILE` 解析，**静默丧失 `O_NOFOLLOW` 防符号链接穿越保护**！
  - **修复方案**：按 `#if defined(__aarch64__)` 与 `#elif defined(__x86_64__)` 显式区分 `O_NOFOLLOW` / `O_DIRECTORY`，并在对应 `.cpp` 中用系统 `<fcntl.h>` 加 `static_assert(O_NOFOLLOW == abi::O_NOFOLLOW)` 强制编译期校验（`src/state/` 与 `src/logging/` 已直接 `#include <fcntl.h>`，天然安全）。

### 1.2 已核验在 `x86_64` 与 `aarch64` 上一致的常量（仍须加 `static_assert` 锁定）
- [socket_options.cppm](../../../src/platform/socket_options.cppm#L123-L130)：`SOL_SOCKET=1`、`SO_REUSEADDR=2`、`SO_KEEPALIVE=9`、`SO_REUSEPORT=15`、`SO_BINDTODEVICE=25`、`SO_MARK=36`、`SO_DOMAIN=39`、`SO_BINDTOIFINDEX=62`、`IPPROTO_IP=0`、`IPPROTO_TCP=6`、`IPPROTO_IPV6=41`、`AF_INET=2`、`AF_INET6=10`、`IP_BIND_ADDRESS_NO_PORT=24`、`IP_MTU_DISCOVER=10`、`IPV6_MTU_DISCOVER=23`（Linux `x86_64` 与 `aarch64` 均共用 `<asm-generic/socket.h>`）。
- [fd.cppm](../../../src/packet/fd.cppm#L16)：`F_GETFL=3`、`O_NONBLOCK=2048`（`04000`），且 [fd.cpp](../../../src/packet/fd.cpp#L13) 已有 `static_assert` 校验。
- `musl` libc 符号兼容：`musl` 与 `glibc` 均提供 `extern "C" int* __errno_location() noexcept;`、`getrandom()`、`epoll_wait()`、`setsockopt()`、`inet_pton()`。

---

## 2. 7 处 `__x86_64__` 宏守卫逐文件放宽清单

| 文件 | 现状 | 放宽至 `aarch64-linux-musl` 改动要点 |
| --- | --- | --- |
| [ip_address.cppm](../../../src/platform/ip_address.cppm#L1) | 仅调 `inet_pton(2/10, ...)` | **最佳实践**：改为纯 C++26 标准 IPv4/IPv6 文本解析（~50 行，零 libc 符号），直接彻底移除 `#if !defined(__linux__) || !defined(__x86_64__)` 限制，成为全平台通用模块。 |
| [socket_options.cppm](../../../src/platform/socket_options.cppm#L1) | 硬编码 Linux socket 常量 | 放宽守卫至 `(defined(__x86_64__) || defined(__aarch64__)) && defined(__LP64__)`，补 `.cpp` 编译期 `static_assert` 对照系统头。 |
| [stream_peer.cppm](../../../src/platform/stream_peer.cppm#L1) | Linux peer 信息边界 | 放宽守卫至 `aarch64`，核验 `sockaddr_in`/`sockaddr_in6` 布局断言。 |
| [linux_random.cppm](../../../src/platform/linux_random.cppm#L1) | 直接声明 `getrandom` | 优先将调用方统一迁到 `crypto::random_bytes`（BoringSSL `RAND_bytes` 原生跨平台），同时放宽该文件守卫至 `aarch64`。 |
| [netlink_abi.cppm](../../../src/platform/netlink_abi.cppm#L3) | 硬编码 netlink 与 `O_NOFOLLOW` | 修复 `O_NOFOLLOW` 架构差异并加 `static_assert`；核验 `struct ifinfomsg` / `rtmsg` / `nlmsghdr` 对齐（均为定宽整型，LP64 一致）。 |
| [sd_bus_abi.cppm](../../../src/platform/sd_bus_abi.cppm#L3) | 仅 Linux `systemd-resolved` | 放宽至 `aarch64`（供 ARM64 Linux 桌面/服务器），Android Profile 直接禁用 `tun-host-dns` 不编入。 |
| [fd.cppm](../../../src/packet/fd.cppm#L1) | 静态 `read`/`write`/`fcntl` 边界 | 放宽守卫至 `aarch64`，[fd.cpp](../../../src/packet/fd.cpp#L13) 既有 `static_assert` 自动兜底。 |

---

## 3. `glibc` 专属调用与 Android Profile 裁剪清单

1. **`posix_spawn_file_actions_addclosefrom_np`**（[tun_network_owner.cpp](../../../src/tools/tun_network_owner.cpp#L108)）：
   - 属于 glibc 2.34+ 扩展（musl 尚未提供）；
   - **Android Profile**：完全不编入 `tun_network_owner`（Android 免 Root 走 `device-fd` + `VpnService`）；
   - **ARM64 Linux musl 静态版**：可用 Linux `close_range(child_socket + 1, ~0U, CLOSE_RANGE_CLOEXEC)` 或子进程入口清理替代，使 `StrictTunOwner` 同样支持 musl 静态编译。
2. **`epoll` 默认锁定**：Android 12–15 `untrusted_app` seccomp 常拦截 `io_uring_setup`，Android Profile 强制走 `epoll`（不链接 `liburing`）。
3. **关闭桌面/服务器特性**：Android Profile 关闭 `log-journald`（无 `libsystemd`）、`tun-host-dns`（无 `sd-bus`）、`tproxy-udp`（免 Root 用不到）。

---

## 4. 21 处 `<arpa/inet.h>` 清理清单（同步为 Windows / macOS 铺路）

以下 17 个非 Linux 专属核心文件当前仅因 `inet_pton` / `inet_ntop` / `htons` 引入 `<arpa/inet.h>`，可在后续重构中统一改用纯 C++ `platform.ip_address` + `std::byteswap` 彻底脱钩 POSIX 头文件：
- `src/rules/{srs_payload.cppm,matcher.cpp,validate.cpp}`
- `src/config/{dns.cpp,dependencies.cpp,dns_rule.cpp}`
- `src/http/connect.cpp`
- `src/tcp/{direct.cpp,direct6.cpp}`、`src/udp/{direct.cpp,direct6.cpp}`
- `src/masque/{connect_ip.cppm,target.cpp}`
- `src/socks5/udp_ingress.cpp`、`src/dns/local_config.cpp`、`src/net/udp_socket.cpp`、`src/tools/rule_fetch.cpp`

（其余 4 处 `tun_host.cpp`、`proxy_run.cppm`、`tproxy_udp.cpp`、`socket_uid.cpp` 属 Linux 宿主/透明代理边界，按平台分离。）
