# 验证体系与实机基线

本文汇总 Nexus 在网络协议栈、DNS 与持久状态、Linux 系统集成与性能基准四个维度的验收准则，以及 Linux x86-64 双后端（`epoll` / `io_uring`）的实机回归与性能基线。当前生产支持范围见 [支持矩阵](proxy-kernel-support-matrix.md)。

---

## 1. 网络协议栈、TLS 与 HTTP 验证

- **自研 TUN 栈**：从内存包设备（单/多流 IPv4/IPv6 TCP 与 UDP、乱序、重传、MTU 分片、RST/半关闭、背压与流表淘汰）起步，再到隔离 Linux netns 的真实 TUN 设备与撤回验证。
- **自研 TLS 与 uTLS**：覆盖 BoringSSL `libcrypto` 密钥交换（X25519 / NIST / `X25519MLKEM768`）、TLS 1.3/1.2 认证握手、证书压缩（zlib/Brotli/Zstandard）、ALPS、ECH、1-RTT PSK 恢复与负例（错名、错 CA、非法记录、OOM 恢复）。浏览器指纹基线通过 `utls-dump` + [audit-utls.py](../../scripts/audit-utls.py) 离线对照上游 `refraction-networking/utls` 或真实浏览器抓包，严格区分数据漂移与能力缺口。
- **HTTP 与代理互通**：覆盖恶意 framing、请求走私边界、431 头超限、CONNECT 半关闭、HTTP/2 流控与 HTTP/3/QUIC 恢复；所有协议均需与独立第三方实现（OpenSSL、Xray、sing-box、OpenVPN/OpenConnect 对端等）实网互通验证，不以自连自测代替互操作。

---

## 2. DNS 与持久状态验证

- **可控测试优先**：使用可编程假上游、虚拟时钟与可注入故障的存储适配器验证 TTL、负缓存、并发请求合并（singleflight）、乐观刷新、视图隔离与清空屏障；再在隔离 netns / 临时目录验证真实 `local` / DoT / DoH / DoQ / DoH3 / `resolved` / `dhcp` / `mdns`。
- **原子落盘与崩溃恢复**：FakeIP WAL、DNS 缓存快照、规则集缓存与策略组状态均验证断电/写失败回滚、旧版兼容迁移与损坏文件降级恢复，确保故障时不破坏上次已提交状态。

---

## 3. Linux 系统集成验证

- **隔离环境要求**：在独立网络命名空间或专用测试机验证，保留操作前后属于本实例的 nftables 表、策略路由、DNS 与服务状态，绝不清空宿主规则。
- **核心场景**：
  - 无特权普通代理模式（不请求 TUN/nft 权限）；
  - `systemd` 启停、配置错误退出码、优雅停止与 `SIGHUP` 热重载多代次并存；
  - `auto-redirect`（TCP `redirect` / UDP `tproxy`、FakeIP 与 DNS 53 优先劫持、本地/绕行保护与防环回）；
  - `systemd-resolved` TUN 链路配置（含 `SetLinkDNSOverTLS("no")` 及退出恢复）与异常崩溃后清理；
  - 物理 socket 绑定（接口、双栈源地址、`routing-mark`、`netns`、`protect-path`、MPTCP、TFO 与候选回退）。

---

## 4. 性能验证准则与 Linux 实机基线

- **基准纪律**：正确性未通过的样本不进入性能对比；固定提交、编译器（Clang `llvm@23.1.6` + 静态 `libc++`）、CPU 亲和性、MTU 与交错重复顺序，保留完整尾延迟、FD、RSS 与 CPU/字节指标。
- **容量与稳定性实测（Linux x86-64，双后端）**：
  - 并发连接：2,048 条活跃流稳定运行且排空后 FD 自动归零；
  - 极限资源护栏：`RLIMIT_NOFILE=192` 触发 `EMFILE` 退避后不中断既有流并可恢复接入；`RLIMIT_AS=160 MiB` 下 256 条活跃流配额拒绝与恢复正常；三代热重载同时承载 192 条活跃连接并平滑回收旧代；
  - 长时混合压测（60 轮：23,040 条短流 + 480 条长流 + 30,720 条 DNS 查询）：`epoll` / `io_uring` 短流 P99 为 `7.18 / 7.28 ms`，DNS P99 为 `1.51 / 1.56 ms`。
- **同机吞吐与延迟基线**（代理绑 CPU 12–13、对端绑 CPU 14–15，三轮中位数）：

| 后端与路径 | 上传 / 下载 Gbit/s | TCP 接入 P95 ms | 长流 CPU ms/GiB | 活跃峰值 FD | SOCKS UDP ms | 独立 UDP DNS ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Nexus `epoll`（常规） | 17.79 / 17.92 | 17.55 | 373.3 | 146 | 0.047 | 0.040 |
| Nexus `io_uring`（常规） | 18.37 / 18.21 | 17.27 | 346.7 | 144 | 0.059 | 0.037 |
| Nexus `epoll` + `splice` | 19.2 / 19.6 | 11.16 | 46.7 | 143 | — | 0.039 |
| Nexus `io_uring` + `splice` | 19.4 / 20.2 | 10.78 | 53.3 | 141 | — | 0.047 |

`splice` 快路径与 per-worker 管道池下，长流 CPU 稳定在 **46.7 / 53.3 ms/GiB**，峰值 FD 141–143 且空闲归零，RSS 稳定在 **13.2–13.8 MiB**。
