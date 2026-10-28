# TUN 接管、出站防环回与故障恢复

状态：跨平台接管的设计草案；当前没有网络管理实现，也未在宿主执行路由、防火墙或 DNS 修改。TUN 设备、网络栈与系统接管是不同职责，见 [TUN 设计](../architecture/tun.md)和[平台抽象](abstraction.md)。本方案默认故障时优先恢复原有网络；明确启用 kill switch 的场景可以选择持续阻断，但不能同时承诺故障后自动恢复联网。

## 前置约束与接管顺序

所有可能发往外部的 Nexus socket 都必须能绕开自身接管，包括 Reality/SS-2022/WireGuard/Hysteria、直接出站、节点和 DNS bootstrap、健康检查与控制面测试。先解析节点及 DNS 引导依赖并检测环；不能让“解析服务器域名”依赖尚未建立的同一代理连接。每条 socket 在连接/发包前设置平台的绕行标识或绑定策略，失败按明确策略报错，不能偷偷走未标记路径。

启动顺序：获取单实例资源锁并快照宿主网络 → 建立 TUN、监听与后台恢复管理器 → 创建并验证外部绕行路径 → 配置 DNS 处理入口及其绕行 → 安装接管 → 验证 IPv4/IPv6、DNS 和代理链路 → 发布就绪。每步失败回滚本次已提交的对象；仅在带身份标识的自有对象上操作，不清空整张系统路由表或宿主防火墙。网络切换时先建立新绕行，再切换接管；旧路径保留到不再使用或明确超时。

## Linux：标记与策略路由

下表中的 `M/MASK`、表与优先级是按实例分配的逻辑值，不是直接可执行命令；不能占用其他防火墙或 VPN 的 mark 位。IPv4 与 IPv6 各配置并检查一组规则：

| 顺序 | 规则与目的 |
| --- | --- |
| 保留系统本地规则 | 保持系统对本机地址的处理，不覆盖优先级 0 的 local 表 |
| 较高优先级 | `fwmark M/MASK lookup nexus_bypass`：选择实际物理网络/经授权上游的路由 |
| 紧随其后 | 同一 mark 对应 `unreachable`：绕行表无匹配时阻止继续落入 TUN 接管表 |
| 随后 | 对选中的未标记流量 `lookup nexus_tun`，默认路由指向 TUN；未接管范围继续按系统策略处理 |

外部 socket 通过 `SO_MARK` 设置对应 mark；在 `connect`/首个 UDP 发送前设置，检查内核权限和返回值。需要 nftables 配合时，在 output/prerouting 的相关链先排除 Nexus mark、回环、TUN 返回流和其他显式排除，再对选中的流量标记/重定向；连接标记与数据包标记之间的复制必须按 hook 顺序设计。`SO_MARK` 标记自身进程**不自动**影响它所创建之外的其他进程，也不能代替 `ip rule`。相关接口以 [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html) 和 [ip-rule(8)](https://man7.org/linux/man-pages/man8/ip-rule.8.html) 为准。

绕行表需明确指向已确认的出口接口/网关或由平台管理的既有有效路由；不能仅写 `lookup main` 后假定 main 的默认路由一定不经过本实例 TUN。监测 netlink 路由、地址、接口和默认网关变化，丢失事件后全量重读；IPv6、无网关直连、多个 VPN、分流与 network namespace 分别验证。表无路由时上面的 `unreachable` 防止规则落空导致自环；还要为保留的 DNS 和健康检查准备实际可用出口。多实例的表、mark、nft chain、优先级及 ownership 必须冲突检测，不能只凭 UID 区分。

## Windows 与 macOS

Windows 上 Wintun 提供包设备，不自动建立系统路由或 DNS。通过 IP Helper 保存/创建指定接口及路由，必要时为代理服务器和 bootstrap 地址安装指向物理接口/网关的 `/32`、`/128` 路由，或对外部 socket 使用 `IP_UNICAST_IF` / 对应 IPv6 接口选择并验证实际最佳路由。路由先按前缀匹配，metric 是同等前缀选择因素，Windows 的有效 metric 还包括接口 metric；**只调 metric 不能保证绕过更具体的 TUN 路由**。[CreateIpForwardEntry2](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/createipforwardentry2)，[Windows socket 选项](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)。接口变化、DNS 返回新 IP、隧道和物理默认路由切换都需更新例外；局域网、其他 VPN 和 IPv6 必须单独验证。

macOS 首选评估 Network Extension 的 `NEPacketTunnelProvider`：以 `NEPacketTunnelNetworkSettings` 声明地址、included/excluded routes 和 DNS；物理接口与系统路由仍可能影响最终结果，不能假定 excluded route 覆盖所有本地路由。[Apple 路由文档](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)说明了接口和系统路由的关系。需要相应权限/entitlement 和宿主生命周期。直接 `utun` 配合自管路由、`pf` anchor 是另一个待验证部署方案；Apple 也建议优先使用 Network Extension，不能把手工 pf 当作所有 macOS 环境的默认做法。

## DNS 接管范围

逐平台保存原始 DNS 配置及所有权，配置系统/隧道 DNS 指向已就绪的本地解析器；将需要接管的 IPv4/IPv6 UDP 和 TCP 53 按平台允许的机制重定向，排除本服务及其 bootstrap。Linux 可评估 nftables redirect/TPROXY 与 resolved；Windows 需分别验证系统 DNS 配置、Windows Filtering Platform 等机制；macOS 可评估 Network Extension 的 DNS 设置，独立评估 pf。是否覆盖本机和转发流量需分别配置。

代理系统 DNS 或端口 53 **不等于**劫持浏览器自带 DoH、DoT、DoQ、进程内缓存或任意硬编码路径。未知加密 DNS 及受限应用的策略应明确允许、阻断或仅诊断，不能虚称全平台全覆盖；恢复时只有当前配置仍是本实例写入的值，才按记录撤销，避免覆盖用户或其他管理器之后的更改。

## SIGKILL 与恢复

SIGKILL 不能运行进程析构。为实现自动回滚，设计独立的、生命周期不与数据平面同死的特权监督者，持有网络变更日志、数据平面进程存活信号与恢复权限；进程死亡或租约失效时按记录反向撤销自有接管、DNS 和路由，恢复/保留绕行直至退出。服务管理器若把监督者和主进程一起终止，需独立 unit/控制组或等效平台监督机制，不能只依赖主进程 `atexit`。监督者只接受经过认证且受限的操作，崩溃重启时检查日志、当前对象身份和存活持有者；跨重启日志必须在修改前持久记录并可幂等重放。

fail-open 默认在监督者检测到异常后撤销自身接管；显式 kill switch 可继续阻断，必须有独立人工恢复入口。监督者也被杀、整机掉电、配置被并发改动或系统 API 失败时，不可能保证即时自动恢复；启动/重启时应先运行独立恢复流程，检测并报告残留，无法确认所有权时停止并给出只针对该实例的修复指导。不能宣称 `ExecStop`、路由 metric、TUN fd 关闭或仅靠下一次启动就能覆盖所有 SIGKILL 场景。

## 验收

在隔离网络环境验证本机/转发流量、IPv4/IPv6、TCP/UDP、DNS、直接出站和每种隧道出口的真实路径；验证 mark 权限缺失、表/优先级冲突、绕行路由失效、网络接口切换、DHCP/DNS 变化、多 VPN 与本地网段共存。逐步注入启动失败、主进程 SIGKILL、监督者失败、日志截断、系统重启及第三方修改，检查恢复身份、顺序和最终路由。不得以仿真成功代表上述各平台已支持。
