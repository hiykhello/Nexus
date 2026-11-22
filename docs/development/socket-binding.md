# 通用物理 socket 绑定

更新：2026-11-01。绑定21100图的正式io CLI111场景及根68项已通过；UDP分片字段现已接入99715正式组合图，生产io CLI32场景、双后端TCP绑定与UDP组件均通过。完整epoll/关闭图仍继续。唯一执行点见[项目进度](../progress.md)，完整拨号字段不因本切片缩减。

## 参数与归属

`direct`、SS-2022、VLESS、Trojan、AnyTLS 的现有拨号节点新增：

| KDL 字段 | 执行行为 |
| --- | --- |
| `bind-interface "lo"` | 物理 TCP/UDP 打开后设置 Linux `SO_BINDTODEVICE`；非空、最多15字节，无 NUL、空白、斜杠或冒号。 |
| `inet4-bind-address "127.0.0.2"` | 对 IPv4 候选的 socket 绑定对应数值源地址，端口由内核分配。 |
| `inet6-bind-address "fd42::2"` | 对 IPv6 候选绑定数值源地址；当前不接受 zone、括号、端口或 IPv4-mapped IPv6。 |
| `bind-address-no-port #true` | TCP 绑定源地址前设置 `IP_BIND_ADDRESS_NO_PORT`，明确 false 亦执行；UDP 无此选项。 |
| `routing-mark 16897` | 对物理 TCP/UDP 设置32位 `SO_MARK`，0亦是明确值。标记本身不创建策略路由。 |
| `reuse-addr #true` | TCP 设置 `SO_REUSEADDR`；UDP 同时设置 `SO_REUSEADDR` 与 `SO_REUSEPORT`，明确 false 亦执行。 |
| `udp-fragment #true` | 物理UDP准备时设置 IPv4/IPv6 PMTU discovery 为 `DONT`，允许内核分片；false 设置为 `DO`，超MTU发送返回 `EMSGSIZE`。省略保留内核默认值，TCP不设置该选项。 |

所有字段重复或类型错误都拒绝。带 detour 的节点拒绝自己的物理 socket 参数；最低物理节点执行参数，显式 `detour "direct"` 借用 direct 的完整设置。连接期限、来源元数据和业务 DNS 条件沿用原契约，bootstrap 不继承业务条件；本切片不把业务 socket 参数偷偷应用到独立 DNS transport。

当前 Linux x86-64/glibc 边界沿用已核验的 `setsockopt`/`getsockopt` C ABI。设置或 bind 失败会拒绝该次准备，返回真实系统错误并清理资源；不静默继续连接或发送。权限、接口存在与源地址是否配置由内核最终判定。后续新增字段的作用范围和验证见下文矩阵。

## 共享实现与成本

`platform::SocketBinding` 是固定字段对象，52字节，合入现有 `TcpSocketOptions` 后该对象84字节。平台函数先设置接口、mark、reuse；TCP 准备再设置 no-port/keepalive、绑定源地址并执行原候选连接流程。空策略无新增 socket option 系统调用，不因只有 binding 而启用 keepalive。

`net::UdpDialSockets` 直接持两个原 `UdpSocket`、借用稳定不可变 policy，无 heap owner 或虚分派。空策略使用原一个 dual-stack fd；只有配置了逐族源地址才按实际访问懒开两个 fd。对象48字节，较原单 `UdpSocket` 的8字节多40字节固定状态。固定轮转保持两族公平；peek/consume 保持同一 fd，raw receive 保持默认每个 SS 包一个 recvfrom。设置失败关闭这组 fd 并保留原系统错误，授权仍在原协议层完成。

同一策略已传入 SOCKS UDP、共享 UoT/Trojan/AnyTLS stream datagrams、SS native UDP relay、VLESS/Vision/HTTPUpgrade XUDP ServerDirect。原 reply authorization、空包、MTU、会话代次和背压/取消规则不变；新数据报 owner 只负责物理 socket 准备。SS listener registry 借用的 policy 活过所有 dispatcher/socket，先停止并排空再销毁。

## 已有独立证据与正式验收

草稿及独立脚本在 `/tmp/nexus-dial-bind-integration/`，base hash 和 applied-source hash 分开保存。新代码只有命名模块 import，没有新增文本 include。

- 新配置测试覆盖全部5种 outbound、默认/显式 false/0、非法类型/地址/范围/重复及 detour 参数归属；连同原 config、HTTPUpgrade、Trojan、AnyTLS 共5项独立实际通过。
- TCP 组件在临时 user/netns 内实测 IPv4/IPv6：接口、真实本地源地址、mark/reuse/no-port 的 get_option、no-port时绑定前端口为0、关闭该选项后预分配端口、坏接口/未配置源地址/非法参数。独立版本先过epoll，正式21100保存bin已过双backend×双族。
- UDP 组件18个策略、失败与恢复场景在真实双族 socket 上通过：对端实见源地址、空包/精确256字节、重复 peek 与 consume/receive、两族轮转、缺接口/缺地址/非法name，普通/数组/aligned C++ new 均为0。该组件检查了 mark 值设置，尚不能替代实际策略路由。
- 普通根 `tcp_socket_options` 保留无需 namespace 权限的 keepalive 检查；新的 `socket-binding-tcp`/`socket-binding-udp` 为独立 bin，在临时 user/netns 下运行。

`tests/socket_binding_network.py <saved-cli> --evidence <json>` 自动只在临时 user/netns 配置 lo 与测试源地址，验证生产入站直连与各协议最低物理出站的真实 TCP/UDP 源地址、显式 direct 与 Trojan detour、workers1/2、两族、空包及设置失败后的会话恢复。它还在临时 namespace 中设置按 origin 端口匹配的 prohibit 规则，检查未标记 TCP/UDP 被拒、指定 mark 实际选中可达路由。21100实际完整111/111通过：入站32、最低物理出站72、准备失败/新会话恢复5、真实mark策略路由2。入站包含SOCKS/nativeSS/SS-UoT/VLESS/Vision/HTTPUpgrade/Trojan/AnyTLS，workers1/2；远端实见默认和配置的两个源地址，Nexus双端保留空UDP。物理出站覆盖 6 协议 × 双族 × own/explicit-direct/Trojan-layer × workers 1/2（部分外部 XUDP 对端仅测非空包）。证据`/tmp/nexus-trojan-verified-ifdg5f2l/21100/binding-evidence.json`与各scope日志/strace。首入站driver漏KDL块间换行导致语法失败，仅修Python后完整32重跑；没有放宽生产校验。

现有 `/tmp/nexus-trojan-verified-ifdg5f2l/epoll-25851/` 不包含本切片，不能用于验证这些新字段；21100已保存64个当前Ninja目标bin/SHA/source，根测试28019为68/68。`/tmp`曾满导致首拷贝不全，较早32330/2851/97439逐文件SHA迁至 `~/.cache` 并保留原路径symlink后，新图完整保存成功；未执行不完整bin。

## UDP 分片正式验收

99715正式组合图的72个选中程序、源码SHA、CDB、Ninja、链接rsp及mcpp成功记录保存于 `target/continuation-20261101/root-99715/`。`udp-formal-1793528632767663846/report.json` 四组均exit0：TCP绑定双backend×双族，原UDP绑定18场景，分片组件20场景，生产CLI32场景。最初直接在宿主权限下运行TCP绑定夹具，实际 `SO_MARK` 返回EPERM；失败trace独立保留，之后按夹具原契约在临时user/netns运行，未修改生产代码或宿主路由。

`tests/udp_fragment_cli.py` 只在owned user/netns中创建MTU1280的veth和另一netns内的双族UDP对端，覆盖8种入站×workers1/2×true/false。每场分别实测IPv4/IPv6的空包、1200B、2048B及新关联256B恢复，对端逐字节核对；AF_PACKET观察实际分片/未分片及末片offset、包长上限。入站为SOCKS、SS native、SS UoT、VLESS、Vision、HTTPUpgrade、Trojan、AnyTLS。生产证据明确为io图，不能代替完整epoll CLI。

组件另验证接口/源绑定开关、两项PMTU setsockopt及SO_DOMAIN getsockopt准备失败前没有业务send、新owner恢复；普通/array/aligned new均0。`SocketBinding`52B、`TcpSocketOptions`84B、`UdpDialSockets`48B保持绑定基线大小，无新增owner、转发协程或逐包选项syscall。全部5类出站的配置/重复/非法类型/detour归属测试随普通根测试继续验收。


## 第 56A 批物理承载矩阵

| KDL 字段 | 物理 TCP | 直连 UDP | 物理 QUIC UDP | WireGuard 外层 UDP |
| --- | --- | --- | --- | --- |
| `bind-interface`、`routing-mark`、`reuse-addr` | 连接前设置 | 发送前设置 | 统一在 UDP 绑定前设置 | 由外层 socket 准备 |
| 双栈数值源地址 | 按实际候选分别绑定 | 按地址族使用各自源地址 | 按对端族绑定 | 按对端族绑定 |
| `udp-bind-port`、`udp-fragment` | 仅用于该出站的数据报路径 | 发送前执行 | QUIC 握手前执行 | 外层发送前执行 |
| TCP 保活、`bind-address-no-port`、MPTCP、TFO | 物理 TCP 路径执行，TFO 受协议和首发数据条件限制 | 仅用于该出站的 TCP 路径 | Hy2、TUIC、MASQUE 拒绝 TCP-only 选项 | 拒绝 TCP-only 选项 |
| `netns`、`protect-path`（第 71B） | 创建及连接前 | 创建及绑定前 | 创建及握手前 | 具名出站外层创建及绑定前 |

`net.udp_connect` 统一 Hysteria 2、TUIC 和 MASQUE 打开与绑定物理 UDP 的路径，已有 detour 保持由底层承载准备 socket。普通 TCP 的准备沿用 `net.tcp_connect`。证据位于 `target/proxy-kernel-parity-2026-11-19/56-dial-*`，包含双后端字段拒绝、真实 QUIC Initial 地址与源端口、同端口绑定恢复和具名 detour。
