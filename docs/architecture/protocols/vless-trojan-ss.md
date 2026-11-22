# VLESS、Trojan 与 Shadowsocks 2022 设计边界

状态：协议设计草案；VLESS/TLS 客户端已有有限实现和互操作，其余组合尚未完成。按[决策 0008](../../decisions/0008-protocol-priorities-and-vmess-deprecation.md)，VLESS/Reality 与 SS-2022 为 P0 目标，Trojan 为 P1；Nexus 不计划提供 VMess 和旧版 Shadowsocks 兼容。优先级不等于已支持或已测性能。

## VLESS

基础 VLESS 请求包含版本、16 字节用户 UUID、长度限定的 addons、命令以及按命令要求出现的目标地址/端口；响应还需解析版本及 addons。普通 TCP/UDP 按命令区分端口与地址布局，Mux/XUDP 等命令采用独立帧格式，不能把单张普通请求示意图套用于所有命令，也不能把 UDP 数据报当连续 TCP 流处理。

`vless` 模块实现了 version 0 请求/响应头编解码（支持 IPv4、IPv6 与 1–255 字节有限 ASCII 域名，拒绝零端口及未支持命令/addons，解析时保留后续 payload），并已完整接入 TLS 1.2/1.3、REALITY（含 `X25519MLKEM768` 与 fallback）、Vision、WebSocket、HTTPUpgrade、gRPC、XHTTP（`packet-up`/`stream-one`/`stream-up`）以及固定目标 UDP / XUDP / `packetaddr`，通过独立互通对端双向双向传输、背压与半关闭验证。

Corosio 客户端将协议头部与已认证 TLS 流组合，允许响应前发送首批数据并在解析响应时保留同记录的后续载荷；服务端适配器把握手核心与字节流组合，在拨号成功后写出响应并保留预读载荷，由调用方负责拨号、期限、取消与对象寿命。

正式代理回环与多 worker VLESS 入出站均通过双向传输、慢读背压、半关闭与串联出站验证，完整支持矩阵见 [支持矩阵](../../planning/proxy-kernel-support-matrix.md)。

正式 VLESS/TLS 入站为每次 TLS 握手设置 8 MiB 固定逻辑预算，并在应用记录接管未消费字节后释放交接预留；额度不足时关闭该连接。预算覆盖目前已计费的握手和异步 I/O 缓冲，证书凭据、容器额外容量、加密库内部对象及握手后的转发并未完整计入，因此不能作为连接实际内存上限。

基础 VLESS 的 UUID 用于识别用户，不提供可替代安全传输的保密性和完整性；Nexus 应要求经验证的 TLS 或经验证的 Reality 承载。本文[配对配置](../../configuration/examples/paired/client.kdl)使用普通 TLS，不启用 Vision。Vision 是单独的流控/传输行为，涉及内层协议检测、封装和切换条件；不能以看到 TLS ClientHello 就直接跳过加密/认证，也不保证所有流量都能裸流或零拷贝。其线格式、双端状态与兼容范围须基于固定实现逐项验证。

增量解析须处理任意分片、长度溢出、未知版本/命令、UUID 认证失败、半关闭及首段业务数据的所有权。验收使用真实 client/server 样本，区分普通 TCP、UDP 和 Vision 等各组合，不因一个组合成功宣称全部支持。

## Trojan

Trojan 通常在受验证 TLS 内用密码的 SHA-224 小写十六进制表示识别用户，请求含 CRLF、命令、地址/端口和后续数据；UDP framing、响应及 TCP 转交按固定互操作目标验证。服务端对鉴权值采用适当的恒时比较，不记录明文密码或散列；密码文件必须有足够熵，TLS 身份校验不能省略。

`trojan` feature 已接入生产双后端 CLI、配置、TLS 1.2/1.3 入出站、TCP 命令 1 与 UDP 命令 3。核心共享无 I/O 地址/数据报编码，TLS 连接器与通用流/数据报转发不包含 Trojan 类型分支，已完成双后端 TCP/UDP、错误凭据与 TLS 身份、分片/合包、预读、空包、双栈、延迟半关闭、队满恢复、DNS 上下文及多层 detour 验收。[成对配置示例](../../configuration/examples/trojan/client.kdl)需要部署者自行提供凭据。

当前认证失败直接关闭，fallback、Reality、Mux 和其他承载的配置会拒绝。未来若增加受控 fallback，是否能无损回放已经读取的内容取决于 TLS 终止位置、缓存所有权和选定目标：不能把错误密码一律解释成可直接转发的普通 HTTP，也不能保证所有 fallback 隐藏代理特征。Fallback 访问目标、递归环、超时、并发和限速须配置和验证。

## Shadowsocks 2022

协议依据 [SIP022](https://shadowsocks.org/doc/sip022.html) 与 [SIP023](https://shadowsocks.org/doc/sip023.html)。目标方法为 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 和可选的 `2022-blake3-chacha20-poly1305`；分别验证对应传输与 EIH，不能推断所有方法支持所有多用户组合。AES-128/256 的 PSK 分别为 16/32 字节，base64 仅是配置编码，必须由安全随机源产生，不能按旧协议把任意密码派生为 PSK。AEAD-2022 不提供前向保密。

- TCP：每条连接使用随机 salt、BLAKE3 derive-key 和 AEAD 分块；双方检查类型和时间戳，client 还检查响应中的 request salt。服务器对已认证且时间有效的请求保存接收 salt **60 秒**，必须检测重复；不能只靠时间戳，不能用会产生假阳性的过滤器冒充规范要求。
- UDP：按 session ID 和 packet ID 管理会话及每会话 1024 包重放窗口，成功认证后才推进窗口与更新客户端 endpoint；响应关联客户端 session，乱序、NAT 重绑定与服务端重启均按 SIP022 处理。单所有者服务端会话表至少保留 62 秒并拒绝时钟回退或过慢，满载拒绝；同一密钥的所有监听器共享同一重放状态，进程重启不共享重放状态。
- 墙钟 Unix 时间戳与本地单调计时各司其职；超过规范规定的 30 秒时间差须视为重放。会话、salt 表与过期队列需要按连接速率、会话数和突发预算定容；资源耗尽时拒绝新会话并诊断，不能把记录提前清除后仍宣称满足重放要求。
- 跨进程与重启后的所有权、持久提交、响应 ID 和恢复约束见 [重放状态设计草案](ss2022-replay-state.md)。
- AES EIH 支持 TCP、UoT v2 与原生 UDP 入站：先用身份密钥定位用户，再用用户密钥验证载荷，随后才更新重放窗口或来源；回复使用用户密钥，热重载时新旧用户代次隔离，双后端均已通过完整互通验证。

BLAKE3 密钥派生由离线锁定源码经独立模块封装，涵盖会话子密钥派生、AES-GCM / XChaCha20-Poly1305 分块（12 字节小端 nonce 严格单调递增、错误即关闭）、TCP/UDP 首部与 30 秒时间窗校验、线程安全有界 salt 抗重放表（单调时钟与墙钟双校验）及双后端 TCP / 原生 UDP / UoT 生产入出站。跨进程重启的防重放保护需由部署与运维策略补充。

## 验收

固定互操作实现版本和样本，对 TLS 身份、普通 VLESS/Trojan 的 TCP/UDP、SS-2022 必选 cipher 的 TCP/UDP 及实际选定 EIH 组合逐项测试。覆盖每字节拆分、非法长度、错误身份、重放、计数溢出、时钟回拨、salt 表满、UDP 乱序/会话过期、重启、带宽/内存预算和取消；所有未通过或未实现组合明确列出。

## UDP 数据报封装的边界

广义“UDP over TCP”指把数据报封装进可靠字节流的能力；UoT v2 则是明确的分帧协议扩展，不可与其他封装格式混用。

| 路径 | 协议封装行为 | 互操作注意事项 |
| --- | --- | --- |
| VLESS（包括使用 Reality 的组合） | 默认支持 XUDP，也可显式选 `packetaddr` 或 `fixed`（普通 VLESS UDP Command=2） | XUDP、packetaddr 和普通 VLESS UDP 分别验证；Reality 是外层安全传输，不决定 UDP 分帧。不要把 XUDP 简化成 VLESS 普通 UDP Command=2 的同义词 |
| Shadowsocks 出站 | 默认使用协议原生 UDP 路径；启用 `udp-over-tcp "v2"` 后经 TCP 流承载 UoT v2 | UoT 是额外扩展，服务端必须支持对应版本；SS-2022 组合需双端一致配置 |
| SOCKS 出站 | 默认使用 SOCKS5 UDP 路径；启用 UoT 时经 TCP 连接承载 | UoT 经 SOCKS 的 TCP 连接承载，需兼容的接收端；普通 SOCKS5 服务器不支持 UoT |
| AnyTLS | 出站以 AnyTLS 流承载 UoT v2；入站使用 UoT 路由器识别 | AnyTLS 的 SYN/PSH 等会话帧负责复用字节流，UoT 帧负责保留 UDP 数据报边界；无需额外 `udp_over_tcp` 配置不代表没有 UoT |

VLESS 的 `packetaddr` 在上述实现中拒绝域名目标；不同版本、传输和多路复用组合须分别验证。UoT v1/v2 的特殊目标和帧格式不同，v2 还区分连接与非连接格式；明确配置版本并测试对端，不能根据名称推断兼容。TCP 有序重传可能引入队头阻塞，适用性和性能需实测。AnyTLS 已按决策 0008 纳入 P1 扩展梯队，重点验证 TLS 会话预热池及客户端元数据脱敏；实现时不由此表改变项目协议优先级。

实现时分别测试原生 UDP、XUDP、packetaddr 和 UoT 的数据报边界、域名/IP 目标、空包及长度限制、分段和合包、关闭/取消、资源上限与双端版本互操作；不得将封装层默认值当作服务端兼容保证。
