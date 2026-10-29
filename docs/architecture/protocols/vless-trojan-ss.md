# VLESS、Trojan 与 Shadowsocks 2022 设计边界

状态：协议设计草案；VLESS/TLS 客户端已有有限实现和互操作，其余组合尚未完成。按[决策 0008](../../decisions/0008-protocol-priorities-and-vmess-deprecation.md)，VLESS/Reality 与 SS-2022 为 P0 目标，Trojan 为 P1；Nexus 不计划提供 VMess 和旧版 Shadowsocks 兼容。优先级不等于已支持或已测性能。

## VLESS

基础 VLESS 请求包含版本、16 字节用户 UUID、长度限定的 addons、命令以及按命令要求出现的目标地址/端口；响应还需解析版本及 addons。所读 [Xray 编解码](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go) 对普通 TCP/UDP 写端口和地址，Mux 等命令有不同布局；不能把一张普通请求示意图用于所有命令。UDP 有单独分帧，不能把数据报当连续 TCP 流。[Xray addons 编解码](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/addons.go)。所引用分支可变，正式实现须固定版本和协议样本。

`nexus.vless` 已实现独立的 version 0 普通 TCP、空 addons 请求与响应头编解码，参考 [Xray-core v1.260327.0 编解码](https://github.com/XTLS/Xray-core/blob/v1.260327.0/proxy/vless/encoding/encoding.go)及[地址编码](https://github.com/XTLS/Xray-core/blob/v1.260327.0/common/protocol/address.go)。它支持 IPv4、IPv6 和 1–255 字节的有限 ASCII 域名，拒绝零端口及未支持命令/addons，解析时保留后续 payload；GCC 16 样本、逐字节边界和负例通过。新增的服务端握手核心接受 1–64 个 UUID，增量解析并在成功认证后交付目标；只有调用方报告拨号成功才生成响应，头部后的数据留给调用方。测试用明文回环夹具与固定版本 sing-box 客户端验证 IPv4、IPv6、域名、首批数据及错误 UUID；夹具模拟拨号成功，没有连接实际目标。该核心未接入 TLS 或正式监听器，未验证比较的恒时性质，不支持 UDP、Vision、Mux 或 Reality。

Corosio 客户端已将该头部与已认证 TLS 流组合，允许响应前发送数据，并在解析响应时保留同记录的后续数据。GCC 16 io_uring 通过受控 Python/OpenSSL 服务端的头部、首批数据、拆分响应和错误 addons 测试。实验代理的 VLESS/TLS 出站与 sing-box 1.15.0-alpha.13（revision `824dbcfb4dd0a95921840b1737b950cde590241e`）VLESS TLS 入站完成回环转发；通过 `uv run python tests/tls_openssl_interop.py --sing-box` 显式执行。该有限测试尚不证明其他协议组合或生产级完整故障覆盖。

私有 Corosio 服务端适配器把握手核心与已有字节流组合，保留预读载荷并在拨号成功后写出响应；调用方负责拨号、期限、取消和对象寿命。GCC 16/io_uring 下验证认证拒绝、拨号失败、预读分段及挂起读取取消；明文双向 relay 与 sing-box 客户端、真实本地 TCP 目标完成数据转发及半关闭；慢读下 32 MiB 上传产生链路背压，恢复读取后完整往返。正式代理的回环 VLESS/TLS 入站经 sing-box 和真实本地目标验证双向传输、背压与半关闭，也验证经另一 Nexus VLESS 出站串接。使用现有 DNS、路由和会话管理；支持单叶 DER 或叶证书在前的 PEM 证书链，服务端不验证链的签名、顺序或有效期；支持 X25519 和 X25519MLKEM768 直接握手及 HelloRetryRequest，尚无 cookie、ALPN、PSK 和 UDP，仍为实验能力。

正式 VLESS/TLS 入站为每次 TLS 握手设置 8 MiB 固定逻辑预算，并在应用记录接管未消费字节后释放交接预留；额度不足时关闭该连接。预算覆盖目前已计费的握手和异步 I/O 缓冲，证书凭据、容器额外容量、加密库内部对象及握手后的转发并未完整计入，因此不能作为连接实际内存上限。

基础 VLESS 的 UUID 用于识别用户，不提供可替代安全传输的保密性和完整性；Nexus 应要求经验证的 TLS 或经验证的 Reality 承载。本文[配对配置](../../configuration/examples/paired/client.kdl)使用普通 TLS，不启用 Vision。Vision 是单独的流控/传输行为，涉及内层协议检测、封装和切换条件；不能以看到 TLS ClientHello 就直接跳过加密/认证，也不保证所有流量都能裸流或零拷贝。其线格式、双端状态与兼容范围须基于固定实现逐项验证。

增量解析须处理任意分片、长度溢出、未知版本/命令、UUID 认证失败、半关闭及首段业务数据的所有权。验收使用真实 client/server 样本，区分普通 TCP、UDP 和 Vision 等各组合，不因一个组合成功宣称全部支持。

## Trojan

Trojan 通常在受验证 TLS 内用密码的 SHA-224 小写十六进制表示识别用户，请求含 CRLF、命令、地址/端口和后续数据；UDP framing、响应及 TCP 转交按固定互操作目标验证。服务端对鉴权值采用适当的恒时比较，不记录明文密码或散列；密码文件必须有足够熵，TLS 身份校验不能省略。

认证失败可按显式配置决定关闭或向受控 fallback 转交。是否能无损回放已经读取的内容取决于 TLS 终止位置、缓存所有权和选定目标：不能把错误密码一律解释成可直接转发的普通 HTTP，也不能保证所有 fallback 隐藏代理特征。Fallback 访问目标、递归环、超时、并发和限速须配置和验证。

## Shadowsocks 2022

协议依据 [SIP022](https://shadowsocks.org/doc/sip022.html) 与 [SIP023](https://shadowsocks.org/doc/sip023.html)。目标方法为 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 和可选的 `2022-blake3-chacha20-poly1305`；分别验证对应传输与 EIH，不能推断所有方法支持所有多用户组合。AES-128/256 的 PSK 分别为 16/32 字节，base64 仅是配置编码，必须由安全随机源产生，不能按旧协议把任意密码派生为 PSK。AEAD-2022 不提供前向保密。

- TCP：每条连接使用随机 salt、BLAKE3 derive-key 和 AEAD 分块；双方检查类型和时间戳，client 还检查响应中的 request salt。服务器对已认证且时间有效的请求保存接收 salt **60 秒**，必须检测重复；不能只靠时间戳，不能用会产生假阳性的过滤器冒充规范要求。
- UDP：按 session ID 和 packet ID 管理会话及每会话重放窗口，成功认证/验证后才推进窗口和更新客户端 endpoint；响应关联客户端 session，乱序、NAT 重绑定和服务端重启按 SIP022 处理。AES 方法与可选 ChaCha 方法的包头/nonce 处理不同。当前已有独立的 1024 包重放窗口、8 字节 session ID 子密钥派生、AES 分离头/GCM 及认证后的主头编解码；测试夹具作为客户端与固定 sing-box 服务端完成两种 AES 方法的 IPv4 短数据往返。另有单所有者服务端会话表，认证及主头校验后按客户端 session ID 提交重放窗口并更新来源，容量满时拒绝，至少保留 62 秒并拒绝时钟回退或过慢；显式到期返回 ID 供调用方关闭对应 relay socket。表还生成服务端响应，使用随机起点和单调分配的服务端 session ID，编码失败也消耗包序号，成功编码刷新期限；固定 sing-box 客户端经 SOCKS UDP 关联与测试夹具完成两种 AES 的连续数据报往返。表须由同密钥所有监听器共享并在该密钥使用期保留，进程重启会丢失重放保护且随机起点不能保证跨重启绝对唯一；实验组合已将会话表接到有界的 Linux 非阻塞 UDP relay，固定 sing-box 客户端通过测试夹具与真实 IPv4 回环目标完成两种 AES 的往返；实验监听器通过有界队列、域名解析和阻断策略处理请求，支持 IPv4/IPv6 回环测试、重绑定和取消。单 registry 在一个 executor 上为每个密钥保留一个状态，监听器替换前须停止并排空以保留重放记录；定时器驱动回包及到期。同一监听 owner 可在单 executor 上同时管理多个 socket，共享会话表，并按最后一次认证的入站 socket 回包；启用 SS-2022 的正式 KDL 服务现同时监听同端口 TCP 和 UDP，同密钥的多个入站由单 executor 与 registry 共享状态；UDP 只实现 direct 和 block，选中其他出口时拒绝。独立进程和进程重启不共享重放状态，重启后仍在时间窗口内的旧数据报可能再次被接受；不得将此视为跨重启防重放。系统 DNS 调用不可强制中断，停止时可能需要等待其返回。
- 墙钟 Unix 时间戳与本地单调计时各司其职；超过规范规定的 30 秒时间差须视为重放。会话、salt 表与过期队列需要按连接速率、会话数和突发预算定容；资源耗尽时拒绝新会话并诊断，不能把记录提前清除后仍宣称满足重放要求。
- 跨进程与重启后的所有权、持久提交、响应 ID 和恢复约束见[重放状态设计草案](ss2022-replay-state.md)；尚未实现。
- EIH 是 SIP023 的独立扩展，身份密钥链、用户密钥与具体 cipher 的兼容性都需固定互测。它不保证任意规模的用户容量或免疫所有主动探测。

固定的 BoringSSL libcrypto 不提供 BLAKE3；实验选用官方 BLAKE3 C 实现 1.8.4（提交 `b97a24f8754819755ef78d8016c0391c65c943c5`，Apache-2.0），经独立模块封装。`nexus.shadowsocks.key` 已实现 SIP022 会话子密钥派生，持有的密钥和临时派生状态会清理；GCC 16 官方派生向量和独立实现的 16/32 字节样本通过。`nexus.shadowsocks.chunk` 提供单向 AES-GCM 分块状态，12 字节小端 nonce 从零递增，限制明文不超过 65535 字节；错误后关闭，nonce 耗尽后关闭。调用方必须保证不同实例不会复用同一密钥和 nonce。独立向量覆盖两个密钥长度和前两个 nonce，尚未实测 nonce 耗尽。`nexus.shadowsocks.header` 编解码 TCP 固定首部和请求可变首部，校验类型、30 秒时间窗口、响应关联 salt、SOCKS 地址结构和填充边界；调用者负责认证后再使用解析结果，并执行 salt 防重放和协议 I/O。`nexus.shadowsocks.replay` 提供线程安全的有界精确 salt 表，登记至少保留 62 秒，表满时拒绝新项；有序索引提供对数查找，时间队列按序回收，增加索引内存且集中到期可能产生清理延迟；结合整数秒时间窗口及一秒采样容差，比较单调时钟和墙钟水位，墙钟回拨或过慢时拒绝请求直至追上。它不执行认证，所有使用同一服务端密钥的 worker 必须共享同一表；显式虚拟时间接口拒绝乱序样本；正式入站在表锁内采样时钟并重新校验认证时间戳，避免 worker 调度顺序误拒。进程重启与表生命周期仍须在集成层处理。`nexus.shadowsocks.request` 将请求首包的密钥派生、两块 AEAD、首部校验和重放登记组合为内存接口，初次读取的单次调用、同次写入、防探测关闭及共享表仍由 socket owner 负责。`nexus.shadowsocks.response` 编解码响应 salt、固定首部及首个非空载荷，并检查时间和请求 salt；调用者仍须生成新随机 salt 并执行规定的 socket 操作。`nexus.shadowsocks.frame` 提供首包后的长度和载荷加密帧及有界增量解析，错误与截断会终止状态；内存测试已串接请求和响应首包。测试专用 socket 夹具与 sing-box 提交 `824dbcfb4dd0a95921840b1737b950cde590241e` 在两种 AES 方法下分别作为客户端和服务端完成 TCP 首包及后续帧的短数据回环；这不是正式代理或完整互操作验证。`nexus.shadowsocks.corosio_client` 提供带期限的客户端首包单次异步提交，生成随机 salt 和非零随机长度填充，部分写入后取消 socket；后续帧支持带期限的异步完整写入，错误或异常关闭编码器并取消 socket；响应首包异步接收严格只做一次初始读取，认证后收集首个载荷并保留预读尾部；后续帧异步读取器支持小缓冲区、预读尾部及干净 EOF/截断区分，错误取消 socket。`nexus.shadowsocks.corosio_relay` 在单 executor 上组合双向转发及半关闭；本地 socket 短数据与挂起取消测试通过，并与固定版本 sing-box 服务端通过两种 AES 方法的短数据、双向半关闭回环；高负载与更广泛故障仍待验证。实验代理服务 API 可添加 SS-2022 TCP 出站并通过索引路由选择；SOCKS5 与 sing-box 服务端的两种 AES 短数据和半关闭已通过。正式 KDL/CLI 已接入 TCP 入站及出站；独立 sing-box 已验证两种 AES、多个 worker、并发数据、半关闭、阻断、重放和停止，SS-2022 入站到 SS-2022 出站的四种算法组合也已验证。正式 UDP 入站通过两种 AES、同密钥双端口、多个 worker、系统 DNS、阻断、bind 回滚及固定 sing-box 回环测试；UDP 出站和跨进程重启防重放尚未实现，更多故障和生产安全验证尚未完成，因此不能视为完整 SS-2022 支持。AES-GCM、XChaCha20-Poly1305、随机源、密钥清理和相关 API 同样需真实构建和已知答案验证。不采用未测得的性能数字或“完全免疫”等保证。

## 验收

固定互操作实现版本和样本，对 TLS 身份、普通 VLESS/Trojan 的 TCP/UDP、SS-2022 必选 cipher 的 TCP/UDP 及实际选定 EIH 组合逐项测试。覆盖每字节拆分、非法长度、错误身份、重放、计数溢出、时钟回拨、salt 表满、UDP 乱序/会话过期、重启、带宽/内存预算和取消；所有未通过或未实现组合明确列出。

## UDP 数据报封装的边界

以下以本地 sing-box 提交 `a6952ccf6` 的出入站实现为参照，描述互操作目标，不表示 Nexus 已实现这些格式。广义“UDP over TCP”是把数据报封装进可靠字节流的能力；SagerNet 的 [UDP over TCP（UoT）](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/) 则是具体协议，不能与其他封装互换。

| 路径 | 此版本 sing-box 的行为 | 互操作注意事项 |
| --- | --- | --- |
| VLESS（包括使用 Reality 的组合） | 未设置 `packet_encoding` 时使用 XUDP；也可显式选 `packetaddr`，或以空字符串关闭额外编码，走普通 VLESS UDP | XUDP、packetaddr 和普通 VLESS UDP 分别验证；Reality 是外层安全传输，不决定 UDP 分帧。不要把 XUDP 简化成 VLESS 普通 UDP Command=2 的同义词 |
| Shadowsocks 出站 | 默认使用协议的 UDP 路径；`udp_over_tcp` 启用后使用 SagerNet UoT | UoT 是额外扩展，服务端必须支持对应版本；SS-2022 支持组合须单独验证 |
| SOCKS 出站 | 默认使用 SOCKS UDP 路径；`udp_over_tcp` 启用后使用 SagerNet UoT | UoT 经 SOCKS 的 TCP 连接承载，需兼容的接收端；普通 SOCKS5 服务器不能仅凭开启客户端选项就支持 |
| AnyTLS | 出站以 AnyTLS 流承载 UoT v2；入站使用 UoT 路由器识别 | AnyTLS 的 SYN/PSH 等会话帧负责复用字节流，UoT 帧负责保留 UDP 数据报边界；无需额外 `udp_over_tcp` 配置不代表没有 UoT |

VLESS 的 `packetaddr` 在上述实现中拒绝域名目标；不同版本、传输和多路复用组合须分别验证。UoT v1/v2 的特殊目标和帧格式不同，v2 还区分连接与非连接格式；明确配置版本并测试对端，不能根据名称推断兼容。TCP 有序重传可能引入队头阻塞，适用性和性能需实测。AnyTLS 已按决策 0008 纳入 P1 扩展梯队，重点验证 TLS 会话预热池及客户端元数据脱敏；实现时不由此表改变项目协议优先级。

实现时分别测试原生 UDP、XUDP、packetaddr 和 UoT 的数据报边界、域名/IP 目标、空包及长度限制、分段和合包、关闭/取消、资源上限与双端版本互操作；不得将封装层默认值当作服务端兼容保证。
