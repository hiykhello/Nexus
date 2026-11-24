# Nexus KDL 配置规范草案

状态：本文完整主配置字段和语义为设计草案；实验代理已实现[有限的 KDL 子集](examples/README.md)，其余节点会拒绝。独立谓词规则集已有有限实现；KDL 2.0 与指定 Glaze 分支是已确定的技术方向，主配置 schema 与默认值尚未冻结。本文定义足以审阅[成对示例](examples/paired/client.kdl)的配置形态，并给出其他协议的字段位置；不能把它当成当前程序的使用手册。

## 文档、名称与加载

主文件包含一个 `schema-version 1`、一个 `role "client"` 或 `role "server"`。`log`、`dns`、`routing`、`control` 最多各一个；`inbounds`、`outbounds` 分别包含可重复的 `inbound`、`outbound`；`endpoint` 可重复，第一位置参数为非空名称，分组内使用类型名作为节点名，例如 `socks5 "local"`、`direct "direct"`（`outbounds` 中 `direct`、`block` 可省略同名参数）；`listen`/`server`/`fallback`/`target` 支持 `"host:port"` 或 IPv6 `"[::1]:port"` 短写；出站组可用 `members "a" "b"` 展开成员；DNS `servers` 同样使用 `udp` 等类型名。规则放在 `rules` 块中，以 `-` 为每条规则的节点名：路由 `rules` 支持可选 `sniff-timeout-ms`、`unknown`、`udp` 属性及有序简写（`- sniff`、`- resolve`、`- hijack-dns`、`- reject`、`- <谓词> <值...> to="出口"`、`- rule-set "集" to="出口"`、`- default "默认出口"`，支持 `routing { default "出口" }`）；DNS `rules` 支持 `- domain-suffix "cn" to="local"` 等属性别名与简写。旧 `inbound`/`outbound`/`server` 加 `type`、传统 `rule kind="rule-set"`、`tcp-program` 和直接 `rule` 写法继续兼容。名称在同一类内唯一；出站与可作为出口使用的 endpoint 在出口引用命名空间内也不得重复。tag 精确匹配，不做环境变量或通配展开。

节点的单值子项只能出现一次，列表项（`address`、`member`、`rule`、`deny-cidr` 等）按文档顺序保留；对必须字段、未知节点/属性、非法类型、重复单值及悬空引用报错。KDL 属性按语言规范后写覆盖，若需要拒绝重复属性须先验证 Glaze 是否保留足够的原始信息，不能声称已能检查。仅下文明确的默认值可省略；其余缺失项的默认值待决定，示例尽量显式写出。

后续设计 `http-clients` 时，其每个子节点的节点名直接作为该 HTTP 客户端的 tag，例如 `http-clients { updates { ... } }` 中的 tag 是 `updates`。字段及生命周期候选见[具名 HTTP 客户端设计](../architecture/http-clients.md)；当前配置解析器不支持此节点。

先解析整份 KDL，再校验类型、引用、能力、地址和协议组合、依赖环与权限需求；构造候选时读取证书和凭据并检查。成功后才准备及接入网络资源。重载的具体事务边界、失败恢复和网络租约按[路由](../architecture/routing-engine.md)、[TUN](../platform/tun-routing-and-loopback.md)与[控制面](../architecture/control-api.md)约束实施；未经验证不能保证全系统操作原子化。规则文件相对路径相对于引用它的主配置所在目录，绝对路径保持绝对；不以当前工作目录解释。示例要求凭据/证书使用绝对路径。

配置、规则、证书与密钥都有各自字节、条目和嵌套上限。受保护文件的读取须校验文件类型、所属和权限，以打开的句柄读取并处理替换竞态；失败不得回退空密钥、关闭校验或转为无认证。密钥不写入日志、API、崩溃报告或规则集。`*-file` 指一个文件中的实际值，不是占位符展开：UUID 文件为 UTF-8 规范 UUID 文本，可有一个末尾换行；密码/token 为约定的 UTF-8 单行值，拒绝额外行、NUL 与空值；WireGuard 密钥为协议要求长度的 base64 值；证书和私钥为 PEM。具体读取权限和轮换生效时机需以实际实现验证。

## 运行日志

`nexus run` 默认在继承的 stderr 输出 `info` 及以上的单行文本，时间使用 UTC RFC 3339，隐私模式为 `redacted`。监听就绪行继续使用 stdout，`--traffic-stats` 的 SIGUSR1 快照仍使用原 stderr 协议。该选项将启动日志的级别设为 `debug`，便于默认配置下读取快照。

```kdl
log {
    level "info"
    format "jsonl"
    timestamp "rfc3339"
    privacy "redacted"
    domain-levels {
        dns "warn"
        route "info"
    }
    sink "stderr"
    sink "file" path="/var/log/nexus/nexus.log" max-size-mib=32 max-files=5
}
```

- 级别依次为 `trace`、`debug`、`info`、`warn`、`error`、`fatal`、`off`。域为 `core`、`net`、`tls`、`quic`、`dns`、`route`、`tun`、`proxy`、`control`、`state`。未单独指定级别的域继承全局级别。
- 格式为 `text` 或 `jsonl`，展示时间为 `rfc3339`、`monotonic` 或 `none`。JSONL 始终保留两个纳秒时钟及级别、域、事件码和代次。文本和 JSONL 的控制字符均转义。默认遮蔽可能含私密标识的运行诊断。显式 `privacy "verbose"` 可显示这类上下文，凭据仍不应出现在日志中。
- 可配置最多四个 sink，按配置顺序由同一个 writer 逐批写入。未列 sink 时使用 `stderr`。`off` 必须独占。启用 `log-journald` 的构建可选 `sink "journald"`，发送 `PRIORITY`、`NEXUS_DOMAIN`、`NEXUS_EVENT`、`NEXUS_GEN` 和 `MESSAGE` 等字段。慢 sink 会延迟同组写入，积压按级别丢弃并可查询计数。
- file 要求规范绝对路径、普通文件、当前有效 UID 所有、mode 0600、单硬链接。父路径组件和文件均拒绝符号链接。活动文件及预留的轮转路径不能与其他输出、配置、规则、已声明凭据或状态路径重叠。`max-size-mib` 可选，范围 1–4096。设置后可用 `max-files` 指定包含活动文件的保留数，范围 1–128，默认 1。旧文件为 `.1`、`.2` 等。单条记录完整写入。
- SIGHUP 验证同一份配置，先排空写入并重开文件，再执行既有路由重载。打开新文件失败时该 sink 保留旧 FD，级别保持原值；多个文件逐一处理。成功重载后应用配置中的级别，覆盖临时控制设置。修改 sink、格式、时间或隐私需重启。停机关闭入口并显式排空，已进入阻塞 I/O 的写入由 writer 完成。

## 部署角色与协议

| 节点 | 草案字段及语义 |
| --- | --- |
| `inbound ... type="mixed"` | 回环监听可显式使用 `authentication "none"` 或 `authentication "password" username="alice" password-file="/etc/nexus/secrets/mixed.password"`。密码模式覆盖 SOCKS5 用户名密码和 HTTP/1.1 Basic CONNECT、正向转发。用户名不能含冒号，转发不会携带代理凭据。UDP 关联使用 SOCKS5。 |
| `inbound ... type="tun"` | `device name=... mtu=...`、多个 CIDR `address`、`auto-route`、多个 `route-include`、`strict-bypass`；`sniff` 的 `enabled`、字节/毫秒预算及 `target-mode "metadata-only"`。自动接管和防环回须按平台实际创建资源，禁止降级成静默回环 |
| `outbound ... type="vless"` | `server host=... port=...`、`bootstrap-resolver`、`authentication { uuid-file ... }`、`tls`；可选 `flow "xtls-rprx-vision"` 启用 Vision TCP 流控。TLS `server-name` 为验证名和 SNI、`ca-file` 为信任锚、`verify #true` 启用身份校验；`key-exchange` 可选 `x25519`、`x25519-mlkem768`（允许回退到 X25519）或 `x25519-mlkem768-only`（不通告 X25519）；端口/拨号名和验证名各自独立 |

| `inbound ... type="vless"` | `listen`、`authentication` 中的多个 `user name uuid-file=...`、TLS `certificate-file` 与 `private-key-file` 或 `reality`；可选 `flow "xtls-rprx-vision"` 要求此监听的所有用户使用 Vision TCP 流控。server 证书须匹配 client 验证名并链到其信任锚；两个 UUID 文件的内容须相同 |
| `outbound ... type="direct"` / `"block"` | 前者经平台保护的连接器直接连接目标，后者拒绝流与数据报；server 示例用 `destination-policy` 限制可连接 IP |
| `outbound ... type="selector"` | 多个 `member` 和初始 `selected`；成员存在、能力适配且不形成依赖环。控制面修改仅影响之后的路由决策；选择 direct 会直接发送业务流量 |

HTTPUpgrade 承载使用 VLESS 节点内的 `transport "httpupgrade" { host "cover.example"; path "/nexus-upgrade"; header "X-Test" "value"; }`。配置及 API 已接线，单/双worker双端固定对端互通、Trojan detour、XUDP、身份/头拒绝和原期限已验证；完整故障/关闭图进度见[项目进度](../progress.md)。本实现要求经过身份校验的普通 TLS，协商 `http/1.1`；与 Reality 或 Vision 的复合配置当前拒绝。它在 HTTP 101 后直接传输 VLESS 字节，不使用 WebSocket 掩码或数据帧。

普通 VLESS TLS 也可使用 `transport "websocket" { host "cover.example"; path "/nexus-upgrade"; }`。两端在 HTTP/1.1 升级时验证 WebSocket 握手，再用二进制帧承载 VLESS TCP 和 XUDP。客户端发送带掩码的帧。服务端支持分片及交错 Ping/Pong。Close 结束整个传输，TCP 半关闭语义限于可保留该行为的承载。该配置与 Reality、Vision 和 gRPC 互斥。

`host` 是 HTTP authority，不改变节点拨号或 TLS 验证名。客户端省略时使用 `server-name`，服务端省略或空值表示不限 authority；指定时大小写敏感精确匹配。客户端 `path` 为线上 origin-form target，可含 percent 编码与 query；服务端 `path` 为解码后的精确路径，不包含 query。两端默认 `/`。`header` 可重复，最多 64 项且受共同 HTTP 头字节上限约束；协议关键头、framing 头及 `Sec-WebSocket-*` 不能通过额外头覆盖。配置值在监听前编译为拥有字符串的 profile。101 不代表 UUID 认证或目标连接成功，原身份、来源与规则条件仍由 VLESS 和真实物理连接提供。

出站的节点解析、TCP、TLS、Upgrade 与 VLESS 请求继续共用 `connect-timeout-ms` 的一次绝对期限。HTTPUpgrade 入站从接受连接开始的 TLS、Upgrade、VLESS 请求和首次目标解析/拨号共用 10 秒上限；部分头不会重启计时。运行时只使用原 TLS reader/writer，按 Upgrade 预读、原 record 后缀、后续 records 的顺序交接数据。固定 Go 对端允许 TLS 无 ALPN 的行为比本 profile 宽，本实现严格要求 h1，当前不承诺该宽松兼容。

实验性的 VLESS Reality 客户端在 `tls` 中使用 `reality { public-key "..."; short-id "..."; }` 代替 `ca-file` 和 `verify`。公钥为 32 字节十六进制，short ID 可省略或为至多 8 字节的偶数位十六进制，较短值右侧补零。仍须设置 `server-name`；客户端的 `key-exchange "x25519-mlkem768"` 在初始 ClientHello 依次发送 X25519MLKEM768 和 X25519，服务端可选其一。`x25519-mlkem768-only` 仅发送混合 share，`x25519` 保留传统模式。REALITY 使用独立 X25519 share 绑定 session ID，只有混合 share 时使用其末尾的 X25519 分量。实际 TLS 密钥和 CertificateVerify 仍按协商算法和握手记录验证。Vision 可以与 REALITY 一起配置。

Reality 入站在 `tls` 中使用以下结构，代替普通证书字段：

```kdl
reality {
    private-key-file "/etc/nexus/reality-x25519.hex"
    server-name "cover.example"
    short-id "0123456789abcdef"
    max-time-difference 60
    fallback host="cover.example" port=443
    // 可选：fallback-resolver "bootstrap"
}
```

X25519 私钥文件包含 64 位十六进制字符，并须满足私有文件权限要求。默认在监听器启动时生成内存中的 Ed25519 签名密钥和证书模板，停止后销毁；也可以同时配置 `certificate-file` 和 `signing-key-file`，提供匹配的 Ed25519 DER 证书及未加密 DER 私钥，签名私钥文件同样须满足私有文件权限要求。可以指定多个 `server-name` 和 `short-id`；short ID 最多 8 字节，短值右侧补零。身份时间偏差以秒计，默认 60；设为 0 关闭时间检查。认证失败时，原始流直接转发到配置的 cover；默认解析使用后台定期读取的 `/etc/hosts` 和 `/etc/resolv.conf` 快照，并通过异步 DNS 查询，不调用 `getaddrinfo`。查询保留开始时的快照；支持有限搜索域与 ndots，mDNS 及 systemd-resolved 分域配置尚未单独实现；文件读取或解析失败时新查询使用空快照。可选 `fallback-resolver` 指向已配置的 DNS server，使用该解析器及其 bootstrap 链，链中的 `local` 也使用上述异步快照解析。此连接是监听器配置的目标，不经过用户目标路由规则。探测和 cover 拨号共用 10 秒期限。回退转发保留双方的 TCP 半关闭，连接重置会传到另一端。转发空闲上限为 5 分钟，从接受连接开始的总时长上限为 10 分钟。认证证书使用 Ed25519。客户端支持 TLS HelloRetryRequest 并保留初始认证 session ID。服务端对携带有效 X25519 或 X25519MLKEM768 share 的 ClientHello 直接协商。

示例只描述普通 TLS 承载的 VLESS，不隐含 Reality 或 Vision。UUID 是身份标识而不是 TLS 的替代品。认证失败、证书不匹配、端口冲突或未编译的协议均应失败。Mixed 的明文无认证仅限本机信任边界，[SOCKS5/UDP 关联](../architecture/protocols/socks5-mixed.md)仍须限制资源和来源。

`destination-policy { deny-cidr ... }` 对直接提供的 IP 和域名解析产生的**每个候选地址**在拨号/发包前检查；禁止的候选不能因先通过域名规则而使用，重解析后重新检查。示例仅列出部分常见私网、回环和特殊地址，不构成完整的服务端访问控制策略；实际部署应根据网络、元数据服务、NAT64/IPv4-mapped IPv6、特殊地址和授权目的地建立完整策略。解析器自身访问与代理用户目标的信任边界应分别配置并验证。

此策略约束经过该 `direct` 出口的连接，包括示例 DNS resolver 的上游连接。若上游位于被拒绝的私网，应为该固定用途设计独立且受限的直连出口，不能为使 DNS 工作而放宽代理用户的目标限制；所需用途隔离须经过实现和验证。

## DNS、Fake-IP 与 TUN

已实现的具名 DNS 服务器写在 `dns { servers { server ... } }` 中，具体字段和兼容性见[配置示例](examples/README.md)。

启用 `dns-tls` 后可配置 `server "protected" type="tls" host="192.0.2.53" server-name="dns.example.test" ca-file="/etc/nexus/dns-ca.pem"`。默认端口为 853，可用 `port` 覆盖。若 `host` 是域名，须用 `domain-resolver` 指定独立的引导解析器。TLS 按 `server-name` 校验证书，握手和 DNS 问答共用查询期限。认证或握手失败会返回查询错误。物理 DoT 按 worker、上游 TLS 配置和实际端点复用连接，每条连接最多同时处理 32 个查询。取消只结束对应的查询。已复用连接发生传输故障时可在原期限内新建连接重试一次。

启用 `dns-https` 时可用 `type="https"`，默认端口 443，`path` 默认为 `"/dns-query"`。使用 POST 发送二进制 DNS 消息。直连及经代理的 HTTP/2 按执行器、上游配置和实际端点复用连接，每条连接支持最多 8 个在途查询。HTTP/1.1 每次查询建立独立连接。启用 `dns-quic` 时可用 `type="quic"`，默认端口 853。DoQ 对同一上游短期复用 QUIC 连接，每个查询使用独立双向流。两种类型沿用 DoT 的证书核验和 bootstrap 配置。显式构建特性 `dns-https3` 启用 `type="https3"`，默认端口为 443，沿用 DoH 的 `path` 和服务器身份配置。此类型使用 HTTP/3 POST，处理 HTTP Age，并在所选路径失败时返回查询错误。连接按执行器、上游配置和实际端点复用，每条连接最多并发四个查询，空闲 15 秒可被回收。取消或拒绝结束对应请求流。

可选构建特性 `dns-quic-resumption` 启用 DoQ 会话恢复。票据只存于内存，与具名上游的配置快照、实际 IP 和端口、信任根、服务端身份及 ALPN 绑定。每条新连接重新协商 QUIC 传输参数。对端拒绝票据时可用完整 TLS 1.3 握手继续。默认在 1-RTT 阶段发送 DNS 查询。对支持早期数据的 DoQ 上游可显式设置 `early-data=#true`，允许在恢复时提前发送一条无 EDNS 的 IN A 或 AAAA 查询。网络上的早期查询可能被重放。对端拒绝早期数据时，仍在有效期限内的查询会在同一连接的 1-RTT 阶段重发一次。

DoT、DoH 和 DoQ 上游可用 `detour="egress"` 指定配置中的具名 direct 出站。加密 DNS 的物理连接继承该出站对应 TCP 或 UDP 的 socket 设置与连接期限，包括 `netns` 和 `protect-path`。DNS 上游仍自行声明服务端验证名、信任根和具名 bootstrap。接口绑定集中在所选 direct 出站。DoT、DoH/1.1、DoH/2、DoH3 和 DoQ 可使用 direct 的网络候选和回退期限。DoQ 只在还未建立认证连接或发送查询字节时切换接口。具名 direct 出站的 TCP Fast Open 可用于 DoT 和 DoH 的 TLS ClientHello，未显式指定 detour 的 DNS 继续使用常规 TCP 建连。内部地址解析和独立 DNS 监听的 DoT、DoH/1.1 和 DoH/2 可通过具名流式代理出站连接。DoQ 和 DoH3 要求代理出站具备数据报能力。普通代理监听及其独立 DNS UDP/TCP 入口支持具名手动 selector、fallback、url-test 和 load-balance。load-balance 按配置的 DNS 上游主机或数值地址选叶。所选叶子变更后，新查询使用新出口和独立的缓存视图，在途查询沿用原视图。解析和下层出站的 bootstrap 依赖会在配置时一起检查，环路会被拒绝。代理 DoT 按执行器、TLS 配置和上游端点复用连接，每条连接最多同时处理 32 个查询。独立监听器在原地址上更换具有代理出口的上游传输配置需重启。

具名 `udp`、`tcp`、`tls`、`https`、`https3` 和 `quic` 上游可指定 `bind-interface="lan0"`。该上游的物理 socket 使用指定 Linux 接口，UDP 截断后的 TCP 回退也沿用此接口。域名上游的引导查询使用引导服务器自己的配置。接口绑定失败时查询失败。

`dns { optimistic-cache-seconds 30; … }` 为内部地址解析、独立 DNS 监听和 SOCKS UDP DNS 劫持启用乐观缓存。参数为 1 至 3600 秒，表示正答复 TTL 到期后可用的最长窗口。同一缓存键只启动一个后台刷新。过期 DNS 消息答复清除 AD，TTL 取剩余窗口和 30 秒中较小的值。查询的缓存开关照常生效。

`dns-fakeip` 为 SOCKS5、Mixed、透明 TCP、Linux UDP TPROXY 和普通 Linux TUN 提供显式 FakeIP 配置。在启用 `dns.listen` 的配置中加入：

```kdl
fake-ip server="business" ipv4-pool="198.18.0.0/16" ipv6-pool="fd15:4231::/96" ttl-seconds=60 state-directory="/var/lib/nexus/fakeip"
```

DNS 规则终止于选定的 `business` 上游时，专用 TCP/UDP 监听器为符合条件的 IN/A 和 IN/AAAA 生成租约。IPv6 池可省略，配置后 A 与 AAAA 共享映射容量。预定义及拒绝规则照常生效，DNSSEC、ECS 和其他未支持的查询选项沿上游路径处理。内部和引导解析仍向上游查询真实地址。池已满或启动隔离期内返回 SERVFAIL。有序流量规则可用 `domain-source="fakeip"` 匹配反查结果。

SOCKS5 UDP 的 FakeIP 回复保留请求中的合成地址和端口。经 Trojan UDP、Shadowsocks UoT v2 或 VLESS XUDP 转发时，每个别名绑定独立的代理流与回包授权，即使多个域名解析到同一真实端点。每个 SOCKS5 UDP 关联最多保留 16 个别名代理流，空闲 60 秒后回收。SOCKS5 FakeIP 直连使用独立 socket，固定 UDP 源端口仍不适用。普通 TUN 的 FakeIP UDP 使用直连，需要 `endpoint-independent-nat #false`，由宿主将 FakeIP 池的路由指向 TUN。

启用 `tproxy-udp` 时，UDP TPROXY 可对合成地址使用 indexed 或有序路由，通过原始合成端点向客户端回包。DNS 规则集重载产生新的策略视图。旧流继续使用原视图，新流使用新视图发布的地址。

状态目录要求当前进程用户拥有且权限为 `0700`，预置权限为 `0600` 的二进制 `instance.id`（16 字节）和 `history.key`（32 字节）。首次启动加 `initialize=#true`，成功后移除此项再重启。重启后的隔离期覆盖历史 TTL、租约宽限和在途缓冲。已记录的 IPv4 范围继续保留，已经写入历史的 IPv6 池须沿用原配置。

内部 A/AAAA 解析的有序 DNS 规则可使用 `rule domain-suffix="example.test" query-type="AAAA" server="remote"`；`domain` 与 `domain-suffix` 二选一，query type 可单独使用。query type 支持 `"A"`、`"AAAA"` 或 1..65535 的整数，当前地址解析只产生 A/AAAA。省略 query type 的旧规则继续作用于两种问题，同一条的条件同时满足后首命中选择服务器。不同服务器的结果须通过规范名、正负答复和地址数量检查后才合并；local 的 hosts、搜索域及在途快照继续保留。DNS 还支持 `domain-keyword` 和 `domain-wildcard`（`*.example.test` 只匹配一层标签），四种域名条件同条最多一个。`action="route"` 选择 server，省略 action 兼容旧行为；`action="reject"` 不带 server，令内部地址解析直接失败。显式 action 可无条件首命中。实际查询的一族被拒绝时整次解析不读缓存、不发上游问题，SOCKS 报规则拒绝、HTTP 报 403；单族策略不会检查未查询的另一族。显式 bootstrap 不应用业务拒绝规则，上游 REFUSED 保持 DNS 错误。执行边界与当前验收见 [支持矩阵](../planning/proxy-kernel-support-matrix.md) 与 [项目进度](../progress.md)。

DNS 问题规则可声明并引用独立规则集，例如 `rule-set "q" path="q.srs" format="srs"` 与 `rule rule-set="q" server="remote"`；也支持 KDL 和 BEVE。规则集与同条规则的其他条件按 AND 组合，适用于消息监听及内部地址解析；SRS 依赖 `srs` 构建功能。支持的条件、来源选项及上下文限制见[规则集](rule-sets.md)。

问题条件 `query-class` 可使用 `"IN"`、`"CH"`、`"HS"`、`"ANY"` 或 1..65535 的整数，与其他条件同时匹配。消息监听使用请求中的 class；内部 A/AAAA 地址解析使用 IN。`"ANY"` 匹配查询中的 class 255，不作为通配符。

启用 `dns-response` 时，`query-dnssec` 匹配 EDNS 的 DO 位，`query-checking-disabled` 和 `query-authenticated-data` 分别匹配请求头的 CD 和 AD 位。三个条件都接受 `#true` 或 `#false`。没有 EDNS 的报文按 DO 清零处理。内部地址解析没有客户端报文时，这些条件取 unknown。

`rule ... action="route-options" disable-cache=#true` 修改缓存选项后继续扫描，不能带 server；`route` 可以用同名布尔属性在终止时覆盖此前设置。`#false` 允许覆盖全局 disable-cache。A/AAAA 分别取得有效设置；相同 local 服务器仍保留一个双栈搜索操作，不因缓存选项不同而分开搜索。禁用缓存的问题不读写缓存或加入查询合并，沿既有有界交换通路执行；另一族可照常复用。显式 bootstrap 使用全局缓存设置。此动作也支持下述期限和 TTL 选项，其余查询/响应选项尚未实现。

DNS `action="reject"` 可选 `reject-method="reply"`（默认，消息监听返回 REFUSED）或 `reject-method="drop"`（消息监听不回复该请求；TCP 继续读取后续帧）。内部地址解析的两种方式均立即返回策略拒绝。其他拒绝选项和动态限速尚未实现。

DNS 问题规则也接受以下业务上下文条件，可以单独使用或与域名、query-type 组合，同条所有条件均须匹配。`network` 表示触发解析的业务流量，和 DNS 上游的 UDP/TCP 传输无关。

可选 `invert=#true` 对整条规则的条件合取取反，例如 `rule domain-suffix="allowed.test" auth-user="alice" invert=#true action="reject"`。已知任一条件不匹配时反转后匹配；所有已知条件匹配但身份等上下文缺失时保持 unknown，不因取反而命中。无条件显式动作的条件为真，因此反转后不会命中。`invert=#false` 等同省略，非布尔值被拒绝。规则仍按原顺序执行，继续型选项和终止动作的语义不变。

启用 `dns-response` 后，`evaluate` 查询上游并保留答复，后续规则可用 `match-response=#true` 和 `response-rcode`、`response-section`、`response-record-type`、`response-record-name`、`response-record-class`、`response-ip-cidr` 匹配，再选择 `respond`、`route` 或 `reject`。区段为 `answer`、`authority` 或 `additional`；区段、类型、名称和类可单独指定，或组合匹配同一记录。IP 条件匹配 answer 中的 A/AAAA 记录。`respond` 使用最近一次成功求得的完整答复；无答复时不能响应。Shadowsocks UDP 需要 `dns-response-ss`；未启用时配置拒绝响应条件和动作。其余 RR 内容及 DNS 动作仍待实现。

带 `match-response=#true` 的规则也可引用含目标地址条件的规则集；地址条件检查答复中的 A、AAAA 及 HTTPS 地址提示。规则集匹配范围和限制见[规则集](rule-sets.md)；单独的 `response-ip-cidr` 等条件仍使用上述 A/AAAA 语义。

`response-authenticated-data` 使用 `#true` 或 `#false` 匹配 `match-response` 选定答复的 AD 位。该位由上游提供，Nexus 只读取标志，无本地 DNSSEC 验签。所选答复缺失时，匹配结果为 unknown。请求中的 AD 位作为独立的能力信号保留在上游查询和缓存键中。 [RFC 6840 §5.7](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7)

`evaluate` 可使用 `tag="name"` 保存命名答复，后续规则通过 `match-response="name"` 匹配并在 `respond` 时使用该答复。标签须在引用前定义且不重复，一组规则最多 16 个标签。无标签的 evaluate 与 `match-response=#true` 使用独立匿名槽；条件不满足而未执行的 evaluate 不产生答复，引用时视为 unknown。每个答复保留自己的 TTL、ECS、来源上游及查询期限，CNAME 续查使用选中答复的来源。当前 evaluate 串行执行，尚不支持 race 或 speculative 并发。

单次 `evaluate` 查询失败或其动作超时后，该答复视为缺失并继续执行后续规则；失败的匿名 evaluate 会替换先前匿名答复，其他已保存的命名答复保留。缺失答复的匹配为 unknown，取反不会令它命中。整个请求被取消或超过总期限时停止处理。

`response-record-ttl-min` 和 `response-record-ttl-max` 可按同一条记录的剩余 TTL（秒，含边界）匹配；OPT 记录不参与 TTL 匹配。`response-record-data-hex` 可进一步指定同一条记录的未压缩 wire RDATA，以十六进制编码；常见名称型记录按 DNS 名称比较并支持答复中的压缩指针，其他类型按原始字节比较。设置名称型记录时应同时指定 `response-record-type`，以明确 RDATA 的编码。

`response-ip-is-private=#true` 按流量规则相同的私有地址定义检查答复地址，`response-ip-accept-any=#true` 匹配至少一个 A/AAAA 答复地址。它们与 `response-ip-cidr` 同属地址条件，任一条件命中即可；与响应码或记录条件同时使用时仍需同时满足。

启用 `dns-response` 时，`route`、`evaluate` 和 `route-options` 可设置正整数 `timeout-ms`。继续型选项为后续查询设置默认超时，具体 route/evaluate 可覆盖；每次查询的期限还受外层请求期限约束，节点名解析、传输回退和答复 CNAME 续查共用该期限。关闭此功能的构建会拒绝该字段。

启用 `dns-response` 时，`route-options`、`route` 和 `evaluate` 可设置 `rewrite-ttl`（0 至 4294967295 秒）。继续型选项为后续查询设置默认值，`route` 或 `evaluate` 可单次覆盖；evaluate 的改写在响应条件匹配前生效，后续 route-options 可以再次调整最终 respond 的 TTL。消息服务改写答复中除 EDNS OPT 外的记录 TTL。内部地址解析不返回 TTL，只要规则中存在此选项就绕过地址缓存，避免响应条件在查询后才决定 TTL。消息服务缓存原始答复，再按规则改写输出。

同一组动作可用 `client-subnet="192.0.2.0/24"` 设置 ECS 前缀，或用 `remove-client-subnet=#true` 移除 ECS；二者不能同时启用。地址可省略前缀长度，此时使用完整地址；包含主机位的前缀会按长度掩码。`route-options` 为后续查询设置默认值，`route` 和 `evaluate` 可单次覆盖。消息服务的规则条件仍依据客户端原始查询，转发答复恢复客户端的 ECS 视图；若上游前缀与客户端不同，恢复答复的 scope 限制为客户端请求前缀。内部地址查询使用选定前缀隔离共享缓存视图。端到端及故障验证仍在推进。

消息服务校验上游 ECS 是否与查询相符；上游未返回 ECS 时，答复回显请求子网并使用 scope 0。上游拒绝带 ECS 的查询时，会在同一期限内去除 ECS 重试。若上游 OPT 后还有其他记录，补 ECS 时会调整已支持名称字段的压缩指针；对不透明 RDATA 保守检查，无法确认安全或指针偏移超出范围时返回服务失败。

消息监听对可读取 DNS 头的畸形查询返回 FORMERR，对未知 opcode 返回 NOTIMP；非法 ECS 也返回 FORMERR。短于 DNS 头的报文和带响应标志的入站报文丢弃，TCP 对可答复的错误帧继续保持连接。

`action="predefined"` 可设 `predefined-rcode`（0–15，默认 0），并在规则子节点中给出资源记录，例如 `record section="answer" name="@" type=1 address="192.0.2.1" ttl=60`。`name="@"` 表示当前问题名称；`section` 为 `answer`、`authority` 或 `additional`，`class` 默认 1、`ttl` 默认 60 秒。A/AAAA 可用 `address`，NS/CNAME/PTR/DNAME 可用 `target`；其他记录可用 `data-hex` 提供未压缩 DNS RDATA，含名称的 RDATA 也须以未压缩 wire 格式提供。三种数据字段选其一。当前内部地址解析使用生成答复中的地址和完整 CNAME 链；仅有 CNAME 且没有目标地址时不再向上游查询。可在 `dns` 块中使用 `listen host="127.0.0.1" port=5353` 启用 UDP 和 TCP 消息监听。消息缓存按查询内容、实际服务器地址和传输隔离并老化 TTL；local 快照换代也会隔离缓存。仅含 ECS 的查询可按精确子网缓存匹配的 ECS 答复，其他 EDNS 选项绕过缓存。local 搜索域、快照换代运行验证及完整验收仍待完成。

| 属性 | 值 |
| --- | --- |
| `network` | `"tcp"` 或 `"udp"` |
| `source-ip-cidr` | IPv4/IPv6 CIDR 字符串 |
| `source-ip-is-private` | `#true`，与流量规则采用相同地址定义 |
| `source-port` / `source-port-range` | 整数 1..65535 / `"起始-结束"` 字符串 |
| `source-interface` | 业务入接口的 Linux 名称 |
| `inbound` | 精确监听器名称 |
| `auth-user` | 验证成功的 SOCKS 用户名或 VLESS UUID 对应的配置用户名 |

例如 `rule domain-suffix="internal.test" network="udp" inbound="edge" auth-user="alice" action="reject"`。原生 SOCKS UDP 使用已接纳数据报的来源地址和端口；SS UDP 使用通过认证的数据报来源；TCP、SS UoT 和 VLESS XUDP 使用承载流对端。匿名 SOCKS/HTTP、单密钥 SS 及没有提供用户名的独立 VLESS API 保留未知身份，未提供监听名的独立代理 API 同样保留未知。缺失条件字段不会被猜测或当作已匹配。routed TUN 提供真实设备名，UDP TPROXY 的解析和 DNS 劫持使用接收报文的入口接口。独立 DNS UDP/TCP 监听器和普通 SOCKS 等未取得入接口的入口将其视为 unknown。显式节点/DNS 服务器 bootstrap 不借用这些业务条件；先执行问题规则，再按实际服务器和缓存选项查询，拒绝规则仍先于已预热的共享缓存。

`dns` 中的 `resolver name type="udp"` 包含 IP 字面量 `server host=... port=...` 和明确的 `outbound`；主 `default-resolver` 给普通解析，`bootstrap-resolver` 专门用于节点名解析。此处 UDP 是示例选择，不表示其加密；业务 DNS 和 bootstrap 通过 direct 出口会向相应上游暴露查询。解析器依赖自身、selector、代理节点的循环须拒绝；出站 socket 必须执行相应 TUN 绕行策略。

`fake-ip` 的 `ipv4-pool`、`ipv6-pool`、`ttl-seconds`、`recovery "quarantine"`、`pool-full "servfail"` 明确池满失败和弱持久恢复方案。该方案在不确定的恢复状态下隔离地址，不保证每个曾应答的映射都能恢复；隔离期不短于配置允许的最大对外 TTL 加传播/时钟缓冲。普通 DNS 缓存与 Fake-IP 分开。`listener` 的 `mode "fake-ip"` 对允许的 A/AAAA 生成映射，其他类型走指定 `resolver`；内部 bootstrap 和直接出站真正解析不能进入 Fake-IP。DNSSEC、直连上游、分视图与原始目标语义见[DNS](../architecture/dns.md)和[Fake-IP](../architecture/dns-fakeip-engine.md)。

连接目标为池内地址时先反查，失败则拒绝；成功时使用映射域名匹配路由并固定 lease。不能把原始 Fake-IP 当普通目标 IP 去匹配私网规则或直接发送；direct 需在正确视图重新解析真实地址，再按访问策略逐个检查。普通真实 IP 请求和嗅探域名各保留来源；嗅探只提供不可信元数据，`metadata-only` 不重写报文或自动替换真实 IP。

样例的 `listener` 监听 `127.0.0.1:1053`，**不会自动修改宿主 DNS，也不会拦截所有 53 端口流量**。要由宿主应用使用 Fake-IP，需由宿主 DNS 管理器/受控重定向明确转发到此非 53 端口，同时覆盖 TCP 与 UDP，避免把 Nexus 自身上游查询重新劫持；端口、回退和恢复需平台集成验证。仅启动 TUN 不等于 DNS 已接管。

`auto-route #true` 配合双栈默认 `route-include` 提出全局捕获意图，`strict-bypass #true` 要求受保护的 socket 及平台策略满足[防环回](../platform/tun-routing-and-loopback.md)，不能只排除一次 DNS 解析得到的节点 IP。TUN 地址、Fake-IP 池须与物理网络、VPN、容器和其他实例不冲突；切换网络时重新验证。系统能力、权限或安全保护不满足时应中止接管并按平台回滚，不保证操作系统、进程及监督者同时失败时自动恢复。

## 规则与热重载

`routing` 的 `rule-set name path=... format="kdl"` 引入独立规则源；`format="beve"` 对应版本化 BEVE 容器；启用 `srs` 构建功能后，`format="srs"` 导入受限的 SRS 二进制条件子集，具体支持范围和三态差异见 [规则集转换](rule-sets.md)。示例使用 `kind "predicate"` 的规则集：重复 `rule type=... value=...` 为任一匹配即成员，支持的示例谓词为 `domain-suffix` 与 `ip-cidr`，不在集合内部携带出口动作。独立规则组件已支持该子集及互转，实验代理支持多个有序规则集引用，命中动作可选 direct、block 或具名 VLESS，默认可选 direct 或具名 VLESS；最多支持 16 个 VLESS 实例。主规则 `rule kind="rule-set" value=... outbound=...` 把集合放到一条有序规则的位置，首次命中执行出口；都不匹配时用 `default-outbound`。未来含动作/逻辑的规则类型须独立定义；KDL↔BEVE 保留当前规则顺序和行为，不保留注释排版。

实验代理对域名先尝试确定阻断，再解析并对每个候选地址结合域名按规则顺序匹配；这会使 IP 谓词匹配解析结果。以下是未来设计：域名条件依来源使用显式代理域名、Fake-IP 反查或受策略约束的嗅探结果；不存在信息时按规则引擎的 unknown/不匹配策略处理，禁止以字段分类索引改变全局首命中顺序。重载规则集先完整验证及构建不可变快照，失败留在旧代；已有会话保持创建时决策。[规则集转换](rule-sets.md)、[路由引擎](../architecture/routing-engine.md)。

## 控制面

本机控制命令 `nexus control SOCKET log-level` 返回各域当前级别及聚合丢弃、sink 错误、排队和队列高水位计数。管理员可用 `log-level global LEVEL` 一次更新全部域，或用 `log-level DOMAIN LEVEL` 更新单域。read-uid 只允许查询。这些命令不返回日志内容，设置仅在当前进程生效。

Linux CLI 可用顶层 `control socket="/run/user/1000/nexus/control.sock"` 开启本机控制，省略即关闭。socket 路径必须为绝对路径。默认父目录必须归运行账户所有且为私有，socket 权限为 `0600`，同 UID 的客户端拥有管理权限。可选的 `read-uid=1001` 为另一个 UID 开放聚合状态、操作结果、事件和传输计数。共享模式的 socket 父目录只能由运行账户写入，并须允许只读账户遍历。修改该配置后需重启。查看状态、分页列出及关闭连接、切换手动 selector 和重载的命令见[原生控制面](../architecture/control-api.md)。

编译启用可选特性 `control-http`（及可选 `metrics-openmetrics`）后，可在顶层 `control` 中启用只读/读写分离的 HTTP `/v1` 控制面与低基数 OpenMetrics `/metrics` 端点：

```kdl
control http-listen="127.0.0.1:9090" bearer-token-file="/etc/nexus/secrets/control.token" metrics=#true
```

- `http-listen` 为 `host:port` 或 `[ipv6]:port`，未显式启用 `control-http` 构建特性时在启动期拒绝。
- 监听非回环地址（非 `127.0.0.0/8` / `::1`）时必须配置 `bearer-token-file`（受保护单行私有文件），使用常量时间比较（`crypto::constant_time_equal`）校验 `Authorization: Bearer <token>`；未配置或校验失败返回 `401 Unauthorized`。
- 提供 `GET /v1/health`、`GET /v1/status`、`GET /v1/outbounds`、`GET /v1/connections`（上限 64 条）、`PUT /v1/groups/{tag}`（支持 `{"member":"..."}` 或 `{"auto":true}`）、`POST /v1/log-level`、`POST /v1/reload`、`POST /v1/state/clear-cache`；开启 `metrics=#true` 且启用 `metrics-openmetrics` 特性时暴露 `GET /metrics`（仅包含固定低基数标签，禁止域名、客户端 IP、URL、端口或用户自由文本进入标签）。
- 并发 HTTP 控制面连接上限 32、请求头上限 8 KiB、请求体上限 4 KiB、单连接出队缓冲上限 64 KiB、写停滞超时 3 秒自动断开慢消费者，不阻塞代理数据面。

`control` 可用 `selector-state-directory="/var/lib/nexus/selectors"` 保存手动选择。目录须已创建，由运行账户所有，权限为 `0700`。为每个运行实例使用独立目录，运行中保留稳定的 `instance.lock`。有效的已保存选择覆盖启动和重载配置中的 `selected`。可读取既有 NXSEL1 快照，下一次成功选择会写入带 BLAKE3 校验的 NXST01 封装。损坏或未知版本的选择快照保留在原处并拒绝启动。目录同步失败时，已替换的选择仍会发布，控制端收到 `selector-active-persistence-uncertain`。要改用配置基线，可在进程停止时迁出该目录的 `selectors.state`。

可在 `dns` 中设置 `message-cache-directory "/var/cache/nexus/messages"` 保存独立 DNS 监听器的应答缓存。开启消息缓存时，可以为多个无显式接口绑定的数值 UDP/TCP 上游及内联 DNS 规则保存视图。旧入口与 FakeIP、系统或加密 DNS 上游和外部 DNS 规则集互斥。统一缓存见下一节。目录须已创建，归运行账户所有且为私有。宿主持有目录独占锁，正常关闭前原子替换至多 1 MiB 的 NXDNS2 快照。每条记录保留所属上游，恢复时校验 DNS 策略与快照完整性并扣除停机时间。策略或上游变化、快照损坏时从空缓存开始。

## 持久状态与缓存

```kdl
state {
    directory "/var/lib/nexus/default"
    cache-directory "/var/cache/nexus/default"
    fakeip-crash-mode "range-reserve"
    dns-cache-max-bytes 4194304
    ruleset-cache-max-bytes 67108864
}
```

`state` 是可选顶层块。两个目录均为绝对路径，须归运行账户所有，权限为 `0700`。可在已存在的父目录下自动创建最后一级。旧的 `control selector-state-directory` 显式配置优先。启用 DNS FakeIP 并省略其旧 `state-directory` 时，使用 `directory/fakeip/`。显式指定旧 `state-directory` 时，继续使用原有认证历史和凭据。

统一 FakeIP 存储将池范围、保留地址、持久实例身份和分配高水位写入 `fakeip.meta`。默认 `range-reserve` 在应答前同步预留最多 256 个地址，段内新映射由后台批写 `fakeip.wal`，达到约 2 MiB 时发布 `fakeip.ckpt` 并截断 WAL。崩溃后重放完整记录，跳过未落盘的预留地址。该范围内缺少映射的地址会明确拒绝反查。小池可能因预留段用尽而停止分配。需要在每次应答前同步确认映射的实例可设置 `per-mapping`。统一存储在普通运行期间单向推进地址游标，池耗尽时拒绝分配。

`cache-directory/dns/` 保存独立 DNS 监听器的 NXDN03 快照。每份快照最多 1 MiB，默认总预算 4 MiB，按 DNS 策略、上游类型、TLS 身份与信任文件、外部规则集内容分片，正常停机时保存，恢复时扣除停机时间。系统本地视图和经运行期代理 detour 的视图仍使用内存缓存。仅使用旧配置时继续读写原格式。远程规则下载使用 `cache-directory/rulesets/`，默认预算 64 MiB，可通过下载命令覆盖。

- `nexus state inspect --config <文件>` 只读输出各组件的存储版本、条目数、字节数及健康状态。输出仅含固定组件名和统计。
- `nexus state clear-cache --config <文件> [--dns] [--rulesets]` 清理选定的 Tier 3 缓存，省略开关时清理两者。清除代次在删除前持久化，阻止清除前开始的磁盘写入重新发布旧数据。运行中 DNS 进程的内存条目继续随 TTL 过期。
- `nexus state reset --config <文件> --target fakeip|selectors --confirm` 将统一 FakeIP 目录或 selector 快照原子移为私有备份。执行前须停止持有该状态的进程。重新启动后使用新的存储或配置默认选择。重置 FakeIP 前应确认客户端不再持有旧地址。

## 实验性 SOCKS UDP over TCP

经 SOCKS5 UDP ASSOCIATE 收到的数据报若由路由选中 VLESS 出站，将通过 VLESS Mux UDP（XUDP）转发；可与该出站的普通 TLS、Reality 和 Vision 配合。每个 SOCKS UDP 关联按出站及地址族维护独立的传输和会话，目标先经过本地解析与路由校验，回复仅接受该会话近期成功发送过的目标。当前不覆盖 TUN UDP 或 VLESS Mux 入站；对端须支持 Mux UDP。

实验代理的 Shadowsocks 2022 出站可显式添加 `udp-over-tcp "v2"`。经 SOCKS5 UDP ASSOCIATE 接收的数据报按既有规则选中该出站后，通过 UoT v2 的 TCP 流转发；省略该节点时不会启用此路径。对端必须支持 UoT v2。当前不支持 v1；可与 `bootstrap-resolver` 一起使用。IPv4、IPv6 分别建立流；这项出站能力尚不覆盖 TUN UDP 或其他协议组合。

direct、SS 和 VLESS 出站可设置 `connect-timeout-ms 12000`，取值为 1 至 3600000 毫秒，默认 10000。普通 TCP 从入站会话开始计时；目标域名解析前若规则已确定出站，解析也使用该出站期限。若规则依赖解析后的 IP，解析期间使用已配置出站的最长期限，选定出站后再检查其期限。SS/VLESS 的节点 bootstrap 解析、TCP 建连及协议握手共用同一截止时间；UoT/XUDP 从各次隧道建立开始计时。共享 DNS 的上游查询本身最多运行 30 秒，也可能提前失败。direct 的此字段目前作用于 TCP；UDP 路径的解析期限仍单独管理。

目标解析出多个地址时，某个候选出站到期后仍会检查后续地址，后续出站使用各自的剩余期限；若没有候选成功，超时结果不会被随后可重试的连接失败覆盖。

SS 和 VLESS 出站可添加 `detour "entry"`，通过名为 `entry` 的出站连接本节点的服务器。例如路由选中 `exit`，且 `exit` 的 detour 是 `middle`、`middle` 的 detour 是 `entry` 时，实际连接顺序为 entry → middle → exit → 目标。省略 detour 或显式指向 direct 时直接连接本节点；block、缺失引用、自引用和环在启动前拒绝。最多配置 16 个隧道出站，仅被 detour 引用的依赖节点也可保留。节点域名使用各自的 `bootstrap-resolver`，省略时使用本地解析，不重新执行业务路由。

整条链使用路由所选末节点的 `connect-timeout-ms`：目标解析、各节点解析、连接和握手持续消耗同一预算；依赖节点不会重新开始计时，也不会用自己的配置期限截短此次建立。流承载 UDP 的每次 UoT/XUDP 建立同样使用末节点的一次期限；承载方式由末节点决定，中间节点只承载 TCP。已验证两/三层 SS、普通 TLS、Reality、Vision 链路及 SOCKS UDP 的 UoT/XUDP，测试入口为 `tests/detour_network.py` 和 `tests/detour_reality.py`；Vision 直通切换的独立观测、更多异步分配故障和性能对照仍待验证。原生 SS UDP 的有序路径可使用代理数据报出站，其 detour 链路仍待验证；TUN UDP 尚未接入该能力。

链内 TLS 节点在尚未发送该节点的 VLESS 请求时，可以在握手失败后尝试其后续解析地址；各次尝试继续消耗原截止时间，不重放已经发送的业务数据。下层已耗尽自己的节点候选时，失败向上传递；同一次业务拨号不会因其他目标地址再次建立同一耗尽出站，仍按规则检查后续地址和其他出站。构造分配故障与双后端验证范围见 [拨号字段覆盖](../planning/dial-field-coverage.md)。

direct、SS 和 VLESS 的 TCP 拨号支持 `tcp-keepalive #true` 或 `#false`、`tcp-keepalive-idle-seconds 17`、`tcp-keepalive-interval-seconds 3`、`tcp-keepalive-count 5`。秒数为 1..32767，次数为 1..127；单独指定探测参数会启用保活，显式关闭与探测参数冲突，重复字段拒绝。未配置时保留系统现状且不增加这些 socket 操作。参数在每个候选的物理 TCP socket 连接前生效，失败则拒绝此次拨号，不静默忽略；不会配置上游代理服务端为目标建立的 socket。

使用隧道 detour 的节点没有自己的物理 TCP socket，因此该节点不能同时设置上述参数；应设置在实际直接建连的头节点。显式 `detour "direct"` 继承具名 direct 的 TCP 参数；省略 detour 时使用本节点参数。UoT/XUDP 的物理 TCP 承载同样适用，原生 UDP 不使用 TCP 保活参数。其余拨号字段仍须继续实现，不能把这些字段当成完整 DialerOptions。

通用物理绑定字段已接入direct、SS-2022、VLESS、Trojan、AnyTLS的拨号节点：`bind-interface "lo"`、`inet4-bind-address "127.0.0.2"`、`inet6-bind-address "fd42::2"`、`routing-mark 16897`、`reuse-addr #true`，以及仅作用TCP的`bind-address-no-port #true`。字段重复/类型/地址族错误拒绝；源地址只接受数值地址，不带zone/port，IPv6不接受IPv4映射。mark为0..4294967295；明确false/0也执行对应设置。TCP使用SO_REUSEADDR，UDP同时使用SO_REUSEADDR/SO_REUSEPORT；binding本身不会启用TCP保活。

Linux 的直连出站可按系统网络快照选择接口。例如优先使用配置为 ethernet 的 `eth0`，在该地址族缺少可用主接口时选用配置为 wifi 的 `wlan0`。

```kdl
outbound "direct" type="direct" {
    network strategy="prefer" type="ethernet" fallback="wifi" {
        interface "eth0" type="ethernet"
        interface "wlan0" type="wifi"
    }
}
```

`strategy="require"` 只接受 `type`，`strategy="prefer"` 另要求不同的 `fallback`。类型由配置声明，可用值为 `ethernet`、`wifi`、`cellular`、`vpn`、`other`。每种选定类型至少声明一个接口，同名接口只能出现一次，最多 16 个。依据当前快照，从载波在线、有该地址族可用全局源地址且主路由表有该族单跳默认路由的接口中选择。若设置了数值源地址，接口也必须拥有该地址。同类型按路由 metric、声明顺序选择。TCP 与直连 UDP 各按实际地址族绑定，新建物理 socket 采用当前快照，已有 socket 保留所选接口。直连 TCP 在同一连接总期限内尝试后续接口，非最后一个接口的连接等待由可选 `fallback-delay-ms` 控制，默认 300 毫秒，范围 1–60000。直连 UDP 只在首包收到同步路由错误时试后续接口。快照或相应族的候选不可用时连接或发送失败。此策略与 `bind-interface` 或 `netns` 互斥，修改策略需要重启。

物理 UDP 源端口可用 `udp-bind-port 5353` 指定，范围为 0..65535；显式 0 由内核分配临时端口，重复字段或错误类型拒绝。该端口与同一物理出口的 `inet4-bind-address` / `inet6-bind-address` 组合，直接 UDP 和 Hy2 UDP 在发送前执行绑定；TCP socket 不使用它。detour 的物理参数归属规则仍适用：由最低物理出口提供，不能在带 detour 的节点重复设置。固定端口已被占用时绑定失败，不回退到随机端口，也不自动启用地址复用。不同关联、双族地址和共享监听器是否能使用同一端口仍受内核绑定和显式复用配置约束。

上述5种节点也可设置 `udp-fragment #true` 或 `#false`，由最低物理UDP socket准备过程执行IPv4/IPv6 PMTU discovery设置。true允许内核分片；false禁止分片，超路径MTU的数据报发送失败；省略保留系统默认值。TCP不执行此选项，detour节点仍拒绝自己的物理参数。MTU1280下的双族实际分片、禁发、空包及新关联恢复已有生产io CLI证据，完整epoll/关闭图仍待验收。

这些设置由最低物理socket执行；有detour的节点拒绝自己的物理参数，显式direct detour继承direct配置。direct UDP包括SOCKS、SS native/UoT、Trojan、AnyTLS及VLESS/Vision/HTTPUpgrade的XUDP，空包和回复授权沿原通路。设置失败拒绝连接/发送，不静默回退。bootstrap/DNS独立transport不继承业务socket参数。Linux权限、接口和地址由内核验证。`multipath-tcp #true` 使用 Linux MPTCP socket，内核不可用时创建失败；对端不支持时遵循内核 MPTCP 协商回退为普通 TCP。该选项仅作用于物理 TCP，Hysteria 2 自身的 UDP 拨号不接受。当前双族/真实策略路由/双backend与验证范围见[通用绑定](../development/socket-binding.md)。

Linux 物理出站可用 `netns "/run/netns/uplink"` 指定已有的网络命名空间。Nexus 在该命名空间创建出站 TCP 或 UDP socket，监听器和执行器保留原命名空间。接口和源地址按出站 socket 的命名空间校验。内核拒绝打开或进入该命名空间时，当前拨号失败。

`protect-path "/run/host/protect.sock"` 指定宿主的 Unix 流 socket。Nexus 在绑定和发起连接前，用 `SCM_RIGHTS` 和一个值为 1 的字节交付一个物理 FD。宿主处理完后回一个字节表示成功，关闭连接表示拒绝。等待确认采用现有拨号期限，最多 250 毫秒。两个字段都使用绝对路径，可同时设置；此时宿主 broker 在 Nexus 的原命名空间接收属于目标命名空间的 FD。显式 direct 下层继承这两个字段；业务和 bootstrap 的 DNS 查询各用自己的传输配置。

direct、Shadowsocks 2022、Snell、Trojan、AnyTLS、ShadowTLS 和 VLESS 物理出站可配置 `tcp-fast-open #true`；`#false` 或省略使用普通连接。SS 或 Snell 首个加密请求、或 TLS ClientHello 发起 Linux TCP Fast Open；SS 的 UoT、Snell 数据报和 VLESS XUDP 承载适用此设置，原生 UDP 不使用它。VLESS 的普通 TLS、Reality、Vision、HTTPUpgrade 和 gRPC 出站均可使用。direct 在已有业务前缀时用它发起 Fast Open；没有预读数据时普通连接，确保 SOCKS/HTTP 成功响应前连接已建立。只能在实际创建物理 socket 的节点设置，带 detour 的节点拒绝该字段；显式 direct detour 继承 direct 设置。AnyTLS 和 gRPC 的每条池连接独立执行该过程。ShadowTLS v3 特殊认证 session ID 在启用 Fast Open 时随 ClientHello 首写提交。候选仅在内核未接受首写数据时重试，首写或 TLS 握手失败后不重放到其他地址，整个过程沿用原连接期限。内核不支持时回退普通连接；是否能在 SYN 中携带数据取决于内核、cookie、服务端和网络，详见 [TCP Fast Open](../development/tcp-fast-open.md)。

Snell v4 出站可启用 `reuse #true` 串行复用已完整关闭的 TCP 逻辑流；默认关闭，UDP 仍使用独立关联。连接和凭据按出站与 worker 隔离；每个 worker 最多保留 10 条空闲连接，空闲 180 秒过期、每 20 秒检查。错误、取消或未完整关闭时连接被丢弃，已提交请求不自动重放。

Shadowsocks 2022 出站可选 `udp-mode "native"`，使用协议自身的 UDP 数据报。它与 `udp-over-tcp "v2"` 互斥，省略二者时该节点只载 TCP。AES-128/256 支持已配置的 identity key 链，ChaCha20 方法在 UDP 使用 XChaCha20-Poly1305。原生模式按业务地址族分别维护 SS 会话，两族共用实际物理 UDP socket；节点也可经支持数据报的下层代理。出站可从普通或有序 SOCKS/TUN、流承载 UDP 及普通或有序 SS 原生入站选用。TCP 仍使用原 SS-2022 流协议。

Shadowsocks 2022 入站可识别 UoT v2 目标并按规则转发数据报到 direct、启用 UoT v2 的 Shadowsocks 出口或支持 XUDP 的 VLESS 出口；block 和其他暂不支持的隧道出口不会转发。UoT 输入流结束即终止关联，尚未转发的排队数据报会丢弃。双后端已验证双栈和空数据报的直连及 Shadowsocks 链式转发，以及非空数据报经普通 TLS 和 Vision XUDP 的双栈转发（部分外部 XUDP 服务实现会丢弃零长度数据帧，后续非空数据报正常）。UoT v1 入站尚不支持。

## 实验性 Trojan TCP/UDP

`mcpp build --features trojan` 的 CLI 支持 Trojan 入站和出站，成对配置见[客户端](examples/trojan/client.kdl)和[服务端](examples/trojan/server.kdl)。它们使用回环监听，须自行提供密码文件、含 `localhost` SAN 的证书及对应私钥；客户端用该证书建立信任。密码文件须满足 PrivateFile 的普通文件、当前属主及私有权限检查，去掉一个末尾换行后长度为 1..4096 字节。服务端的 `authentication` 包含 1..64 个具名 `user`，相同密码和重复名称拒绝；密码派生为 SHA-224 小写 hex 后清理临时明文，入站按固定长度恒时比较，不记录凭据。

入站必须配置 `certificate-file` 和 `private-key-file`。出站必须配置 `password-file`、`server-name`、`ca-file`、`verify #true`，可配置既有 `key-exchange`、`bootstrap-resolver`、`detour`、`connect-timeout-ms` 和 TCP 保活参数。detour 与物理 socket 参数的归属、全链一次绝对期限沿用上文契约；节点 DNS、TLS 和认证头不重新启动预算。配置总量仍为 16 个隧道出口，合计 SS/VLESS/Trojan。

VLESS、Trojan 和 AnyTLS 出站的 `tls` 块可选 `fingerprint`，默认 `native`。可选 `tls13-grease`、`tls13-randomized` 及 TLS 1.3 形状 `chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`random`。认证、信任根、SNI 和所选 `key-exchange` 保持生效。配置适用于物理 TCP、TCP Fast Open 和代理 detour 内层 TLS。VLESS 普通 TLS、Reality、Vision、HTTPUpgrade 和 gRPC 支持该字段。Reality 的客户端形状会在需要时补充 Ed25519 签名方案，以完成协议认证。

普通 VLESS、Trojan 与 AnyTLS 的 TCP 客户端也可显式设置 `fingerprint "tls12"`，使用 TLS 1.2 的 ECDHE、AES-GCM 和扩展主密钥。该形状保留证书链、服务端名及握手签名核验，要求默认的 X25519 和记录大小设置。VLESS 的普通 TCP、HTTPUpgrade、WebSocket 和 gRPC 已与强制 TLS 1.2 对端验证双族目标。Reality 和 Vision 使用各自的 TLS 1.3 握手。

构建启用 `tls-certificate-compression` 时，Chrome/Edge 可接收 Brotli 压缩的服务端证书，Safari 可接收 zlib，`tls13-randomized` 则支持 zlib、Brotli 和 Zstandard。握手允许服务端继续发送普通证书；压缩的证书也须通过同一证书链与身份校验。

TCP TLS 出站（VLESS、Trojan 和 AnyTLS）的 `tls` 可选 `record-size-limit 1024`，范围 64..16385，默认不通告。该值限制对端在协商此扩展后发送的 TLS 1.3 明文记录大小（包括内容类型和填充）；对端未响应时沿用原协议上限。此字段也适用于 VLESS 的 Reality、Vision、HTTPUpgrade 和 gRPC，以及 TCP Fast Open 与代理 detour；Hysteria 2/QUIC 不支持并拒绝此字段。较小数值会增加记录开销。

TCP 使用命令 1，没有额外成功响应；UDP 使用命令 3，并为每个数据报保留独立地址、长度和 CRLF。SOCKS UDP 可选 Trojan 出站；Trojan 和 SS UoT 入站的流承载 UDP 共用 DNS、规则、回复授权和有界队列，支持 direct、SS UoT、VLESS XUDP 和 Trojan 出口。UDP 关联结束会取消未完成转发。fallback、Reality、Mux、其他承载、原生 UDP 及 TUN UDP 尚未开放，未知或未实现字段拒绝。当前支持范围见 [支持矩阵](../planning/proxy-kernel-support-matrix.md)。

## 本机部署与认证选项

- SOCKS5 和 Mixed 入站可配置 `udp-advertise-ip "198.51.100.5"` 或 IPv6 地址。UDP ASSOCIATE 回复使用该地址和实际分配的 UDP 端口。监听地址、转发策略和数据报关联校验仍由入站负责。
- Trojan 与 AnyTLS 出站的 `tls` 块支持 `certificate-sha256 "指纹1" "指纹2"`，最多 16 项。每项接受 64 个十六进制字符或 32 组冒号分隔的字节，大小写均可。必须先通过常规 CA、有效期和 SAN 校验，再在验证成功的证书路径中匹配任一证书 DER 或 SPKI 的 SHA-256。配置 pin 时每次重新校验证书。
- Tailscale endpoint 支持 `listen host="192.0.2.10"` 和独立的 `listen-port 41641`。省略端口或设为 `0` 由内核分配，既有 `listen host="…" port=41641` 写法也可用。两种端口写法互斥。
- MASQUE H3 `mode "connect-ip"` 可用 `protocol "cf-connect-ip"`、`path "/"` 和重复的 `header "Cf-Connect-Proto" "cf-connect-ip"` 等字段指定兼容参数。标头名按 HTTP/3 规范转成小写，权威地址用 `authority`。备用协议要求至少一个静态 `local-address`。IPv6 或动态分配的 MTU 下限为 1280，静态 IPv4 可以用 68–1500。重新建连会重新应用静态地址。
- Linux `fixed-tcp` 可在 `listen unix-path="/run/service/proxy.sock"` 或 `target unix-path="/run/service/origin.sock"` 使用 Unix 流套接字，也支持 `@name` 抽象地址。两侧各自可选择 TCP 或 Unix。一侧使用文件监听时，父目录必须由当前用户所有且组和其他用户不可写，监听节点为 `0600`。Unix 入站使用单 worker。Unix fixed-tcp 配置使用普通 direct 出站，监听路径变更通过进程重启。

## 其他协议的配置位置示意

下面是片段，不是额外的成对部署配置或已验证语法/API。完整主文件仍须配置路由、解析器、权限和密钥。WireGuard endpoint 独立拥有双向隧道，可作为路由出口；它不是将同一 peer 重复建为两个独立入站/出站。

```kdl
endpoint "wg" type="wireguard" {
    private-key-file "/etc/nexus/secrets/wg-private.key"
    local-address "10.8.0.2/32"
    local-address "fd73:1234:5678::2/128"
    mtu 1420
    peer "server" {
        public-key-file "/etc/nexus/keys/wg-server-public.key"
        endpoint host="wg.example.net" port=51820
        bootstrap-resolver "bootstrap"
        allowed-ip "0.0.0.0/0"
        allowed-ip "::/0"
        persistent-keepalive-seconds 25
    }
}
```

标准 WireGuard 使用零 reserved 字节；可选 `preshared-key-file` 是 peer 级密钥。仅显式的 `provider-profile "warp"` 可配置恰好三个 `reserved` 字节，非零属于未经验证的服务端特定兼容，不改变标准 profile；分配地址、peer 公钥和授权配置由用户提供。[WireGuard/WARP](../architecture/protocols/wireguard.md)。

WireGuard endpoint 可配置 `require-cookie #true` 始终要求握手 cookie；可选 `auto-cookie #true` 根据入站握手报文压力临时要求 cookie，默认关闭。自动模式允许每秒约 32 个握手报文并容许 32 个短时突发，超过时进入至少一秒的保护期；普通 WireGuard 数据报不计入该阈值。此信号只根据报文格式，未经认证来源可以触发保护期，使合法 peer 增加一次 cookie 往返；它不代表准确的 CPU 负载或完整拒绝服务防护。cookie 验证后的来源共享有界握手限额，同一 NAT 出口的多个 peer 也共享该限额；满表可能暂时拒绝新来源。

```kdl
// 单用户 SS-2022 客户端/服务端片段，密钥文件内容须一致
outbound "ss" type="shadowsocks" {
    server host="ss.example.net" port=8388
    bootstrap-resolver "bootstrap"
    method "2022-blake3-aes-256-gcm"
    key-file "/etc/nexus/secrets/ss.key"
}
inbound "ss-in" type="shadowsocks" {
    listen host="127.0.0.1" port=8388
    method "2022-blake3-aes-256-gcm"
    key-file "/etc/nexus/secrets/ss.key"
}
```

PSK 使用安全随机源生成并以 base64 写入私有文件。AES-128 使用 16 字节，AES-256 和 `2022-blake3-chacha20-poly1305` 使用 32 字节。ChaCha20 方法支持 TCP 和原生 UDP 入站，原生 UDP 使用 XChaCha20-Poly1305。出站可设置 `udp-over-tcp "v2"`。

AES EIH 支持 TCP、UoT v2 和原生 UDP 入站。入站用 `key-file` 指定身份密钥，在 `authentication { user "alice" key-file="/etc/nexus/secrets/alice.key"; }` 中配置用户密钥。认证成功后，路由可按 `auth-user` 匹配。原生 UDP 同端口换代时，新会话使用新用户配置，已有会话在旧代排空。TCP 和 UoT 出站的 `key-file` 指定用户密钥，以一个或多个 `identity-key-file` 按链路顺序指定身份密钥。[SS-2022 协议](../architecture/protocols/vless-trojan-ss.md)

```kdl
// 客户端片段：Hysteria 2 的 UDP/QUIC 出站
outbound "hy2" type="hysteria2" {
    server host="hy.example.net" port=443
    bootstrap-resolver "bootstrap"
    authentication { password-file "/etc/nexus/secrets/hy2.password"; }
    tls {
        server-name "hy.example.net"
        ca-file "/etc/nexus/ca/hy-ca.pem"
        verify #true
    }
}

// 服务端片段：对应认证与证书内容由部署者提供
inbound "hy2-in" type="hysteria2" {
    listen host="0.0.0.0" port=443
    authentication { user "alice" password-file="/etc/nexus/secrets/hy2.password"; }
    tls {
        certificate-file "/etc/nexus/tls/hy-fullchain.pem"
        private-key-file "/etc/nexus/tls/hy-private.pem"
    }
}
```

Hysteria 2 使用 UDP、TLS 1.3、HTTP/3 认证和 QUIC DATAGRAM。`hy2-cli` 的 `quic` 块支持 `udp`、`handshake-timeout-ms`、`idle-timeout-ms`、`native-bytes`、`max-udp-payload-size`、`disable-path-mtu-discovery`、`send-bps`、`receive-bps`、`disable-loss-compensation` 和可选的 `salamander-password-file`；入站还支持 `ignore-client-bandwidth`。混淆密码文件使用私有文件权限并需两端一致。监听地址支持不带区域标识的 IPv4 或 IPv6 数字地址，包括通配地址，IPv6 使用独立 socket。

入站和出站的 `quic` 块都可同时指定四个接收窗口，单位为字节。

```kdl
quic {
    init-stream-receive-window 262144
    max-stream-receive-window 1048576
    init-conn-receive-window 1048576
    max-conn-receive-window 4194304
}
```

四项范围均为 65536–67108864。每项最大值须大于等于相应初始值，连接的初始和最大窗口须分别大于等于流的初始和最大窗口。`native-bytes` 至少比连接最大窗口多 65536 字节。初始值写入实际 QUIC 传输参数，最大值限制 ngtcp2 的接收窗口自动扩展。Hysteria 2 的 TCP 接收缓冲按需分配，与 QUIC 和 HTTP/3 原生内存共享每连接的硬预算。省略四项时保留既有默认值。QUIC 关闭后释放关联的 UDP 会话和 FD，静默断链以协商的 QUIC 空闲超时为检测边界。

出站 `quic { lazy-tcp-response #true; }` 允许在收到服务端 TCP 应答前发送业务数据，适用于等待首包才应答的对端。对端应答仍受 `connect-timeout-ms` 限制，拒绝或超时会关闭已开启的本地流。默认在收到成功应答后才向本地报告连接成功。

`send-bps` 和 `receive-bps` 的单位为字节每秒，范围 0–1000000000000，默认 0 表示未指定。入站根据客户端通告的接收速率和本端发送速率选择 Brutal，出站根据本端发送速率和服务端认证响应选择 Brutal；自动协商时使用标准 QUIC 拥塞控制。入站 `ignore-client-bandwidth #true` 且本端接收速率为 0 时使用自动模式；该选项为 `#true` 且本端接收速率非零时，客户端必须通告非零接收速率。`disable-loss-compensation #true` 关闭 Brutal 的丢包补偿，默认为 `#false`。速率按每个 QUIC 连接独立计算，允许短时突发并受对端、路径、拥塞窗口和丢包影响，不能作为进程总带宽或严格瞬时上限。

当前极低速配置在下一数据包的等待时间超过协商的 QUIC 空闲期限时，活动传输可能因空闲超时关闭；例如 100 字节/秒与 1 秒空闲期限已复现此情况。低速下应结合两端空闲期限评估，相关活性处理仍在开发。

出站支持 TCP 和 UDP，物理 UDP socket 可配置接口、源地址、routing mark、复用、分片和源端口；TCP 保活和无端口绑定显式拒绝。显式 direct detour 继承 direct 的物理配置，包括双栈接口选择。首选接口在回退等待时间内未完成 QUIC 握手时，可在原连接期限内尝试下一候选接口；TLS 握手完成后发生的 Hysteria 2 认证失败不会触发接口回退。代理 detour 需要具备数据报承载能力，例如 SS UoT、Trojan、VLESS XUDP、AnyTLS、Snell 或 Hy2。双 backend 已通过双族 TCP/半关闭、UDP 空包和分片、错误认证、期限及停机，以及上述六种代理下层的 TCP、UDP 与活动停机验证；详见 [支持矩阵](../planning/proxy-kernel-support-matrix.md)。

`max-udp-payload-size` 限制发送的单个 UDP 载荷字节数，范围为 1200–1500；启用 Salamander 时包括其 8 字节盐，因而最小值为 1208。省略时沿用原传输默认值。`disable-path-mtu-discovery #true` 关闭 QUIC 路径 MTU 探测，默认为 `#false`；关闭后 native 使用基本路径大小，不保证达到所配置的上限。这两个选项分别作用于入站或出站的 QUIC 层，代理 detour 的物理路径由下层出站管理。

Salamander 在入站和出站各自的 `quic` 块中使用 `salamander-password-file "/绝对路径"`，双方需使用相同的独立密码文件；文件遵循项目密码文件的权限和内容限制。省略该字段时不启用混淆。双 backend 的双族入站、物理出站及六种代理下层已验证 TCP/UDP 与入站半关闭。路径 MTU 探测预留 8 字节盐的空间；探测包遇本地 `EMSGSIZE` 时按丢包处理，已验证路径上的较大普通包遇相同错误时回退至 1200 字节 QUIC 载荷并交给 QUIC 恢复可靠流。被拒绝的 QUIC DATAGRAM 可能丢失；回退后独立的 QUIC 探测包尝试恢复更大的路径上限，未恢复时每十分钟再次探测。最小包被拒绝或其他发送错误仍终止连接。双 backend 的 Nexus 双端已在隔离环境验证 MTU 1280 及从 1500 突降至 1280。

## 验收

用指定 Glaze 分支验证 KDL 语法及动态文档映射，再用 Nexus 语义校验器验证每个示例、字段错误、重复项、未知项、协议能力和依赖环；KDL 语法成功不表示 schema 或部署有效。成对联调要实际提供密钥与证书，在隔离网络核对客户端 Mixed/TUN → VLESS/TLS → 服务端 → 目标，覆盖 TCP、UDP、DNS/Fake-IP、防回环、规则和失败恢复。示例中没有真实凭据或可部署服务器，不能在未经实现和集成测试前运行。

显式启用 TCP 有序动作时，可在 `routing` 内声明 `tcp-program`，并继续使用 `rule-set` 引用规则文件：

```kdl
routing {
    rule-set "blocked" path="rules/blocked.kdl" format="kdl"
    tcp-program sniff-timeout-ms=100 unknown="skip" {
        rule action="sniff"
        rule action="reject" rule-set="blocked" domain-source="sniffed"
        rule action="resolve"
        rule action="route" outbound="direct"
    }
    default-outbound "direct"
}
```

规则按顺序执行；省略 `rule-set` 表示无条件动作。`action` 支持 `sniff`、`resolve`、`route`、`reject`，只有 `route` 要求 `outbound`。带规则集时可选 `domain-source="explicit"` 或 `"sniffed"`，默认 explicit；FakeIP 和反查来源尚未接生产数据，配置会被拒绝。`unknown="pause"` 遇未知条件停止并拒绝当前连接；`"skip"` 跳过该条规则，继续执行后续动作。嗅探期限为 1–10000 毫秒，并受连接总期限约束；客户端等待 CONNECT 成功才发送应用数据时，嗅探到期后再选路和回复。默认出站仍通过 `default-outbound` 指定。

`resolve` 可指定 `rule action="resolve" route-only=#true`，也可写成 `rule { action "resolve" route-only=#true; }`。有序 TCP 使用本机 DNS 候选进行后续 IP、CIDR 和私有地址匹配。选中可以承载域名的代理出站时，发送原始域名；选中直连时，复用已经解析的候选。默认为 `#false`，沿用数值目标。纯 IP 出站收到需要保留域名的连接时拒绝该连接。该选项的域名转发语义适用于 TCP。

有序规则可在规则体内写逻辑谓词，具名引用使用同一个 `routing` 块的 `rule-set` 声明。

```kdl
rule action="route" outbound="direct" {
    all {
        rule-set "corp"
        not { port 443; }
    }
}
```

`all`、`any` 和 `not` 分别对应规则集格式的 `and`、`or` 和 `not`。引用匹配具名规则集中的任一根谓词，允许被引用的 KDL/BEVE 集继续引用其他已声明的集合。每次启动或规则热重载在发布前检查未知 tag、引用环、展开深度和节点总数。负向条件会传播未知值。更新规则文件失败时保留此前已发布的路由。

当前 `tcp-program` 支持 SOCKS5/Mixed 的 TCP CONNECT、Mixed 的普通 HTTP 正向请求、Trojan TCP、AnyTLS TCP、SS-2022 TCP 和普通 VLESS TCP 入站，不能与旧的 `routing` 规则混用；配置中其他入站类型会被拒绝；有序策略下 VLESS 多路复用会被拒绝，VLESS Vision 和 gRPC 目前不支持该配置。默认情况下 SOCKS UDP ASSOCIATE 被拒绝，SS 独立 UDP 监听器不启动；在 `tcp-program` 设置 `udp=#true` 可显式对 SOCKS UDP、Trojan UDP、AnyTLS UoT、普通 VLESS UDP、SS UoT 和 SS 原生 UDP 数据报使用同一有序规则。UDP 的 sniff 识别 DNS 查询；构建启用 `quic-sniff` 时还识别单个数据报内完整的 QUIC v1/v2 Initial ClientHello。SOCKS UDP、Trojan UDP、AnyTLS UoT、普通 VLESS UDP、SS UoT 和 SS 原生 UDP 可在嗅探期限内暂存并重组跨数据报的 Initial。ECH、无法解密或其他数据报的嗅探域名保持未知，报文与目标边界保留。普通 HTTP 请求在改写转发前对已接收的完整请求头嗅探，继续由 HTTP 解码器处理请求体。路由、隧道和 DNS 的完整互通与故障验收仍在进行。

在有序程序的 `sniff` 动作之后，KDL 或 BEVE 规则集可用 `rule type="protocol" value="http"` 匹配已识别的 HTTP 请求。该谓词也接受 `tls`、`dns`、`ssh` 和 `stun`，分别匹配 TCP ClientHello、有效 UDP DNS 查询、TCP 客户端 SSH 标识行及 UDP STUN 消息。SSH 在嗅探期限内按分段接收标识行。STUN 检查固定头、长度和属性边界。两者提供协议字段，嗅探域名为空。启用 `quic-sniff` 时，`quic` 匹配完整有效的 QUIC Initial ClientHello，ECH 仍保留协议并隐藏外层名称。数据报跨包重组沿用各入站的既有范围。依据 [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html#section-4.2) 和 [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html#section-5)。协议与域名分别记录，因此数字 Host、无 SNI 的 TLS 或带 DNS 服务标签的查询也能匹配协议。未识别的输入按程序的 `unknown` 策略处理。

`protocol "tls"` 匹配普通 TLS 以及带 ECH 扩展的 TLS。`protocol "tls-ech"` 等价于 `tls-ech #true`，只匹配嗅探到 TLS 且携带 `0xfe0d` 扩展的流量，包含 GREASE ECH。`tls-ech #false` 匹配已识别且未携带该扩展的 TLS。嗅探器读取 ClientHello，因此 ECH 条件反映客户端是否发送扩展。缺少 TLS 识别结果时，ECH 条件为未知。

`rule action="route-options" connect-timeout-ms=250` 可缩短剩余连接预算并继续执行后续规则。TCP 从会话开始计时，SOCKS UDP 从报文接收时计时。连续命中时取最早的到期点。该期限涵盖之后的 DNS、嗅探和连接或数据报交接。UDP 模式下，Trojan 和 Shadowsocks 入站暂不接受该动作。

`rule action="hijack-dns" rule-set="dns-targets"` 使用配置的 `dns` 执行消息规则。支持 SOCKS5、Mixed、启用 UDP 的 TPROXY、routed TUN、Trojan UDP、AnyTLS UoT 和普通 VLESS 命令 2（含 packetaddr），需要 `udp=#true`。每个 UDP 报文单独检查 DNS 查询格式。无谓词的劫持规则只适用于目的端口 53。显式带谓词的规则也可劫持命中的其他端口上的有效 DNS 查询。其他数据报继续评估后续路由规则。同一 SOCKS5 UDP 或 routed TUN UDP 关联切换目标地址或端口时会重新选路。劫持响应沿用原目标地址和端口以及查询事务编号。routed TUN 可在入站设置 `dns-hijack-tcp #true`，允许同一动作匹配 TCP。TCP 分支按两字节长度读取 DNS 消息，保留嗅探预读并在原连接上顺序返回答复。每连接最多处理 64 个请求。每个请求有五秒预算，首请求同时受路由期限约束。TCP 路径可单独启用。其他 TCP 入站跳过该动作。

SS 原生 UDP 按认证会话及代次、来源、入站和原目标隔离暂存流；同一流从认证入队起依次推进规则和 DNS，参与同一 Initial 重组的报文在各自执行 sniff 动作时取得结果。不同 CID 或无关报文不继承该域名。每个监听所有者最多保留 32 个流、64 包；每流最多 8 包、256 KiB，报文还受原调度器总预算约束。容量满时拒绝新增包；若该包属于正在等待的既有流，该流按 unknown 继续。超时保留原报文并按配置的 unknown 策略处理，停止时取消暂存。顺序保证覆盖规则推进及交给发送方；报文选择不同出站时，实际网口发送顺序取决于各出站进度。

### 解释流量规则

`nexus rule explain <配置> <入站名> <tcp|udp> <主机:端口> [字段=值…]` 读取和代理相同格式的配置与规则文件，显示命中的规则文件、谓词、选中的组和实际出站。可附加 `source-ip`、`source-port`、`auth-user`、`protocol`、`sniffed-domain` 和一个或多个 `resolved-ip`。用 `protocol=tls tls-ech=false` 描述无 ECH 的 TLS，`protocol=tls-ech` 描述携带 ECH 的 TLS。有序解析显示为 `resolve(route-only)` 时保留域名出站语义。未给出的上下文保持未知，`sniffed-domain=-` 表示嗅探已完成且没有域名。命令按程序执行顺序解释动作，显示需要补充的上下文，不建立代理连接。它使用该文件的启动配置。运行中探活和热切换的结果由代理进程持有。

### 出站拨号的具名 DNS 视图

出站的 `domain-resolver` 可引用 `dns` 块里的物理服务器或具名视图。旧写法 `bootstrap-resolver` 仍可使用。每个出站最多设置其中一个。引用服务器时直接使用该服务器的原有解析路径。引用视图时，拨号主机名经过当前发布的 DNS 规则，包括规则集、按 QTYPE 分流、响应策略及缓存选项。规则未选中终止动作时使用该视图的 `final`，缓存按实际服务器和查询上下文维护。名称必须在同一个 `dns` 块里可解析，视图名与服务器名不得重复。

```kdl
dns {
    server "private" type="udp" host="192.0.2.53"
    server "public" type="udp" host="198.51.100.53"
    rule domain-suffix="internal.example" server="private"
    view "dial" final="public"
    final "private"
}
outbound "edge" type="http-connect" {
    server host="edge.internal.example" port=8080
    domain-resolver "dial"
}
```

启动和配置重载会检查出站、detour、selector、DNS 服务器和 DNS 视图的依赖。视图依赖规则可能选中的所有上游及自己的 `final`。视图使用的上游若直接或间接需要经同一出站拨号，配置会被拒绝。主机名解析使用原连接的绝对期限。

`local` 解析器使用宿主发布的搜索域，因而也可使用宿主 Tailscale DNS 的私域搜索后缀。单标签相对名按 `ndots` 和搜索域顺序尝试。尾点表示绝对名，`printer.` 只查询 `printer`，`host.tailnet.ts.net.` 只查询该完整名称。

UDP DNS 响应在 Question 和各资源记录区复用已编码的名称后缀。CNAME、NS、PTR、MX、SOA 等允许压缩的 RDATA 名称也可复用后缀。HTTPS、SVCB、SRV 和未知扩展类型的 RDATA 保留原始字节。无 EDNS 使用 512 字节上限，使用 EDNS 时按客户端声明的 UDP 上限判断。压缩后仍超限时设置 TC，客户端可用 TCP 重试。 [RFC 1035 §4.1.4](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4) · [RFC 3597 §4](https://www.rfc-editor.org/rfc/rfc3597#section-4)

### Linux 透明 TCP

`redirect` 和 `tproxy` 可配置数字 IPv4 或 IPv6 监听地址。使用现有流量规则或 `tcp-program`，源匹配基于接受的连接，目标来自 Linux 内核的原始目的地址。普通直连入站 socket 的连接不作为透明流量。

```kdl
inbounds {
    redirect "local" { listen host="127.0.0.1" port=11080; }
}
```

宿主负责配置 REDIRECT 或 TPROXY 的内核规则。TPROXY 启动会设置透明 socket 选项，需宿主授权。同一宿主捕获本机流量时，可通过出站的 `routing-mark` 配合宿主规则排除代理自身的流量。

### 运行中重载流量规则

向使用 `nexus run --config` 启动的进程发送 SIGHUP，可重新读取启动配置中 `routing` 和 `dns` 引用的规则文件。相对路径以配置所在目录为基准。所有候选规则都通过校验后一起发布，文件缺失、无效或超限时继续使用当前规则。普通代理会话及活动查询继续使用各自取得的代次。修改主路由规则结构需要重启。

使用普通 TCP 入站、原生 Shadowsocks UDP 和可选独立 DNS 监听器的配置，可用 SIGHUP 增删、迁移或更换监听器。全部候选监听器准备好后一起开放接入。同一地址和端口保留原有 TCP 监听队列，切换后的接入使用新配置。准备或绑定失败时，原有监听器继续工作。旧代会话在 `shutdown-grace-ms` 期限内继续运行。未配置该字段时，监听器换代的排空期限是 5000 毫秒。同端口切换 TCP 透明模式需改用不同的绑定地址或端口。CLI 日志与 `control status` 报告已发布的监听代次。

独立 DNS 同绑定换代时，新查询采用新的上游、规则和缓存，正在处理的查询保留旧代。已有 DNS TCP 连接的下一条查询可采用新代。迁移或移除 DNS 绑定时，旧连接和已经接收的 UDP 查询在排空期内继续处理。沿用相同的 FakeIP 池和持久历史时可保留地址分配状态。新增 FakeIP 或修改池、TTL、历史目录需重启。

原生 Shadowsocks UDP 按已验证的会话 ID 保留原代的路由和回包。新会话由当前代接入，旧代会话在排空期内仍可使用原端口。相同密钥跨代共享防重放记录。

顶层 `shutdown-grace-ms 1500` 为普通 Server 监听设置停机排空时间，范围为 0 至 30000 毫秒，默认 0。收到 SIGINT 或 SIGTERM 后先停止接收新连接，现有会话可使用剩余时间完成，达到期限后取消。独立包设备及独立协议宿主沿用各自的停止流程。

顶层 `sessions-per-listener 256` 设置各监听器的 Server 会话配额，范围为 1 至 4096，默认 64。一个监听器的 worker 共用同一配额，各监听器独立记账。使用 Server 配额的协议子流也计入其中，独立数据报和包设备仍使用各自的资源预算。超限的普通 TCP 接入会关闭，已有会话继续转发。修改配额需重启。

有具名认证用户的 SOCKS5/Mixed、Trojan、ShadowTLS、AnyTLS、VLESS、SS-2022 EIH、Hysteria 2 和 TUIC 入站可设置 `user-limits`。各 worker 按入站名和用户共用计数，在认证成功后占用额度。每项范围为 0 至 4096，0 拒绝新接入，省略则沿用协议和监听器的总额度。

```kdl
user-limits {
  user "alice" connections=2 streams=8
}
```

AnyTLS、Hysteria 2 和 TUIC 的 TCP 子流与 UDP 关联共用 `streams`。VLESS 的 `streams` 限制 XUDP 逻辑流，VLESS/gRPC 在 RPC 内确认身份后按 RPC 记入 `connections`。SS-2022 EIH 的 TCP 和原生 UDP 会话共用 `connections`。支持监听器换代的入站在 SIGHUP 后对新接入使用新限额，旧会话保留原代及已占用的额度。用 `nexus control SOCKET user-usage LISTENER_INDEX` 查看当前占用及分项拒绝数。

Mixed/SOCKS 用户密码认证、AnyTLS、Trojan、VLESS、SS-2022 EIH、ShadowTLS、Hysteria 2 和 TUIC 的具名用户条目支持 `byte-quota`、`bytes-per-second` 和 `burst-bytes`。流量按业务载荷字节计，TCP 与 UDP 子流和上下行共用同一用户预算。`byte-quota` 设定累计额度，0 允许空数据报。`bytes-per-second` 的范围为 1 至 1000000000。`burst-bytes` 须和速率同时配置，范围为 1 至 16777216，省略时取一秒速率对应的字节数，最低 16384，最高 16777216。

TCP 可等待速率恢复，累计配额耗尽时结束受影响的子流。额度不足时丢弃整份 UDP 数据报。控制命令另报告 `upload`、`download`、`unconfirmed` 和 `byte-limit-denials`。已经提交且交付结果未知的字节记入 `unconfirmed` 并占用配额。同名入站和用户在监听器换代时沿用累计用量，旧流与新流同时使用更新后的字节预算。

Linux 顶层 `tcp-splice-pipes 64` 为裸 TCP 直连启用内核转发。各监听器的 worker 共用管道预算，每个启用的转发方向占一条管道和两个 FD。范围为 0 至 256，Linux 默认 64（显式设 0 可禁用）。无法分配管道时该方向使用缓冲转发。代理隧道和普通 HTTP 正向代理继续走各自的协议转发。启用时 CLI 忽略 `SIGPIPE`，由转发操作处理写错误。修改配置需重启。

新接入会话使用发布后的规则。已接入的 TCP 连接和 SOCKS5 UDP 关联保留原有规则代次。包协议监听器及 TUN 设备的绑定修改需要重启。

### 具名出站选择器

把选择器和实际出站一起放在 `outbounds` 中。例如，已有实际出站 `direct` 和 `edge` 时，可以添加：

```kdl
selector "preferred" {
    member "edge"
    member "direct"
    selected "edge"
}
```

`member` 可引用实际出站或另一选择器。每组允许 1–16 个各不相同的成员，最多 16 组。省略 `selected` 时选择首个成员。解析会检查全部成员和 detour 构成的依赖图，包括当前未选中的路径。规则及动作用实际选中的叶子出站执行，所用协议和 detour 仍受该调用路径的能力约束。

普通 `nexus run --config` 可以在配置文件中修改 `selected` 后发送 SIGHUP。选择和规则文件共同发布。组名、成员、出站配置、规则结构和 DNS 上游沿用启动配置。仅切换选择器时继续使用现有监听器。会改变运行中 detour 的实际底层出站时需要重启。将选择切到 `direct` 后，新会话可直接连接业务目标。

普通 Server 的路由也可使用 `fallback`、`url-test`、`load-balance`。前两类共享 `member` 和 `probe-url`，默认 `probe-mode "http"` 向明确配置的 `http://` 目标发 HEAD 并默认以 `200..299` 计为成功；可选 `probe-expected-status` 指定 1–16 个期望状态码或区间（如 `204`、`"200..204"`，不匹配或 `4xx`/`5xx`/截断响应一律判 `down`，并在 `group-health` 上报 `last-status`）；也可选 `probe-mode "h2-ping"` 对 `http://`（`h2c`）或 `https://`（ALPN `h2`，可配 `probe-ca-file` 与 `probe-server-name`）目标发 RFC 9113 `PING` 帧并以 `PING ACK` 往返计 RTT。可配置 `probe-interval-ms`（默认 300000）和 `probe-timeout-ms`（默认 5000）。`fallback` 选首个可用成员，`url-test` 选延迟最低的成员并可用 `tolerance-ms` 抑制反复切换，且支持通过本地控制面 `control select <group> <member>` 临时手动覆盖（不落盘、后台继续刷新各成员延迟但不冲掉覆盖，`status`/`group-health` 标明 `override=1`）及 `control select <group> --auto` 恢复自动优选。全部失败时保留当前选择。探测轮次完成后发布组选择，新会话使用新代次。

`load-balance` 使用 `member` 列表，按目标主机选择成员。一个域名的多条解析结果和同一目标的 TCP、UDP 使用同一选组依据。自动组可用于普通 Server 的默认路由和规则动作。独立数据面、具名 HTTP 客户端与固定 detour 使用手动选择器。加密 DNS detour 的自动选择见上文。探活成员须能确定实际出站，支持在负载均衡组内嵌探活组。

### 具名 HTTPS 规则下载

`http-client` 启用 `nexus rule fetch <配置> <客户端> <HTTPS URL> <kdl|beve> <输出文件> [--sha256 <十六进制值>]`。在已有配置中加入具名客户端，引用同一配置中的出站和 DNS 服务器。

```kdl
http-clients {
    updates {
        outbound "direct"
        domain-resolver "bootstrap"
        ca-file "/etc/nexus/update-ca.pem"
        protocol "auto"
        timeout-ms 3000
        max-response-bytes 1048576
        header "User-Agent" "nexus-rules"
    }
}
```

客户端以 URL 的主机验证证书，并用选定的 `domain-resolver` 解析源站。TCP 连接通过直连或所选出站的 detour 链。代理服务器自己的域名沿用其出站引导解析器。默认总期限为 10000 毫秒，正文上限为 1 MiB，可配置至 8 MiB。

默认协议为 `http/1.1`，支持固定长度、分块和由 TLS `close_notify` 定界的响应。`http-client-h2` 启用 `protocol "h2"`。`protocol "auto"` 通过 TCP ALPN 协商已启用的 HTTP/2 和 HTTP/1.1。同时启用 `http-client-h3` 时，`rule watch` 可根据完整校验并发布的响应中的同主机 `Alt-Svc`，在后续刷新时尝试 HTTP/3。候选端口按 `ma` 和 `Age` 到期，配置变化清除候选。HTTP/3 尝试限总期限的三分之一且最多 500 毫秒，失败后使用原出站和源站身份经 TCP 重试。[RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.html)

`http-client-h3` 启用 `protocol "h3"`，可使用直连 UDP，或经具名出站传输数据报，例如 Trojan UDP、启用 `udp-over-tcp "v2"` 的 Shadowsocks 或启用 UDP 的 Hysteria 2。直连使用所选出口的 UDP 绑定及系统候选接口，经代理时由链上实际拨号出口配置。直连 HTTP/1.1、HTTP/2 和 HTTP/3 在总期限内按所选接口及其回退等待时间建立连接。显式 h3 连接失败时保留现有规则。h3 可设置 `max-udp-payload-size`（1200–1500 字节）和绝对路径 `ech-config-file`（二进制 ECHConfigList）。配置 ECH 后，只有被源站接受的 ECH 握手才能继续下载。显式 h3 可用 `disable-path-mtu-discovery #true` 关闭主动探测。

启用 `quic-resumption` 后，具名 HTTP/3 客户端可用 TLS 1.3 会话票据建立新连接，并在 1-RTT 阶段提交请求。票据由客户端实例在内存中持有，按实际对端地址和端口、信任根、验证身份和 ALPN 隔离。配置静态 ECH 的连接执行完整握手。

具名客户端可用 `fingerprint` 选择 TLS 指纹，并用 `key-exchange` 选择 `x25519`（默认）、`x25519-mlkem768` 或 `x25519-mlkem768-only`。显式 HTTP/1.1 或 h2 支持 `record-size-limit`（64–16385 字节）。`fingerprint "tls12"` 要求显式 HTTP/1.1 或 h2、X25519 和默认 TLS 记录大小。QUIC 使用适用的 TLS 1.3 ClientHello，TLS 身份始终来自源站 URL。

每个客户端可用多条 `header "名称" "值"` 为 HTTP/1.1、HTTP/2 和 HTTP/3 添加请求字段。名称按 ASCII 大小写无关处理，最多 16 条且合计字段预算为 4096 字节。配置拒绝重复名称、非法字符和由协议管理的字段，例如 `Host`、`Content-Length`、`Connection`。规则下载使用 URL 的源站，从同主机 Alt-Svc 改用 HTTP/3 时也发送这些字段。

下载接受 HTTPS 200 和 identity 内容编码。设置 `max-redirects` 可在本次请求的总期限内跟随最多 5 次 301、302、303、307 或 308。默认值 0。允许同源的 HTTPS 绝对地址和相对引用。重定向保留同一 TLS 验证身份、出站和请求字段，自动 ETag 仅用于其对应的最终路径。 [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4) · [RFC 3986 §5.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-5.2)

可选的 `--sha256` 使用 64 个十六进制字符校验去除 HTTP framing 后的正文。格式支持 KDL、BEVE 和启用 `srs` 时的 SRS。摘要和规则格式通过校验后原子替换输出文件。

`nexus rule watch <间隔毫秒> <配置> <客户端> <HTTPS URL> <kdl|beve|srs> <输出文件> [--sha256 <十六进制值>]` 启动后立即检查，并在每次检查结束后等待指定间隔。成功发布的响应若含有效 ETag，后续刷新发送 `If-None-Match`。收到 304 时校验已发布文件的摘要并保留该文件，文件丢失或改变时下次请求完整内容。ETag 随进程或客户端配置变动清除。显式请求条件或 Range 优先于自动 ETag。间隔范围为 100–86400000 毫秒。物理直连的订阅可跨轮复用 HTTP 连接，配置、信任文件、静态 ECH 或本地解析文件变动后重建客户端。经代理拨号或代理 DNS 的订阅每轮重新装载客户端。刷新失败保留上一份可用文件，SIGINT 和 SIGTERM 取消在途请求。文件读取者可见完整旧文件或完整新文件。对支持热加载的 `nexus run --config` 进程发送 SIGHUP，可在运行中应用已发布的规则。DNS 与流量配置引用相同路径的文件时，同一候选发布使用同一次读取的内容。

### 远程规则缓存

`rule fetch` 和 `rule watch` 可用 `--cache-dir /absolute/private-directory` 启用磁盘缓存。目录由运行账户创建，权限为 `0700`。缓存仅管理该目录下 `rulesets/` 的 NXRS01 索引及其内容寻址文件。配置文件和输出路径须位于缓存树之外。未指定该选项时，使用顶层 `state.cache-directory`，两者都省略时使用内存订阅语义。

缓存按 HTTPS URL、格式、解析器版本和具名客户端配置分区。URL 的源站部分规范化，实际请求路径和查询串原样区分。索引与正文均为私有文件，URL 的查询串也保存在索引中。缓存正文上限为 1 MiB，索引最多 64 项。正文总预算默认 64 MiB，可用 `--ruleset-cache-max-bytes <字节>` 调整。同摘要正文只占一份空间，超额时优先淘汰最早写入或验证的条目。已知的孤立正文和中断写入的临时正文会被回收。

命中时仅对记录该 ETag 的响应路径自动发送 `If-None-Match`。304 按正文的 BLAKE3、SHA-256、规则格式和当前 SHA-256 pin 验证，并可恢复丢失的目标文件。200 的正文先通过校验和缓存提交，再原子发布目标。设置 `--offline-cache` 须同时提供 `--sha256`，用于连接准备或握手失败的缓存回退。回退要求完整正文与 pin 一致且距最近成功获取或验证不足 24 小时。收到无效 HTTP 响应或新正文校验失败时保留既有输出。

`nexus rule fetch --clear-cache /absolute/private-directory` 仅清理该目录下的远程规则缓存。清理由持久化 epoch 拦截已开始、尚未存盘的下载。若损坏文件无法删除，命令报告删除阶段的系统 errno。

## 实验性 VLESS XHTTP

编译启用 `xhttp-vless` 后，可在 VLESS 入站和出站添加 `transport "xhttp"`。HTTP/1.1 支持 `packet-up`，HTTP/2 和 HTTP/3 支持 `packet-up`、`stream-one` 和 `stream-up`。HTTP/3 使用 UDP 和普通证书 TLS。HTTP/2 在普通 TLS 上协商 `h2`，明文使用 HTTP/2 prior knowledge。TCP 承载可使用 REALITY。普通 TLS 和明文出站的 `auto` 默认选择 `packet-up`；HTTP/2 REALITY 出站的 `auto` 默认选择 `stream-one`，配置独立下载时选择 `stream-up`。入站配置一个 worker。同一监听器的路径与 Host 配置须和对端对应。

```kdl
transport "xhttp" {
    protocol "h2"
    mode "stream-one"
    path "/edge"
    host "edge.example"
    x-padding-bytes "100-1000"
    x-padding-placement "referer"
}
```

`path` 会补齐末尾的斜杠。填充还可使用 `query` 或自定义 `header`，后者使用 `x-padding-header` 指定名称。使用 `header "name" "value"` 添加 HTTP 请求头。`no-grpc-header #true` 可省略长 POST 的 `Content-Type`。分离模式的出站可配置 `download-settings`，为下行指定独立的服务端地址、HTTP 版本、Host、路径和 TLS。使用 `stream-up` 时，两侧都要支持流式 HTTP/2 或 HTTP/3。协议限制包括 `sc-max-each-post-bytes`、`sc-min-posts-interval-ms`、`sc-max-buffered-posts`、`buffer-bytes`、`max-sessions` 和 `pair-timeout-ms`。

`stream-one` 和 `stream-up` 用 HTTP/2 END_STREAM 或 QUIC 流 FIN 传递 EOF。`packet-up` 以独立短 POST 交付上行数据，上传停止没有单独的 EOF 消息。

出站 `xmux` 按工作线程和上下行连接池复用载体。`max-connections` 限制物理连接数，`max-concurrency` 限制每条载体同时承载的隧道数。HTTP/1.1 每条连接同时处理一个请求。`c-max-reuse-times`、`c-max-lifetime-ms`、`h-max-request-times` 和 `h-max-reusable-secs` 分别限制额外复用次数、连接寿命、请求数和可复用时长。超预算载体保留正在进行的流直至关闭，新请求使用可用载体。

## SOCKS5 和 HTTP CONNECT 出站

`type="socks5"` 与 `type="http-connect"` 可作为具名 TCP 出站或 TCP 下层。省略 `authentication` 时分别使用 SOCKS5 无认证或无 Proxy-Authorization 的 HTTP/1.1 CONNECT。配置用户名及私有密码文件时分别使用 SOCKS5 用户名密码和 HTTP Basic。HTTP Basic 的用户名不能包含冒号。两种出站均在物理连接上发送代理握手，业务目的地址按现有路由和 DNS 选择后发送给上游。

```kdl
outbound "upstream" type="http-connect" {
    server host="127.0.0.1" port=8080
    authentication username="proxy-user" password-file="/run/secrets/proxy-password"
    connect-timeout-ms 3000
}
```

支持 `bootstrap-resolver` 和具备 TCP 能力的 `detour`。物理节点可配置 TCP socket 选项及 Fast Open。显式 `detour "direct"` 继承相应 direct 配置，代理层沿用已选下层的载体。解析、上游握手和认证共用连接期限。

SOCKS5 出站可显式配置 `udp #true`，使用上游 UDP ASSOCIATE。控制连接及数据报使用同一物理接口，控制连接关闭时撤回关联。支持同控制连接地址族的数值中继地址，也接受该族通配地址并使用已连接的代理地址。UDP 可使用物理直连或 `detour "direct"`。空数据报及 IPv4/IPv6 业务目标均可转发。

编译启用 `http-connect-tls` 后，HTTP CONNECT 出站可配置 `tls { server-name "proxy.example"; ca-file "/etc/nexus/ca.pem"; verify #true; }`。该块适用于物理 TCP、Fast Open 和 TCP 代理下层。Nexus 完成 TLS 1.3 验证后才发送 CONNECT 和代理凭据。

## HTTP 与固定 TCP 入站

`inbound` 的 `type="http"` 接受 HTTP/1.1 CONNECT 和正向转发，使用 Mixed 的 HTTP 认证和路由。监听端点为 `127.0.0.1` 或 `::1`，配置 `authentication "none"` 或 `authentication "password"`。同一个入站只处理 HTTP 请求。

```kdl
inbound "app-port" type="fixed-tcp" {
    listen host="127.0.0.1" port=18080
    target host="internal.example" port=8080
}
```

`fixed-tcp` 在双栈回环端点接受原始 TCP 流，每条流使用该监听器在准入时的配置目标。目标可为数值 IPv4、IPv6 或域名，经过常规 DNS、路由和 TCP 转发。旧流使用旧目标，新流使用成功热重载后的目标。状态中的应用协议为 `fixed-tcp`。

## TUIC 和 MASQUE 出站 detour

TUIC 和 MASQUE CONNECT-UDP 出站可设置 `detour "lower"`，通过具备数据报能力的下层访问 QUIC 服务器。已验收 Trojan UDP 和启用 `udp-over-tcp "v2"` 的 Shadowsocks。TUIC 的 TCP 与 UDP 业务可使用同一配置，UDP 可选择原生数据报或 QUIC 流。节点的引导 DNS、QUIC 握手和连接建立共用该节点的连接期限。TLS 仍使用 QUIC 节点的 `server-name`、CA 和 ECH 配置。

显式 `detour "direct"` 继承具名直连出站的 UDP 源地址、源端口和其他绑定选项。带代理 detour 的节点由下层负责物理 socket，节点自身的绑定字段会被拒绝。下层不可用时，本次连接失败。每个 MASQUE CONNECT-UDP 请求绑定一个 UDP 目标。同一 SOCKS 或 routed TUN 关联可为不同地址或端口建立独立请求和承载。VLESS 固定目标 UDP 在 endpoint-independent TUN 映射上也按目的地址和端口分别建立流。

普通 MASQUE CONNECT-IP 出站同样支持有数据报能力的代理 detour 和具名 direct。独立 CONNECT-IP TUN 的承载选项及限制见下文。

启用构建特性 `quic-resumption` 后，具名 TUIC、MASQUE CONNECT-UDP 和 Hysteria 2 出站可恢复 TLS 1.3 会话。票据只保留在内存中，并按具名配置、对端 IP 与端口、信任根、服务端身份及 ALPN 隔离。使用 ECH 时执行完整握手。每条新连接都要在握手后完成协议认证。TUIC 使用该连接的 TLS exporter 生成认证令牌，MASQUE 为每次请求提交所配置的授权信息。

## WireGuard 出站

WireGuard 出站可用 `detour "direct"` 继承 direct 的物理 UDP 参数，包括源地址、`udp-bind-port` 和 `routing-mark`。也可指向能传输数据报的下层出站，例如开启 `udp-over-tcp "v2"` 的 Shadowsocks。源端口已占用时，该次连接失败，端口释放后可重新连接。使用 WARP 兼容格式时，`reserved 17 34 51` 设置三字节字段。

## 实验性 MASQUE CONNECT-UDP 入站

通过 `masque-cli` feature 可启用受限的 HTTP/3 CONNECT-UDP 入站。当前只支持一个 MASQUE 入站、`workers 1`、默认 direct 出口和系统 local DNS；全局 DNS、路由规则、其他入站/隧道和 direct 拨号选项会被拒绝。该入站尚不支持 CONNECT-IP、自定义 URI 模板或多 worker 的连接 ID 分发。示例：

```kdl
schema-version 1
role "server"
workers 1
inbound "masque" type="masque" {
  listen host="127.0.0.1" port=9443
  authority "localhost"
  authentication { bearer-file "/etc/nexus/masque-token"; }
  tls { certificate-file "/etc/nexus/cert.pem"; private-key-file "/etc/nexus/key.pem"; }
  allow cidr="127.0.0.0/8" first-port=1 last-port=65535
}
outbound "direct" type="direct"
routing { default-outbound "direct"; }
```

监听地址须为不带 zone 的数字地址，`authority` 必须与请求匹配。Bearer 文件使用绝对路径和现有私有文件检查，去掉最多一个末尾换行后须为 1..255 字节的 Bearer token。token 须至少包含一个 ASCII 字母、数字或 `-._~+/` 字符，`=` 只能出现在末尾；证书及私钥也使用绝对路径。CONNECT-UDP 需要至少一项 `allow`，以 CIDR 和闭区间端口授权。CIDR 不能有 host bits，域名解析后的数值地址也须通过此策略。最多 256 项。可选 `dns-timeout-ms` 为 1..60000，默认 5000；`native-bytes` 为 65536..1073741824，默认 8388608。这里的 CIDR 示例只允许回环目标，实际授权应按所需目标配置。当前验证范围与未完成互通见[项目进度](../progress.md)。

普通 VLESS 入站支持固定目的地 UDP（命令 2）。认证后的流使用两字节长度前缀保留数据报边界，可承载空包，并按 UDP 使用现有 DNS、路由和限额。普通 TLS 入站也识别 packetaddr，在每帧内读取 IPv4 或 IPv6 目标。有序路由需要 `tcp-program udp=#true`。Vision UDP 继续使用现有 XUDP 路径。VLESS 出站可配置 `packet-encoding "packetaddr"`，经普通 VLESS TLS 或 HTTPUpgrade 发送 IPv4/IPv6 数据报。默认及显式 `packet-encoding "xudp"` 使用 XUDP。`packet-encoding "fixed"` 在普通 VLESS TLS 或 HTTPUpgrade 上按目标 IP 与端口使用独立命令 2 流，数据报前缀为两字节长度。域名按现有 UDP 路由策略解析后使用数值目标。SOCKS 和共用流式 UDP 关联最多为该编码并行保留 16 个目标流。

## Linux TUN 严格路由

普通 TUN 入站的 `stack` 只接受 `"system"`，可省略。它使用 Linux TUN 和 Nexus 内置的 TCP/UDP 引擎。

普通 TUN 入站可用 `device-fd 3 ownership="borrow"` 接入宿主配置好的 Linux TUN。文件描述符须已在当前进程打开，使用非阻塞读写和无额外头部的 IP 包。默认 `borrow` 会复制描述符，停止时关闭副本。`ownership="adopt"` 在接入时接管原描述符，结束或启动回滚时关闭。每次重新启动接管模式须提供有效的新描述符。`interface-name` 可指定预期设备名，省略时从描述符获取。宿主负责设备 MTU、地址、路由和防回环，`mtu` 应与宿主设备一致。这种方式可用于 CLI 继承或宿主进程提供的描述符，不能与 Nexus 管理 TUN 地址、自动路由、严格路由或 CONNECT-IP TUN 同时使用。

普通 TUN 入站可以在 `auto-route #true` 下设置 `strict-route #true`。严格路由独占该配置的入站，按已启用的地址族安装捕获及绕行规则，允许本地流量继续使用内核 local 表。Nexus 为外层 socket 设置 `socket-mark`，省略时使用 `0x6e780001`。具名物理 DNS 上游也使用该标记，使这些查询沿物理路由发出。标记流量经验证的物理路由绕行，找不到绕行路由时返回不可达。进程退出时撤回策略及设备，路由表或相应规则发生外部变更时停止。

代理物理出站使用数字服务器地址。显式 outbound `routing-mark` 必须与 TUN 的 `socket-mark` 相同。启动需要管理目标网络命名空间路由与策略的权限。

严格路由的 CLI TUN 可设置 `host-dns "resolved"`。需要启用 `tun-host-dns` 构建特性，并在同一配置中将 DNS 的 UDP/TCP 监听器绑定到配置的 TUN 地址和 53 端口。独立网络所有者在该链路上配置 systemd-resolved 的默认路由域，代理进程退出时撤回自有配置和设备。已有 DNS 设置或其他链路的冲突路由域会使启动失败。

`endpoint-independent-nat` 控制直接 UDP 的映射键。`udp-filtering` 独立控制回包的来源检查，可选 `"address-port-dependent"`（默认）、`"address-dependent"` 或 `"endpoint-independent"`。后两种分别允许来自已发送目标地址的其他端口，或来自任意来源的回包。经过代理隧道和 FakeIP 的回包仍执行各自的授权。

`udp-reject "icmp"` 为命中显式拒绝或 block 出站的未分片单播 UDP 返回 ICMPv4 或 ICMPv6 管理禁止报文，每个 TUN 的一秒限额为 32 个。默认 `udp-reject "drop"`。TCP 使用现有 RST 路径。 [RFC 1812](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.7.1) · [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1)

routed TUN 可设置 `udp-reply-fragment #true`。超设备 MTU 的已授权 UDP 回包以 IPv4 或 IPv6 分片交付，每组最多 64 片。发送队列必须能同时接收整组。缺省丢弃超设备 MTU 的回包。该选项作用于返回 TUN 的数据报。

普通 routed TUN 可重组入向 UDP。支持无选项的 IPv4 分片及 IPv6 固定头后紧接 Fragment 头的 UDP 分片。每个设备最多保留 32 组，每组最多 64 片，自首个接收分片起 15 秒到期。重叠片令整组失效，重组完成后执行 UDP 长度和校验和检查。

启用 `strict-route` 时，可配置最多 16 条 `route-exclude "192.0.2.0/24"` 和 `route-exclude "2001:db8:1::/64"`。被排除的目的前缀在内核路由阶段直接进入物理绕行表，使用相同地址族的已验证路由。无可用物理路由时内核返回不可达。

`route-exclude-private #true` 追加启用地址族的私有前缀，包括 RFC 1918、RFC 6598、IPv4 和 IPv6 链路本地以及 IPv6 ULA。与手写条目完全相同时去重。未排除的目的地继续按标记策略路由。

`include-routing-mark 0x20 mask=0xf0` 将满足掩码的标记限定为 TUN 捕获对象，其他标记继续走系统路由。省略 include 时捕获所有未排除流量。`exclude-routing-mark 0x23` 直接使用物理绕行表，优先于 include。两个选项各接受一个无符号 32 位标记，可选非零 `mask` 默认为 `0xffffffff`。代理自己的 `socket-mark` 始终先走隔离的物理绕行表。启用标记过滤时，TUN 的 IPv4 反向路径检查从 strict 临时调整为 loose，以接收重新注入的无标记回包。

### Linux TUN 原生 TCP 重定向

`auto-redirect #true` 要求 `auto-route #true`，并隐式启用 `strict-route`。外部 `device-fd`、CONNECT-IP TUN 和显式 `strict-route #false` 与该选项冲突。默认关闭。

```kdl
inbound "system" type="tun" {
    interface-name "nexus0"
    inet4-address "198.19.0.1/32"
    inet6-address "2001:db8:100::1/128"
    auto-route #true
    auto-redirect #true
    route-exclude-private #true
}
```

内核在 `inet` 表的 output 与 prerouting NAT hook 将本机和转发 TCP 送入同一个内部端口。监听器根据原始目的地址使用 TUN 的流量规则、嗅探、DNS 和 FakeIP 视图。重定向跳过回环、转发入口的本地目的路由以及带 Nexus 防环 mark 的流量。透明 TCP 可读取源和网关邻接信息，DSCP 保持未知。UDP、ICMP 和其他 IP 流量继续使用 TUN 策略路由。

`exclude-routing-mark` 优先于 `include-routing-mark`。通过标记条件后，配置的 FakeIP 池及已启用的 53 端口 DNS 劫持优先于目的前缀排除。其他目标按 `route-exclude` 和 `route-exclude-private` 绕行。关闭选项时不打开 netfilter socket。

独立网络所有者直接通过 `NETLINK_NETFILTER` 原子安装专属表。代理正常退出或因 SIGKILL 关闭控制通道后，所有者用单次批量事务删除该表并撤回自有路由。表绑定内核 netlink 所有者 socket，提供额外的异常回收。需要内核支持 inet NAT、REDIRECT 及表所有权，同时需要该网络命名空间的管理权限。任一条件不满足时启动失败。启动时读取最多 32 个本地目的前缀，运行期间本地目的路由变更会触发严格路由停止。

CLI 的严格路由由独立网络进程持有。代理停止或单独异常退出后，网络进程按内核所有权记录撤回路由、恢复反向路径设置并关闭非持久 TUN。网络所有者同时被强制终止时，需要宿主处理残留策略。

## MASQUE CONNECT-IP 出站

`masque-outbound` 的 `type="masque"` 出站可设置 `mode "connect-ip"`。使用 `local-address` 指定已约定的本地 IP，或从对端接收地址分配。每份地址分配和路由通告会替换上一份，相关变更会关闭当前流。HTTP/3 数据报预算不足时，出站可使用可靠 Capsule。请求流关闭后，新业务可触发有界退避重连。默认路径支持通配和数值前缀；`path` 可指定双方约定的路径。

启用 `masque-ip-endpoint` 后，Linux TUN 入站可选用具名 CONNECT-IP 出站转发原始 IP 包。

```kdl
inbound "office" type="tun" {
  interface-name "nx-office"
  connect-ip-outbound "edge"
  connect-ip-route "198.51.100.32/28"
  connect-ip-route "2001:db8:42::/96"
  mtu 1280
}
outbound "edge" type="masque" {
  mode "connect-ip"
  server host="192.0.2.10" port=443
  authority "edge.example"
  authentication { bearer-file "/etc/nexus/masque-token"; }
  tls { server-name "edge.example"; ca-file "/etc/nexus/masque-ca.pem"; verify #true; }
}
```

至少配置一项 `connect-ip-route`，最多 16 项。每项使用网络地址及非零前缀长度。内核路由只安装在本地允许前缀、对端通告和请求目标的交集内，地址使用已分配的单主机地址。CONNECT-IP 服务器必须使用数字地址，本地允许前缀和对端分配的地址均不能覆盖外层端点。默认请求路径可用通配符或数字目标。设备 MTU 默认 1280，范围 1280–1500。此模式使用对端动态分配，配置静态 TUN 地址、自动路由或 L4 栈选项会被拒绝。运行进程需要在目标网络命名空间创建 TUN 并管理地址和路由的权限。

独立 CONNECT-IP TUN 可用 `detour "direct"` 继承具名直连出站的 UDP 绑定和按地址族的接口选择，也可使用最后一跳支持 Trojan UDP 或 Shadowsocks UoT v2 的 Trojan/Shadowsocks 链。物理首选路径若在认证握手时停滞，可在原连接期限内使用备用接口。CONNECT-IP 请求与后续 TUN 租约继续使用已选路径。代理路径要求只有一个 TUN 入站。下层可用具名引导解析器，解析与连接共用外层期限。按 CONNECT-IP 服务器和实际拨通的物理下层对端检查路由覆盖，握手成功并取得地址后创建设备。代理路径的 socket 参数在物理出站配置，TUN 的 `socket-mark` 字段只用于直接承载。

## MASQUE CONNECT-IP 入站

`masque-ip-server` 在 MASQUE 入站中启用 `connect-ip` 块。服务端复用入站的 authority、TLS 和 bearer，按请求建立独占 Linux TUN 租约。当前每个监听器允许一个活动 IP 请求。双栈分别填写同族本机和客户端主机地址，并通过 `allow-ip` 限定远端访问范围。

```kdl
connect-ip {
  interface-name "nx-ip-edge"
  local-address "198.51.100.42"
  local-address "2001:db8:60::42"
  client-address "10.60.0.2"
  client-address "fd60::2"
  allow-ip "198.51.100.42/32"
  allow-ip "2001:db8:60::42/128"
}
```

服务端接受默认 URI 模板的通配或数字目标，通告请求范围与允许前缀的交集。客户端包必须使用服务端为该连接分配的源地址。MTU 为 1280；接收 HTTP Datagram 和 Capsule，回包使用可靠 Capsule。退出或请求关闭时移除客户端主机路由和 TUN。远端路由由 Linux 负责，跨网段转发需要在相应网络命名空间配置转发和回程路由。CONNECT-UDP 可以通过同一入站的独立 `allow` 条目启用。

## QUIC 出站 ECH

Hysteria 2、TUIC 和 MASQUE 出站可在 `tls` 中使用 `ech-config-file "/etc/nexus/edge.ech"` 或 `ech-dns #true`。文件内容为二进制 ECHConfigList。`ech-dns` 需要 `dns-response` 和已配置的 DNS，优先使用出站的 `domain-resolver`（或 `bootstrap-resolver`），否则使用 DNS `final`。用于这组 ECH 辅助查询的具名视图须采用仅按请求判定的 DNS 规则。Nexus 查询 `server-name` 的 HTTPS 和 SVCB ServiceMode 记录，只接受保持当前目标及端口的记录。CONNECT-IP TUN 使用静态文件方式。

启用 ECH 后，`server-name` 必须是 DNS 名称，证书仍按该名称验证。配置缺失、ECH 发现失败或服务端拒绝都会终止连接。当前支持 X25519 和 HKDF-SHA256，使用配置中通告的 AES-GCM 或 ChaCha20-Poly1305。连接不尝试用服务端返回的重试配置重新拨号。[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)

## 实验性 Tailscale 端点

启用 `tailscale-endpoint` 后，通过 `nexus endpoint check --config <file>` 校验，通过 `nexus endpoint run --config <file>` 运行。该入口绑定一个明确的物理 UDP 地址并建立 Linux TUN，使用受信 CA 和固定 Noise control key 连接配置的 Control 服务。

```kdl
schema-version 1
role "client"
endpoint "mesh" type="tailscale" {
  control-url "https://control.example"
  control-address "192.0.2.10"
  control-key "mkey:0000000000000000000000000000000000000000000000000000000000000001"
  ca-file "/etc/nexus/control-ca.pem"
  auth-key-file "/etc/nexus/tailscale-auth"
  state-dir "/var/lib/nexus/tailscale"
  interface-name "nxmesh"
  listen host="192.0.2.20" port=41641
  accept-routes #false
}
```

示例 pin 为占位值，部署时填写实际公钥。`auth-key-file` 由进程所有且权限为 `0600`。`state-dir` 是已创建的 `0700` 私有目录，持久化 Machine 和 Node 私钥。`ephemeral #true` 使用进程内身份。`hostname` 默认为端点名，MTU 为 1280–1500，默认 1280。`control-address` 固定数字地址，`control-url` 提供 TLS 名称与端口。

可加 `derp` 块，包含 `server-url`、`server-address`、`server-key`、`ca-file` 和 `region-id`。也可配置最多八个同字段的 `derp-candidate`，由 Control Map 的区域和节点匹配启用其中一个候选。启用候选需要匹配区域、主机名、端口及显式地址，仍按本地 CA 和 DERP key 验证服务。Map 断开时撤回设备和路由。当前数据面处理双栈 TCP 和 UDP，接收入站新流时执行 PacketFilter，活动出站保留有界回程记录。Tailnet Lock 和无法解释的安全能力会拒绝安装。

`discover-paths #true` 启用通过已授权 Disco key 验证的直连路径。可设置 `stun-server host="192.0.2.10" port=3478`，用同一物理 UDP socket 观测映射并向 Control 发布。直连失效后可回到区域匹配的 DERP。当前每个端点同时使用一个 DERP 区域。

需要通过代理访问此端点时，在同一网络命名空间运行 `nexus run`，将 direct 出站的 `bind-interface` 设为该端点的 `interface-name`。SOCKS5 TCP 和 UDP 使用端点安装的路由。

`tailscale-outbound` 也提供用户态出站。使用绝对路径 `endpoint-file` 引用上述 Tailscale 端点配置，并将该出站选为默认或通过流量规则选择它。当前支持单 worker 及一个 SOCKS5 或 Mixed 入站。进程内的 TCP/UDP 引擎承载业务，内核无需安装 TUN 和路由。

```kdl
outbound "mesh" type="tailscale" {
  endpoint-file "/etc/nexus/tailnet.kdl"
}
```
