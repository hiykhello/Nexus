# 配置示例

## 可运行的实验与低内存配置

- [low-memory-client.kdl](low-memory-client.kdl)：面向 50 MiB 移动端扩展与 128 MiB OpenWrt 路由器的低内存客户端基线（`workers 1`、`tcp-splice-pipes 4`、有界 DNS/规则集缓存与本机控制面），已通过 `nexus check --config docs/configuration/examples/low-memory-client.kdl` 三产物实机校验。
- [ergonomic-client.kdl](ergonomic-client.kdl)：展示简洁人类可读 KDL 语法（`direct`/`block` 自动命名、`host:port` 短写、`members` 列表、`rules` 有序直连/分流/劫持规则与 DNS 规则简写）。

[socks5.kdl](socks5.kdl) 可由 Linux 实验代理使用：`nexus run --config docs/configuration/examples/socks5.kdl`。它监听 `127.0.0.1:1080`，对示例规则命中执行 block，其余 direct；IPv4 映射 IPv6 目标同时检查两种地址族的 IP 规则；规则文件相对配置文件所在目录解析。[mixed.kdl](mixed.kdl) 将入站类型改为 `mixed`，同一端口支持 SOCKS5、HTTP/1.1 CONNECT 及有限的单次 HTTP 正向代理（支持 Content-Length 和 chunked 请求体）。入站和出站分别放在 `inbounds` 和 `outbounds` 块，DNS 服务器放在 `dns { servers { ... } }` 中；分组内用协议类型作节点名，`dns` 和 `routing` 的规则写在 `rules` 块内，并以 `-` 开始每条规则。旧的顶层 `inbound`/`outbound` 和 `dns` 下直接 `server` 暂兼容，同类配置不得混用新旧写法。当前支持最多 16 个入站（名称和监听地址/端口组合不能重复；IPv4 与 IPv6 回环可共用端口）、一个 direct 出站、可选 block 出站和最多 16 个具名 VLESS、SS-2022 和 Trojan 隧道出站（合计），以及最多 256 组 KDL/BEVE 规则集和 256 条有序引用规则；`role` 为 `client` 或 `server`，当前只作校验，不改变行为。配置和单个规则文件各限 1 MiB，规则文件合计限 8 MiB，展开后的谓词合计限 16384 条；未知节点、属性及未支持的组合均拒绝，加载成功后才监听。当前不支持重载或 HTTP 连接复用；SOCKS5 UDP ASSOCIATE 的受限能力见 [SOCKS5 说明](../../architecture/protocols/socks5-mixed.md)，Mixed 仅支持无认证。SOCKS5/Mixed 监听地址可选 IPv4 回环 `127.0.0.1` 或 IPv6 回环 `::1`。SS-2022 入站支持下述有限 UDP 路径。

可使用带名称的 `dns` 服务器列表选择代理目标解析的上游服务器（未配置 `dns` 块时继续使用系统解析器；旧顶层 `dns-upstream` 已移除）：

```kdl
dns {
    servers {
        local "system"
        udp "resolver" host="127.0.0.1" port=5353
    }
    rules {
        - domain="internal.example" server="system"
        - domain-suffix="example.net" server="resolver"
    }
    final "resolver"
    strategy "prefer_ipv6"
    disable-cache #true
    edns #true
}
```

`final` 可省略，默认选择第一个服务器；`udp` 和 `tcp` 的 `port` 可省略，默认为 53。`local` 使用现有系统解析器；`udp` 与 `tcp` 使用明文 DNS；`tcp` 直接发起 TCP 查询，每次查询建立连接。规则按顺序匹配，第一个命中选择服务器；`domain` 精确匹配，`domain-suffix` 匹配该域名及其子域名，忽略 ASCII 大小写且要求完整标签边界。无命中使用 `final`。域名采用不带末尾点的 ASCII 标签，最多声明 64 个服务器和 256 条规则。名称必须唯一，缺失的服务器引用、未知字段与不支持的类型会被拒绝。

可选 `strategy` 为 `prefer_ipv4`、`prefer_ipv6`、`ipv4_only` 或 `ipv6_only`，作用于代理目标域名。显式上游按优先族顺序查询并返回地址，单族模式只查询该族；双族模式中任何临时故障仍使解析失败。`local` 使用系统解析后按策略过滤或排序，不能保证系统本身只查询一个地址族。未配置时显式上游按 A、AAAA 顺序查询，系统解析保留其原有顺序；指定 `bootstrap-resolver` 时，VLESS 上游域名也使用该策略。

`disable-cache #true` 禁用 Nexus 的显式上游正结果和否定结果缓存，包括引导查询；省略或设为 `#false` 时启用。此选项不能控制系统解析器或上游自身的缓存。

`edns #true` 为显式 UDP/TCP 上游和引导查询启用无选项 EDNS(0)，通告 1232 字节；默认关闭。收到不含 OPT 的 FORMERR 时，重新抽取事务 ID 回退普通 DNS，沿用原有总期限；UDP 截断仍回退 TCP。响应必须携带版本 0、无标志和无选项的 OPT，其他 EDNS 语义尚不支持，会拒绝该响应；系统 `local` 解析不受此设置控制。

远程 DNS 服务器的 `host` 可以是域名，此时必须用 `domain-resolver` 指定另一具名服务器，例如：

```kdl
dns {
    servers {
        tcp "remote" host="dns.example" domain-resolver="bootstrap"
        udp "bootstrap" host="127.0.0.1" port=5353
    }
    final "remote"
}
```

引导依赖可多级引用，启动前拒绝缺失引用与循环；数值地址不得指定 `domain-resolver`。引导查询与目标解析共用会话期限和地址族策略，不走普通 DNS 规则；未配置策略时，引导使用 IPv4 优先。某个服务器域名解析出多个地址时，传输错误可尝试该服务器的下一个地址，否定答案和其他错误不切换其他服务器。引导链只有显式引用 `local` 才调用系统解析器；系统 `getaddrinfo` 不可中断，停止可能等待它返回。尚不支持服务器组故障切换、出口选择或热重载。

启用 `--crypto=y` 的 Linux 构建可将 VLESS/TLS 设为默认出站或规则集命中的出站：配置需提供 `server`、绝对路径的 `uuid-file`、TLS 的 `server-name` 和绝对路径 `ca-file`、`verify #true`。启动前加载并校验 UUID 和 CA；SOCKS5 CONNECT、Mixed HTTP CONNECT 和有限的单次普通 HTTP 请求可通过上游转发。每条规则的动作可选择 direct、block 或 VLESS，默认动作可选择 direct 或 VLESS；规则及默认动作按名称选择具体 VLESS 实例，每个实例都须被路由引用。域名在能确定阻断时先拒绝，否则使用配置的目标 DNS 解析器，逐个解析地址应用路由，选中的数字地址发送给对应出站。VLESS 上游默认使用系统解析器；在 VLESS 出站中加入 `bootstrap-resolver "boot"` 可使用 `dns` 中名为 `boot` 的服务器解析其域名。此字段要求节点 host 为域名，引用必须存在；不走普通 DNS 路由规则，查询失败不回退系统解析器。解析器为 `local` 或引导链引用 `local` 时仍会使用系统解析器。UDP、连接复用和生产级并发/故障覆盖尚未实现。默认 `--crypto=n` 构建明确拒绝 VLESS 配置。

出站 TLS 默认使用 X25519。可在 `tls` 块中加入 `key-exchange "x25519-mlkem768"`，优先使用混合组，同时通告 X25519 以便对端通过 HelloRetryRequest 选择回退；显式 `key-exchange "x25519"` 与默认行为相同。混合模式允许回退，因此不能保证每条连接都使用混合密钥交换。使用 `key-exchange "x25519-mlkem768-only"` 时仅通告混合组，无法协商该组的对端会握手失败。

对于同一域名的多个候选地址，阻断的地址被跳过，direct 连接失败后尝试下一个候选并重新匹配路由；若 VLESS 在发送请求前解析或连接上游失败，继续按规则尝试其他候选；请求开始发送后失败则结束会话，避免重复提交。系统解析器的查询可能无法中断，停止可能需要等待它返回。

经 VLESS/TLS 的普通 HTTP 关闭定界响应会改写为 chunked，仅在收到认证的 TLS 关闭后发送终止块；TLS 异常中断时客户端可识别正文截断。直连的关闭定界响应仍依赖连接关闭，无法区分上游正常结束和异常截断。

其余主配置文件为**未实现的配置结构草案**，没有真实凭据、证书或可连接服务器。

## Trojan 成对实验配置

[trojan/client.kdl](trojan/client.kdl) 与 [trojan/server.kdl](trojan/server.kdl) 对应 `trojan` feature 的 TCP/UDP 入出站。两程序在本机分别监听 SOCKS5 `127.0.0.1:1080` 和 Trojan/TLS `127.0.0.1:2443`；须提供相同的私有密码文件、含 `localhost` SAN 的证书与对应私钥。客户端信任该证书，所有文件均按示例绝对路径读取，不会自动生成。协议、DNS/规则与 detour 的实际验证和保留限制见 [配置规范](../spec.md#实验性-trojan-tcpudp) 与 [支持矩阵](../../planning/proxy-kernel-support-matrix.md)。

## 网络 worker

可在主配置顶层加入 `workers 2`，范围为 1–16，省略时为 1。单 worker 由调用方线程运行；多 worker 在 Linux 上各用一个事件循环和监听器，每个入站的各 worker 共享该入站的 64 会话上限；不同入站分别计数。系统 DNS 的阻塞线程池按入站和 worker 分配，增加 worker 也会增加潜在后台线程。多 worker VLESS 在 `--crypto=y` 下可用；该能力仍为实验性，详见[并发架构](../../architecture/concurrency.md)。

## SOCKS5 用户名密码

SOCKS5 入站的 `authentication "none"` 可以改成：

```kdl
authentication "password" username="alice" password-file="/absolute/path/to/password"
```

密码文件必须是当前有效用户拥有的普通文件，禁止最终路径符号链接和组/其他用户访问；文件内容为 1–255 个可打印 ASCII 字节，可带一个末尾换行。用户名同样限 1–255 个可打印 ASCII 字节。服务只在启动时读取，修改后需重启；错误会阻止监听。父目录必须由可信用户控制，检查不会阻止可信属主并发改写文件。密码不会被写入配置诊断；明文 RFC 1929 不提供传输加密。当前只允许回环 SOCKS5 使用该配置，Mixed 会拒绝密码配置以免 HTTP 路径绕过认证。

## 成对 client/server 草案

- [paired/client.kdl](paired/client.kdl)：本机 Mixed 和双栈 TUN，DNS/Fake-IP，有序规则、selector、VLESS/TLS 出站与原生控制面。
- [paired/server.kdl](paired/server.kdl)：对应的 VLESS/TLS 入站、受限制 direct 出站与规则。
- [阻断谓词集合](paired/rules/blocked.kdl)、[私网谓词集合](paired/rules/private.kdl)：作为主配置有序规则的一项引用。

拟定路径为应用 → Mixed/TUN → 根据规则选择 `preferred`（初始为 `edge`）→ VLESS/TLS → server → direct 目标；拒绝规则和私网直连规则先于默认出口。域名经 Fake-IP 反查或显式代理地址传给路由，完整机制见[配置规范](../spec.md)。selector 可由获授权的原生 API 修改；选中 `direct` 会改变业务路径。

部署者未来须自行提供并验证以下内容：

- `edge.example.net`、`*.example` 是文档域名，`192.0.2.53/54` 是文档地址，须替换成实际可达、受信的节点和 DNS。IPv4/IPv6 TUN 与 Fake-IP 网段只是示例，须为本地环境选取互不冲突的范围；生成适合实际部署的 ULA。
- client 的 `edge.uuid` 与 server 的 `client-1.uuid` 文件应含相同 UUID；server 证书及私钥对应 client 的验证名与信任锚。所有密钥、证书和控制 token 都须由部署者生成、保护和分发；仓库没有提供任何示例秘密文件。
- client 的 DNS listener 是 `127.0.0.1:1053`，不会自动接管宿主 DNS。须由受控的宿主集成显式设置 DNS 转发，验证 TCP/UDP、回退、资源恢复与自身查询绕行；TUN 默认路由不表示 DNS 自动生效。
- server 的目标拒绝列表只是示例，不覆盖所有特殊网络或组织策略；需对直接地址与解析出的每个候选地址执行实际授权检查。client 和 server 的 UDP、IPv6、访问控制和系统权限须分别测试。
- `allow-origin`、UID、端口、路径、MTU、路由及所有文件权限须按环境检查；操作系统、进程与监督者同时失败时不能保证自动恢复。

字段语义、校验、WireGuard/WARP、SS-2022 和 Hysteria 2 片段见[配置规范草案](../spec.md)。这些成对配置尚不能运行，不应将其用于生产。

## 最初的静态转发结构

[client.kdl](client.kdl) 与 [server.kdl](server.kdl) 只演示 `tcp-forward`、`direct` 和默认路由；两者不是具有协议握手或认证的一组端到端配置，保留为早期结构参考。

启用 `--crypto=y` 时，回环 VLESS/TLS 入站可配置为：

```kdl
inbounds { vless "edge" {
    listen host="127.0.0.1" port=8443
    authentication { user "client" uuid-file="/etc/nexus/client.uuid"; }
    tls { certificate-file "/etc/nexus/server.pem"; private-key-file "/etc/nexus/server-key.pem"; }
} }
outbounds { direct "direct"; }
routing { default-outbound "direct"; }
```

配置还须包含 `schema-version 1` 和 `role "server"`。证书文件可为单个 DER 叶证书，或以叶证书开头、按发送顺序排列的 PEM 证书链（最多 16 个证书）；编码后的证书列表总长最多 1 MiB，每张证书的编码额外占 5 字节。私钥为未加密 DER 或 PEM，格式可分别选择。服务端检查叶证书与私钥匹配，但不校验证书链的签名、顺序、名称或有效期；配置者须提供正确的证书链。私钥及 UUID 文件须由当前用户拥有、权限不授予组或其他用户，且最终组件不能是符号链接。服务端支持 X25519 和 X25519MLKEM768 及其 HelloRetryRequest；当前不支持 cookie、ALPN、PSK 或 UDP。

## SS-2022 TCP 出站实验

启用 `--crypto=y --ss2022=y` 后，可将默认路由指向 SS-2022 节点：

```kdl
schema-version 1
role "client"
inbounds { socks5 "local" { listen host="127.0.0.1" port=1080; authentication "none"; } }
outbounds {
    direct "direct"
    shadowsocks "edge" {
        server host="127.0.0.1" port=8388
        method "2022-blake3-aes-128-gcm"
        key-file "/etc/nexus/ss2022.key"
    }
}
routing { default-outbound "edge"; }
```

方法也支持 `2022-blake3-aes-256-gcm`。密钥文件须分别包含 16 或 32 字节 PSK 的标准带填充 Base64，可带一个末尾换行；须为当前用户拥有的私有常规文件，最终路径组件不能是符号链接。节点域名默认使用系统解析；可在出站中添加 `bootstrap-resolver "boot"`，引用 `dns` 配置中的命名解析器，失败时不回退系统解析。此选项要求节点为域名。代理目标域名先经目标 DNS 解析，逐个地址匹配路由，选中的数字地址发给 SS 节点；域名阻断可在解析前生效。当前仅 TCP 出站；独立对端测试覆盖短数据、8 条并发连接的双向 2 MiB 传输和活动会话停止。特定内核背压、异常注入及更多取消时序仍需验证。

## SS-2022 入站实验

启用 `--crypto=y --ss2022=y` 后，可配置单用户入站：

```kdl
schema-version 1
role "server"
inbounds {
    shadowsocks "ss-in" {
        listen host="127.0.0.1" port=8388
        method "2022-blake3-aes-128-gcm"
        key-file "/etc/nexus/ss2022.key"
    }
}
outbounds { direct "direct"; }
routing { default-outbound "direct"; }
```

也支持 `2022-blake3-aes-256-gcm`，密钥文件格式和权限要求与出站相同。入站只监听回环地址，支持单用户 TCP 和 UDP。TCP 按现有路由策略处理目标，也可将默认路由指向 SS-2022 出站；四种 AES 入站和出站组合已通过独立对端链路测试。UDP 支持 direct 和 block，选中其他出站时拒绝，不会降级为 direct；SS-2022 UDP 出站尚未实现。相同密钥的监听器和 worker 在同一进程内共享各自协议的重放状态，但进程重启后记录丢失，不同进程之间也不共享；不要让多个进程使用同一密钥并依赖完整的重放保护。独立对端互通测试覆盖两种算法、TCP 1/2 worker、8 路双向 2 MiB、IP 阻断、活动会话停止及 UDP 并发回环。直接 SS-2022 客户端先半关闭发送方向后，目标仍可回送响应；部分外部 SOCKS 到 SS-2022 路径会提前返回 EOF。特定内核背压和更多取消时序仍需按场景验证。
