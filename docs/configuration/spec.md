# Nexus KDL 配置规范草案

状态：本文完整主配置字段和语义为设计草案；实验代理已实现[有限的 KDL 子集](examples/README.md)，其余节点会拒绝。独立谓词规则集已有有限实现；KDL 2.0 与指定 Glaze 分支是已确定的技术方向，主配置 schema 与默认值尚未冻结。本文定义足以审阅[成对示例](examples/paired/client.kdl)的配置形态，并给出其他协议的字段位置；不能把它当成当前程序的使用手册。

## 文档、名称与加载

主文件包含一个 `schema-version 1`、一个 `role "client"` 或 `role "server"`。`logging`、`dns`、`routing`、`control` 最多各一个；`inbounds`、`outbounds` 分别包含可重复的 `inbound`、`outbound`；`endpoint` 可重复，第一位置参数为非空名称，分组内使用类型名作为节点名，例如 `socks5 "local"`、`direct "direct"`；DNS `servers` 同样使用 `udp` 等类型名。规则放在 `rules` 块中，以 `-` 为每条规则的节点名。旧 `inbound`/`outbound`/`server` 加 `type` 和直接 `rule` 写法暂兼容。名称在同一类内唯一；出站与可作为出口使用的 endpoint 在出口引用命名空间内也不得重复。tag 精确匹配，不做环境变量或通配展开。

节点的单值子项只能出现一次，列表项（`address`、`member`、`rule`、`deny-cidr` 等）按文档顺序保留；对必须字段、未知节点/属性、非法类型、重复单值及悬空引用报错。KDL 属性按语言规范后写覆盖，若需要拒绝重复属性须先验证 Glaze 是否保留足够的原始信息，不能声称已能检查。仅下文明确的默认值可省略；其余缺失项的默认值待决定，示例尽量显式写出。

后续设计 `http-clients` 时，其每个子节点的节点名直接作为该 HTTP 客户端的 tag，例如 `http-clients { updates { ... } }` 中的 tag 是 `updates`。字段及生命周期候选见[具名 HTTP 客户端设计](../architecture/http-clients.md)；当前配置解析器不支持此节点。

先解析整份 KDL，再校验类型、引用、能力、地址和协议组合、依赖环与权限需求；构造候选时读取证书和凭据并检查。成功后才准备及接入网络资源。重载的具体事务边界、失败恢复和网络租约按[路由](../architecture/routing-engine.md)、[TUN](../platform/tun-routing-and-loopback.md)与[控制面](../architecture/control-api.md)约束实施；未经验证不能保证全系统操作原子化。规则文件相对路径相对于引用它的主配置所在目录，绝对路径保持绝对；不以当前工作目录解释。示例要求凭据/证书使用绝对路径。

配置、规则、证书与密钥都有各自字节、条目和嵌套上限。受保护文件的读取须校验文件类型、所属和权限，以打开的句柄读取并处理替换竞态；失败不得回退空密钥、关闭校验或转为无认证。密钥不写入日志、API、崩溃报告或规则集。`*-file` 指一个文件中的实际值，不是占位符展开：UUID 文件为 UTF-8 规范 UUID 文本，可有一个末尾换行；密码/token 为约定的 UTF-8 单行值，拒绝额外行、NUL 与空值；WireGuard 密钥为协议要求长度的 base64 值；证书和私钥为 PEM。具体读取权限和轮换生效时机需以实际实现验证。

## 部署角色与协议

| 节点 | 草案字段及语义 |
| --- | --- |
| `inbound ... type="mixed"` | `listen host=... port=...`；`authentication "none"` 仅用于显式可信的回环监听；`udp-associate` 指 SOCKS5 UDP 关联能力。远程监听必须明确认证和访问控制，认证子项细节待定 |
| `inbound ... type="tun"` | `device name=... mtu=...`、多个 CIDR `address`、`auto-route`、多个 `route-include`、`strict-bypass`；`sniff` 的 `enabled`、字节/毫秒预算及 `target-mode "metadata-only"`。自动接管和防环回须按平台实际创建资源，禁止降级成静默回环 |
| `outbound ... type="vless"` | `server host=... port=...`、`bootstrap-resolver`、`authentication { uuid-file ... }`、`tls`。TLS `server-name` 为验证名和 SNI、`ca-file` 为信任锚、`verify #true` 启用身份校验；`key-exchange` 可选 `x25519`、`x25519-mlkem768`（允许回退到 X25519）或 `x25519-mlkem768-only`（不通告 X25519）；端口/拨号名和验证名各自独立 |
| `inbound ... type="vless"` | `listen`、`authentication` 中的多个 `user name uuid-file=...`、TLS `certificate-file` 与 `private-key-file`。server 证书须匹配 client 验证名并链到其信任锚；两个 UUID 文件的内容须相同 |
| `outbound ... type="direct"` / `"block"` | 前者经平台保护的连接器直接连接目标，后者拒绝流与数据报；server 示例用 `destination-policy` 限制可连接 IP |
| `outbound ... type="selector"` | 多个 `member` 和初始 `selected`；成员存在、能力适配且不形成依赖环。控制面修改仅影响之后的路由决策；选择 direct 会直接发送业务流量 |

示例只描述普通 TLS 承载的 VLESS，不隐含 Reality 或 Vision。UUID 是身份标识而不是 TLS 的替代品。认证失败、证书不匹配、端口冲突或未编译的协议均应失败。Mixed 的明文无认证仅限本机信任边界，[SOCKS5/UDP 关联](../architecture/protocols/socks5-mixed.md)仍须限制资源和来源。

`destination-policy { deny-cidr ... }` 对直接提供的 IP 和域名解析产生的**每个候选地址**在拨号/发包前检查；禁止的候选不能因先通过域名规则而使用，重解析后重新检查。示例仅列出部分常见私网、回环和特殊地址，不构成完整的服务端访问控制策略；实际部署应根据网络、元数据服务、NAT64/IPv4-mapped IPv6、特殊地址和授权目的地建立完整策略。解析器自身访问与代理用户目标的信任边界应分别配置并验证。

此策略约束经过该 `direct` 出口的连接，包括示例 DNS resolver 的上游连接。若上游位于被拒绝的私网，应为该固定用途设计独立且受限的直连出口，不能为使 DNS 工作而放宽代理用户的目标限制；所需用途隔离须经过实现和验证。

## DNS、Fake-IP 与 TUN

已实现的具名 DNS 服务器写在 `dns { servers { server ... } }` 中，具体字段和兼容性见[配置示例](examples/README.md)。

`dns` 中的 `resolver name type="udp"` 包含 IP 字面量 `server host=... port=...` 和明确的 `outbound`；主 `default-resolver` 给普通解析，`bootstrap-resolver` 专门用于节点名解析。此处 UDP 是示例选择，不表示其加密；业务 DNS 和 bootstrap 通过 direct 出口会向相应上游暴露查询。解析器依赖自身、selector、代理节点的循环须拒绝；出站 socket 必须执行相应 TUN 绕行策略。

`fake-ip` 的 `ipv4-pool`、`ipv6-pool`、`ttl-seconds`、`recovery "quarantine"`、`pool-full "servfail"` 明确池满失败和弱持久恢复方案。该方案在不确定的恢复状态下隔离地址，不保证每个曾应答的映射都能恢复；隔离期不短于配置允许的最大对外 TTL 加传播/时钟缓冲。普通 DNS 缓存与 Fake-IP 分开。`listener` 的 `mode "fake-ip"` 对允许的 A/AAAA 生成映射，其他类型走指定 `resolver`；内部 bootstrap 和直接出站真正解析不能进入 Fake-IP。DNSSEC、直连上游、分视图与原始目标语义见[DNS](../architecture/dns.md)和[Fake-IP](../architecture/dns-fakeip-engine.md)。

连接目标为池内地址时先反查，失败则拒绝；成功时使用映射域名匹配路由并固定 lease。不能把原始 Fake-IP 当普通目标 IP 去匹配私网规则或直接发送；direct 需在正确视图重新解析真实地址，再按访问策略逐个检查。普通真实 IP 请求和嗅探域名各保留来源；嗅探只提供不可信元数据，`metadata-only` 不重写报文或自动替换真实 IP。

样例的 `listener` 监听 `127.0.0.1:1053`，**不会自动修改宿主 DNS，也不会拦截所有 53 端口流量**。要由宿主应用使用 Fake-IP，需由宿主 DNS 管理器/受控重定向明确转发到此非 53 端口，同时覆盖 TCP 与 UDP，避免把 Nexus 自身上游查询重新劫持；端口、回退和恢复需平台集成验证。仅启动 TUN 不等于 DNS 已接管。

`auto-route #true` 配合双栈默认 `route-include` 提出全局捕获意图，`strict-bypass #true` 要求受保护的 socket 及平台策略满足[防环回](../platform/tun-routing-and-loopback.md)，不能只排除一次 DNS 解析得到的节点 IP。TUN 地址、Fake-IP 池须与物理网络、VPN、容器和其他实例不冲突；切换网络时重新验证。系统能力、权限或安全保护不满足时应中止接管并按平台回滚，不保证操作系统、进程及监督者同时失败时自动恢复。

## 规则与热重载

`routing` 的 `rule-set name path=... format="kdl"` 引入独立规则源；`format="beve"` 对应版本化 BEVE 容器。示例使用 `kind "predicate"` 的规则集：重复 `rule type=... value=...` 为任一匹配即成员，支持的示例谓词为 `domain-suffix` 与 `ip-cidr`，不在集合内部携带出口动作。独立规则组件已支持该子集及互转，实验代理支持多个有序规则集引用，命中动作可选 direct、block 或具名 VLESS，默认可选 direct 或具名 VLESS；最多支持 16 个 VLESS 实例。主规则 `rule kind="rule-set" value=... outbound=...` 把集合放到一条有序规则的位置，首次命中执行出口；都不匹配时用 `default-outbound`。未来含动作/逻辑的规则类型须独立定义；KDL↔BEVE 保留当前规则顺序和行为，不保留注释排版。

实验代理对域名先尝试确定阻断，再解析并对每个候选地址结合域名按规则顺序匹配；这会使 IP 谓词匹配解析结果。以下是未来设计：域名条件依来源使用显式代理域名、Fake-IP 反查或受策略约束的嗅探结果；不存在信息时按规则引擎的 unknown/不匹配策略处理，禁止以字段分类索引改变全局首命中顺序。重载规则集先完整验证及构建不可变快照，失败留在旧代；已有会话保持创建时决策。[规则集转换](rule-sets.md)、[路由引擎](../architecture/routing-engine.md)。

## 控制面

`control` 省略即关闭。`http.listen`、`read-token-file` 和 `manage-token-file` 分别建立只读与管理身份；本示例管理身份具有读取、selector 切换、终止会话及重载权限，细粒度 scope 及 token 轮换待实现。`allow-origin` 为精确 origin，可重复；`allow-no-origin` 单独控制 CLI。监听非回环需显式配置 TLS、授权和网络访问限制；示例只监听本机。`ipc.path` 是 Unix stream socket，`max-frame-bytes` 限制 BEVE payload，`read-uid`/`manage-uid` 是允许的本机账户；管理身份包含读取权限。Windows 使用 named pipe/SID 时的节点待独立设计。API 路由、帧格式和授权细节见[原生控制面](../architecture/control-api.md)。

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

```kdl
// 单用户 SS-2022 客户端/服务端片段，密钥文件内容须一致
outbound "ss" type="shadowsocks-2022" {
    server host="ss.example.net" port=8388
    bootstrap-resolver "bootstrap"
    method "2022-blake3-aes-256-gcm"
    key-file "/etc/nexus/secrets/ss.key"
}
inbound "ss-in" type="shadowsocks-2022" {
    listen host="0.0.0.0" port=8388
    method "2022-blake3-aes-256-gcm"
    key-file "/etc/nexus/secrets/ss.key"
}
```

以上为两个角色各自的片段，监听须分别打开 TCP 和 UDP。所示方法的文件须包含安全随机生成、base64 编码的 32 字节 PSK，而非任意密码；EIH 多用户配置需另行规定。BLAKE3 实现来源、所需密码原语及互操作尚待验证，参见 [SS-2022](../architecture/protocols/vless-trojan-ss.md)。

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
    congestion "cubic"
}

// 服务端片段：对应认证与证书内容由部署者提供
inbound "hy2-in" type="hysteria2" {
    listen host="0.0.0.0" port=443
    authentication { password-file "/etc/nexus/secrets/hy2.password"; }
    tls {
        certificate-file "/etc/nexus/tls/hy-fullchain.pem"
        private-key-file "/etc/nexus/tls/hy-private.pem"
    }
    congestion "cubic"
}
```

Hysteria 2 需要 UDP 可达、TLS 1.3/HTTP3、QUIC DATAGRAM 与双方相同认证；传输速率参数的单位和 0/auto 语义需遵守[协议设计](../architecture/protocols/hysteria2.md)。`cubic` 是普通算法目标，Brutal、端口跳跃和混淆均需单独配置/验证，示例不表示已实现。自研 TLS 对 ngtcp2/nghttp3 的接入仍是候选验证，不自动添加 libssl。

## 验收

用指定 Glaze 分支验证 KDL 语法及动态文档映射，再用 Nexus 语义校验器验证每个示例、字段错误、重复项、未知项、协议能力和依赖环；KDL 语法成功不表示 schema 或部署有效。成对联调要实际提供密钥与证书，在隔离网络核对客户端 Mixed/TUN → VLESS/TLS → 服务端 → 目标，覆盖 TCP、UDP、DNS/Fake-IP、防回环、规则和失败恢复。示例中没有真实凭据或可部署服务器，不能在未经实现和集成测试前运行。
