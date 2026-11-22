# 第 93 批实现蓝图 · 路由与 DNS 高频增强

更新：2026-11-20。本蓝图将路由与 DNS 核心需求精确映射到 Nexus 源码文件、数据结构与双后端验收用例。

## 93A · 有序路由动作与协议嗅探增强

### 1. `resolve` 动作增加 `route-only`
- **问题**：当前有序规则执行 `resolve` 后，后续出站直接用解析得到的 IP 发起连接，导致远端代理服务器拿不到原始域名（无法做服务端分流或日志审计）。
- **源码改造点**：
  - `src/rules/rules.cppm` / `src/rules/program.cpp`：`ResolveAction` 增加 `bool route_only = false;`。
  - 行为契约：当 `route_only == true` 时，执行 DNS 解析并将解析出的 IP 列表写入后续规则匹配的 `candidates`（供后续 IP/CIDR/私有地址规则命中），但**不覆写会话发往代理出站的逻辑目标域名**；若最终命中的是 `direct` 出站，可直接复用已解析的候选 IP 避免重复查询。
  - `src/config/routing.hpp` + KDL 解析：支持 `action "resolve" route-only=#true`。
  - `src/tools/rule_explain.cpp`：输出 `resolve(route-only)` 动作标识。
- **验收**：双后端 SOCKS5/Mixed → Trojan/VLESS 链路实测：本地根据解析出的目标 IP 命中代理规则，同时远端代理服务端收到的目标地址仍为原始域名而非 IP。

### 2. 逻辑规则内联引用 `rule-set`
- **源码改造点**：
  - `src/rules/rules.cppm` / `src/rules/validate.cpp` / `src/rules/matcher.cpp`：允许 `all` / `any` / `not` 逻辑节点子节点包含 `rule-set "<tag>"` 引用，在规则编译期展开并共享已加载的 `RuleSet`（保留最大深度与节点总数预算，拒绝循环引用与未知 tag）。
- **验收**：KDL/BEVE 往返与双后端路由实测 `all { rule-set "corp"; not { port 443 } }` 精准命中与三态 `unknown` 传播。

### 3. `tls-ech` 嗅探谓词
- **现状优势**：`src/sniff/tls.cppm:82` 的 `TlsSniffer` 已解析扩展 `0xfe0d` 并输出 `TlsStep::ech_offered`！
- **关键语义约束**：**不要把 `Protocol::tls` 改成互斥的 `tls_ech`**，否则现有 `protocol "tls"` 规则会意外漏掉带 ECH 的 TLS 流量。
  - 在 `MatchInput`（`src/rules/rules.cppm`）增加 `std::optional<bool> tls_ech;`（同时支持 KDL 谓词 `tls-ech #true` 及 `protocol "tls-ech"` 语法糖：命中 `protocol == tls && tls_ech == true`，且 `protocol "tls"` 依然对两者均为真）。
  - 在 `src/sniff/route_tcp.cppm` 将 `TlsStep::ech_offered` 透传到路由上下文。
- **验收**：双后端真实 TLS 1.3 普通握手与携带 ECH（真实 ECH 与 GREASE ECH）握手对照验证：`protocol "tls-ech"` 仅命中 ECH，`protocol "tls"` 两者皆命中。

## 93B · Linux 透明入口 L3 元数据与 TUN Mark 过滤

### 1. L3 `dscp` 匹配
- **源码改造点**：
  - `src/rules/rules.cppm` / `matcher.cpp`：`MatchInput` 增加 `std::optional<std::uint8_t> dscp;`（有效范围 0–63），规则支持单值与列表匹配，缺失时返回三态 `unknown`。
  - Linux 数据源：
    - **routed TUN**（`src/packet/ipv4.cpp`, `src/packet/ipv6.cpp`, `src/tools/tun_host.cpp`）：直接从 IPv4 `TOS >> 2` 与 IPv6 `(byte0 & 0x0f) << 2 | (byte1 >> 6)` 读取真实 6-bit DSCP；
    - **TPROXY UDP**（`src/proxy/tproxy_udp.cpp`）：开启 `IP_RECVTOS` / `IPV6_RECVTCLASS` 读取控制消息；
    - 非透明普通入站（SOCKS5/HTTP）保持 `unknown`。

### 2. 源/网关 MAC 地址匹配
- **源码改造点**：
  - `src/platform/network_state.cpp`：通过 netlink `RTM_GETNEIGH` 缓存受限邻接表快照（IPv4/IPv6 → 6 字节 MAC，按网络代次刷新，有条目硬上限）。
  - `src/rules/rules.cppm`：`MatchInput` 增加 `std::optional<std::array<std::uint8_t,6>> source_mac, gateway_mac;`；规则支持 `source-mac` / `gateway-mac`（标准 `aa:bb:cc:dd:ee:ff` 规范化）。

### 3. Linux TUN `include-routing-mark` / `exclude-routing-mark` 与 `route-exclude-private`（对照 `#3277`, `#2858`）
- **源码改造点**：
  - `src/config/tun.cpp`、`src/packet/tun_default_policy.cppm`、`src/tools/tun_network_owner.cpp`：在独立网络所有者安装的 `ip rule` / 策略路由规则中支持显式排除或限定指定 fwmark，以及一键排除 RFC 1918 / RFC 6598 / ULA / Link-Local 私有前缀（依然受 `tun_network_owner` 的异常退出自动回滚保护）。

### 实施与验收

- DSCP 和 MAC 适用于 indexed 与有序路由。UDP TPROXY 在每个排队数据报上固定元数据，同一会话可按不同 DSCP 或新邻接代次重新分流，保留原有源/目标和会话计数。
- routed TUN 在首个 SYN 固定 TCP DSCP，UDP 逐包读取。IPv4 标记过滤在必要时对 TUN 临时使用 loose 反向路径检查，允许内核接收重新注入的无标记回包。策略使用自有 socket mark、私有前缀和排除标记优先，再按 include 筛选捕获。
- epoll 与 io_uring 均通过离线锁定优化构建和各 19 项验收。隔离双栈 netns 覆盖 TUN 本机 TCP/UDP、转发 UDP、TPROXY UDP 同一五元组切换 DSCP、邻接修改与恢复、内核绕行优先级、SIGKILL 零残留和重启。KDL/BEVE 互转和普通 SOCKS5/HTTP 三态匹配通过。证据保存在 `target/batch93b/`。

## 93C · DNS 拨号路由、响应压缩与防误劫持边界

### 1. 拨号侧域名解析走 DNS 规则策略
- **源码改造点**：`src/config/dependencies.cpp`、`src/tools/outbound_config.cpp`、`src/dns/`：允许出站 `domain-resolver` 指向具名 DNS 策略视图（而非仅限单个物理 upstream），在启动期沿用既有有向依赖环检测，拒绝拨号与解析互环。

### 2. UDP DNS 响应域名压缩
- **源码改造点**：`src/dns/message.cpp` 的 `encode_response()`：实现标准 RFC 1035 §4.1.4 名称压缩指针表（追踪已写入的 suffix offset `< 16384`，校验不构造回环），确保无 EDNS 客户端在长 CNAME 链下回复不超过 512 字节而不被错误截断为空。

### 3. 必测防御回归（前车之鉴）
- **单标签搜索域补全**（`#4006` / `#4619`）：核查 `local` 与 Tailscale 私域 DNS 对尾点与单标签主机名的搜索域拼接。
- **UDP 源端口复用防误劫持**（`#4199`）：`hijack-dns` 仅针对实际目的端口为 53（或被 DNS 规则显式拦截的包）逐包校验，不把同一客户端源端口发往其他目标的 STUN 包黏连到已劫持的 DNS 会话。
- **UDP 逐目标路由防首包绕过**（`#2991`）：核查 SOCKS5 UDP / TUN UDP 同一关联切换新目的地址/端口时，均重新执行目标路由策略而不复用首包放行结论。

## 93D · Linux 原生 nftables 与 TUN `auto-redirect`

- **定位与动机**：当前 Linux TUN 在 `auto-route` / `strict-route` 下由自研用户态 TCP/UDP 栈承接流量；在不需要用户态 L3/L4 协议栈的场景（或需要跑满内核 TCP 协议栈吞吐/GSO/BBR 时），直接通过内核 nftables 将本机及转发的 TCP 流量零用户态 TCP 栈重定向到既有透明入站（`redirect` / `tproxy`），是 Linux 桌面、软路由与容器网关的核心体验。
- **架构与零外部依赖约束**：
  - 新增无前缀模块 `platform.nftables`（`src/platform/nftables.cppm` 与配套实现，直接走 Linux `NETLINK_NETFILTER` / `nf_tables` 事务批量消息 `NFNL_MSG_BATCH_BEGIN` → `NFT_MSG_NEWTABLE` / `NEWCHAIN` / `NEWSET` / `NEWRULE` → `NFNL_MSG_BATCH_END`），**严禁 shell 调用 `nft`/`iptables` 二进制，也不引入 `libnftnl` 外部依赖**。
  - **独立表与原子生命周期**：所有规则全部装入 Nexus 独占的 `inet` 表（例如 `inet nexus_auto_redirect_<id>`，按实例隔离、绝不修改宿主机已有 `filter`/`nat` 表）。
  - **托管在 `StrictTunOwner` 独立网络所有者进程**（`src/tools/tun_network_owner.cpp`）：与 `ip rule` / `systemd-resolved` 策略一致，主进程即使被 `SIGKILL`，所有者子进程感知 `SOCK_SEQPACKET` 对端关闭后立即发送单个 `NFT_MSG_DELTABLE` 事务原子卸载整张表，杜绝宿主机断网或残留死规则。
- **数据面与配置契约**：
  - `src/config/tun.cpp` / `src/packet/tun_network_types.cppm`：TUN 入站新增 `auto-redirect`（默认 `#false`，要求同时开启 `auto-route=#true`）、可选 `auto-redirect-input-mark` / `auto-redirect-output-mark` / `auto-redirect-reset-mark` / `auto-redirect-nfqueue`（首期仅做 mark + redirect/tproxy，预留扩展位）。
  - **流量分流拓扑**：
    - **本机出站 TCP（`output` hook）**：跳过回环、跳过 Nexus 自身出站 `so_mark`（防环）、跳过 `route-exclude-private` / `route-exclude-address` 与 93B 的 `exclude-routing-mark` / `include-routing-mark`，将其余 TCP 流量直接 `redirect to :<internal-redirect-port>`，交由既有 `redirect` 透明 TCP 入站（`SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`）通过原生内核 TCP 栈接管。
    - **网关/LAN 转发 TCP（`prerouting` hook，路由转发场景）**：可选支持转发链重定向至同一透明 TCP 入站（或按需走 `tproxy`），UDP 与 ICMP/非 TCP 流量按策略继续走 TUN 或可选 TPROXY UDP 入站。
    - **DNS 劫持与 FakeIP 协同**：对命中 FakeIP 网段或 53 端口的 TCP/UDP 流量保持与 `hijack-dns` / TUN 路由一致，避免 DNS 绕过或回环。
    - **不支持或内核缺 `nf_tables` 模块时**：启动期明确报错（`auto-redirect` 显式开启不静默降级），或在 `auto-redirect` 关闭时完全零开销、不触碰 netfilter。
- **验收**：
  - 隔离 netns 实测（双后端 `epoll` / `io_uring`）：
    - 开启 `auto-route=#true` + `auto-redirect=#true` 后，验证本机与转发 TCP 经内核 nftables 直接进入透明 TCP 接管链路并跑通代理与直连（且不经过用户态 TUN TCP 状态机，对比延迟/吞吐）；
    - 验证 Nexus 自身 `so_mark` 防环、`exclude-routing-mark` / `include-routing-mark`、私有网段排除及 FakeIP 兼容；
    - 故障注入：对主进程发送 `SIGKILL`，核验 `tun_network_owner` 在毫秒级内通过 `NFT_MSG_DELTABLE` 完全清除独占 `inet` 表，netns 内网络与既有 nftables 表零残留。

### 实施与验收

- `auto-redirect` 默认关闭，开启时隐式启用严格路由。首期复用 `socket-mark`、`include-routing-mark` 与 `exclude-routing-mark`，两条 NAT hook 使用内核原生 REDIRECT。转发入口按严格路由监控的本地目的前缀保留本机服务。配置与内核要求见[配置规范](../configuration/spec.md#linux-tun-原生-tcp-重定向)。
- epoll 与 io_uring 均通过离线锁定优化构建及各 15 项验收。真实双栈覆盖本机和转发 TCP 的直连及 HTTP CONNECT 出站、mark 与私有前缀、TCP/UDP DNS、FakeIP、UDP TUN、本地监听和本地路由变更。SIGKILL 故障注入在 18.1 / 15.7 ms 观察到自有表、规则、路由及设备回收，外部表保持完整。重启夹具单独验证网络所有者，未启用控制 socket。
- 同一隔离网段的小流量样本中，原生路径 TCP 建连中位数为 0.023–0.229 ms、回显速率为 86.6–752.0 MiB/s。用户态 TUN TCP 分别为 3.302–3.524 ms、6.5–8.2 MiB/s。各后端、地址族的原始样本和校验和见 `target/batch93d/`。
- TLS/HTTP 去前缀迁移通过两套构建图、旧名称全仓扫描和 TLS/ECH、HTTP CONNECT、HTTP/3 回归。
