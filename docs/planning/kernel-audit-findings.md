# Nexus Core 审计缺陷与修复跟踪

本文记录针对基线提交 `d10c429`（Round 1：`5 P1 + 2 P2`）与 `0e52ae8`（Round 2：`3 P1 + 4 P2`）的两轮内核专项审计发现，明确触发条件、影响范围、根因定位、修复设计与回归验收目标，配合源码修复与自动化单元测试同步闭环。

## 1. Round 1（基线 `d10c429`：5 P1 + 2 P2）

### 1.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `P1-1` | P1 | TUN 热重载 | 仅修改 `route-address-set` / `route-exclude-address-set` 引用文件时未同步系统路由 | 修复中 |
| `P1-2` | P1 | 全局路由模式 | `mode global <组名>` 手动切换策略组成员后新连接仍走旧成员 | 修复中 |
| `P1-3` | P1 | OpenVPN | 控制消息分段到达时 `pump_app_recv()` 空转至超时 | 修复中 |
| `P1-4` | P1 | OpenConnect DTLS | DTLS 1.3 `ClientHello` 不符合 RFC 9147 §5.3 版本与扩展规范 | 修复中 |
| `P1-5` | P1 | OpenConnect 数据面 | 严格 DTLS 模式（`dtls #true`, `dtls-fallback #false`）握手前仍经 CSTP 发包 | 修复中 |
| `P2-1` | P2 | 控制面日志订阅 | WebSocket（`/v1/ws`）与 SSE（`/v1/events/logs`）积压超 64 条时静默跳条 | 修复中 |
| `P2-2` | P2 | Tailscale MagicDNS | 增量 `MapResponse` 仅含 `Domain` 且省略 `DNSConfig` 时清空已有分域 DNS 配置 | 修复中 |

---

### 1.2 P1 级缺陷明细

#### P1-1 — TUN 规则文件热更新后系统路由未同步

- **触发与影响**：热重载期间仅更新 `route-address-set` 或 `route-exclude-address-set` 引用的外部规则文件而主配置未改动时，代理路由快照已切换，但操作系统 TUN 路由表仍停留在旧网段，导致新增或变更网段无法按新规则进入或绕过 TUN。
- **涉及模块**：`src/tools/proxy_tun_reload.cppm`、`src/tools/proxy_run.cppm`、`src/tools/tun_device_runtime.cppm`、`src/tools/route_files.cppm`、`src/tools/route_files_nxmm.cppm`。
- **根因**：热重载仅凭主配置标识/指纹决定是否下发系统路由；当主配置未变时直接跳过 `update_routes(...)`，未比较 `apply_tun_route_sets(...)` 展开后的实际 CIDR 集合。
- **修复设计**：发布新快照前对候选 TUN 配置展开规则集，将展开后的 `route_includes` 与 `route_excludes` CIDR 集合与当前已应用集合逐项比较；只要有差异就先执行 `update_routes(...)`，失败则中止重载并保持旧快照，成功后持久化最新已应用 CIDR 集合。
- **回归验收**：单元测试保持主配置不变、仅变更外部规则集文件，断言展开后的 CIDR 差异触发 `update_routes(...)`，且失败路径不发布不一致状态。

#### P1-2 — 全局模式下手动切换策略组后新连接仍走旧成员

- **触发与影响**：在 `mode global <组名>` 运行时，通过 UDS 或 HTTP 控制面（如 `POST /v1/groups/{tag}/select`、自动重置等）切换 selector 策略组活动成员后，新发起连接依然路由到切换前的旧成员。
- **涉及模块**：`src/tools/proxy_run.cppm`、`src/tools/proxy_control_operations.cppm`、`src/tools/proxy_mode.cppm`。
- **根因**：`route_mode` 缓存了 `global` 模式下目标策略组当前活动成员的出站索引；手动 `select` 或自动重置更新策略组快照后，部分控制路径遗漏调用 `route_mode.sync(reload_config)`。
- **修复设计**：检查所有会修改策略组成员状态的路径（手动切换、自动重置、UDS 与 HTTP 控制面入口），在快照发布成功后统一调用 `route_mode.sync(reload_config)` 同步缓存索引。
- **回归验收**：单元测试配置 `mode global <selector_group>`，在手动切换成员及执行 `reset_group_auto` 后立即校验解析出的出站索引指向新成员。

#### P1-3 — OpenVPN 控制消息分段时 `pump_app_recv()` 空转至超时

- **触发与影响**：OpenVPN 握手阶段服务端 `KeyMethod2` 响应或控制消息分片跨多个 TLS 记录到达时，客户端陷入忙等空转直至截止时间超时断连。
- **涉及模块**：`src/relay/openvpn_transport.cppm`、`src/relay/openvpn_outbound.cpp`。
- **根因**：首片明文不足以完成整帧解码时，调用方将残余字节留在 `app_plain` 中再次调用 `pump_app_recv()`；该函数以 `!app_plain.empty()` 立即返回，未继续从 TLS 通道读取后续明文。
- **修复设计**：在 `pump_app_recv()` 入口记录 `before = app_plain.size()`，循环读取直到本次调用实际追加了新字节（`app_plain.size() > before`）或遇到 EOF、错误或截止时间才返回。
- **回归验收**：单元测试将服务端 `KeyMethod2` 响应拆分为多段跨多个 TLS 记录投递，断言 `pump_app_recv()` 持续拉取后续分片并无空转完成解码。

#### P1-4 — OpenConnect DTLS 1.3 `ClientHello` 不符合 RFC 9147 §5.3

- **触发与影响**：OpenConnect 协商 DTLS 1.3 时发出的 `ClientHello` 报文格式违背 RFC 9147 §5.3，无法与标准 DTLS 1.3 服务端互操作。
- **涉及模块**：`src/openconnect/dtls.cppm`、`src/openconnect/dtls.cpp`、`src/openconnect/types.cppm`。
- **根因**：编码 DTLS 1.3 `ClientHello` 时将 `0xfefc` 直接写入 `legacy_version` 字段，且缺少 `supported_versions` 扩展（`0x002b`）。
- **修复设计**：遵循 RFC 9147 §5.3 将 `ClientHello.legacy_version` 编码为 `0xfefd`（DTLS 1.2），并添加 `supported_versions` 扩展（`0x002b`）通告 `0xfefc`（DTLS 1.3）；同步核对 `ServerHello` 编解码对 `legacy_version = 0xfefd` 与 `supported_versions = 0xfefc` 的处理及异常版本拒绝逻辑。
- **回归验收**：单元测试直接校验编码后原始线规字节中的 `legacy_version == 0xfefd` 及 `0x002b` 扩展携带 `0xfefc`，并经独立严格 RFC 9147 §5.3 校验逻辑验证握手互操作。

#### P1-5 — OpenConnect 严格 DTLS 模式握手前仍经 CSTP 发业务包

- **触发与影响**：配置 `dtls #true` 且 `dtls-fallback #false` 时，在 DTLS 握手尚未完成前到达的首批业务 IP 数据包仍被写入 CSTP 发送队列，破坏禁止 TCP 回退的安全与性能契约。
- **涉及模块**：`src/relay/openconnect_dtls.cppm`、`src/relay/openconnect_outbound.cpp`。
- **根因**：发送 DTLS `ClientHello` 后即标记出站通道就绪，且业务数据发送路径未在严格 DTLS 模式下阻断握手完成前的 CSTP 入队。
- **修复设计**：严格模式（`dtls && !dtls_fallback`）下，须等待 DTLS 握手成功完成（`dtls_ready`）后才开放出站数据通道；业务包发送路径同步执行同一策略，绝不允许未完成握手时向 CSTP 队列回退发包。
- **回归验收**：单元测试以 `dtls = true, dtls_fallback = false` 启动连接，断言仅发送 `ClientHello` 时数据通道未就绪、握手前发包不进入 CSTP 发送队列、握手完成后经 DTLS 正常收发。

### 1.3 P2 级缺陷明细

#### P2-1 — WebSocket 与 SSE 日志订阅在积压超 64 条时静默跳条

- **触发与影响**：客户端通过 `/v1/ws` 或 `/v1/events/logs` 持续拉取日志时，若积压未读条目超过单次批大小 64 条（例如 100 条），第 1 批交付 `1..64` 后游标直接越过剩余未交付条目，导致 `65..100` 静默丢失。
- **涉及模块**：`src/control_api/http_ws.cppm`、`src/control_api/http_stream.cppm`、`src/control_api/http_format.cppm`。
- **根因**：单次轮询使用 `logs since=<cursor> limit=64`，但更新 `peer.log_cursor`（WS）与 `peer.stream_cursor`（SSE）时误用了日志环全局 `parsed.latest_seq`，而非本批实际交付的最后一条日志序号。
- **修复设计**：返回批次非空时，游标严格推进至本批最后一条交付条目的 `seq`；仅在返回批次为空（所有新增条目均已被过滤或因环覆盖淘汰）时才安全推进到全局最新序号边界。
- **回归验收**：单元测试生成 100 条未淘汰日志并通过 WS 与 SSE 订阅路径连续拉取：断言第 1 批返回 `1..64` 且游标推进至 `64`，第 2 批完整返回 `65..100` 且零漏条。

#### P2-2 — Tailscale 增量 Map 更新省略 `DNSConfig` 时清空已有分域 DNS 配置

- **触发与影响**：当控制面下发仅含 `Domain` 且省略 `DNSConfig` 的增量 `MapResponse` 时，既有上游解析器 `Resolvers`、分域路由 `Routes`、搜索域 `Domains` 与 `Proxied` 标志全部被清空，造成内网分域解析中断。
- **涉及模块**：`src/tailscale/magic_dns.cppm`、`src/tailscale/magic_dns.cpp`、`src/tailscale/map_session.cppm`。
- **根因**：`parse_dns_config` 在 `DNSConfig` 为 `Presence::absent` 且 `Domain` 为 `Presence::value` 时构造空 `DnsConfig` 仅填充域名后缀，随后直接整份替换已存 `dns_config_`。
- **修复设计**：按 JSON 字段存在性（`Presence::absent` / `Presence::null_value` / `Presence::value`）增量合并：`DNSConfig` 缺省而 `Domain` 存在时保留既有解析器、分域路由、搜索域与 `Proxied` 仅更新域名；`DNSConfig` 显式为 `null` 时按协议语义清空；`DNSConfig` 为有效对象时应用新配置并准确合并 `Domain`。
- **回归验收**：单元测试先应用包含完整 `Resolvers`、分域 `Routes`、`Domains` 与 `Proxied: true` 的初始 `MapResponse`，再应用仅含 `Domain` 的增量更新，断言上述分域配置完整保留且域名正确更新。

---

## 2. Round 2（基线 `0e52ae8`：3 P1 + 4 P2）

### 2.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R2 P1-1` | P1 | DNS 消息缓存与热重载 | 配置 `message-cache-directory` 后 DNS 监听器忽略规则文件热更新 | 修复中 |
| `R2 P1-2` | P1 | `fixed-udp` 直连出站 | `fixed-udp` 直连出口忽略 `udp-bind-port`、源地址与接口等 socket 绑定配置 | 修复中 |
| `R2 P1-3` | P1 | 加密 DNS 统一磁盘缓存 | 使用系统 CA（省略 `ca-file`）组合 `state.cache-directory` 阻止启动 | 修复中 |
| `R2 P2-1` | P2 | DNS 缓存清理与持久化 | 在线 `clear-cache dns` 后同一监听器的新查询无法再持久化落盘 | 修复中 |
| `R2 P2-2` | P2 | `fixed-udp` 零长数据报 | `fixed-udp` 入口丢弃合法 0 字节数据报，反向路径将 0 字节应答误判为 EOF | 修复中 |
| `R2 P2-3` | P2 | 路由模式持久化回报 | 状态目录 `fsync` 失败致持久性未确认时控制命令仍返回成功（退出码 `0`） | 修复中 |
| `R2 P2-4` | P2 | mDNS 转发 | mDNS 转发将所有 A/AAAA 记录 TTL 写死 `60` 秒，且返回 `TTL = 0` 撤销记录 | 修复中 |

### 2.2 P1 级缺陷明细

#### R2 P1-1 — 配置 `message-cache-directory` 后 DNS 监听器忽略规则文件热更新

- **触发与影响**：启用 `message-cache-directory` 后热更新 DNS 规则文件，运行中的 DNS 监听器新查询仍继续按旧上游解析，直至进程重启。
- **涉及模块**：`src/tools/dns_message_runtime.cpp`、`src/tools/dns_cache_state.cppm`、`src/tools/dns_cache_unified.cppm`。
- **根因**：`src/tools/dns_message_runtime.cpp` 在 `program->cache_scope` 存在时跳过读取 `program->rules()` 快照，直接回退空规则快照。
- **修复设计**：无论是否启用磁盘缓存都持续读取最新 `program->rules()` 快照，并使消息缓存键包含规则代次与视图隔离维度，防止规则热更新后跨代次命中过期缓存。
- **回归验收**：单元测试启用 `message-cache-directory` 并热切换规则快照指向新上游，验证后续查询立即按新规则命中新上游且不串联旧规则缓存。

#### R2 P1-2 — `fixed-udp` 直连出口忽略 socket 绑定配置

- **触发与影响**：在 `fixed-udp` 模式下为直连出口配置 `udp-bind-port`、指定源地址、绑定网卡或标记等选项时，实际发包仍从通配地址与随机端口 `0` 发出。
- **涉及模块**：`src/relay/fixed_udp_inbound.cpp`。
- **根因**：`fixed-udp` 直连上游建连时直接绑定通配地址和端口 `0`，未复用普通直连 UDP 出站的 `SocketBinding` 绑定逻辑。
- **修复设计**：复用普通 UDP 直连出站的 socket 绑定流程，完整应用 `udp-bind-port`、源地址、网络接口、路由标记等绑定参数。
- **回归验收**：环回单元测试为 `fixed-udp` 直连出口配置 `udp-bind-port`（及源地址绑定），断言对端收到的 UDP 数据报源端口与配置一致。

#### R2 P1-3 — 使用系统 CA 的加密 DNS 组合 `state.cache-directory` 阻止启动

- **触发与影响**：配置 DoT/DoH/DoQ/DoH3 等加密 DNS 上游且省略 `ca-file`（使用系统信任库），同时开启 `state.cache-directory` 时，进程在初始化统一磁盘缓存身份阶段报错退出。
- **涉及模块**：`src/tools/dns_cache_unified.cppm`、`src/tools/dns_cache_state.cppm`。
- **根因**：计算缓存身份摘要时无条件把空字符串 `server.upstream->tls->ca_file` 当作普通文件路径调用 `read_regular_file(...)` 读取而触发 I/O 错误。
- **修复设计**：当 `ca_file` 为空时不再按文件路径读取，改用实际加载的系统信任库摘要或明确的系统 CA 规范标识参与缓存身份哈希，并与自定义 `ca-file` 严格区分。
- **回归验收**：单元测试以空 `ca_file`（系统 CA）加密 DNS 组合 `state.cache-directory` 启动统一缓存，断言初始化成功且缓存身份与自定义 `ca-file` 区分清晰。

### 2.3 P2 级缺陷明细

#### R2 P2-1 — 在线 `clear-cache dns` 后同一监听器的新查询无法再持久化

- **触发与影响**：在线执行 `clear-cache dns` 之后，同一运行中 DNS 监听器后续产生的新解析结果无法再次持久化到磁盘，优雅关闭后目录仅剩 `epoch.state`。
- **涉及模块**：`src/tools/dns_cache_unified.cppm`、`src/tools/dns_cache_state.cppm`、`src/tools/dns_message_runtime.cpp`。
- **根因**：写入器永久持有启动时读取的 `clear_epoch`；`clear-cache dns` 推进 `epoch.state` 后，后续每次落盘返回 `state::Stage::stale_epoch` 且被上层按成功静默忽略。
- **修复设计**：继续拒绝清除前在途旧代次写入，同时在清除完成或新查询写入周期同步刷新运行中监听器的有效代次，使清除后的新解析条目以新代次正常落盘。
- **回归验收**：单元测试填充缓存后执行 `clear-cache dns`，断言清除前旧写入因 `stale_epoch` 被拒，而随后新查询在刷盘关闭后正确持久化于新代次文件。

#### R2 P2-2 — `fixed-udp` 丢弃合法零长度数据报

- **触发与影响**：经 `fixed-udp` 转发合法的 0 字节 UDP 载荷时，入站方向直接丢弃；反向收到 0 字节 UDP 应答时误判为连接关闭（EOF）并取消整个 UDP 流。
- **涉及模块**：`src/relay/fixed_udp_inbound.cpp`。
- **根因**：入口过滤 `len == 0` 载荷，且反向 `recv_from` 路径把无错误的 `n == 0` 应答等同于 EOF 触发流终止。
- **修复设计**：严格以错误码/取消状态区分流终止与成功接收的 0 字节数据报，在入站与反向出站双向完整转发合法 0 字节 UDP 数据报。
- **回归验收**：环回单元测试依次经 `fixed-udp` 发送普通包、0 字节请求并接收 0 字节应答，断言双向零长数据报均完整到达且后续普通数据报仍可正常通信。

#### R2 P2-3 — 路由模式持久化未确认时控制命令仍返回成功

- **触发与影响**：当状态目录 `fsync` 返回 `EIO` 导致文件虽可见但持久性未确认时，控制面执行路由模式切换仍返回成功（退出码 `0`），隐藏掉电回滚风险。
- **涉及模块**：`src/tools/proxy_mode.cppm`、`src/tools/selector_state.cpp`、`src/tools/proxy_control_operations.cppm`、`src/tools/proxy_run.cppm`。
- **根因**：`SelectorState::save_route_mode(...)` 返回 `std::expected<bool, ...>` 中值为 `false` 表示持久性未确认，而 `proxy_mode.cppm` 仅检查 `!saved` 错误态，忽略了 `*saved == false`。
- **修复设计**：保持内存中已生效的新运行模式不回滚，同时在 `saved.has_value() && !*saved` 时向 UDS 与 HTTP 控制面调用方显式返回持久化未确认错误/非零状态，与策略组持久化语义保持一致。
- **回归验收**：单元测试模拟 `save_route_mode` 返回 `false`，断言内存运行模式已切换生效且控制面调用明确返回持久化未确认错误而非静默成功。

#### R2 P2-4 — mDNS 转发把所有 A/AAAA 记录 TTL 写死 `60` 秒

- **触发与影响**：mDNS 转发生成的标准 DNS 响应忽略上游实际 TTL 并统一写死 `60` 秒；同时把 RFC 6762 §10.1 定义的 `TTL = 0` 撤销（goodbye）记录当作有效地址返回。
- **涉及模块**：`src/tools/dns_mdns_transport.cpp`。
- **根因**：`build_mdns_standard_response(...)` 在构造 `A` / `AAAA` 应答时常量硬编码 TTL 为 `60` 而未透传 `rec.ttl`，且缺少对 `rec.ttl == 0` 撤销记录的过滤。
- **修复设计**：解析 mDNS 应答时过滤 `rec.ttl == 0` 的撤销记录，并在生成的 `A` / `AAAA` 标准 DNS 响应中透传真实 `rec.ttl`。
- **回归验收**：单元测试输入 TTL 分别为 `5`、`120` 与 `0`（goodbye）的 mDNS 记录，断言标准响应原样保留 TTL `5` 与 `120` 且完全过滤 TTL `0` 记录。
