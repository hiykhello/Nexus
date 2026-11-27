# Nexus Core 审计缺陷与修复跟踪

本文记录针对基线提交 `d10c429`（Round 1：`5 P1 + 2 P2`）、`0e52ae8`（Round 2：`3 P1 + 4 P2`）、Round 3（`4 P1 + 3 P2`）、Round 4（`1 P1 + 8 P2 + 1 P3`）、Round 5（`5 P2`）及 Round 6（`3 P1 + 6 P2`，源码与本地实测复现）共六轮 45 项（`16 P1 + 28 P2 + 1 P3`）内核专项审计发现，明确触发条件、影响范围、根因定位、修复设计与回归验收目标，配合源码修复与自动化单元测试同步闭环。

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

---

## 3. Round 3（4 P1 + 3 P2，均已本地复现验证）

### 3.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R3 P1-1` | P1 | 凭据导入与清理 | 同一 `--secrets-dir` 中同名节点二次导入失败时误删上次成功导入的凭据文件 | 修复中 |
| `R3 P1-2` | P1 | 订阅凭据热重载 | 文件订阅仅轮换密码且路径不变时热重载走纯路由分支，未重建出站 | 修复中 |
| `R3 P1-3` | P1 | 多订阅节点展开 | 多订阅含同名节点时全局按裸标签保留首项，导致策略组 `use "<订阅>"` 指向错误服务器 | 修复中 |
| `R3 P1-4` | P1 | 第三方 YAML 订阅导入 | `src/provider/clash_yaml.cpp` 单遍遍历组名，前向引用子组被替换成全部节点 | 修复中 |
| `R3 P2-1` | P2 | 热重载排空连接治理 | 监听器热重载后控制面查不到也关不掉 `retired_tcp` 排空期旧连接 | 修复中 |
| `R3 P2-2` | P2 | 策略组健康探测状态 | 普通配置下成功的策略组探测被 `group-health` 与 HTTP 状态持续报告为 `stale` | 修复中 |
| `R3 P2-3` | P2 | 策略组成员去重顺序 | 策略组中 `use` 与显式 `member` 书写顺序决定配置能否通过校验启动 | 修复中 |

### 3.2 P1 级缺陷明细

#### R3 P1-1 — 导入失败删除上次成功导入的凭据

- **触发与影响**：在同一 `--secrets-dir` 先成功导入可用节点（如生成 `uuid.secret`），随后导入同名但字段非法（如无效 REALITY 公钥）的节点时，第二次转换虽仅告警退出，却删除了原先正常的凭据文件，导致原可用配置失效。
- **涉及模块**：`src/provider/kdl_emit.cpp`、`src/provider/kdl_expand.cpp`、`src/tools/proxy_providers.cpp`。
- **根因**：`SecretWriter` 在节点校验完成前即直接覆盖正式目标凭据路径，失败回滚清理时又按新建文件将其删除。
- **修复设计**：在节点生成与校验阶段将凭据暂存于内存或同目录 `0600` 临时文件，仅在节点校验完全通过后原子替换正式凭据路径；失败路径只丢弃暂存数据或清理本次新建临时文件，严禁修改或删除既有正式凭据。
- **回归验收**：单元测试先向临时 `--secrets-dir` 导入有效 VLESS 节点并记录 `uuid.secret` 内容，再尝试导入含非法 REALITY 公钥的同名节点，断言原 `uuid.secret` 依然存在且内容丝毫未变。

#### R3 P1-2 — 文件订阅仅轮换密码时热重载未重建出站

- **触发与影响**：仅更新文件订阅中代理节点密码（凭据文件路径保持不变）并触发热重载后，日志报告纯路由重载完成，但既有出站仍在内存中持有构造期读取的旧密码，新连接继续使用旧密码直到重启。
- **涉及模块**：`src/tools/proxy_tun_reload.cppm`、`src/tools/proxy_run.cppm`、`src/tools/proxy_listener_reload.cppm`、`src/tools/outbound_config.cpp`。
- **根因**：重载差异比较仅比对出站配置中的凭据文件路径字符串，未读取或摘要凭据文件内容，因而误判出站未变更而走纯路由快路径。
- **修复设计**：将出站引用的全部凭据与证书文件（如 `password_file`、`uuid_file`、`key_file`、`salamander_password_file`、`ca_file`、客户端证书/私钥等）实际内容哈希纳入出站重载指纹比较；任意文件内容变化即触发出站重建。
- **回归验收**：单元测试保持出站 `password_file` 路径不变而修改其文件内容，断言重载配置指纹变化并触发出站重建而非纯路由重载。

#### R3 P1-3 — 多订阅同名节点导致 `use "<订阅>"` 指向错误服务器

- **触发与影响**：订阅 `a` 与订阅 `b` 均包含同名节点 `edge`（分别指向不同端口/服务器）且策略组仅声明 `use "b"` 时，展开后实际流量静默路由到订阅 `a` 的服务器。
- **涉及模块**：`src/provider/kdl_expand.cpp`、`src/tools/proxy_providers.cpp`。
- **根因**：多订阅展开按全局裸节点名去重并保留首项（订阅 `a`），同时策略组 `use "b"` 仅展开写入裸标签 `member "edge"`，丢失节点所属订阅归属。
- **修复设计**：在多订阅展开时保留节点订阅归属（对跨订阅冲突标签做消歧映射使 `use "a"` 与 `use "b"` 精确命中各自节点，并对歧义显式裸名引用给出清晰诊断，或直接拒绝歧义同名冲突），确保绝不静默路由至错误订阅节点。
- **回归验收**：单元测试构造订阅 `a`（`edge:18801`）与订阅 `b`（`edge:18802`）以及仅含 `use "b"` 的策略组，断言展开配置绝不将 `use "b"` 指向 `18801` 而准确指向订阅 `b` 的目标。

#### R3 P1-4 — 第三方 YAML 订阅导入器将前向引用子组替换成全部节点

- **触发与影响**：导入格式为第三方 YAML 订阅且 `proxy-groups` 中父组声明位于其引用的子组之前时，子组引用被丢弃，父组被静默回填为全部代理节点列表。
- **涉及模块**：`src/provider/clash_yaml.cpp`。
- **根因**：解析器单遍顺序遍历策略组并只记录已访问组名；遇到前向引用子组时判定未知导致成员列表为空，进而触发兜底填充全部节点。
- **修复设计**：改为两遍解析：第一遍收集全部声明的规范化策略组名，第二遍再依据完整节点集合与完整组名集合解析每个组的成员引用。
- **回归验收**：单元测试构造 `parent` 先于 `child` 声明的 YAML 订阅（`child` 仅含 `edgeB`，总节点含 `edgeA`、`edgeB`），断言导入后 `parent` 精确引用 `child` 而非 `[edgeA, edgeB]`。

### 3.3 P2 级缺陷明细

#### R3 P2-1 — 监听器热重载后控制面查不到/关不掉 `retired_tcp` 排空期旧连接

- **触发与影响**：监听器端口热重载后，仍存活的旧 TCP 连接随原监听器移交至 `retired_tcp` 排空队列；此时控制面查询单连接返回 `unknown-connection`，执行 `close-all` 返回 `closed=0`，无法观测或中止排空期连接。
- **涉及模块**：`src/tools/proxy_listener_reload.cppm`、`src/tools/proxy_control_operations.cppm`、`src/tools/proxy_http_control.cppm`、`src/tools/proxy_run.cppm`。
- **根因**：控制面连接快照、按 ID 查询、按 ID 关闭及全部关闭操作仅遍历当前活跃监听器列表，遗漏 `listener_reload.retired_tcp`。
- **修复设计**：将 `listener_reload.retired_tcp` 纳入连接列表、详情查询、单连接关闭与全部关闭的统一遍历范围。
- **回归验收**：单元测试在存在 `retired_tcp` 排空监听器连接时验证控制面连接查询与 `close-all` 均能定位并关闭该连接。

#### R3 P2-2 — 普通配置下成功的策略组探测被持续报告为 `stale`

- **触发与影响**：未显式配置 `direct_network` 的普通配置下，策略组健康探测明明成功，但 UDS `group-health` 与 HTTP `/v1/groups` 状态却始终报告 `stale`。
- **涉及模块**：`src/tools/proxy_run.cppm`、`src/tools/proxy_control.cppm`、`src/tools/proxy_http_control.cppm`、`src/tools/proxy_group_health.cppm`。
- **根因**：写入探测结果时记录了网络监视快照代次（如 `net_gen = 1`），但控制面查询仅在 `running->direct_network` 存在时才传入 `network->generation`，否则传 `std::nullopt`，导致代次永不相等。
- **修复设计**：统一探测写入与控制面（UDS / HTTP）查询两处的网络代次口径，均直接取自同一 `network` 代次来源。
- **回归验收**：单元测试在未配置 `direct_network` 且 `network` 代次为 `1` 时执行成功健康探测，断言 UDS `group-health` 与 HTTP `/v1/groups` 均报告 `up` 而非 `stale`。

#### R3 P2-3 — 策略组中 `use` 与显式 `member` 顺序决定配置能否启动

- **触发与影响**：对于订阅 `a` 提供的节点 `edge`，在策略组中先写 `member "edge"` 再写 `use "a"` 可通过校验启动；调换为先 `use "a"` 再 `member "edge"` 则生成两条重复 `member "edge"` 导致校验失败无法启动。
- **涉及模块**：`src/provider/kdl_expand.cpp`、`src/tools/proxy_providers.cpp`。
- **根因**：显式 `member` 处理分支虽将名称写入去重集合，但未在已存在时跳过原节点输出，导致先前 `use` 展开的同名成员与显式成员重复输出。
- **修复设计**：无论 `member` 位于 `use` 之前还是之后均执行一致去重，若显式 `member` 已由先前的 `use` 展开则跳过重复发射。
- **回归验收**：单元测试分别展开 `member "edge"` + `use "a"` 与 `use "a"` + `member "edge"` 两种顺序，断言均只输出唯一一条 `member "edge"` 且均通过配置解析校验。

---

## 4. Round 4（1 P1 + 8 P2 + 1 P3，实测复现）

### 4.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R4 P1-1` | P1 | HTTP 控制面清缓存 | 清缓存请求 `target` 类型无效时意外执行 `all` 并返回 HTTP `200` | 修复中 |
| `R4 P2-1` | P2 | `nexus check` 预检 | `nexus check` 放行缺失本地 DNS `rule-set` 的配置，实际启动时失败 | 修复中 |
| `R4 P2-2` | P2 | `state` CLI 子命令 | `state` 子命令（`inspect` / `clear-cache` / `reset`）忽略全局 `-D` 工作目录 | 修复中 |
| `R4 P2-3` | P2 | 嵌入式 C API | `nexus_core_run_args` 返回后未恢复工作目录，后续调用沿用上次 `-D` | 修复中 |
| `R4 P2-4` | P2 | TUN 桥接出站读包 | TUN 出站读取遇短缓冲区先丢弃队首包再报告队空 | 修复中 |
| `R4 P2-5` | P2 | HTTP-Only 控制面 | 仅开启 HTTP 控制端时 `/v1/status` 返回空 `instance_id` | 修复中 |
| `R4 P2-6` | P2 | 配置目录分片加载 | 目录内的显式 `--host-override` 先被当作普通分片扫描触发 `duplicate workers` | 修复中 |
| `R4 P2-7` | P2 | POSIX CLI 日志跟踪 | `control ... logs --follow` 将游标推至全局 `latest` 导致跳条 | 修复中 |
| `R4 P2-8` | P2 | HTTP 策略组切换 | `POST /v1/groups/{tag}/select` 拒绝 `{"auto":true}` 且 `--auto` 回显错误 `selected` | 修复中 |
| `R4 P3-1` | P3 | HTTP 日志查询解码 | HTTP 日志搜索静默丢弃含 `%2F` 的过滤条件 | 修复中 |

### 4.2 P1 级缺陷明细

#### R4 P1-1 — 清缓存请求 `target` 类型无效时意外执行 `all`

- **触发与影响**：向 HTTP 清缓存接口发送非法类型或非法值的 `target`（如 `{"target":123}`、`{"target":true}`、`{"target":"invalid"}` 或畸形 JSON）时，服务端静默退回默认 `all` 清空全部缓存并返回 HTTP `200`。
- **涉及模块**：`src/control_api/http_extra_routes.cppm`。
- **根因**：请求体字段解析失败时未中止处理，直接保留默认值 `all` 进入清缓存执行路径。
- **修复设计**：严格区分字段缺省（空请求体或 `{}` 默认 `all`）与字段存在但类型/取值非法或 JSON 畸形，后者在调用清理逻辑前直接返回 HTTP `400`。
- **回归验收**：单元测试断言 `{}` 与 `{"target":"dns"}` 返回 `200`，而 `{"target":123}`、`{"target":true}`、`{"target":"invalid"}` 及畸形 JSON 全部返回 `400` 且清理回调零调用。

### 4.3 P2 级缺陷明细

#### R4 P2-1 — `nexus check` 放行缺失本地 DNS `rule-set` 的配置

- **触发与影响**：配置中引用了不存在的本地 DNS `rule-set` 文件时，`nexus check` 校验通过，但在 `nexus run` 启动阶段失败。
- **涉及模块**：`src/tools/rule_explain.cpp`、`src/tools/proxy_run.cppm`。
- **根因**：`nexus check` 预检流程漏掉了 `proxy_run.cppm` 启动阶段执行的 `load_dns_rules` 校验。
- **修复设计**：在 `rule_explain.cpp` 的 `check` 路径补齐与 `proxy_run.cppm` 一致的 `load_dns_rules` 加载校验。
- **回归验收**：单元测试对缺失本地 DNS `rule-set` 的配置执行 `check`，断言返回非零失败状态。

#### R4 P2-2 — `state` 子命令忽略全局 `-D`

- **触发与影响**：带全局 `-D <dir>` 调用 `state inspect` / `state clear-cache` / `state reset` 时，相对路径配置与状态目录按旧工作目录解析，操作落到错误目录。
- **涉及模块**：`src/tools/state_cli.cpp`。
- **根因**：`state` 子命令共用的配置读取路径未优先应用全局 `-D` 工作目录。
- **修复设计**：在 `state_cli.cpp` 加载配置前与 `check` / `run` 保持一致，先切换/应用全局 `-D` 目录。
- **回归验收**：单元测试通过 `-D <temp_dir>` 传入相对配置名调用 `state` 子命令，断言准确命中 `<temp_dir>` 下的配置与状态。

#### R4 P2-3 — 嵌入式 C API 沿用上次调用的 `-D`

- **触发与影响**：嵌入式调用方先执行带 `-D` 的 `nexus_core_run_args`，返回后再调用相对路径检查（如 `check_config("core.kdl")`）时仍停留在上次 `-D` 目录。
- **涉及模块**：`src/tools/core_c_api.cpp`、`src/tools/route_files.cpp`。
- **根因**：`nexus_core_run_args` 退出时仅清除运行状态标记，未保存并恢复进程工作目录。
- **修复设计**：通过 RAII 守卫在 `nexus_core_run_args` 入口记录原工作目录，退出任意路径自动恢复原工作目录。
- **回归验收**：单元测试在调用带 `-D` 的 `nexus_core_run_args` 返回后断言当前工作目录及相对路径解析恢复至调用前状态。

#### R4 P2-4 — TUN 出站读取遇短缓冲区丢包并报队空

- **触发与影响**：嵌入式 TUN 桥接出站读包接口收到小于队首包长的缓冲区时，队首数据包被直接弹出丢弃，且调用方收到“队列为空”结果。
- **涉及模块**：`src/platform/tun_bridge.cppm`、`src/tools/core_c_api.cpp`、`include/nexus/core_c_api.h`。
- **根因**：读取路径在校验调用方缓冲区容量前已将队首数据包从队列移除。
- **修复设计**：弹出前先比较 `buf_len < front.size()`；容量不足时保留队首包不动，通过输出长度写回所需字节数并返回明确的容量不足错误码（区分成功与队空）。
- **回归验收**：单元测试先以短缓冲区读取 128 字节包，断言返回容量不足错误与 `128` 所需长度，随后以 128 字节缓冲区重试成功取回完整原包。

#### R4 P2-5 — 仅开启 HTTP 控制端时 `/v1/status` `instance_id` 为空

- **触发与影响**：仅启用 HTTP 控制面而关闭本地 UDS 控制套接字时，`/v1/status` 返回空 `instance_id: ""`，客户端无法识别 Core 进程重启。
- **涉及模块**：`src/tools/proxy_http_control.cppm`、`src/tools/proxy_run.cppm`、`src/tools/control_posix.cpp`。
- **根因**：HTTP 状态接口仅从本地 UDS 控制对象读取实例标识，未在 HTTP-only 场景下独立生成并持有实例标识。
- **修复设计**：在未启用 UDS 控制时为运行实例生成并持有稳定唯一的非空 `instance_id`（复用同源标识生成逻辑），保证每次进程启动在 `/v1/status` 返回独立非空值。
- **回归验收**：单元测试在 UDS 控制未激活时查询 HTTP 状态快照，断言 `instance_id` 非空且两次独立实例生成不同标识。

#### R4 P2-6 — 目录内的显式 `--host-override` 先被当作普通分片扫描

- **触发与影响**：将 `--host-override` 指向配置目录内的某个 `.kdl` 文件时，目录扫描先把它当作普通分片合并一次，随后覆盖合并阶段再次加载引发 `duplicate workers` 等重复字段错误。
- **涉及模块**：`src/tools/route_files.cpp`。
- **根因**：目录分片扫描未排除命令行显式指定的 `--host-override` 文件路径。
- **修复设计**：规范化比对 `--host-override` 目标路径并在目录分片枚举阶段跳过该文件，使其仅参与最终覆盖合并阶段。
- **回归验收**：单元测试在配置目录内放置 `--host-override` 文件执行加载，断言不触发重复字段错误且覆盖值正确生效。

#### R4 P2-7 — POSIX CLI `logs --follow` 跳条

- **触发与影响**：POSIX 命令行执行 `nexus control ... logs --follow --limit 1` 跟踪多条积压日志时，首条输出后游标跳过中间未打印条目。
- **涉及模块**：`src/tools/control_posix.cpp`。
- **根因**：轮询循环将下一次请求的 `since` 游标推进至日志环全局 `latest`，而非本批实际打印的最后一条日志序号。
- **修复设计**：本批存在交付条目时将游标推进至末条已打印日志的 `seq`；仅在空页/已淘汰场景才安全推进至 `latest`。
- **回归验收**：单元测试模拟 5 条未淘汰积压日志配合 `--limit 1` 连续拉取，断言按序完整输出 `seq=1..5` 且零跳条。

#### R4 P2-8 — HTTP 策略组接口拒绝 `{"auto":true}` 且 `--auto` 回显错误 `selected`

- **触发与影响**：调用 `POST /v1/groups/{tag}/select` 发送规范允许的 `{"auto":true}` 恢复自动选择时被拒绝；传入 `{"member":"--auto"}` 时响应字段 `selected` 原样回显 `"--auto"` 而非实际生效成员名。
- **涉及模块**：`src/control_api/http_server.cpp`。
- **根因**：请求解析未支持布尔 `auto` 字段，且响应构造直接回填请求字符串而未回查策略组当前实际生效成员。
- **修复设计**：按控制面规范支持 `{"auto":true}`（并拒绝非法类型的 `auto` 字段返回 `400`），恢复自动选择后在 `selected` 字段返回策略组实际解析出的当前成员名。
- **回归验收**：单元测试校验 `{"auto":true}` 与 `{"member":"--auto"}` 均成功恢复自动选择且响应 `selected` 为真实成员名（非 `"--auto"`），非法 `{"auto":"yes"}` 返回 `400`。

### 4.4 P3 级缺陷明细

#### R4 P3-1 — HTTP 日志搜索静默丢弃含 `%2F` 的过滤条件

- **触发与影响**：HTTP 日志检索查询参数包含 URL 编码斜杠 `%2F`（如路径或 CIDR 过滤串）时，过滤条件被静默丢弃并返回未过滤日志。
- **涉及模块**：`src/control_api/http_format.cppm`。
- **根因**：查询参数值解析误复用了拒绝编码斜杠的路径解码函数，且在解码失败时静默忽略该查询参数。
- **修复设计**：提供专用的查询参数百分号解码器，允许合法 `%2F` 解码为 `/`，并在遇到畸形百分号转义时显式返回 HTTP `400` 而非静默丢弃条件。
- **回归验收**：单元测试校验含 `%2F` 的日志查询参数正确解码并生效过滤，畸形 `%ZZ` 查询参数返回 HTTP `400`。

---

## 5. Round 5（5 P2，Linux 本地实测复现）

### 5.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R5 P2-1` | P2 | 文件订阅热重载 | 重载失败后原有文件订阅停止自动周期刷新 | 修复中 |
| `R5 P2-2` | P2 | 订阅模式热重载校验 | 启用订阅时更换 `selector-state-directory` 误报成功却继续写旧目录 | 修复中 |
| `R5 P2-3` | P2 | 热添加策略组切换 | 已有文件订阅的实例首次热添加手动策略组后可见但 `select` 报 `selection-unavailable` | 修复中 |
| `R5 P2-4` | P2 | 远程 DNS 规则集热重载 | 更换远程 DNS `rule-set` URL 后热重载未拉取新地址而报错 | 修复中 |
| `R5 P2-5` | P2 | 进程累计流量统计 | 监听器换代排空回收后同一进程的 `/v1/status` 累计流量倒退回 `0` | 修复中 |

### 5.2 P2 级缺陷明细

#### R5 P2-1 — 重载失败后原有文件订阅停止刷新

- **触发与影响**：文件订阅按周期（如 `1s`）自动刷新正常运行期间，提交一份移除订阅且校验失败的配置触发重载失败；随后恢复原配置并更新订阅节点内容，自动周期刷新停止直至再次手动重载。
- **涉及模块**：`src/tools/proxy_providers.cpp`、`src/tools/proxy_run.cppm`。
- **根因**：`prepare_initial` 在完整候选配置校验与发布成功之前就清空了当前活动订阅表，导致失败路径虽然保留了旧代理配置，但活跃订阅调度表已被清空。
- **修复设计**：对候选配置订阅表采用暂存与原子提交（staging + atomic commit），仅在候选配置校验和重载发布完全成功后替换活动订阅表；任意失败路径保持原活动订阅表及刷新周期不受影响。
- **回归验收**：单元测试先验证文件订阅自动刷新生效，再触发一次移除订阅且失败的重载，修改订阅文件内容后断言原自动刷新继续生效。

#### R5 P2-2 — 启用订阅时更换策略组状态目录报告成功却继续写旧目录

- **触发与影响**：启用文件订阅时将 `selector-state-directory` 从目录 `A` 改为目录 `B` 并执行热重载，控制面返回 `succeeded`，但后续 `select` 仍写入 `A/selectors.state`，重启后丢失选择。
- **涉及模块**：`src/tools/proxy_run.cppm`、`src/tools/proxy_listener_reload.cppm`。
- **根因**：启用订阅后普通重载走 `provider_refresh` 分支，该分支遗漏了 `selector_state_directory` 等不可热变更的进程级身份字段检查。
- **修复设计**：在 `provider_refresh` 分支补齐 `selector_state_directory` 及全部进程级不可热改字段的变更比对，命中变更时明确返回需要重启的错误。
- **回归验收**：单元测试在启用订阅场景下变更 `selector-state-directory` 触发重载，断言返回需重启错误而非假成功。

#### R5 P2-3 — 已有文件订阅的实例首次热添加手动策略组后可见但不可切换

- **触发与影响**：在已有文件订阅但原先无策略组的实例上首次通过热重载新增手动策略组后，`status` 可见 `group=manual selected=direct`，但执行 `select manual block` 返回 `selection-unavailable`（冷启动同样配置可正常切换）。
- **涉及模块**：`src/tools/proxy_listener_reload.cppm`、`src/tools/proxy_run.cppm`。
- **根因**：热重载仅在旧实例已持有 `group_route_files` 或新配置启用 `group_health` 时才保存切换所需路由文件，首次热添加纯手动策略组时未保存 `group_route_files` 与对应路由快照。
- **修复设计**：当新配置包含任意策略组（`!reload_config->selectors.empty()`）时亦同步保存 `group_route_files` 并初始化路由快照，使首次热添加的手动策略组立即支持切换。
- **回归验收**：单元测试对已有文件订阅的无组实例热添加手动策略组并立即执行 `select`，断言切换成功且无需重启。

#### R5 P2-4 — 更换远程 DNS `rule-set` 的 URL 无法热生效

- **触发与影响**：将远程 DNS `rule-set` 指向同一 HTTPS 服务的路径从 `/first` 改为 `/second` 后执行热重载，报错 `DNS rule-set: open input: No such file or directory`，且 HTTPS 服务端未收到新路径请求。
- **涉及模块**：`src/tools/proxy_listener_reload.cppm`、`src/tools/route_files.cpp`、`src/tools/proxy_run.cppm`。
- **根因**：热重载仅通过 `remote_rulesets.seed_cached(...)` 注入旧 URL 缓存，新 URL 未命中缓存时直接落入本地文件路径打开逻辑。
- **修复设计**：热重载执行 `load_dns_rules` 与 `load_route_files` 之前，先拉取并暂存候选配置新增或变更的远程 DNS 与路由 `rule-set` URL 写入候选输入，仅在重载发布成功后提交新缓存状态，拉取或校验失败不破坏既有规则集。
- **回归验收**：单元测试将远程 DNS `rule-set` URL 从 `/first` 切换至 `/second` 并执行热重载，断言服务端收到 `/second` 请求且新规则热生效，同时失败路径保留旧缓存。

#### R5 P2-5 — 监听器换代导致同一进程累计流量倒退

- **触发与影响**：通过代理传输数据（如 `4096B`）后仅修改监听器名称触发热重载，进程 `instance_id` 未变，待旧代监听器排空回收后 `/v1/status` 上下行累计流量回退至 `0`。
- **涉及模块**：`src/tools/proxy_host.cppm`、`src/tools/proxy_http_control.cppm`。
- **根因**：`poll_retired()` 回收并销毁已排空的 `RetiredTcpGeneration` 时，未将其最终 `rx_bytes` / `tx_bytes` 并入进程级单调累计计数器。
- **修复设计**：维护进程级已回收累计字节计数（`reclaimed_rx_bytes` / `reclaimed_tx_bytes`），在 `poll_retired()` 移除旧代前先折叠其最终字节数，并在状态统计中汇总 `reclaimed + active + draining_retired`，保证同进程累计流量单调不退且不重复计算。
- **回归验收**：单元测试在产生流量并完成监听器换代与旧代排空回收后查询状态统计，断言累计字节数保留既有总量、绝不回退且不双计。

---

## 6. Round 6（3 P1 + 6 P2，源码与本地实测复现）

### 6.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R6 P1-1` | P1 | HTTP 订阅缓存 | 订阅更换 URL 后仍按订阅名发送旧 ETag 并在 `304` 时沿用旧资源节点 | 修复中 |
| `R6 P1-2` | P1 | 远程规则集校验 | 同 URL 的多条远程规则集引用仅沿用首条校验策略，后声明的 `sha256` 未生效 | 修复中 |
| `R6 P1-3` | P1 | ACME 凭据原子提交 | ACME 可将证书与私钥不匹配的一代分步落盘并标记续签成功，TLS 拒绝未回传 | 修复中 |
| `R6 P2-1` | P2 | SS-2022 原生 UDP | 原生 UDP 规则加载对已 mmap 的 NXMM 索引规则读到空串报 `invalid NXMM file size` | 修复中 |
| `R6 P2-2` | P2 | `fixed-udp` 路由模式 | `fixed-udp` 有序规则分支跳过运行模式判断，切至 `direct` 后仍支配新流 | 修复中 |
| `R6 P2-3` | P2 | ACME 订单状态机 | 订单迟到的 `ready` 状态错过唯一 `finalize` 分支导致永远无法提交 CSR | 修复中 |
| `R6 P2-4` | P2 | SRS 派生 NXMM 缓存 | 派生目录 `cache/nxmm` 无预算回收持续增长，且 `clear-cache --rulesets` 遗漏清理 | 修复中 |
| `R6 P2-5` | P2 | Windows 控制面实例 ID | Windows 命名管道 `LocalControl::instance()` 返回固定管道名，跨重启不变 | 修复中 |
| `R6 P2-6` | P2 | Linux KDE 系统代理 | KDE 后端接受 `--pac-url` 后仅写 `ProxyType=2`，未读写/恢复 `Proxy Config Script` | 修复中 |

### 6.2 P1 级缺陷明细

#### R6 P1-1 — HTTP 订阅换 URL 后沿用上一个资源的节点

- **触发与影响**：同名 HTTP 订阅更换资源 URL 后，请求仍携带上一资源的 `ETag`；若新地址返回 `304`，内核继续复用旧 URL 的节点正文。
- **涉及模块**：`src/tools/proxy_providers.cpp`、`src/tools/proxy_providers.cppm`。
- **根因**：缓存文件仅按订阅名寻址，未将完整资源 URL 纳入缓存身份与验证器同源校验。
- **修复设计**：将缓存身份绑定至完整规范化 URL，严格校验验证器与正文同源；URL 变更时绝不发送旧 `If-None-Match` 且不复用旧正文。
- **回归验收**：单元测试将同名 HTTP 订阅切换至新 URL，断言请求不携带旧 `ETag` 且绝不复用旧节点正文。

#### R6 P1-2 — 同 URL 的远程规则集引用共用第一条引用的校验策略

- **触发与影响**：路由或 DNS 中多处引用同一远程规则集 URL 且附带不同 `sha256`（或仅后者声明 `sha256`）时，后声明的摘要约束未参与校验。
- **涉及模块**：`src/config/`（远程规则集配置校验）、`src/tools/route_files.cpp`、`src/tools/proxy_listener_reload.cppm`。
- **根因**：下载任务按 URL 收集时仅保留首条声明，后续引用绑定同 URL 缓存正文时未重新核对自身 `sha256` 约束。
- **修复设计**：配置期直接拒绝同一 URL 下的冲突 `sha256` 声明，并在每次将缓存或下载正文绑定到规则集引用时再次校验该引用的 `sha256` 约束。
- **回归验收**：单元测试验证同 URL 冲突 `sha256` 在配置期报错，且绑定阶段对每条引用强制执行独立 `sha256` 校验。

#### R6 P1-3 — ACME 可把证书与私钥不匹配的一代保存为续签成功

- **触发与影响**：ACME 签发结果若与 CSR 私钥不匹配或落盘中途失败，磁盘可能残留跨代错配 cert/key 且续签循环误判成功休眠至过期；冷启动亦先安装磁盘错配记录。
- **涉及模块**：`src/service/acme/client.cpp`、`src/service/acme/store.cpp`、`src/tools/svc_acme.cpp`。
- **根因**：签发阶段仅检查证书有效期即分两次独立替换 cert/key 文件并更新续签状态，未做公私钥配对校验，且 TLS 加载拒绝未回传至签发流程。
- **修复设计**：落盘前与冷启动加载时均校验叶证书公钥与私钥配对；cert+key 以整对原子提交消除跨代窗口；先发布激活在线 TLS 凭据并回传失败，仅在激活成功后更新续签状态。
- **回归验收**：单元测试注入公钥不匹配证书断言被拒绝（不落盘、不激活、不更新续签时间），匹配证书则原子提交并成功激活。

### 6.3 P2 级缺陷明细

#### R6 P2-1 — SS-2022 原生 UDP 遇到 NXMM 索引规则阻止实例启动

- **触发与影响**：含 NXMM 索引规则的配置通过 `nexus check`，但在启用 SS-2022 原生 UDP 启动时报错 `invalid NXMM file size`。
- **涉及模块**：`src/tools/route_files.cpp`、`src/tools/route_files_nxmm.cppm`（及原生 UDP 规则加载路径）。
- **根因**：规则加载器将 mmap 匹配器保存在 `data_mmaps[i]` 并留空 `data[i]` 字节串，原生 UDP 路径仍从空 `data[i]` 重新解析 NXMM。
- **修复设计**：让原生 UDP 与 TCP 路径共享已加载的 `data_mmaps` / `MmapMatcher` 表示，避免重复解析空字节串。
- **回归验收**：单元测试使用真实 NXMM 索引规则初始化 SS-2022 原生 UDP 路由，断言启动成功且按预期命中分流。

#### R6 P2-2 — `fixed-udp` 有序规则仍支配 `direct` 模式下的新流

- **触发与影响**：`fixed-udp` 配置有序 `block` 等规则并将运行模式切换至 `direct`（或 `global`）后，新建立的 UDP 流仍受有序规则支配。
- **涉及模块**：`src/relay/fixed_udp_inbound.cpp`。
- **根因**：`fixed-udp` 有序规则分支直接执行命中动作，跳过了运行模式决策。
- **修复设计**：与普通 UDP 入口共用运行模式决策（`direct` / `global` / `rule`），在评估有序规则前先按运行模式路由。
- **回归验收**：环回单元测试配置有序 `block` 规则后切至 `direct` 模式，断言新客户端 UDP 数据报直连到达并回显。

#### R6 P2-3 — ACME 订单迟到的 `ready` 状态无法进入 `finalize`

- **触发与影响**：ACME 订单在首轮轮询结束时仍处于 `pending`，进入第二轮后才转为 `ready` 时，客户端持续空等 `valid` 永不提交 CSR。
- **涉及模块**：`src/service/acme/client.cpp`。
- **根因**：实现拆为两段无退避循环且仅在首段结束后检查一次 `finalize`，二段不再触发 `finalize`。
- **修复设计**：改为统一的状态机驱动轮询循环（含退避间隔与总截止时间），按 `pending`/`ready`/`processing`/`valid`/`invalid` 状态流转并在 `ready` 时执行一次 `finalize`。
- **回归验收**：单元测试模拟多轮 `pending` 后才转 `ready` 的 ACME 服务端，断言 `finalize` 被正常调用且签发成功。

#### R6 P2-4 — SRS 派生缓存 `cache/nxmm` 持续增长且清规则缓存后仍保留

- **触发与影响**：SRS 编译派生的 `cache/nxmm` 文件随更新无限增长，且执行 `state clear-cache --rulesets` 或在线清理规则集缓存后仍残留磁盘。
- **涉及模块**：`src/tools/route_files_nxmm.cppm`、`src/state/ruleset_cache.cppm`、`src/state/ruleset_cache.cpp`、`src/tools/state_cli.cpp`。
- **根因**：派生 NXMM 文件未纳入规则集缓存字节预算回收，且清理路径遗漏 `cache/nxmm` 目录。
- **修复设计**：为 `cache/nxmm` 增加按规则集缓存预算淘汰最旧非活跃文件的回收机制，并将该目录纳入 CLI 与控制面 `clear-cache` 的 `rulesets` / `all` 清理范围。
- **回归验收**：单元测试验证超预算触发旧派生文件淘汰，以及 `clear-cache --rulesets` 与在线清理均完整清除 `cache/nxmm`。

#### R6 P2-5 — Windows 管道实例标识跨进程重启不变

- **触发与影响**：Windows 端重启同一配置的 Core 进程后，`LocalControl::instance()` 返回值完全相同，无法区分跨重启进程实例。
- **涉及模块**：`src/tools/control_windows.cpp`。
- **根因**：`LocalControl::instance()` 直接返回确定性的规范化命名管道路径 `pipe_utf8`。
- **修复设计**：在创建 `LocalControl` 时为每个进程实例生成独立高熵随机实例标识并由 `instance()` 返回。
- **回归验收**：单元测试验证连续创建的实例生成彼此不同的非空实例标识，且保持 Windows C++23 编译洁净。

#### R6 P2-6 — KDE 后端接受 PAC URL 后未写入该地址

- **触发与影响**：Linux KDE 系统代理后端接收 `--pac-url` 返回退出码 `0`，但实际未写入 PAC 脚本地址且禁用时未恢复原配置。
- **涉及模块**：`src/platform/system_proxy.cpp`。
- **根因**：启用路径仅写入 `ProxyType=2`，遗漏对 `Proxy Config Script` 的快照读取、写入与禁用恢复，状态查询亦未读取该键。
- **修复设计**：快照保存既有 `Proxy Config Script`，启用时同时写入 `Proxy Config Script` 与 `ProxyType=2`（任一失败即返回错误），状态查询读取该键，禁用时完整恢复或清除。
- **回归验收**：隔离 `PATH` 下的模拟 `kreadconfig6`/`kwriteconfig6` 单元测试验证启用同时写入两键、状态可读回、禁用完整恢复原值。
