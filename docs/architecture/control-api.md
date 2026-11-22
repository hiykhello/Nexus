# Nexus 原生控制面与 BEVE IPC

Linux CLI 提供本机控制 socket。本文后半的 HTTP/JSON 与跨平台 BEVE IPC 为设计草案。

## Linux 本机控制

在配置中加入顶层 `control socket="/run/user/1000/nexus/control.sock"`。默认要求运行账户拥有私有父目录，服务使用 Unix `SOCK_SEQPACKET`、`0600` 权限和 `SO_PEERCRED`，同 UID 的客户端拥有管理权限。路径被占用时启动失败，正常退出时删除自己绑定的 socket。

可在同一配置节点增加 `read-uid=1001`，授权一个独立 Linux UID 查询聚合状态、重载结果、事件和传输计数。共享 socket 以 `0666` 发布，以内核认证的 UID 限定访问。socket 的父目录须为运行账户所有，写权限限于目录 owner。给只读账户提供目录遍历权限，例如使用 `0711` 的专用目录。该账户通过 `nexus control SOCKET --server-uid 1000 status` 显式验证服务端 UID。只读状态省略组成员选择，事件不包含规则、用户名、地址、会话、凭据或原始配置错误。

| 命令 | 结果 |
| --- | --- |
| `nexus control SOCKET status` | 监听序号、端口、活动连接、上下行累计和手动选择。支持监听器换代时，`listener-generation` 给出最近一次成功发布的代次。Linux 的 `network-generation` 随链路、地址和路由快照更新，附双栈默认路由计数。快照暂不可用时报告 `unknown`。 |
| `nexus control SOCKET connections LISTENER [AFTER_ID]` | 列出 ID 大于游标的活动连接，每页最多 96 条并受回包字节上限约束，有下一页时返回 `next`。已取得的可执行文件路径以 `process-path` 返回 |
| `nexus control SOCKET close LISTENER ID [GENERATION [INSTANCE]]` | 向会话所在的 executor 排队取消，处理完成后该条目退出活动表 |
| `nexus control SOCKET select GROUP MEMBER [GENERATION [INSTANCE]]` | 原子发布手动选择，新会话使用新代，已建立会话沿用旧代 |
| `nexus control SOCKET group-health GROUP` | 返回组类型和当前成员，以及每个成员的实际出站、最近探测和探测进行状态 |
| `nexus control SOCKET reload` | 将既有主配置的重载排入宿主循环，返回操作 ID 和 `pending`。有操作待处理时返回 `reload-busy` |
| `nexus control SOCKET operation ID` | 查询 `pending`、`succeeded` 或 `failed` 及对应 `control-generation`。最近 64 个操作有效。失败时，服务日志保留详细原因 |
| `nexus control SOCKET events [AFTER_ID [INSTANCE]]` | 从最近 128 条操作及选择事件中按序读取至多 32 条。使用首行的 `next` 和 `instance` 拉取下一页，`gap=1` 表示已有部分历史被覆盖 |
| `nexus control SOCKET diagnostics` | 返回已授权接入、未知 UID 拒绝、读请求超时和回包失败计数 |

每个连接交换一条请求和一条响应，请求上限 1024 字节，响应上限 65536 字节。最多保留 32 个已接受连接，请求等候期为两秒。服务器尝试一次非阻塞回包后关闭连接，事件客户端可从游标重新拉取。请求以 `NEXUS/1 ` 开头，后接子命令。每个参数前加一个 NUL 字节，参数可以包含空格或 Unicode。响应首行为 `NEXUS/1 OK` 或 `NEXUS/1 ERROR`，后跟换行和结果。含特殊字符的组名和成员名用双引号包裹并转义。列表游标基于活动 ID，跨页期间会话可变化。监听序号、会话 ID、事件序号、操作 ID 和控制代次的作用域为当前进程实例。成功重载或发布组选择后递增控制代次。新进程发布新 `instance`，客户端用它识别重启。

在 `select` 或 `close` 中带上状态返回的 `control-generation` 和 `instance` 可防止旧操作作用于换代或重启后的目标。传入的代次或实例不匹配时返回 `stale-generation`。

自动探测组的成员状态为 `unknown`、`up`、`down` 或 `stale`。`stale` 表示成员的实际出站已变化，旧测量不再参与选择。正在重测时，`probing=1` 与最近有效结果同时显示。成功样本报告 `latency-ms`，成功或失败样本均报告 `sample-age-ms`。手动选择和负载均衡组显示 `not-probed`。读取状态不会触发探测。

在 `control` 上设置 `selector-state-directory="/var/lib/nexus/selectors"` 后，手动选择写入该私有目录的 `selectors.state`。宿主持有目录独占锁，先编译候选路由，再同步临时文件和原子替换，最后发布新选择。写入或替换失败保留当前选择。替换成功但目录同步失败时，新选择生效，命令返回 `selector-active-persistence-uncertain`。

启动和重载先应用配置，再用已保存的手动选择覆盖对应组。错误版本、截断或不再合法的组和成员会阻止候选启动或发布，保留状态文件供恢复。自动探测结果和活动会话只存在于当前进程。

Linux UDP TPROXY 的活动条目额外返回 `transport-source`、`original-destination` 及可用的 `ingress-ifindex`。前两项是内核交付的端点，IPv6 地址用方括号。入接口索引属于代理的网络命名空间。透明 UDP 的 `source-uid` 和 `process-path` 保持未知，因而省略。相同源端口可以由多个发送 socket 共享，内核的 IP 辅助数据只提供包的网络元数据。

普通 Server 的会话保留建立时的 `route-generation`，初始代次为 1，每次成功发布递增。已成功拨号的 TCP 和已转交数据报的 UDP 条目返回 `route-mode`、`route-rule`、`route-target` 和实际物理 `outbound`。规则与 indexed 谓词编号从 1 开始，与 `rule explain` 一致，后备出口显示 `route-rule=default`。UDP 关联可能访问多个目的，这些路由字段描述最近成功转交的数据报。透明 TPROXY 的原目的始终保存在独立字段。

## 本机流量快照

用 `nexus run --traffic-stats --config config.kdl` 启动。向运行中的进程发送 `SIGUSR1`，从标准错误读取快照。每条 `traffic` 给出监听器序号、端口、活动会话数和双向累计。其后的 `connection` 行显示该监听器内的会话 ID、协议、源和目标端口、转发类型、双向字节以及 `can-close`。最后一行 `traffic-total` 汇总各监听器。按代次隔离的活动会话由各自的 executor 管理。多个 worker 共用监听器的统计表，会话退出后保留已提交字节。

TCP 记录交给目标 socket 或出站协议的应用字节，以及交给客户端的字节。直连按成功的部分写入计数，代理出站通常按完整写操作计数。预读和 TCP Fast Open 的前缀只计一次。普通 HTTP 正向代理计实际转发的 HTTP 消息，包括 HTTP 应用头。SOCKS5 协商、CONNECT 响应和外层代理帧排除。

UDP 记录完整转交的 payload。统计按所有者的逻辑关联划分，关联可以覆盖多个目标。CONNECT-IP 连接记录承载的完整 IP 包，包括 IP 头。MASQUE 服务端的下行字节在对应 Capsule 完成确认时累加。由 TUN 设备转发的 TCP/UDP 则按入队和 socket 写入等对应的交付边界计数，对重传的包不重复计算 TCP payload。

嵌入式调用方可用 `Server::request_traffic_close(id)` 请求关闭标记为 `can-close=1` 的会话。接受请求后由该流的 executor 执行关闭，活动记录在其转发任务清理后退出。原生 SS-2022 UDP 保留由其认证会话决定的撤回和过期规则。

快照按监听器采样。并发写入时各流的读数可能相差一个写入时点，累计字节按无符号 64 位回绕。

## HTTP/JSON API

采用 HTTP/1.1，远程部署可组合自研 TLS；HTTP framing 与证书校验遵守[HTTP](http.md)和[TLS](tls.md)设计。根路径为 `/v1`，路径、JSON 结构和操作均为待验证草案；API 主版本与配置/BEVE schema 分开。响应 `Content-Type: application/json`；错误形态为 `{"error":{"code":"...","message":"...","request_id":"..."}}`，不包含凭据或内部栈。未知字段/操作、状态码、分页和兼容规则须形成版本化规范和测试样本。

| 方法与路径 | 拟定语义 |
| --- | --- |
| `GET /v1/status` | 返回进程实例 ID、版本、已编译/启用能力、当前路由 generation 与可公开健康状态；健康状态区分运行中和依赖可用 |
| `GET /v1/outbounds` | 列出具名出口的类型、TCP/UDP/L3 等能力与运行状态，不返回节点凭据 |
| `GET /v1/selectors` | 列出 selector、允许成员、当前选择与所属配置代次 |
| `PUT /v1/selectors/{id}` | JSON `{"member":"edge","generation":"7"}`；仅对存在且允许操作的 selector 生效；代次或成员已变化时 409；成功返回新的选择。已建立会话保持原决策 |
| `GET /v1/sessions` | 有界分页返回会话 ID、开始时间、入站、原目标与已知的域名来源、出口链、命中规则及双向字节；附快照代次/分页游标和是否还有后续页 |
| `DELETE /v1/sessions/{id}` | 请求取消该会话，接受后 202；活动/已结束状态以会话状态或事件为准，不因已接收取消就声称资源已全部释放 |
| `GET /v1/rules` | 按配置顺序有界分页返回当前规则的可公开表示、动作与 generation，不将索引次序当规则次序 |
| `GET /v1/stats` | 返回进程实例、单调采样间隔、双向累计和速率、活跃会话数及受限聚合指标；各字段定义见下文 |
| `POST /v1/config/reloads` | 对已配置的主配置发起重新加载，返回 202 和操作 ID；不接收任意路径、任意远程 URL 或秘密配置内容 |
| `GET /v1/operations/{id}` | 返回重载进行中、成功或失败及实际提交的 generation、可公开诊断；操作状态有界保留并可过期 |
| `GET /v1/events?topics=stats,sessions,operations` | Server-Sent Events（SSE）流；事件 `id`、`event`、JSON `data` 含实例与序号，供经授权的客户端接收有界更新 |

selector 请求使用 generation 避免从旧页面修改新配置；同一 selector 的变更串行化，成功响应是提交后的值。`POST` 接受只表示排队，具体结果以 operation 状态为准。重载先解析、校验和编译候选，再按[路由引擎](routing-engine.md)发布；成功记录已提交 generation，失败保留旧规则。路由快照和系统网络修改不自动组成全局事务；操作状态须区分整体成功、失败/回滚和恢复仍需处理，不能在网络状态未恢复时只报告路由已更新。

分页 token 绑定进程实例、查询条件与可用的有限快照，限制创建成本和过期时间；并发变化可采用固定短期快照或明确标注弱一致，不承诺无成本全局一致。过期 token 应返回明确错误，客户端重新查询。路径参数只做一次正确 URL 解码并限定长度，不能作为文件路径。规则和会话读取都受独立的敏感信息权限控制。

示例状态与统计响应如下，字段和数值仅用于说明（`instance_id` 在进程重启时变化）：

```json
{"instance_id":"example-instance","version":"0.0.0-dev","route_generation":"7","capabilities":["sessions.read","stats.read","selectors.write"]}
```

```json
{"instance_id":"example-instance","sample_interval_ms":1000,"upload_bytes_total":"1250000","download_bytes_total":"8400000","upload_bytes_per_second":1024.0,"download_bytes_per_second":4096.0,"active_sessions":3}
```

所有可能超过 JavaScript 安全整数范围的累计字节、代次与序号在 JSON 中编码为十进制字符串；小范围的会话数量和采样间隔使用 JSON 整数，速率为有限非负数，单位 B/s。拒绝无法精确解析的输入、负数和超范围数值。不同进程实例的计数/代次不能直接比较；这只是示意性 wire 约定，其他响应字段、状态码和版本兼容需实现后固定。

SSE 客户端用支持自定义请求头的 `fetch` 流发送 Bearer token，而不是把秘密放入 URL；每条事件的序号使客户端能够检测丢失或重连。首版不保证事件历史重放，断线或发现序号缺口后调用快照 API 重建状态；`Last-Event-ID` 不意味着历史一定可用。慢消费者合并中间统计快照或断开，不能无限排队。WebSocket 和订阅历史不是当前必要能力。

## 认证、浏览器与暴露范围

默认控制服务关闭；启用 HTTP 时示例绑定回环并要求独立强随机 token 文件。每个请求用 `Authorization: Bearer <token>`，验证后映射到配置的只读或控制权限；token 比较使用抗时序泄漏机制。校验失败 401，权限不足 403。控制 selector、终止会话和重载配置分开授权；默认只读。禁止 query token，不返回或记录认证头、密钥和完整配置。

对带 Origin 的请求使用显式精确的 scheme/host/port 白名单，处理预检并只开放必需方法/头；拒绝未允许的跨源请求。无 Origin 的本地 CLI 是否允许由配置单独规定，不能据此放宽浏览器 Origin；CORS 不是认证。绑定非回环地址须显式启用 TLS、认证、网络 ACL 与受控 Origin；明文 token 不应跨不可信网络传输。反向代理头、浏览器混合内容、证书验证和本地网页的信任均需实际验证。

对请求头/体、连接数、每来源速率、分页快照、订阅、发送队列及空闲时间设上限；连接元数据、进程路径、目标域名可能敏感。控制操作记录审计事件与结果，不输出密钥。浏览器客户端只在用户明确选择后获得 token；面板本身能读取该 token，因此必须纳入信任评估。

## 计数与快照

每个逻辑会话在公共转发边界记录上行（客户端发往目标）和下行的有效载荷字节，TCP、数据报都须定义实际成功转交的计数时点；同一字节不得因代理链多层重复计数。内部 TLS/QUIC framing、重传和链路层字节单列，不混入用户流量。为 splice、批处理和零拷贝路径规定同一统计契约，异步取消、半关闭、丢弃/截断不会计为成功转交。

进程累计与会话计数使用有界无符号计数并定义溢出；重启后进程累计从零开始，不把持久流量历史当作已有能力。速率由两次单调时钟采样的差值除以实际间隔计算，单位 B/s；快照同时含进程实例 ID、采样时间与间隔，允许多个原子计数略有时间偏差，不声称全局强一致。会话关闭/删除时不重复计总量；汇总指标标签不使用任意域名/会话 ID。

## BEVE 原生 IPC

Linux/macOS 首选 Unix domain stream socket，Windows 使用仅本机的 byte-mode named pipe。由受限目录权限及 socket 权限或 named pipe DACL 控制连接，再验证 OS 提供的 peer UID/GID 或进程令牌/SID 与配置授权；组权限、身份获取和远程拒绝按平台逐项验证。不要只凭可预测路径名授权，也不能用未经校验的报文自称 UID。读、控制 selector、终止会话、重载配置分开授权；没有可用身份验证的后端默认拒绝。创建、重启和清理时防止跟随符号链接、覆盖别人的 socket 或误删其他实例的文件。

帧格式草案：**4 字节无符号大端 payload 长度 + 恰好一条 BEVE 消息**。长度不含前缀，拒绝零值和超过配置上限（建议 1 MiB）的长度，在分配前检查；按流读精确长度，处理半帧、合并帧、截断和超时。每连接限制未完成请求数、解码嵌套、字符串/数组大小和总字节；malformed/不支持版本返回有限错误或关闭连接。BEVE 是消息编码，不提供边界、版本、授权或机密性。

建立连接后先完成 `hello`：握手消息 envelope 的 `version=0` 表示版本协商，客户端提供可接受版本和能力，服务端以版本 0 响应选中的版本、实例 ID、能力与限额；不兼容即关闭。随后消息只使用已选版本。每个 envelope 至少包含 `version`、`kind`（request/response/event）、`request_id`、`operation` 和有界 payload；请求 ID 在连接内非零且不复用在途 ID，响应关联该 ID，事件用 0 并包含订阅 ID/序号。可用操作草案为 `stats.snapshot`、`sessions.list`、`selector.set`、`session.close`、`config.reload` 与 `events.subscribe`；只有授权且启用的能力可调用。响应包括成功值或稳定错误码及可公开诊断，不能传原始指针或 C++ 布局；操作 schema、Glaze 选项和版本兼容策略需锁定并保存样本。

IPC 和 HTTP 共同调用同一服务及授权决策，不默认具有相同 wire 格式。断线后客户端无法仅凭 request ID 判断可变操作是否生效，须查询状态或使用后续定义的幂等键；不得盲目重试造成重复副作用。订阅有最大数量/频率、队列字节和丢弃策略；慢消费者丢弃中间快照并报告序号缺口或断开。

## 验收

- 用固定版本的自有 API 客户端验证身份、跨源、只读与各控制权限、分页、订阅断线、selector 修改及重载成功/失败/恢复；保存兼容性样本。
- 以直接流、代理链、UDP 和加速路径注入已知字节量，对比双向计数、速度、失败和重启；并发关闭/selector 切换/路由发布保持一致的生命周期语义。
- 模拟慢消费者、错误 Origin、凭据泄漏路径、URL/JSON 边界、帧拆分、超长/截断、重复 ID、非法 BEVE、未授权账户、重载失败和网络配置失败；覆盖 Unix socket 和 Windows named pipe 各自身份与清理行为。
