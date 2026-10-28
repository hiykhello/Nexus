# Nexus 原生控制面与 BEVE IPC

状态：**设计草案，未实现**。控制面以 Nexus 的会话、路由、出口、配置代次为模型，参考本地 sing-box `a6952ccf6907c18e18917fcb763a433e8e36937b` 的组件状态、统计和生命周期处理，使用自定义原生 API；不以 Clash API 或特定仪表盘兼容为目标。HTTP/JSON 与本地 BEVE IPC 共享窄服务接口，不直接拥有数据面对象，也不能绕过路由、资源或权限校验。

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
