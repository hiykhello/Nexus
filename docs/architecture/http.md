# HTTP/1.1、HTTPS 与后续 HTTP/2

状态：HTTP/1.1 与 HTTPS 自研方向已确定；HTTP/2 接入优先级已提高，当前已加入固定 libnghttp2 1.70.0 的可选包、模块封装及实验性无 I/O 服务端会话，内存测试覆盖头部限额、DATA 事件和分片驱动；运行时 h2 适配仍未完成。实验代理已有有限的 HTTP/1.1 CONNECT 解析与隧道及有限的单请求 HTTP 正向转发（包括定长和 chunked 请求/响应及 100-continue）；通用 HTTP framing、HTTPS 和 HTTP/2 尚未实现。具体完整特性和默认限额仍为草案。方向见[决策 0005](../decisions/0005-http-stack.md)。

## 分层与复用

HTTP/1.1 自行实现增量解析、编码、消息边界及连接状态，不将第三方 HTTP 库或解析器作为其实现。HTTPS 由该 HTTP 层叠加[自研 TLS](tls.md)、证书验证和异步流组成，两个方向均沿用该分层。密码底座按[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)采用 BoringSSL libcrypto，具体接入仍待验证。

后台用途的具名客户端及配置依赖见[具名 HTTP 客户端设计](http-clients.md)，目前仍是草案。

当前 chunked 解码器可报告消费的输入长度，使调用方保留后续消息的预读字节；它仍输出经验证的 chunked framing，不提供完整连接复用。实验性异步 TLS 客户端已使用现有 HTTP 响应解析器验证 OpenSSL 的关闭定界响应，这尚不是正式 HTTPS 客户端。

无 socket 响应状态机组合现有响应头和 chunked 校验，逐步报告输入消费量与重写后的输出；支持中间响应、HEAD、定长、chunked 和关闭定界，调用方必须区分认证关闭与截断。每步最多处理 16 KiB，最多接受八条中间响应。GCC 16 分片、边界与 EOF 测试及异步 TLS/OpenSSL 关闭定界互操作通过；Mixed 普通 HTTP 正向代理也已使用该状态机，并通过转发、上传与 Expect 回归。输出沿用代理的 `Connection: close` 策略，尚不提供连接池或正式 HTTPS 调度。

私有 `https_exchange` 将已认证 TLS 连接与该状态机组合为一次请求，默认要求 `http/1.1` ALPN，调用者可以显式允许对端不选择 ALPN；输出通过同步、非重入回调分段交付。调用方负责建立连接、验证身份、构造请求、管理期限和对象寿命；结果不可用于连接复用。GCC 16 io_uring/OpenSSL 验证了大请求、关闭定界、定长、chunked 和无正文响应，以及截断、畸形 chunk、ALPN 缺失和回调拒绝；广泛故障注入及正式业务接入仍待验证。

| 边界 | 职责 |
| --- | --- |
| HTTP 公共模型 | method、URI/authority、状态码、字段、body/trailer 事件及应用语义 |
| HTTP/1.1 核心 | 增量字节输入、语法/消息长度、编码、连接复用及切换状态 |
| HTTP/2 适配（未来） | libnghttp2 session、帧/流事件、HPACK、流控及错误映射 |
| 异步连接驱动 | Corosio 部分读写、背压、deadline、取消、TLS 流与输出寿命 |
| 应用适配 | 正向代理/CONNECT、规则集获取、可选管理接口和 HTTP 承载各自的策略 |

公共模型不暴露 nghttp2 对象，也不将 HTTP/2 的所有语义硬套为 HTTP/1.1 文本消息。不同用途声明支持的 method、消息大小、重定向、认证和内容编码；共享协议实现不代表同时实现浏览器、通用 Web 服务器和完整缓存代理。

## HTTP/1.1 状态与消息边界

核心接收字节片段与显式 EOF，返回已消费长度、需要更多数据、头/体事件、消息完成或错误。输入和输出均支持部分处理；头部、chunk、body 与下一条消息可能落在同一缓冲中，不能丢掉剩余字节。解析器可暂停，body 以有界片段传递，不能要求收齐整个响应后才转交。

消息 framing 以 [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html) 为规范依据；方法、状态与 CONNECT/Upgrade 的含义依据 [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)。实现前固定采用章节和勘误，以下是重点验收范围，不宣称已经完整实现规范：

- 请求行、状态行、请求目标各种形式、字段名称和值、CRLF 及严格语法策略。
- Content-Length、Transfer-Encoding、chunked、trailer 和关闭定界，区分无 body 与零长度 body。
- HEAD 响应、1xx/最终响应、204/304 及成功 CONNECT 对 framing 的影响，绑定对应请求上下文判断。
- 不同消息长度描述的冲突与重复字段，绝不将有歧义的输入继续透传成另一端的不同消息边界。
- chunk 长度及计数溢出、提前 EOF、部分 header/body、管线化消息和持久连接边界。

安全草案采用严格接收策略：拒绝不支持/有歧义的 TE/CL 组合、非法长度和折行，不先“修复”后盲目转发。字段保留顺序与重复值信息，不能用单值 map 隐去 framing 冲突；按字段定义处理组合，不合并 Set-Cookie 等不适用字段。

代理适配负责验证 target/Host/authority 一致性、逐跳字段及 Connection 指定字段、代理认证作用域。协议核心不得把字符串拼接当作 header 编码，写入路径也检查注入和长度。首期若不支持 pipelining、多种 Transfer-Encoding 或特定 Upgrade，应明确策略并安全结束连接，不能错位解析下一请求。

## HTTPS 与 CONNECT

HTTP/1.1 over TLS 继续由 Nexus 完成握手、验证身份和 HTTP 处理。连接地址、SNI、验证名称与 HTTP authority 分别建模，连接池不能因同一 IP 就跨身份或代理凭据复用。

HTTP 正向代理建立 CONNECT 后，成功应答完成才切换为隧道；应答和隧道首字节相邻时保留预读内容。通过 CONNECT 转发客户端 HTTPS 时，隧道内 TLS 属于客户端与目标，代理不自动终止或解密它。自研 HTTPS 不等于加入透明解密功能。

TLS ALPN 只通告实际可用的应用协议。尚未接入 HTTP/2 时不能为追求握手指纹通告 h2 后继续按 HTTP/1.1 解析；版本选择是连接建立状态的一部分，协商后的数据不能任意回退重解码。

## 后续 libnghttp2 接入

nghttp2 官方说明核心库不执行网络 I/O，接收输入字节、产生输出字节，并通过回调交付协议事件，适合放在自有运行时中。此处“纯状态机”指无 socket/TLS/event-loop 的协议边界，不是无内部状态、无分配或所有应用策略均由库完成。[官方架构说明](https://nghttp2.org/documentation/programmers-guide.html)

接入时优先评估 `nghttp2_session_mem_recv2` 与 `nghttp2_session_mem_send2`，具体 API 以锁定版本为准。适配层维护 consumed 长度、暂停与恢复；库输出 buffer 具有受限寿命，下一次取输出前必须完成发送或复制到有预算的自有队列，不能持有它跨异步写入后又驱动下一次发送。[输入 API](https://nghttp2.org/documentation/nghttp2_session_mem_recv2.html)、[输出 API](https://nghttp2.org/documentation/nghttp2_session_mem_send2.html)

每个 session 的驱动串行化；回调中提交允许的事件/帧，返回后再驱动输入输出，不从回调重入 send/recv。NGHTTP2 的 C 回调不承载可挂起协程，错误映射为公共 expected/事件，并避免异常穿越 C 边界。

适配器还需处理连接/流两级窗口、消费后窗口更新、DATA 延迟供应、RESET、GOAWAY 和流生命周期；头列表、HPACK 状态、并发流、待发送 body 与控制帧开销全部计入预算。单流超时不能直接销毁承载其他流的 session。GOAWAY 后重试依据请求是否已执行、幂等性与 body 可重放性，不能自动重发任意请求。

仅引入 libnghttp2 核心库，工具、示例服务器和它们使用的 TLS/事件循环不进入 Nexus 运行依赖。当前通过 `xmake f --http2=y` 启用固定包和实验性内存服务端会话。会话同步交付借用的头部与 DATA，调用方必须在回调返回前处理数据；输出复制到调用方缓冲区，禁止驱动重入。并发流 SETTINGS 和头块限额尚非完整的会话内存预算；响应提交现支持有界空体和会话拥有的有界响应体，数据经 nghttp2 provider 分片读取；重复提交、未知流、单响应超限和并发响应总预算超限均被拒绝。输入 DATA 回调可暂停，调用方必须显式恢复后再提交后续输入。接收侧关闭 nghttp2 自动窗口更新，`accepted` DATA 在回调内确认，`pause` DATA 由 `resume_input` 确认；`ServerLimits::outbound_ack_frames` 还限制输出停滞时自动排队的 PING/SETTINGS 确认帧，超限会使会话失败。HPACK 编码动态表上限配置给 nghttp2，解码动态表上限通过 SETTINGS 通告；对端确认之前解码表仍按协议默认值处理。内存对端已验证零表大小的 SETTINGS 和后续请求，尚未测量全部 HPACK 分配或恶意对端的资源使用。两阶段关闭接口先排队 GOAWAY 通知，再以最后处理的流 ID 排队最终 GOAWAY，并继续处理已接受的流；调用方负责发送通知、等待在途请求、排空输出和关闭传输。异步输出背压和连接级完整总内存预算尚未实现。HTTP/2 网络连接驱动、TLS ALPN、应用适配、h2c、扩展 CONNECT 和服务器推送仍未实现，不能通告 h2。

## 资源、停止与验收

头部字节/数量、请求行、单字段、chunk 扩展、trailer、body 队列、活动连接/流和池有独立预算；body 可流式处理，业务文件大小限额由调用者设定。头部/body 进度超时和完整操作 deadline 分开，持续滴入字节不能无限占用资源。解析工作每轮有预算，防止始终就绪的连接独占执行器。

HTTP/1.1 连接只有消息边界明确、无未处理输入/输出且按策略可复用时进入池；取消、未读 body、framing 错误和关闭定界响应需明确排空或关闭。共享 session 停止先拒绝新操作，再按期限排空与取消，最后销毁协议状态和 TLS/底层连接。

验证从分割到每字节的固定报文开始，覆盖恶意 framing、重复字段、请求走私差异、EOF、首包、背压、超时和池复用。HTTPS 加入证书负例、ALPN 与独立实现互操作；HTTP/2 后续增加流控、HPACK 资源、RESET/GOAWAY 和驱动不重入测试。自实现两端互通不能单独证明正确，验收入口见[网络验证](../planning/network-validation.md)。
