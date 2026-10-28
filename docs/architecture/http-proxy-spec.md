# 自研 HTTP/1.1 代理线规草案

状态：Linux 实验代理已实现有限的 HTTP/1.1 CONNECT 隧道和解析；有限的普通 HTTP 正向代理已实现；通用正向代理及 CONNECT-UDP 尚未实现。通用 HTTP framing、TLS 组合和后续 HTTP/2 边界见[HTTP 设计](http.md)及[决策 0005](../decisions/0005-http-stack.md)；Mixed 前缀识别与 SOCKS5 路径见[SOCKS5/Mixed](protocols/socks5-mixed.md)。

## 当前实现

`type="mixed"` 支持无认证 CONNECT，限定 IPv4、方括号 IPv6 或 ASCII 域名及必需端口，域名不作 IDNA 转换；Host 必须存在且与目标一致，Host 端口可省略。头部最多 16 KiB、100 字段、单行 8192 字节，严格使用 CRLF；拒绝 Content-Length、Transfer-Encoding、Proxy-Authorization、Expect 和 Upgrade。CONNECT 不支持的特性返回 501，畸形报文返回 400，超限返回 431，阻断返回 403，拨号/解析失败返回 502；拒绝后关闭连接。预读字节保留到 200 之后转发，同一握手 10 秒总时限和 64 会话上限适用。域名与解析出的 IP 均经阻断规则检查。系统解析器不可中断，停止可能等待其返回。

GCC 16/Linux 测试覆盖请求逐字节分片、报文尾部透传、客户端半关闭后接收目标响应、SOCKS5 共端口、IPv4/IPv6、域名解析与规则、非法请求、请求头限额、分段握手总超时、并发会话、连接失败及 curl CONNECT 互通。它不是通用 HTTP/1.1 解析器，尚未验证全部异常、并发和互操作场景。

普通 HTTP 路径支持一次 HTTP/1.1 请求，允许合法 token 方法及 Content-Length 或单一 chunked 请求体，接受 `http://` 绝对 URI，依据目标重建 Host 和 origin-form 请求行，丢弃逐跳头及 Connection 指定的字段，强制两侧连接关闭；Host 不一致时以 URI 为准。请求或响应含不支持的 framing、升级或代理认证会拒绝；不支持连接复用、请求升级或代理认证。支持单个 `Expect: 100-continue`，原样转发给上游并转发其 100 或最终响应；代理不自行生成 100，也不强制客户端等待。其他期望或重复 Expect 返回 417，`Connection` 不得指定 Expect。请求体与响应并发转发，所用缓冲有界；可及时转发上游提前返回的中间或最终响应。最终响应发送后先关闭客户端发送方向并丢弃剩余输入，最多等待 5 秒后回收连接，避免未读上传数据使已排队的响应被重置截断；期间仍占用一个会话额度。请求体畸形或提前 EOF 时向上游关闭发送方向，继续等待上游响应；已发出的请求内容无法撤回。HTTP/1.1 中间响应最多转发 8 条，剥离逐跳头；拒绝 101 升级及带 Content-Length 或 Transfer-Encoding 的 1xx。最终响应到来前上游断开、报文畸形或超过中间响应限额时返回 502。响应支持 Content-Length、单一 chunked 编码、HEAD/204/205/304 无体及关闭定界；204 允许且仅允许值为 0 的 Content-Length，205 仅允许值为 0 的 Content-Length，拒绝 Transfer-Encoding 和非零正文，304/204 拒绝 Transfer-Encoding；拒绝 Content-Length 与 Transfer-Encoding 同时出现或其他传输编码。请求和响应的 chunked 块增量校验大小、扩展、数据分隔符及 trailer，重写块大小并丢弃扩展和 trailer；拒绝 trailer 中影响消息定界或连接语义的字段；块大小行限 8192 字节，trailer 限 16 KiB、100 字段。完成消息后的额外字节不转发。响应头发出后若正文畸形或提前 EOF，则关闭连接，chunked 路径不会发送终止块，客户端可识别不完整响应；此前已发送的内容无法撤回。输入/响应头限 16 KiB、100 字段，逐次读取与写入有限缓冲。curl GET/POST（含 chunked 请求和 100-continue）、大正文、持续上传期间提前返回的大响应、会话回收、1xx 的及时转发及合包/拆包、错误 framing、截断、额外字节与停止经本地端到端测试；完整 HTTP 尚未实现。

## 请求解析与目标

使用有界增量解析器处理请求行、头部与消息体，支持任意 TCP 分片及一次读取中多个阶段的数据。请求行、字段数、单行长度、总头大小、耗时和在途缓冲分别设限；拒绝格式错误、含糊的 Content-Length/Transfer-Encoding 组合和请求走私风险。`string_view`/`span` 只能借用会话拥有的缓冲，跨异步交接前必须保证寿命或复制；仅在合适的已备缓冲场景减少分配，不承诺整个解析和转发路径零分配。

按请求类型校验 target：普通 forward proxy 的 absolute-form URI、CONNECT 的 authority-form `host:port`，以及 Host 与目标的一致性遵循 [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) 和 [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)。代理认证与访问策略在拨号前执行；Basic 凭据只是编码，未经保护的远程 HTTP 代理不能视作安全认证。对不支持的方法、升级和 malformed 请求明确拒绝，不能把它们错误转入隧道。

## CONNECT 生命周期

解析并鉴权 → 路由与能力检查 → 连接目标 → 写入成功响应 → 移交剩余字节和连接所有权 → 双向转发。目标连接失败要返回相应的代理错误，不能先回成功再假设已连通。只有成功响应的头部完成且语义允许交接后才结束 HTTP 消息解析；解析时预读的隧道字节须原样交给后续路径，不得丢失或重复。输出排队、部分写入、超时、半关闭与取消均按真实连接状态处理。

后续只在两端状态、加密封装、统计与平台条件允许时尝试 Linux `splice()`；它不是 CONNECT 必有行为，也不能绕过 TLS record 处理。普通 HTTP 请求仍按 framing 和连接复用规则处理，不因成功响应就一律移交裸套接字。

## CONNECT-UDP 的独立能力

[RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html) 的 UDP 隧道需要 URI Template、授权、目标处理与 [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) 的 HTTP Datagram/Capsule 语义。HTTP/1.1 使用 `GET` 和 `Upgrade: connect-udp`，成功时以 `101 Switching Protocols` 转换；HTTP/2 或 HTTP/3 则使用协商后的 Extended CONNECT，携带 `:protocol = connect-udp`。不能发送名为 `CONNECT-UDP` 的 HTTP/1.1 方法或用普通 CONNECT 的 200 响应冒充标准握手。

Capsule 依次包含 varint 类型、varint 长度和指定长度的内容；HTTP Datagram 类型的内容还包含 Context ID 和数据。必须正确区分 Capsule framing 与 DATAGRAM 内容，处理未知类型、长度超限、跨 read 分片、截断、背压、UDP 目标和生命周期。HTTP/3 还可使用不可靠 QUIC DATAGRAM；经 Capsule 的流式传输具有不同的可靠性和阻塞特性。两种承载与目标授权、大小限制和错误处理都需单独验证。

CONNECT-UDP 不是 Mixed 首期默认承诺，也不自动由支持普通 HTTP/1.1 或 SOCKS5 UDP 获得；启用前需完成目标协议的协商、代理限制、隔离互操作和资源验证。

## 验收

逐字节拆分头部和首段隧道内容，测试普通请求、CONNECT 的成功/失败、代理认证、混合 framing、超限、半关闭与取消；对照 RFC 样本和常用客户端互测。若实现 CONNECT-UDP，分别验证 HTTP/1.1 Upgrade、选定的 HTTP/2/3 承载、完整 Capsule 长度解析、不可达目标、过大数据报和授权失败。不得以仅能解析请求头宣称可代理或零拷贝。

经 VLESS/TLS 的关闭定界响应会重写为 HTTP/1.1 chunked；上游 HTTP/1.0 状态行同时升级。只有认证的 TLS 关闭才产生终止块，传输截断不产生终止块。直连关闭定界仍无法区分正常关闭和传输截断。普通请求仅接受 HTTP/1.1。
