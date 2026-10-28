# 接手记录

更新日期：2026-10-28。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- VLESS/SS 出站连接改为各自 stop source 加 quitter，删除 `canceled_` 及每次 await 后检查；传输入口仍检查停止状态，取消显式通知底层 owner。VLESS 挂起 TLS 后停止不尝试后续候选、重试/阻断/部分请求边界及链式传输通过；SS DNS 超时和活动连接停止互通通过。

- VLESS/SS 入站双向转发改用共享会话令牌和 quitter，完成/停止回调各减少一次在途计数；父任务继续等待两个子任务后释放借用连接。VLESS 双 worker 真实活动连接停止、四处异常注入及背压半关闭通过；SS 独立构建、单/双 worker 活动连接停止、互通及半关闭通过，VLESS 链式出站回归通过。

- Mixed 会话引入 stop source，握手、HTTP 上传/排空及双向转发使用同一停止令牌；转发切换 quitter，完成回调负责收尾。单/双 worker 活跃连接停止、重启、半关闭、HTTP 上传及 sing-box VLESS 转发回归通过；受控阻塞解析器仍等调用返回。出站停止源和底层 owner 的取消范围见最新记录。

- 代理直连已使用导出的 Corosio `connect`，逐候选判策略；遇到隧道或策略错误时暂不分类后续项，回到异步隧道后继续。真实代理覆盖拒绝/阻断/成功和失败 VLESS 与直连交错的顺序及错误；失败 socket 显式关闭。

- HTTP/2 真实 TLS 双流回归验证上传流暂停时另一流响应和关闭，暂停状态仍保持，随后上传恢复、两流完成；epoll/io_uring 均通过。

- HTTP/2 TLS 驱动在输入暂停时仍排空已排队输出，避免响应等待上传恢复；输出排空后报告暂停。真实 TLS 对端验证暂停期间提交和发送响应、随后恢复上传，epoll/io_uring 和既有会话/内存回归通过。

- 实际 Mixed 代理的受控系统解析回归新增正反候选顺序，验证阻断、连接拒绝与成功的组合，以及 SOCKS `REP=2/5` 和 HTTP `403/502`；已拨号失败优先于其他被阻断候选。成功与实际回环数据转发也已验证。此基准尚未覆盖隧道候选或取消。

- Corosio 多 owner 停止回归验证两个独立 accept 与本地读取同时挂起时，`stop()` 不完成操作；关闭操作 owner 并重启后排空取消，epoll/io_uring 均通过。对端同时关闭时读取可先得到 EOF。尚未覆盖挂起 connect 和跨线程竞态。

- HTTP/2 响应体改为精确大小的独占数组，新增 `response_memory_used()`；普通关闭、RST 和 nghttp2 响应提交 OOM 均验证回收。服务端、内存预算及 TLS/curl 双后端测试和行数检查通过。该计数不涵盖分配器开销、头部、TLS 和传输缓冲。

- HTTP/2 响应支持校验过的 `content-length`：普通响应必须匹配实际体积，HEAD/304 的表示长度由应用负责，204 禁止该字段。HEAD 不能发送响应体；初始请求头未完成前拒绝响应。内存分片测试及 curl HTTPS/HTTP/2 HEAD/GET 通过。

- HTTP/2 响应可提交有界普通响应头（默认 32 项、8192 字节）；拒绝伪头、大写或非法名称、非法值、连接专用字段；`content-length` 现已按响应语义校验。内存对端验证复制、空体、限额与拒绝；curl 验证 HTTPS 响应 `content-type`。

- HTTP/2 会话使用 nghttp2 自定义分配器，默认限制 4 MiB 活跃请求大小及计数头，支持配置并报告当前和峰值。测试覆盖初始化及提交 OOM、PING 洪泛触限和排空回收；TLS/curl 双后端回归通过。该预算不含 Nexus 缓冲、分配器开销及 realloc 临时副本，不是完整连接内存预算。

- HTTP/2 TLS 驱动区分网络操作超时与一般 TLS 错误；非阻塞 socket 的真实连接测试在 epoll/io_uring 下覆盖挂起读超时、主动取消及失败后拒绝复用，并用 curl HTTPS/HTTP/2 验证证书、ALPN 和响应。

- HTTP/2 TLS 驱动在报告排空或对端关闭时记录会话版本；若应用随后改变会话，关闭通知会被拒绝，必须重新驱动。真实 TLS 测试覆盖对端关闭后排队 GOAWAY 的过期状态，以及正常双向关闭、截断和多流。
- 按用户建议导出 Capy 条件和 `std::is_error_condition_enum` using，直接导出 Corosio 泛型 `connect`；无上游头文件的独立消费者在 GCC 16 epoll/io_uring 下通过重试、条件回调与取消。`connect_candidates` 仍提供失败时关闭 socket 的额外契约。
- HTTP/2 实验驱动已组合 Corosio、TLS `h2` ALPN 和 nghttp2 会话；Python/OpenSSL 测试覆盖分片请求、上传暂停恢复、两个并发流、两阶段 GOAWAY 与关闭通知。测试未模拟 GOAWAY 间 RTT 等待。

## 当前

- 当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 固定 nghttp2 的 DATA chunk 回调只支持正常返回、暂停或连接级失败，流级取消需由应用在暂停后明确恢复并调用 `reset_stream`。回归已覆盖部分 DATA 帧暂停、取消后连接窗口回收与其他流进展；HTTP/2 的 TLS/Corosio 实验驱动已接通，已验证基本网络多流和 TLS 双向关闭，仍需验证更广泛场景。
- 地址工厂、socket quitter owner unwind 以及新的候选连接回归已通过。`connect_candidates` 只接受 `tcp_socket` 和 endpoint vector，公开结果为 error plus connected endpoint；上游组合模板和 Capy condition 现已导出并通过独立消费者测试。失败/取消关闭 socket，但真实 resolver 并发候选、超时和多挂起 accept/connect 仍未覆盖。实际代理现按候选判策略并使用 Corosio 组合直连；隧道边界避免预分类后续候选，取消与超时的更广泛交错仍需验证。
- HTTP/2 无 I/O 服务端已修复跨流关闭时的响应 provider 生命周期；TLS/Corosio 握手和应用记录适配器仍保持既有验证范围。HTTP/2 实验驱动已与 Python/OpenSSL 简单对端互通；完整连接级预算、正式应用接入及更广泛的网络关闭验证仍未完成。

## 下一步

1. 补实际组合拨号的超时、候选上限、异步取消及 resolver/连接 owner 回收；继续验证 VLESS/SS 停止异常、完成回调及共享会话生命周期的其他竞态。
2. 继续核对 Corosio/Capy 的 `io_context` stop/drain 在挂起 connect、跨线程和其他多操作下的 owner 语义。固定 Capy 的 `execution_context::shutdown()` 为 protected、非线程安全，由 `io_context` 析构调用；不能作为 worker 协调器公开屏障或代替完成任务的排空。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再以清楚描述改动的主题提交，并更新本窗口，只保留新的上一步/当前/下一步；`where` 不是必需前缀。
