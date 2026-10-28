# 接手记录

更新日期：2026-10-28。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- HTTP/2 共享额度纳入请求头逻辑计费（字段对象及名称和值字节）；头块释放 vector 并归还额度，超额重置流，后续流继续。分片及共享额度回收、nghttp2 会话、TLS 双后端互通回归通过；实际容器容量、TLS/传输及分配器开销仍未计入。

- 实际代理 UDP DNS 返回两个候选，首个目标监听队列饱和；通过 `/proc` 确认代理 socket 处于 SYN_SENT，再验证停止或 10 秒超时均不连接第二候选且首个连接未留在队列。epoll/io_uring 单、双 worker 通过。

- 实际代理系统 resolver 和 UDP DNS 的候选数边界已在 epoll/io_uring、单/双 worker 测试：64 项可连接，65 项拒绝且没有拨号，随后新会话可连接；既有系统地址回退测试通过。

- 实际代理挂起拨号的停止、10 秒期限及服务继续响应回归现已在 epoll 和 io_uring 的单/双 worker 通过；新增 `/proc` socket 描述符检查，确认入站和拨号 socket 回收。epoll 的 timerfd 可延迟创建，因此按 socket 而非总 FD 数比较。

- 实际代理在原生回环目标饱和队列下验证挂起直连：io_uring 单/双 worker 均能停止并在新端口重启；10 秒期限到达后返回 SOCKS 超时或由会话清理关闭，服务仍接受新握手，释放队列后无残留连接。现已在实际代理 epoll 配置下重复。

- 修正候选分类前发生 timeout 时可能丢失超时错误；原生回环监听器饱和队列触发真实挂起 connect，epoll/io_uring 验证 timeout、socket 关闭和不尝试下一候选；代理 SOCKS 回归通过。Corosio io_uring acceptor 预设 multishot accept，测试需原生监听器保持队列饱和。

- 代理直连候选循环加入会话启动后的 10 秒绝对 deadline；超时取消挂起 connect 并关闭目标 socket。Corosio epoll/io_uring 回归覆盖已过期 deadline、候选重试、失败回收和取消，代理目标构建通过。
- HTTP/2 共享额度回归覆盖两流竞争：第二响应先超额拒绝，第一流收到 RST 后归还额度并允许第二流提交；响应体保留时 PING 确认帧可耗尽同一额度，计数未越界。内存预算测试通过。

- HTTP/2 新增可配置共享额度，合计限制 nghttp2 活跃分配和响应体；直接拒绝超额响应，nghttp2 提交 OOM 后回收响应体。内存和会话回归通过；此额度仍不含头部、TLS、传输及分配器开销。

- HTTP/2 响应 DATA 帧部分输出后，交错接收对端 RST 并提交另一流响应；逐字节核对剩余帧内容和另一流完成，服务器会话回归通过。nghttp2 输出缓冲借用至下次发送调用；该场景未发现需要修改的实现。

- VLESS/SS 出站使用独立 stop source 和 quitter，移除 `canceled_` 与 await 后轮询；传输入口仍检查停止状态，显式取消底层 owner。真实 VLESS 挂起握手停止、候选顺序、链式转发及 SS DNS 超时/活动连接停止通过。受控阻塞系统解析测试对两种出站和单/双 worker 验证超时后服务响应，以及停止等待解析返回。
- VLESS/SS 入站双向子任务使用 quitter 和会话停止令牌，父任务等待两子任务完成后释放借用连接；VLESS 异常注入、活动连接停止、链式传输，SS 单/双 worker 停止、互通及半关闭通过。
- Mixed 转发使用 quitter 和会话停止令牌，完成回调收尾；单/双 worker 活动连接停止、半关闭、HTTP 上传及 VLESS 转发通过。代理直连已使用 Corosio `connect` 逐候选判策略，遇到隧道时暂停分类并在异步尝试后继续，真实错误顺序和隧道交错已验证。
- HTTP/2 TLS 驱动暂停输入期间可排空输出；真实 TLS 双流验证另一流响应、关闭后上传恢复，epoll/io_uring 通过。响应体精确大小分配，关闭、RST、提交 OOM 回收；nghttp2 有独立预算，尚无完整连接预算。

## 当前

- HTTP/2 的 nghttp2、响应体与请求头逻辑计费已有共享预算，尚无完整连接级预算；下一步核对头部、应用数据及 TLS/传输缓冲的所有权和限额，再确定可执行的预算边界。

- 当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 固定 nghttp2 的 DATA chunk 回调只支持正常返回、暂停或连接级失败，流级取消需由应用在暂停后明确恢复并调用 `reset_stream`。回归已覆盖部分 DATA 帧暂停、取消后连接窗口回收与其他流进展；HTTP/2 的 TLS/Corosio 实验驱动已接通，已验证基本网络多流和 TLS 双向关闭，仍需验证更广泛场景。
- 地址工厂、socket quitter owner unwind 以及新的候选连接回归已通过。`connect_candidates` 只接受 `tcp_socket` 和 endpoint vector，公开结果为 error plus connected endpoint；上游组合模板和 Capy condition 现已导出并通过独立消费者测试。失败/取消关闭 socket，但真实 resolver 并发候选、超时和多挂起 accept/connect 仍未覆盖。实际代理现按候选判策略并使用 Corosio 组合直连；隧道边界避免预分类后续候选，取消与超时的更广泛交错仍需验证。
- HTTP/2 无 I/O 服务端已修复跨流关闭时的响应 provider 生命周期；TLS/Corosio 握手和应用记录适配器仍保持既有验证范围。HTTP/2 实验驱动已与 Python/OpenSSL 简单对端互通；完整连接级预算、正式应用接入及更广泛的网络关闭验证仍未完成。

## 下一步

1. 补实际组合拨号的超时、候选上限、异步取消及 resolver/连接 owner 回收；继续验证 VLESS/SS 停止异常、完成回调及共享会话生命周期的其他竞态。
2. 继续核对 Corosio/Capy 的 `io_context` stop/drain 在挂起 connect、跨线程和其他多操作下的 owner 语义。固定 Capy 的 `execution_context::shutdown()` 为 protected、非线程安全，由 `io_context` 析构调用；不能作为 worker 协调器公开屏障或代替完成任务的排空。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再以清楚描述改动的主题提交，并更新本窗口，只保留新的上一步/当前/下一步；`where` 不是必需前缀。
