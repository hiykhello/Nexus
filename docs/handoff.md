# 接手记录

更新日期：2026-10-28。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- 按用户建议导出 Capy 条件及 `std::is_error_condition_enum` using，并直接导出 Corosio `connect`；无上游头文件的独立消费者在 GCC 16 epoll/io_uring 下通过特化、重试、条件回调和取消测试。保留 `connect_candidates` 的失败关闭 socket 契约；泛型接口要求调用方处理失败清理。

- HTTP/2 TLS 驱动增加排空状态和发送 close_notify 的接口；Python/OpenSSL 实际连接验证两个并发流响应、两阶段 GOAWAY 与 TLS close_notify。测试主动立即进入最终 GOAWAY，未模拟 RTT 等待或等待对端关闭；正式应用接入与连接预算仍待完成。

- 新增实验性 HTTP/2 TLS/Corosio 单所有者逐步驱动，保留未消费明文，暂停后由应用恢复；Python/OpenSSL 实际连接验证证书、`h2`、分片 GET 以及 POST DATA 暂停恢复。驱动尚未接到正式应用，完整预算与更广泛关闭场景仍需验证。

- TLS 服务端握手支持要求单个 ALPN：验证完整客户端列表及匹配项，在加密扩展中发送选择，握手完成后开放结果；未配置时保持原行为。增量测试覆盖缺失、不匹配、畸形列表和重试；Corosio 与 OpenSSL `h2` 及无 ALPN 连接通过。HTTP/2 会话现已有实验性 TLS 网络驱动，尚未接入正式应用。

- HTTP/2 内存对端新增暂停 DATA 后恢复并取消流的回归：取消后另一条流上传 80,000 字节，验证连接级 WINDOW_UPDATE 和后续流进展。进一步在 DATA 帧首个负载字节暂停，恢复并排队取消后继续输入该帧余下字节；真实网络驱动仍未覆盖。

- HTTP/2 服务端新增应用主动 RST_STREAM 接口：排队后拒绝重复重置和响应，关闭回调时释放响应预算；暂停的 DATA 必须先恢复。内存对端覆盖已排队响应的取消、其他流继续、预算回收、重入和暂停边界。
- HTTP/2 无 I/O 服务端加入两阶段 GOAWAY 关闭：先通知、再用最后处理的流 ID 排队最终 GOAWAY，既有流可完成，输出及活跃流排空后报告完成。内存对端验证了两帧、响应及重复调用状态；等待 RTT、超时与实际传输关闭仍由未来驱动负责。
- HTTP/2 服务端增加 HPACK 编码动态表上限及解码表 SETTINGS 配置，默认均为 4096 字节，可设为零。内存对端确认零表设置并完成请求；设置生效前解码侧仍有协议默认值，尚未测量全部 HPACK 分配。
- HTTP/2 服务端新增自动 PING/SETTINGS ACK 队列上限，默认 64 帧，零值拒绝；停滞输出时的 PING 洪泛触发 nghttp2 `FLOODED` 并将会话置为失败。此项不是完整连接内存预算。
- HTTP/2 服务端流存储改为稳定地址：nghttp2 响应 DATA provider 持有流指针，先前 `vector::erase` 在关闭较早流时会移动后续流。新增并发响应回归，先重置前一个流、再读取后一个流；旧存储复现错误，新实现及 nghttp2 内存回归通过。
- 在当前切片中，Corosio Module 新增窄的 `connect_candidates` 包装：组合连接模板只在 Module 内实例化，失败与取消都会关闭最后一个 socket。独立消费者在 epoll/io_uring 下验证首候选失败后的重试、全失败回收、预取消不重试以及 context drain。
- 在 `f6762ff where:corosio.endpoint:export address factories and validate module boundary` 及 `5e2fa66 where:corosio.module:keep composed connect private until capy condition export` 中，Corosio Module 导出了 `make_endpoint`、`make_local_endpoint` 和格式识别；独立测试覆盖 IPv4/IPv6、缺省端口、非法输入、本地路径及路径长度。尝试导出组合 `connect` 时发现上游模板依赖未穿透 Module 的 Capy error-condition 特化，已撤回该公共导出并记录边界。隔离 GCC 16/io_uring 构建与运行通过。
- 在 `ff67327 where:capy.quitter:verify stop-aware owner unwind with async waker` 中，新增 `async_waker` 停止回归：Capy `quitter` 在 epoll/io_uring 下收到 stop 后执行 RAII unwind 并排空 owner。该证据限于无 socket 的等待器。
- 在 `f87bd45 where:capy.quitter:exercise socket cancellation before owner teardown` 中扩展为真实 `local_stream_socket` 挂起读；stop 后读取消、RAII owner unwind、socket 关闭和 context drain 在 epoll/io_uring 均通过。
- 上一个窗口完成 Capy 0.2.2 / Corosio 0.3.3 升级收口：代理 accept loop 使用值返回 `tcp_acceptor::accept()`，`reuse_port` 使用 Corosio 选项 API，FakeIP TCP 夹具使用 acceptor 便捷构造；I/O、代理、UDP、VLESS、FakeIP chain、reuseport 和故障回归已有通过记录。

## 当前

- 当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 固定 nghttp2 的 DATA chunk 回调只支持正常返回、暂停或连接级失败，流级取消需由应用在暂停后明确恢复并调用 `reset_stream`。回归已覆盖部分 DATA 帧暂停、取消后连接窗口回收与其他流进展；HTTP/2 的 TLS/Corosio 实验驱动已接通，已验证基本网络多流和 TLS 单向关闭，仍需验证更广泛场景。
- 地址工厂、socket quitter owner unwind 以及新的候选连接回归已通过。`connect_candidates` 只接受 `tcp_socket` 和 endpoint vector，公开结果为 error plus connected endpoint；上游组合模板和 Capy condition 现已导出并通过独立消费者测试。失败/取消关闭 socket，但真实 resolver 并发候选、超时和多挂起 accept/connect 仍未覆盖。曾试接代理 direct 路径，路由候选、系统 resolver fallback 和顺序测试通过，但预分类后续地址可能改变逐候选策略判断与错误顺序，故已撤回；现有代理仍逐地址拨号。
- HTTP/2 无 I/O 服务端已修复跨流关闭时的响应 provider 生命周期；TLS/Corosio 握手和应用记录适配器仍保持既有验证范围。HTTP/2 实验驱动已与 Python/OpenSSL 简单对端互通；完整连接级预算、正式应用接入及更广泛的网络关闭验证仍未完成。

## 下一步

1. 为实际拨号设计逐候选策略回调或其他保持原有路由及错误顺序的组合连接接口，再补超时、候选上限、异步取消和 resolver/连接的 owner 回收。
2. 核对 Corosio/Capy 的 `io_context` stop/drain 在 accept、connect 和多挂起操作下的 owner 语义，补最小回归。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再以清楚描述改动的主题提交，并更新本窗口，只保留新的上一步/当前/下一步；`where` 不是必需前缀。
