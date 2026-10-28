# 接手记录

更新日期：2026-10-29。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- 系统 DNS 挂起时客户端预发数据并半关闭：VLESS 隧道收到完整上传、上游观察到 TLS 半关闭且下行成功；SS-2022 项目测试对端解码 `hello`、确认 TCP 半关闭并返回 `worldagain`。epoll/io_uring 单、双 worker 通过。
- VLESS/SS-2022 取消挂起系统 resolver 并等待其成功返回后，同一进程可建立新的隧道：VLESS 验证认证和双向传输，SS-2022 验证加密请求；epoll/io_uring 单、双 worker 通过。
- VLESS/SS-2022 系统 resolver 挂起时复位客户端，确认会话 socket 回收；解除阻塞并确认解析成功返回后，未拨打返回的地址，独立会话仍可进展。超时后停止仍等待阻塞 resolver 排空；epoll/io_uring 单、双 worker 均通过。
- HTTP/2 TLS 驱动在握手余量超过 4096 字节时立即失败并使已认领会话失效，避免先消费 HTTP/2 输出；超限缓冲释放及无网络输出在 epoll/io_uring 验证。
- HTTP/2 会话仅允许一个 TLS 驱动认领；重复驱动返回无效状态，取消或销毁被拒驱动不会影响原 socket 和会话。epoll/io_uring 及独立对端回归通过。
- HTTP/2 TLS 驱动销毁时使关联会话失效，包括没有待处理输入的空闲状态，防止协议会话被错误地绑定到新传输；空闲销毁和独立对端回归在 epoll/io_uring 通过。
- TLS 驱动读取截断、取消、超时或预算不足时使会话失效，挂起操作完成后归还输入预留；部分写入失败、暂停及输出背压交错均有回归。
- HTTP/2 TLS 输入在读取前预留 16384 字节共享逻辑额度；暂停输入与另一流响应竞争额度、恢复后释放均已验证。

## 当前

- HTTP/2 TLS 明文输入有最大记录逻辑预留；TLS 密文、输出、重组、异步写副本、容量、临时副本和传输开销尚无完整计费。

- HTTP/2 的 nghttp2、响应体、活动流、请求头及响应字段数组逻辑计费已有共享预算，尚无完整连接级预算；下一步核对应用数据及 TLS/传输缓冲的所有权和限额，再确定可执行的预算边界。

- 当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 固定 nghttp2 的 DATA chunk 回调只支持正常返回、暂停或连接级失败，流级取消需由应用在暂停后明确恢复并调用 `reset_stream`。回归已覆盖部分 DATA 帧暂停、取消后连接窗口回收与其他流进展；HTTP/2 的 TLS/Corosio 实验驱动已接通，已验证基本网络多流和 TLS 双向关闭，仍需验证更广泛场景。
- 地址工厂、socket quitter owner unwind 以及新的候选连接回归已通过。`connect_candidates` 只接受 `tcp_socket` 和 endpoint vector，公开结果为 error plus connected endpoint；上游组合模板和 Capy condition 现已导出并通过独立消费者测试。失败/取消关闭 socket；代理真实 resolver 候选上限、挂起连接超时和停止已覆盖，多挂起 accept/connect 及更复杂交错仍未覆盖。实际代理现按候选判策略并使用 Corosio 组合直连；隧道边界避免预分类后续候选，取消与超时的更广泛交错仍需验证。
- HTTP/2 无 I/O 服务端已修复跨流关闭时的响应 provider 生命周期；TLS/Corosio 握手和应用记录适配器仍保持既有验证范围。HTTP/2 实验驱动已与 Python/OpenSSL 简单对端互通；完整连接级预算、正式应用接入及更广泛的网络关闭验证仍未完成。

## 下一步

1. 补实际组合拨号的 resolver/连接 owner 回收、错误监视与隧道握手的更复杂交错；继续验证 VLESS/SS 停止异常、完成回调及共享会话生命周期的其他竞态。
2. 继续核对 Corosio/Capy 的 `io_context` stop/drain 在挂起 connect、跨线程和其他多操作下的 owner 语义。固定 Capy 的 `execution_context::shutdown()` 为 protected、非线程安全，由 `io_context` 析构调用；不能作为 worker 协调器公开屏障或代替完成任务的排空。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再以清楚描述改动的主题提交，并更新本窗口，只保留新的上一步/当前/下一步；`where` 不是必需前缀。
