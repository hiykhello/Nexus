# 接手记录

更新日期：2026-10-29。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

- TLS 握手解码器、记录分帧器、Hello 流、客户端和服务端握手及 I/O 包装层的异常失效已加固；真实加密记录、HelloRetryRequest、服务端 ClientHello 和 Finished 的逐位置分配失败回归通过，服务端 OpenSSL 互通通过。
- Corosio 客户端、服务端握手及客户端 owner 在异常时失效并回收状态；读写抛异常、挂起读取时对端关闭、取消、超时及服务端 OpenSSL 互通已验证。
- 服务端异步握手已验证客户端 Finished 与首条应用记录同次读取的交接，包括写入后立即关闭对端；未消费密文由应用记录正确解密。
- TLS 应用记录、无 I/O 和异步连接异常时失效并清理；HTTP/2 TLS 逻辑预算覆盖主要输入、输出和暂存缓冲，但并非完整内存上限。

## 当前

- HTTP/2 TLS 明文输入和应用输出密文/写副本有逻辑预留；TLS 输出控制记录及写副本也有逻辑预留；输入密文记录也有逻辑预留；步骤输出数组也有逻辑预留；常驻读取缓冲也有逻辑预留；握手重组、容量、协程帧、临时副本和传输开销尚无完整计费。

- HTTP/2 的 nghttp2、响应体、活动流、请求头及响应字段数组逻辑计费已有共享预算，尚无完整连接级预算；下一步核对应用数据及 TLS/传输缓冲的所有权和限额，再确定可执行的预算边界。

- 当前分支为 `main`，远端 `origin/main` 没有可追踪分支。
- 固定 nghttp2 的 DATA chunk 回调只支持正常返回、暂停或连接级失败，流级取消需由应用在暂停后明确恢复并调用 `reset_stream`。回归已覆盖部分 DATA 帧暂停、取消后连接窗口回收与其他流进展；HTTP/2 的 TLS/Corosio 实验驱动已接通，已验证基本网络多流和 TLS 双向关闭，仍需验证更广泛场景。
- 地址工厂、socket quitter owner unwind 以及新的候选连接回归已通过。`connect_candidates` 只接受 `tcp_socket` 和 endpoint vector，公开结果为 error plus connected endpoint；上游组合模板和 Capy condition 现已导出并通过独立消费者测试。失败/取消关闭 socket；代理真实 resolver 候选上限、挂起连接超时和停止已覆盖，多挂起 accept/connect 及更复杂交错仍未覆盖。实际代理现按候选判策略并使用 Corosio 组合直连；隧道边界避免预分类后续候选，取消与超时的更广泛交错仍需验证。
- HTTP/2 无 I/O 服务端已修复跨流关闭时的响应 provider 生命周期；TLS/Corosio 握手和应用记录适配器仍保持既有验证范围。HTTP/2 实验驱动已与 Python/OpenSSL 简单对端互通；完整连接级预算、正式应用接入及更广泛的网络关闭验证仍未完成。

## 下一步

- 继续核查客户端侧握手成功后的应用记录交接及取消、对端关闭的更复杂交错；组合拨号与隧道握手仍需扩大 owner 回收验证。

1. 补实际组合拨号的 resolver/连接 owner 回收、错误监视与隧道握手的更复杂交错；继续验证 VLESS/SS 停止异常、完成回调及共享会话生命周期的其他竞态。
2. 继续核对 Corosio/Capy 的 `io_context` stop/drain 在挂起 connect、跨线程和其他多操作下的 owner 语义。固定 Capy 的 `execution_context::shutdown()` 为 protected、非线程安全，由 `io_context` 析构调用；不能作为 worker 协调器公开屏障或代替完成任务的排空。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再以清楚描述改动的主题提交，并更新本窗口，只保留新的上一步/当前/下一步；`where` 不是必需前缀。
