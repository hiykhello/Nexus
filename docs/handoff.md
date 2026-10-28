# 接手记录

更新日期：2026-10-28。仅保留动态接力窗口：上一步、当前、下一步。固定约束和完整能力说明分别见[实施路线](planning/roadmap.md)、[构建说明](build/xmake.md)及专题文档。

## 上一步

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
- 地址工厂、socket quitter owner unwind 以及新的候选连接回归已通过。`connect_candidates` 只接受 `tcp_socket` 和 endpoint vector，公开结果为 error plus connected endpoint；上游组合模板和 Capy condition 现已导出并通过独立消费者测试。失败/取消关闭 socket，但真实 resolver 并发候选、超时和多挂起 accept/connect 仍未覆盖。曾试接代理 direct 路径，路由候选、系统 resolver fallback 和顺序测试通过，但预分类后续地址可能改变逐候选策略判断与错误顺序，故已撤回；现有代理仍逐地址拨号。
- HTTP/2 无 I/O 服务端已修复跨流关闭时的响应 provider 生命周期；TLS/Corosio 握手和应用记录适配器仍保持既有验证范围。HTTP/2 实验驱动已与 Python/OpenSSL 简单对端互通；完整连接级预算、正式应用接入及更广泛的网络关闭验证仍未完成。

## 下一步

1. 为实际拨号设计逐候选策略回调或其他保持原有路由及错误顺序的组合连接接口，再补超时、候选上限、异步取消和 resolver/连接的 owner 回收。
2. 核对 Corosio/Capy 的 `io_context` stop/drain 在 accept、connect 和多挂起操作下的 owner 语义，补最小回归。
3. 回到 HTTP/2 流生命周期、连接级预算、输入/输出背压，再接 TLS ALPN、Corosio 应用记录和独立网络对端。
4. 每完成一个切片，先运行与范围匹配的验证，再以清楚描述改动的主题提交，并更新本窗口，只保留新的上一步/当前/下一步；`where` 不是必需前缀。
