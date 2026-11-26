# TCP Fast Open 接入边界

目标是让各使用物理 TCP 的出站共享 Fast Open，同时保留一个连接期限、候选地址顺序、取消、半关闭和首写背压。当前 direct、SS-2022、Snell、Trojan、AnyTLS 与 VLESS 物理出站开放配置。

Linux `TCP_FASTOPEN_CONNECT` 在没有 cookie 时立即发送 SYN；已有 cookie 时 `connect` 可以立即返回，直到首次写入才发送 SYN。直接在现有 `prepare_tcp_socket` 设置该选项会改变 `connect_until` 的成功含义：SOCKS/HTTP 可能在内核握手前报告成功，先读后写的服务也可能一直等待。直接设置 socket 选项不足以实现现有连接契约。

延迟连接式 TCP Fast Open（启用后先返回流对象，首次写入才携首批数据拨号，空首写回退普通拨号）必须与既有绝对期限、候选重试和取消语义严格兼容，绝不因等待首写而丢失超时与取消控制。

现有内部 `tcp_fast_open` 为非空首写使用 `MSG_FASTOPEN`，等待可写并检查 `SO_ERROR`，返回已接受字节和错误；空首写普通连接，候选循环只在无字节接受时重试，内核不支持时同候选普通连接回退。双 backend、双族、首写/部分写、读先行、拒绝、候选重试、禁用 TFO 回退和隔离黑洞期限/取消已做真实 socket 验证；实际出现连接拒绝但内核先接受 32 KiB，证明错误时不能假设零提交。支持范围见 [支持矩阵](../planning/proxy-kernel-support-matrix.md)。

内部 `FastOpenStream` 已持有候选与连接期限：首次写入可携带数据连接，读先行、空首写和半关闭走普通连接；单 executor 的一个读者和一个写者共享连接并保留首写偏移。双 backend、双族实际并发读写、半关闭、连接期限后继续读写及黑洞取消已窄验证；所有者仍须在销毁前取消并排空，单操作放弃和更多故障尚待。该流已被 TLS、SS、VLESS、AnyTLS、Snell 和 direct 物理路径复用；完整协议故障矩阵仍待。

`FastOpenPhysicalConnector` 已组合 TLS ClientHello、上述流及字节流适配器，TLS 失败后保守停止而不尝试另一个候选；握手、取消及期限的双 backend 窄检查见本日接手。Trojan、AnyTLS 和 VLESS 物理出站通过 `tcp-fast-open #true` 使用该连接器；SS-2022 和 Snell 使用同一延迟流首写加密请求，支持各自 TCP 和流承载数据报。VLESS 的 Vision 使用适配器执行直通读写，其新生产路径的实际直通状态仍待独立观察。direct 对 HTTP 已读/改写数据及有序嗅探前缀用 TFO 拨号并避免重放；无前缀时普通连接，以保持 SOCKS/HTTP 成功响应的既有语义。带 detour 时拒绝本节点配置；显式 direct detour 使用 direct 的物理选项，其他 detour 的物理连接属于下层。

隔离网络命名空间的 IPv4 loopback 抓包已观察到首次无 cookie SYN 为空、获得 cookie 后的 SYN 携带 32768 字节。这不代表其他网络或协议的 SYN 必然带数据。

验收仍需按各协议和路径覆盖有/无 cookie、服务端支持/拒绝、黑洞、读先行、空写、部分写、超时和取消；仅 `setsockopt` 成功或普通连接成功不是 Fast Open 证据。
