# QUIC TLS 1.3 PSK_DHE 1-RTT 恢复接口

本切片把既有 socket-free TLS 恢复材料接到原 QUIC 状态 owner 和原 ngtcp2 回调，不引入第二套 Hello、HRR、KDF、Finished 或 ticket 派生算法。`quic-resumption` feature 显式启用；默认 QUIC owner 仍没有恢复 runtime 字段。它不提供 0RTT、生产 Budget、异步 endpoint 或 CLI 配置。

## 材料与认证所有权

`ClientResumptionSetup` 从同一 immutable borrowed PKI anchors/name/time snapshot 同时构造证书验证策略和票据绑定，再从调用者有界 cache 取走一个票据。绑定加入 QUIC 专用域和调用者 application scope，避免挪用 TCP 或另一配置的材料。QUIC start 再次核对这份绑定。调用者必须让借用的名称、anchors、cache 与 ALPN 在 owner 生命周期内保持有效且配置不变。

`ResumingTlsClient` 直接继承原 `TlsClient<ResumptionPki>`，只持一次具体 policy；`ResumingTlsServer` 直接继承原 `TlsServer`，只持服务器 policy。它们继承同一 start/receive 算法，未写另一个转发或解析循环。Connection callbacks 在编译期检测恢复材料能力，仅启用 owner 传一个直接 policy 引用；默认参数包为空。默认接口方法由模板承担，兼容原调用源码，不承诺旧二进制符号 ABI。

TLS 失败、异常和 Connection.stop 都清理 enabled 材料；stop 不依赖应用的 connection_closed 回调代清，即使 native 构造尚未成功也能取消这次尝试。调用者拥有的 cache/store 中已发布且有效的票据继续有效。

## 票据与发送边界

认证完成后的 NewSessionTicket 通过 1RTT CRYPTO 交给原唯一 handshake decoder，随后复用 `ResumptionCache::receive` 的 ticket parser、nonce PSK 派生和有界 admission。TCP `ResumptionReceiver` 也调用这个相同算法。

服务器只有验证 client Finished 并纳入 transcript 后，才能 take_issuer。PendingServerTicket 继续显式 publish；`ngtcp2_conn_submit_crypto_data` 复制到 native retransmit queue，仅证明排队成功，不证明 UDP 已发出或对端已认证接收。调用者须在自己的可验证发送/确认边界 publish。验证 fixture 使用对端已认证接收 ticket 后的应用消息作为障碍；丢弃或失败的 pending 不污染 store。

[RFC9001 §4.5](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.5) 允许在关闭 0RTT 时恢复，此时 QUIC 自身不要求记住旧 transport 参数。新连接使用当前认证参数；测试实际降低新连接额度。若将来启用 0RTT，必须另外实现旧 transport/application 状态、拒绝重置及重放策略。

## 必要协议校验

即使关闭 0RTT，[RFC9001 §4.6.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.6.1) 仍要求 ticket 若含 early_data，其 max 值只能为 0xffffffff。共享 parser 的静态 QUIC 分支执行此检查；presence 布尔值填入原 ticket view 的 padding，view 仍48B。合法 sentinel 可接收并保存，但当前客户端仍不发送 early_data offer。非法0、1或0xfffffffe返回 QUIC PROTOCOL_VIOLATION，不入 cache。普通无恢复 QUIC 的 ticket discard 路径也执行同一规则；TCP parser 不施加这个 QUIC 专用限制。

## 验证范围

独立测试包含三证书、五 group、三 cipher、direct/真实 HRR、首次与连续两次恢复、真实 Go IPv4/6 UDP、拒票后的 PKI 回退与再恢复、fragment/coalesced tickets、renewal、stream FIN/ACK/credit、DATAGRAM、错误分类、取消和同 cache/store 新 owner 认证恢复，并在 Go QUIC 测试对端核验 VerifiedChains/DidResume。标准 Go client 的 hybrid4588 配置会直接发送目标 share，不能用 `hrr` 参数名字证明实际 HRR；Nexus client 的空 share 和 native fixture 中均已验证真实 hybrid HRR。

校准 linker wrapper 先主动调用 TCP RecordLayer factory 证明拦截有效，再要求 QUIC 全路径 factory 次数0。分配故障使用真实 BoringSSL hook 与 C++ new，含 single-shot/persistent；每点验证 native/C++ live count/bytes 回基线并能用同 store/cache 新 owner 再次完成认证。先前收到但未在服务器发布的票据允许被拒后走完整 PKI 回退，cache 非空不意味着必须恢复。覆盖范围不等于所有随机执行路径或所有 group 每个分配的穷尽。

普通 QUIC client9088/server288，既有13owner及TCP policy1752保持；cache-enabled policy1760，enabled QUIC client10912/server456。独立 `-O0 -freflection` 图的主 owner body 保持原指令，但 ticket 接收分支多了上述必须校验，不声称所有代码/CPU/栈或正式图都零成本。
