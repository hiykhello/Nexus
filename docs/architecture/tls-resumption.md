# TLS 1.3 PSK_DHE 1-RTT 材料与接口

本切片提供 socket-free 的双端票据恢复，以及客户端 external PSK。它复用原 TLS Hello、HRR、密钥派生、证书验证、记录和 Finished 算法。它不是完整 uTLS、浏览器身份或生产 endpoint 配置实现。

`nexus.protocols` 的 `tls-resumption` feature 显式引入恢复材料模块；普通 `tls` feature 只需要空的编译期模式定义。默认调用没有恢复实参，普通具体 owner 不保存恢复指针、optional、callback 或额外字段。启用路径由外层 owner 直接持材料，并把一个具体 policy 引用传入同一算法。

原 `obj.feed(bytes)` 一类默认调用源码保持。共享方法现在是默认空参数包的成员模板，其符号和方法地址取用方式会改变；不提供旧二进制 ABI 的兼容承诺。

## 客户端

- `ResumptionCache<Capacity>` 是调用者拥有的有界票据缓存。`take` 将一张匹配且未过期票据转移给一次尝试；失败不会把其 secret 暗中放回缓存。
- `make_ticket_binding` 用认证名称、精确 SNI、ALPN、CA 集合以及调用者配置代次 scope 绑定材料。新连接创建时再次按实际参数计算和核对，防止把另一服务、验证身份或信任配置的票据挪用。
- `PskClientPolicy<ResumptionTicket,Clock>` 与 `ResumingClientSession<Policy>` 直接组合必要材料和原 `ClientSessionHandshake`。首次握手、服务器拒绝 PSK 后的完整证书回退与真实恢复共用状态机。
- 按原 session 契约写完并确认每条出站记录。只有覆盖 client Finished 的恢复主密钥已派生且 Finished 已发送，才能 `take_application`。
- `ResumedApplication::open_event` 在原唯一 application record loop 中解析认证的 NewSessionTicket，将 nonce 派生的独立 PSK 交给指定 cache。普通 `ApplicationRecords::open_event` 仍丢弃有效票据，不持恢复状态。
- `ExternalPsk` 使用不同 binder 标签，客户端 policy 类型明确区分 external PSK 与 ticket resumption；external 成功不能报告为票据恢复。

Hello 最终 key share、扩展顺序和 padding 确定后才计算 binder；PSK extension 永远最后。HRR 更新 age、过滤散列不匹配或过期票据，并在原交换 owner 中按第一 Hello 的 synthetic transcript 重新计算 binder。

## 服务端

- `ServerTicketStore<Capacity>` 由一个 executor 拥有。所有借用它的 policy 和 issuer 必须遵守同一执行所有权，当前接口没有隐含跨线程锁或全局缓存。
- `ResumingServerHandshake<Store,Clock>` 直接组合原 `ServerHandshakeIo` 与必要 policy。恢复成功时省略 Certificate/CertificateVerify，并继续验证同一 Finished 算法。
- ticket 绑定精确 SNI、ALPN、credential chain 摘要与调用者 scope，服务器独立检查存储期限。opaque identity 是 CSPRNG 生成的 32B；secret 使用现有清理 `Secret`。
- 只有 client Finished 已验证并加入 transcript，才可 `take_issuer`。`ServerTicketIssuer::prepare` 使用单调 nonce、随机 age_add 和 opaque identity 产生待发送票据。
- `PendingServerTicket::publish` 必须在整条认证 ticket record 写完后调用；未发送或失败的 pending owner 不污染 store。成功 publish 只允许一次。

## 验证与成本边界

独立证据覆盖两散列 binder/票据的 Python HMAC/HKDF oracle、真实标准 OpenSSL 双端和 Go 五组密钥交换的认证与恢复、direct/HRR、服务器拒绝后的完整认证回退、坏 binder 拒绝、索引/散列/身份/SNI/ALPN/credential/过期负控。全流程 X25519 的 single-shot/persistent C++ 与真实 native 分配失败扫描同时检查同 store/cache 的新 owner 认证恢复；不能外推为所有随机执行路径或所有组的每个分配都已穷尽。

13 个普通 owner 布局保持。独立 `-O0 -freflection` 图的 29 个主要方法中，26 个在校准 callee 名称与重定位后指令相同；Exchange take_flight 的原局部 lambda 被内联，RawServer create 的证书局部生命周期和输出排列改变，Application open_event 的异常 cleanup 多一跳转。因此不声称所有 CPU、代码量、栈或异常路径都零成本。正式图仍须独立校准和验证。

当前 API 切片未接入完整生产 Budget、异步 adapter、endpoint/CLI 配置，也未提供 QUIC 恢复、psk_ke 或 0-RTT。不会通告未完成的 early_data 能力。完整 TLS 1.2、证书压缩和现代/历史浏览器 profile 继续属于后续原范围。
