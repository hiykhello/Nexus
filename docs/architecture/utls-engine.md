# ClientHello 指纹编排设计

状态：**第 94C 批的浏览器 TCP/QUIC 形状、同连接版本协商和 TCP 1-RTT 恢复已通过双后端定向验收**。自研 TLS 将 ClientHello 的协议内容与可选 profile 分开。profile 控制扩展、顺序、GREASE 和填充，证书验证独立执行。真实浏览器的指纹随版本、平台与网络条件变化。

## 当前实现与证据

`tls.hello_config` 单一提供原有 `make_client_hello`，旧模块继续重导出原API；`tls.fingerprint` 提供同步 `FingerprintConfig` 与 `make_fingerprint_hello`。Nexus 提供 `native`、`tls13-grease`、`tls13-randomized` 及具名浏览器 TLS 1.3 形状，具体配置见 [KDL 规范](../configuration/spec.md)。实现允许已支持套件顺序、CSPRNG GREASE、拒绝采样的扩展排列、TCP session ID 和有界padding；ALPN由实际协议调用方提供。普通TLS ClientProfile通过显式handshake overload使用策略，默认profile不新增存储字段。

TCP、QUIC和Reality共用同一编排与密钥交换算法。单/双真实X25519与MLKEM share保存在原两个key owner中，按服务端选择取用；HRR保留随机/顺序并按新share重新计算padding。QUIC保持空session ID，替换真实local transport parameters后重新计算最终wire大小；QUIC 包保护支持 AES-128-GCM、AES-256-GCM 和 ChaCha20-Poly1305。生产 Hy2 出站使用 Firefox 形状，分别在 OpenSSL 4.1 强制这三种套件时完成认证握手。epoll 与 io_uring 均覆盖 IPv4 和 IPv6，记录在 `target/batch73/quic-suites`。Reality的新groups span overload与旧scalar factory共享同一首Hello认证，不改变证书/Finished校验；固定参考端的强制cover HRR仍为明确拒绝边界。

独立冻结基础包 `/tmp/nexus-utls-engine-S6BV5P/frozen-v1` 已按21file SHA纳工作区：108个OpenSSL认证/错名/错CA场景逐次观察实际1600B ClientHello，48个真实Go UDP QUIC场景及校准wrapper下另48个均通过（TCP RecordLayer构造0）。另有2738逐次普通/array/aligned C++分配失败及恢复、24密钥调度、64随机shape和3旧TLS单元。共享 Reality addon 独立 auth 48 与实际对端 12（8 正向 + 4 强制 cover HRR 拒绝）通过。正式构建与运行状态见 [项目进度](../progress.md)，不把独立结果当当前正式图通过。

同编译参数下原/新对象尺寸均为Hello136、Exchange8232、Driver8432、Session9856、ClientProfile88、QUIC TlsClient9064字节。新增编排不含任务或协程、虚派发、额外heap owner或隐藏实现存储；算法产生的配置/编码/密钥分配是必要协议工作，不能据此声称指令等价、网络握手零分配或nativecrypto OOM全覆盖。具名浏览器原始样本、更广 TLS 版本和 PSK/0-RTT 验证仍在推进。

`tls-certificate-compression` 构建特性为 TLS 1.3 客户端添加 zlib、Brotli 和 Zstandard 解压。Chrome 和 Edge 通告 Brotli，Safari 通告 zlib，`tls13-randomized` 通告三种算法。压缩消息的编码仍进入 transcript，解压后的证书链走既有信任、主机名和 CertificateVerify 校验。解压结果必须精确等于声明长度，并受各承载的证书限制。epoll 和 io_uring 分别对 OpenSSL 4.1 验证了 TCP 与 QUIC 的三种压缩认证握手，TCP 同时覆盖无压缩回落和错名拒绝。关闭特性的 epoll 组合产物无需 Brotli 或 Zstandard，SRS 仍使用 zlib。日志见 `target/batch73`。[RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html)

Trojan 和 AnyTLS TCP 出站的显式 `tls12` 形状使用完全握手、扩展主密钥和 AES-GCM。epoll 与 io_uring 对 OpenSSL 4.1 及 TLS 1.2-only AnyTLS 对端验证了 X25519、RSA-PSS、RSA PKCS#1、P-256/P-384/P-521 ECDHE/ECDSA、跨记录转发和逻辑 FIN。日志见 `target/batch73/tls12-*`。[RFC 8422](https://www.rfc-editor.org/rfc/rfc8422.html)

第 94C 批提供 `chrome-133`、`firefox-135` 和 `safari-18`，沿用家族短名。普通浏览器 TCP 握手由同一 ClientHello 的 ServerHello 选择 TLS 1.3 或 TLS 1.2。1.2 路径使用四个 ECDHE AES-GCM 和两个 ECDHE ChaCha20-Poly1305 套件。QUIC 浏览器形状只协商 TLS 1.3，使用实际 transport parameters。Chrome、Edge 和 Firefox 的 GREASE ECH 在显式 ECH 握手中让位。Chrome 和 Edge 的 TCP h2 ALPS 以 EncryptedExtensions 进入 Finished transcript。Firefox 委托凭据当前覆盖 ClientHello 声明，服务器选用委托凭据时仍缺验证实现。OCSP 与 SCT 的 TLS 报文解析沿用现有 PKI 认证策略。

普通物理 TCP 出站的 TLS 1.3 恢复缓存容量为 32 张票据，按实际目的端点、验证身份、信任锚及 ALPN 隔离，取出即消费，按期清理。普通 VLESS 按配置目的绑定恢复。通用 Fast Open 和 layered 拨号未启用该共享缓存，Vision 与 REALITY 保留专用握手路径。TCP 应用数据在 Finished 后发送。实网和字节快照见 [第 94C 批](../planning/batch94-protocols-xhttp-utls-design.md#94c--utls-高保真现代浏览器指纹补强)。

## Profile 与握手语义

先定义稳定的握手描述：版本与 cipher、SNI、ALPN、supported groups、key shares、签名算法、session tickets、扩展及其顺序。profile 从该能力集中选择与排列，TLS 状态机负责实际的握手和认证；用户要求尚未实现或不安全的组合时拒绝，不生成无法完成握手的伪报文。TLS 1.3 要求某些扩展遵循特定顺序和语义，PSK binder、重试和 transcript 等不能只靠重排字节处理。

只通告真正支持的 ALPN：例如 HTTP/2 未实现时不可为了拟真宣称 `h2`。SNI、验证名、信任根独立配置；profile 不等于服务器身份验证。对 HTTP/2、TCP 指纹、时间、证书与上层请求的观察也会影响识别，JA3/JA4 摘要不是浏览器完整行为的证明。

## GREASE 与混合密钥交换

按 [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) 选择保留的 GREASE 值以检验扩展性；不同字段的选择、出现位置与随机策略按目标 profile 和标准约束定义，不能假设所有版本使用同一个固定布局。一个扩展块中不得重复同一扩展类型；不应通过静默重试移除 GREASE 来掩盖互操作失败。

如实现 `X25519MLKEM768`，按 [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) 的目标版本验证编码：客户端 key share 为 ML-KEM-768 公钥 1184 字节在前、X25519 公钥 32 字节在后；服务端为 ML-KEM 密文 1088 字节在前、X25519 公钥 32 字节在后。名称顺序不等于字节顺序。组合 secret、无效公钥、握手重试与算法协商均须遵守规范并用向量测试；BoringSSL 固定提交是否提供所需 API、具体浏览器 profile 是否采用该组都需验证，不能只填充随机字节冒充真实密钥交换。

Padding 仅在 profile 和协议允许时应用，计算包含各层长度字段的完整编码；不得假设 1024–1536 字节是普适的真实浏览器分布。缓冲必须有界，超过容量返回可诊断错误；`std::inplace_vector` 只影响一个容器的分配，不保证密码、证书或整个握手零堆分配。

## 验收

为每个声明支持的 profile 固定参考浏览器版本、平台、配置与原始样本，解析后比较扩展内容、顺序分布、GREASE、key share、padding、分片及完整握手；同时测证书错误、非法输入、ALPN 不支持和协商失败。标准向量与真实服务器互操作分别验证安全性和兼容性，profile 匹配度和性能仅报告实测结果；任何未覆盖的组合明确列出。
