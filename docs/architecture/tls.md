# 自研 TLS 与 uTLS 类指纹能力

状态：自研 TLS 与指纹、BoringSSL libcrypto 密码底座已确定；协议范围、具体接口和所需验证仍为草案或待决定项。

[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)修订了最初完全排除 BoringSSL 的约束。具体版本与接入尚未验证，详见[底座评估](boringssl-libcrypto.md)和[第三方依赖封装](../build/third-party-xmake.md)。

## 目标与参考边界

Nexus 计划自行实现 TLS 协议处理及 uTLS 类 ClientHello 定制能力，使用 C++ Modules 组织，通过 Corosio 接入异步传输，同时服务于 client/server。

HTTP/1.1 已确定自研，HTTPS 由自研 HTTP 与本 TLS 层组合；HTTP/2 若后续启用可使用 nghttp2 的无 I/O 核心。ALPN 仅通告实际可驱动的应用协议，具体连接与隧道边界见[HTTP 设计](http.md)。

“uTLS 类能力”在本文指可配置的握手表现与指纹 profile，不代表直接依赖 Go uTLS 库。sing-box 在已调研快照中依赖 Go `crypto/tls`、`crypto/x509` 和外部 uTLS；Nexus 借鉴它的配置与集成设计，自研范围由本项目独立定义。详见[参考分析](../references/sing-box.md)。

## 依赖边界

Nexus 的 TLS 协议引擎自研，密码原语使用静态 BoringSSL libcrypto；不使用第三方 libssl 或引入独立 OpenSSL 实现作为后端或回退。此约束需覆盖实际引入的直接与传递依赖、静态组件和最终链接输入。

自研 TLS 与所有密码原语均自写是不同范围。哈希、HKDF、AEAD、密钥交换、签名及 ASN.1/X.509 需按所选 libcrypto 提交验证具体能力；操作系统随机源、信任根与证书验证策略各自确定接入方式。这些能力均未标为已实现。

后续应记录密码学能力矩阵，包括算法、实现来源、硬件路径、已知答案测试及依赖关系。操作系统随机源与证书信任存储通过独立平台接口接入，是否复用系统证书验证能力另行决策。

## 建议分层

| 层 | 责任 |
| --- | --- |
| 密码原语接口 | 随机数、摘要、KDF、AEAD、密钥交换与签名 |
| 证书与身份 | 编解码、链验证、名称验证、信任根与证书配置 |
| TLS 核心 | 记录层、握手状态机、密钥调度、transcript、告警和关闭 |
| ClientHello profile | 有序扩展、套件与组列表、GREASE、padding 和编码策略 |
| 会话配置 | 身份、ALPN、版本策略、profile 选择与恢复策略 |
| 异步连接适配 | 握手、读写、超时、取消与连接状态导出 |

TLS 核心应可由输入字节和显式事件驱动，输出待发送字节或所需操作，避免状态机直接依赖某种 socket。每条连接持有自己的状态、密钥和缓冲区，配置模板在连接间共享时保持不可变。

## 协议实现路线草案

建议先建立受控 TLS 1.3 client/server 互操作，再逐项扩展算法与行为。TLS 1.2 是否进入首期支持范围尚未决定。TLS 1.3 的历史规范入口为 [RFC 8446](https://www.rfc-editor.org/info/rfc8446/)，接入前应核对其状态页列出的替代规范与勘误，固定实际采用的规范版本。

握手正确性需要覆盖密钥调度、transcript、Finished、CertificateVerify、HelloRetryRequest、记录序号和 KeyUpdate。恢复、ticket、PSK、0-RTT、ECH、客户端认证与 QUIC 握手适配分别列入能力清单，未实现时明确拒绝相关配置。

证书验证与握手指纹分别配置。SNI、用于验证的身份和实际连接地址分别建模，profile 不得隐式改变信任策略。X.509 设计参考 [RFC 5280 及其更新记录](https://www.rfc-editor.org/info/rfc5280/)，具体信任策略仍待确定。

## 指纹 profile

profile 描述按顺序编码的 ClientHello 特征，包括套件、扩展、supported groups、signature algorithms、ALPN、key share、GREASE 和 padding。GREASE 的行为参考 [RFC 8701](https://www.rfc-editor.org/info/rfc8701/)。

profile 表达的能力必须和 TLS 引擎实际实现相符。不能为了匹配某个指纹而通告无法完成的算法，也不能在序列化后任意改字节而不更新 transcript、长度、binder 等关联数据。

建议每个 profile 记录来源样本、浏览器或客户端版本、采集条件、能力要求及预期变化字段。若提供 `auto` 别名，应记录它在每个 Nexus 版本中解析到的具体 profile。随机、会话恢复和 ALPN 会影响表现，应分别验证。

验收同时检查握手能否完成和线上的编码表现；JA3/JA4 等摘要可作辅助指标，不能单独证明完整浏览器行为一致。TCP 分段、TLS 记录分片与 ClientHello 的逻辑内容也应分别测试。

## 与平台的集成

建议通过 facade 暴露 TLS 流与必要连接状态，避免向业务模块暴露内部密码对象。下层可以是 Corosio socket、代理流或内存传输。

握手期间处理部分读写、背压、取消和超时，关闭时处理告警、在途写入和敏感数据生命周期。Linux kTLS 已作为设计方向，适用条件和回退行为仍需验证；不能以性能优化名义隐式引入被排除的第三方 TLS 引擎。

验证范围见[网络栈验证](../planning/network-validation.md)。当前只有下述 TLS 基础组件，完整 TLS 与指纹引擎尚未实现。

私有异步应用连接在读、写、密钥更新或关闭操作抛出异常时取消连接、恢复相应操作标志，并将异常传播给调用方；仍须等任何并发操作完成后销毁所有者。

应用记录的密文输出在完全写出后释放持有的向量分配，部分写入期间继续保留；流式读取器消费完整明文事件后也释放其向量分配。释放分配不保证内存立即归还操作系统，且不构成连接总内存预算。

TLS 记录发送在消耗序号后、完整密文构造成功前保持记录层失效；分配异常不会允许继续使用已不同步的序号。明文暂存缓冲在异常展开时也会清除；消耗序号前的分配失败允许调用者重试。

应用记录处理加密、解密或密钥更新时若抛出异常，整个应用记录状态失效；调用方不能重新提交可能已推进序号的记录。无 I/O 适配器在记录处理或分帧抛出异常时取消自身、释放输入及待写密文，再传播异常。

## 发送密钥使用预算

TLS 记录发送方向对每个密钥时期保守限制为 2^24 条记录，低于 [RFC 9846 §5.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-5.5) 中 AES-GCM 的 2^24.5 条满长记录参考值；同一保守值也用于 ChaCha20-Poly1305。应用数据在剩余一条时返回 `key_update_required`，保留该记录发送 KeyUpdate 或 close_notify，更新后重置预算。接收方向不强制此本地发送预算，认证失败仍立即终止。记录 API 只允许降低预算，便于测试；无 socket 的应用记录 API 要求调用方响应错误并更新或关闭；私有 Corosio 连接的发送操作会在预算到达边界时自动先发送 KeyUpdate，再发送应用数据。

## 当前实验：TLS 1.3 密钥调度

可选 `nexus.tls.schedule` 实现 SHA-256/384 的 HKDF-Expand-Label、Derive-Secret、早期/握手/主密钥和 Finished 校验值计算；握手阶段的 transcript 哈希由调用方提供。密钥结果为不可复制的拥有对象，析构时清理其存储，调用方复制的数据和输入由调用方管理；标签、上下文和长度检查不代替握手状态验证。`nexus.crypto` 同时提供 HMAC 与等长常量时间比较，长度本身公开。

GCC 16 测试使用 [RFC 8448 简单握手](https://www.rfc-editor.org/rfc/rfc8448.html#section-3) 核对 SHA-256 早期、握手和主密钥、双向握手流量密钥、服务器握手 key/IV 和 Finished key；Finished HMAC 另用独立计算样本、HMAC 本身用 RFC 4231 向量。SHA-384 仅验证早期密钥长度，完整 SHA-384 调度向量、握手状态机、证书认证和互操作均未完成；这些原语不能作为可用 TLS 连接。

`nexus.tls.transcript` 使用私有 libcrypto 增量摘要保存 transcript，每次接收一条完整握手消息（含四字节握手头，不含记录头），支持不改变状态的快照；调用方负责分片重组、消息语义和握手顺序。HelloRetryRequest 重写仅允许在首条 ClientHello 后执行一次，将其替换为合成 `message_hash`，然后由调用方追加真正的 HelloRetryRequest；不能从网络直接追加合成类型。GCC 16 测试核对 RFC 8448 的 ClientHello/ServerHello transcript 哈希及衔接流量密钥，另以独立计算的 SHA-256/384 样本验证重试重写、快照和畸形长度拒绝。完整握手、PSK binder 截断和分片处理尚未实现。

可选 `nexus.tls.record` 提供 TLS 1.3 单方向、单密钥时期的加密记录：AES-128/256-GCM 和 ChaCha20-Poly1305，头部作为 AAD，静态 IV 与序号异或生成 nonce；每个对象不可复制，移动后源失效，密钥存储在析构时清理。接收端要求完整的一条记录，校验长度、类型、填充和认证，任何非法记录或认证失败均终止该状态；序号不得回绕。GCC 16 验证 RFC 8448 早期应用数据样本、连续记录、填充、长度和篡改，以及其他算法往返。调用方必须确保同一密钥和 IV 不被多个发送状态复用，按算法规定的安全使用限额提前更新密钥，处理记录分帧和握手顺序，清理自己的密钥副本。尚无完整握手状态机、证书验证集成、密钥更新协议或 TLS 对端互操作，不能作为完整 TLS 连接。

可选 `nexus.tls.handshake` 提供有界握手消息 framing：输入可以拆分、合并或跨记录，单次输入不超过 16 KiB，解码器逐条产出消息类型和消息体，单条消息有可配置上限（默认 1 MiB），只保留当前不完整消息；拒绝网络上的合成 `message_hash` 类型。编码器检查三字节长度和同一上限，`finish` 在截断输入时永久终止状态。该层不判断握手消息语义、顺序、扩展或证书，调用方仍需将产出的消息接入 transcript 和状态机。GCC 16 测试覆盖逐字节拆分、同批多消息、空消息、超限、截断、非法类型和终止后的访问。

可选 `nexus.tls.hello` 提供拥有式 ClientHello 编解码：检查 legacy version、32 字节随机数、session ID、偶数密码套件列表、包含 null 的压缩方法和扩展长度/唯一性，并提供 TLS 1.3 `supported_versions` 必须包含 0x0304 的最小校验。扩展数据保持原样，便于后续接入 key_share、signature_algorithms 与 ALPN；该层不选择套件、不生成密钥、不验证证书，也不把扩展存在当作已支持能力。GCC 16 测试包含 RFC 8448 ClientHello、编解码往返、TLS 1.3 版本校验、重复扩展、截断和字段上限。

可选 `nexus.tls.key_share` 编解码客户端列表、服务端条目和 HelloRetryRequest 的选定组。客户端空列表允许，单个 key_exchange 不可为空，拒绝重复组及无效长度；不验证组支持、组间关系或公钥有效性。GCC 16 测试覆盖三种格式、空列表、重复和截断，并将 RFC 8448 ClientHello 逐字节送入握手 framing，解析 X25519 key share，往返编码并送入 transcript。服务端协商和完整 TLS 握手尚未实现。

`nexus.tls.server_hello` 编解码 ServerHello 并识别 HelloRetryRequest；`validate_x25519` 仅验证无 PSK 的 TLS 1.3 X25519 子集：版本、压缩、会话 ID 回显、客户端实际提供的受支持套件、扩展唯一性、版本、组与公钥长度，并交叉检查客户端支持的组和 key_share。它拒绝重试和其他扩展，由调用方处理握手状态；验证返回公钥后仍必须执行 X25519 并拒绝低阶输入。GCC 16 测试以 RFC 8448 两条 Hello 样本验证编码、协商、X25519 共享值、握手密钥及 transcript，并覆盖截断、版本、组、套件、扩展、低阶公钥等负例。这不构成完整握手或证书身份认证。

`nexus.tls.server_hello_stream` 在明文阶段有界重组记录和 ServerHello，报告消费量，识别一次重试并在调用方发送第二次 ClientHello 后继续；只接受合法兼容性 CCS，拒绝握手分片中插入 CCS、第二次重试和同一记录内跨阶段尾部。它只检查消息 framing 和基本解析，调用方仍须在发送前验证重试、生成新 key share，并在最终 Hello 到达后验证协商。GCC 16 分片及错误状态测试和 OpenSSL 直接/强制重试互操作通过；握手告警与生产传输调度尚未接入。

`make_client_hello` 生成受限 TLS 1.3 客户端 Hello，分别指定可选 DNS SNI、ALPN 和已实现的 X25519/混合组；证书验证名仍由 `ClientTlsConfig` 单独提供。调用方必须只通告实际可用的 ALPN；该生成器不声称模拟浏览器指纹。

私有 `OwnedClient` 持有 TCP socket，以同一个绝对期限执行数字端点连接和 TLS 握手，认证成功后才提供应用连接。单执行器调用方须在取消后排空所有协程再销毁；GCC 16 io_uring 测试覆盖预取消、握手挂起取消、重复启动、期限已过与连接失败，独立 OpenSSL HTTPS 互操作经此所有者通过。域名解析、生产配置和更广泛的拨号竞态仍待接入验证。

私有 Corosio 应用连接支持按协商记录上限分片发送整个输入，整个操作共享截止时间并排斥其他写入；密钥预算到界时在分片间自动更新。失败可能已有前缀到达对端，调用方不能盲目重试，且须保持输入存活至协程完成。GCC 16 的 epoll/io_uring 低上限测试验证分片、密钥更新、背压取消和并发写拒绝；OpenSSL 异步互操作使用超过单条记录的 HTTP 请求。该接口仍是私有实验，尚未接入正式代理。

私有字节流读取适配器保留一条已认证记录中未读数据，按调用方提供的缓冲区分批返回；控制事件和背压显式交付，调用方负责写出 KeyUpdate 响应。认证关闭事件之后报告 EOF，底层截断和失败仍报告错误。该适配器独占连接的读取方向，读取时缓冲和对象均须保持存活；GCC 16 epoll/io_uring 测试验证短缓冲和预读多记录，OpenSSL 异步互操作验证实际 HTTP 响应。

`ClientTlsConfig` 为异步适配器提供拥有式握手配置：复制 ClientHello、信任锚、验证身份、时间和初始组，避免这些视图在连接生命周期中失效；创建仍拒绝空锚、非法身份和超限输入。它不自动选择系统信任路径或协议能力。

`nexus.tls.client_session_handshake` 组合 Hello 生成、临时密钥、重试、明文和密文握手、证书认证与 Finished。调用方写完每条输出后确认，Finished 确认前不能取得应用记录；输入按消费量继续提交。GCC 16 和 OpenSSL X25519/X25519MLKEM768 直接与强制重试测试通过，包含三套件、身份失败、应用数据与关闭。它仍不管理 socket、部分写入、超时、取消或握手警报，不是生产 TLS 流。

`nexus.tls.record_stream` 将任意分片的字节流重组为一条完整记录，每次只返回一条及已消费字节数，调用方可在消费剩余输入前切换明文/密文阶段；部分记录期间切换阶段会终止解码器。明文及密文分别限制 2^14 和 2^14+256 字节，限制错误、非法头和截断将终止该状态，移动后源失效。此层只验证基本头部/长度，不处理握手阶段规则、兼容 CCS、告警或认证；调用方按状态决定允许的类型与版本，并将密文记录交给 `RecordLayer`。GCC 16 验证每个拆分点、同批记录、阶段切换、错误、以及两条加密记录重组后解密并组成握手消息。

`nexus.tls.client_keys` 将实际 ClientHello/ServerHello 字节、X25519 私钥、协商校验和 transcript 接入 TLS 1.3 握手密钥调度：消费私钥并检查其公钥与客户端 share 一致，拒绝低阶对端值，再生成双方握手流量 secret 和客户端收发记录状态。支持 0x1301/1302/1303 的非 PSK、无重试路径，调用方必须避免从流量 secret 重建并重复使用相同发送密钥和 nonce。GCC 16 测试使用 RFC 8448 验证双向握手流量 secret、记录加解密，以及另外两种套件的组合往返、错误私钥、长度和低阶公钥。结果只是未认证握手阶段材料，调用方必须继续验证握手顺序、证书、CertificateVerify 和 Finished，不能向应用交付数据。

`nexus.tls.finished` 提供客户端 Finished 交换的有限状态：对完整服务端 Finished 按先前 transcript 恒时核对 verify_data，成功后追加 transcript，再为无客户端认证场景生成并追加客户端 Finished；校验或格式失败后状态失效，移动后源失效。调用方必须先验证证书和 CertificateVerify 并将正确消息追加 transcript；本组件不会完成这些认证，也不处理客户端证书。GCC 16 测试将 RFC 8448 两条 Hello 和服务端完整消息序列写入 transcript，验证双方 Finished，另以独立计算的 SHA-256/384 样本验证顺序、失败和最终 transcript。样本证书与签名在此测试中未验证，不能据此声称对端身份可信。

`nexus.tls.certificate_verify` 在固定 libcrypto 内部解析完整 DER 证书，按客户端已提供的签名算法验证 TLS 1.3 服务端 CertificateVerify；支持 RSA 公钥的 `rsa_pss_rsae_sha256`、P-256 公钥的 `ecdsa_secp256r1_sha256` 和 `ed25519`，RSA 显式固定 PSS SHA-256、MGF1 SHA-256 和 32 字节 salt。GCC 16 使用 RFC 8448 证书和 transcript 验证签名并衔接双方 Finished，另验证签名/摘要篡改、未提供算法和截断。此接口不验证证书链、域名、期限、用途或握手顺序；样本签名通过不代表证书可信。

## 后量子密钥交换

后量子能力是 TLS 的明确目标，并非现有 X25519 的隐含能力。优先实现 [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) 的 X25519MLKEM768，按 FIPS 203 验证 ML-KEM-768 密钥生成、封装、解封和隐式拒绝，再验证混合 share 编码、秘密组合、协商/HRR、恶意输入和独立实现互操作；仅在端到端实现后才在 ClientHello 中通告。当前固定 BoringSSL 的 `openssl/mlkem.h` 提供 ML-KEM-768 API，Nexus 已提供下述独立原语封装；已实现独立混合交换核心，但尚未在 TLS 协商中启用该组。X-Wing 是另一种组合，不能直接替代 TLS 的 X25519MLKEM768；证书签名与后量子密钥交换也分别验收。

`nexus.crypto.mlkem` 私有封装 ML-KEM-768：64 字节 d||z 种子或随机生成密钥，公钥编码、封装及解封；私钥和共享值不可复制，移动后私钥失效，析构清理拥有的敏感存储。GCC 16 验证固定 BoringSSL 自带的 NIST 密钥生成样本完整公钥、随机往返、公钥/长度拒绝、移动和密文篡改后的隐式拒绝。正确长度的无效密文返回确定性伪随机共享值，不能用解封成功判断密文有效；必须通过后续认证检测失败。调用方负责清理传入种子和自己的复制品；此结果不证明完整 TLS 混合协商或独立对端互操作。

`nexus.tls.hybrid` 提供 RFC 10024 X25519MLKEM768 的独立客户端/服务端交换核心，组 ID 为 `0x11ec`。客户端 share 为 ML-KEM 公钥后接 X25519 公钥，服务端 share 为 ML-KEM 密文后接 X25519 公钥，64 字节秘密为 ML-KEM 秘密后接 X25519 秘密；客户端完成尝试消耗私钥，服务端消耗传入的独立临时 X25519 私钥。GCC 16 验证 NIST ML-KEM 公钥和 RFC 7748 X25519 样本的布局、两端秘密、无效公钥、长度、密文隐式拒绝和单次使用，并将结果送入握手密钥调度。此核心本身不处理协商、握手时序或认证；客户端不能将解封成功当成认证。

`nexus.tls.hybrid_client_keys` 将 X25519MLKEM768 交换接入实验性客户端 Hello 校验与握手密钥调度：检查客户端实际 share 和临时私钥匹配、服务端选择的组、版本、套件和 session 回显，以精确 Hello transcript 派生双向握手记录状态。GCC 16 内存测试覆盖两端构造 Hello、派生和记录解密、组/私钥不匹配；ML-KEM 密文被篡改时解封返回秘密，随后记录认证失败并终止。该组件也支持重试密钥派生；完整连接须结合证书策略、Finished 和传输状态机。

正式 VLESS/TLS 入站现接入 X25519MLKEM768 服务端协商：优先使用已提供的混合 share，未提供时可使用已提供的 X25519；两种都未提供时可请求混合组重试。GCC 16/io_uring 下与独立 OpenSSL 客户端验证混合组直接握手及强制 HelloRetryRequest、证书认证和 VLESS 回环转发；三种套件的密钥与 transcript 也有双端对照。正式 VLESS 出站默认使用 X25519，可显式选用混合组并允许服务端请求回退到 X25519。

`nexus.tls.certificate_trust` 可从 Linux 常规文件加载有界 PEM 信任包，允许证书之间的空白及 `#` 注释，拒绝未知内容、重复证书和畸形或超限输入；通过已打开的文件描述符读取，允许系统信任包常见的符号链接。不自动选择路径或设置信任策略，读取失败不会回退。GCC 16 测试解析本机 118 个系统信任锚，并用超过 64 个锚验证证书链；独立 OpenSSL 互操作从 PEM 文件加载测试根。

`nexus.tls.certificate_trust` 使用调用方显式提供的 DER 信任锚和叶证书及中间证书，借助固定 libcrypto 验证链、TLS 服务端用途、指定 POSIX 时间及 DNS/IP 身份；DNS 仅匹配 SAN，不回退到 CN。单证书最大 1 MiB，输入总量最大 4 MiB，最多接收 16 张证书和 1024 个信任锚；实际验证路径最多 8 个中间证书。GCC 16 固定证书测试验证链、DNS 通配/IP、错误名称、CN 回退拒绝、用途、期限、缺失中间证书、错误锚、签名篡改、DER 尾部及资源上限。调用方负责取得可信锚和正确的身份、时间，校验证书撤销，并将同一叶证书绑定到 CertificateVerify、Finished 和握手状态；该接口不自行证明完整 TLS 身份或对端互操作。

`nexus.tls.client_auth` 串接服务端 Certificate、CertificateVerify 和 Finished：解析空 request context、无条目扩展的证书消息，以显式信任锚验证后保存叶证书；按先前 transcript 和客户端提供的算法检查该叶证书的签名，再验证服务端 Finished 并生成客户端 Finished。认证失败使该状态终止，乱序操作不能推进。GCC 16 使用固定证书链、真实 RSA-PSS 签名和计算的 Finished 验证成功、乱序、信任错误、未提供算法、签名及 Finished 篡改；样本前面的握手消息是测试 framing，不代表 TLS 互操作。调用方负责验证并追加此前的 ClientHello、ServerHello 和 EncryptedExtensions，确保提供的算法与实际 ClientHello 一致，并处理撤销、记录解密及应用密钥。当前支持 RSA-PSS SHA-256、ECDSA P-256 和 Ed25519，不支持证书条目扩展、客户端认证或完整握手，不能据此交付应用数据。

`nexus.tls.encrypted_extensions` 检查完整 EncryptedExtensions 消息与实际解析的 ClientHello：支持空的 server_name 确认、单个已提供的 ALPN、服务端 supported_groups 和 record_size_limit；拒绝重复、未请求、未支持及格式错误的扩展。返回的 ALPN 和记录大小只是协商结果，调用方必须分别限制写给服务端的记录和执行自身通告的接收限制，并在成功后将原始消息追加 transcript。GCC 16 测试包含 RFC 8448 服务端消息、ALPN 匹配、重复和未请求扩展、无效限制与截断。此组件不验证握手时序，不支持 early_data 等其他扩展，尚未接入完整 TLS 连接。依据 [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)、[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) 和 [RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)。

`nexus.tls.client_flight` 将精确 ClientHello/ServerHello、X25519 或 X25519MLKEM768 握手密钥、EncryptedExtensions、证书认证与 Finished 按顺序组合；签名算法从实际 ClientHello 提取。它可解密完整握手记录并限制接收明文长度，生成握手密钥加密的客户端 Finished。调用方必须仅从已认证记录输出重组完整握手消息并依次提交，处理记录分帧、分片、关闭和协商结果；接口本身不会阻止调用方传入其他字节。GCC 16 测试结合 RFC 8448 Hello、固定证书链及实际签名验证 X25519 全部认证步骤、加密 Finished、记录篡改与失败终止；混合组只测试 Hello、扩展和信任失败路径。完整握手调度、HRR 及独立对端互操作尚未完成，不能视作完整 TLS 连接。

`ClientFlight` 在服务端 Finished 验证后，以包含该消息的 transcript 派生双向应用流量密钥；生成客户端 Finished 后可一次取得独立应用记录状态。记录状态分别执行协商后的收发长度上限，认证错误或超限接收后终止，发送过大载荷拒绝而不消耗序号。调用方必须先发送客户端 Finished，再发送应用记录；还须处理记录分帧、警报、关闭、KeyUpdate 和密钥使用限额。GCC 16 测试基于 RFC 8448 主密钥和固定链验证双向应用记录、单次取得、篡改及 64 字节限制；尚未完成与独立 TLS 对端的互操作。记录大小限制仅在双方协商后生效，见 [RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)。

`nexus.tls.client_handshake` 在 ServerHello 已验证后串接密文记录分帧、握手消息增量重组、扩展和证书认证、Finished 与应用密钥移交。每次报告消费字节，记录完成后调用方继续提交未消费部分；认证成功返回客户端 Finished 密文，后续输入属于应用密钥时期，调用方须先发送 Finished。服务端 Finished 后同一握手记录还有额外消息或不完整尾部时拒绝，防止跨密钥时期拼接。GCC 16 测试逐字节拆分、多条记录、单条合包、错误顺序、名称失败、截断、密钥切换尾部及客户端 Finished 解密。该组件不处理 ClientHello 发送、明文 ServerHello/HRR、警报、关闭、KeyUpdate、生产异步 I/O 或独立对端互操作；返回的扩展结果在 Finished 验证前未认证。

服务端握手创建接口可指定证书列表字节上限，按每张 DER 证书加五字节条目开销计数，默认沿用 1 MiB 限制；超过上限在创建握手缓冲前拒绝并保留调用方凭据。现有 VLESS 配置使用默认值，此接口尚未接入配置或总连接预算。服务端构造握手 flight 时按 16 KiB 分片封装各握手消息，不再拼接一份完整明文 flight；证书消息编码后释放原正文。适配器在每条记录完整写出后释放对应分配，部分写入期间保持其存活；应用记录成功移交后销毁握手 flight，释放其握手密钥状态，已认证的 ALPN 仍可读取。失败或取消释放部分输入记录、flight 和握手缓冲；释放分配不保证内存立即归还系统，也不构成握手内存预算。GCC 16 测试覆盖证书链上限边界、输出缓冲释放、取消、移交后的应用解密和 ALPN，并用约 20 KiB 的证书验证跨记录的 transcript 和 Finished；异步 OpenSSL 与 HTTP/2 对端验证正常交接。

异步服务端握手可选接收共享逻辑预算：为读取数组、异步写入副本及交接余量分别预留；额度不足返回 `budget_exceeded`，挂起 I/O 取消完成后释放预留。余量预留由返回对象持有；调用方转移余量时须保证新所有者已计费，或保留原结果直到该分配释放。测试覆盖读取和写入挂起取消、额度不足、Finished 与首条应用记录同次读取及 HTTP/2 交接；该预留不包括握手内部其余分配和协程帧开销，正式 VLESS 入站目前未传入共享预算。

独立互操作夹具 `tests/tls_openssl_interop.py` 用临时 CA/服务端证书启动系统 OpenSSL `s_server`。阻塞客户端覆盖 X25519 和 X25519MLKEM768、三种套件的直接握手及强制 HRR，验证 ALPN、KeyUpdate、HTTP 和关闭；异步 Corosio 客户端覆盖两组的强制 HRR、ALPN 和数据交换。异步客户端还验证 SNI 与 DNS 验证名独立、错误名称及不可信根拒绝；IP 身份测试使用 IP SAN、不发送 SNI，并验证错误 IP 拒绝。不同默认证书和 SNI 证书使测试能检测这些选择错误；OpenSSL 切换至第二上下文的 SNI 专项未协商 ALPN，其余正常路径仍检查 ALPN。OpenSSL 仅为测试对端，不链接项目客户端；互操作不代表 TLS 已接入正式代理。

CertificateVerify 的 ECDSA P-256 与 Ed25519 已用 OpenSSL 生成的证书及签名验证成功，并验证签名/摘要篡改、未提供算法和密钥类型不匹配拒绝；OpenSSL 服务端对两种证书分别通过 X25519 与 X25519MLKEM768 握手及应用数据交换。签名验证仅覆盖已列出的三种 scheme，其他曲线、RSA-PSS 变体和算法仍需实现和验证。

应用记录状态现支持认证后的 `close_notify`、`user_canceled` 和 fatal alert 事件；收到 close_notify 后仅关闭接收方向，本端仍可发送数据及自身 close_notify。发送关闭后不再允许发送，缺少对端 close_notify 的传输 EOF 报截断；fatal、畸形或认证失败终止状态。GCC 16 验证双向半关闭、重复操作、截断、错误告警与篡改；OpenSSL 独立对端的十个握手组合均接收并验证服务端 close_notify。调用方负责实际发送本端告警和解释 EOF，握手期告警、KeyUpdate 和生产连接关闭调度仍未实现。语义参见 [RFC 8446 §6](https://www.rfc-editor.org/rfc/rfc8446#section-6)。

应用记录状态现支持 TLS 1.3 KeyUpdate：使用旧密钥封装更新消息后轮换发送密钥，接收完整且对齐记录末尾的更新后轮换接收密钥；支持更新消息跨记录拆分，拒绝插入其他记录、错误请求值与切换边界后的额外数据。收到更新请求后，必须先生成并按顺序发送不请求对端更新的响应，才能继续生成应用数据。调用方负责按生成顺序写入记录、限制密钥使用量、处理事件和关闭；当前接受 KeyUpdate 并校验后丢弃会话票据，不支持会话恢复及其他握手后消息。GCC 16 测试覆盖双向轮换、分片、非法值与交错；独立 OpenSSL 十组互操作中客户端请求更新、收到响应后交换数据与关闭通过。参见 [RFC 8446 §4.6.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3)。

应用记录按客户端或服务端角色区分握手后消息：客户端支持有界重组并解析服务端 NewSessionTicket，服务端拒绝客户端发送的票据（见 [RFC 8446 §4.6.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1)），校验结构、非空票据和扩展长度/重复后丢弃，不保存票据或启用恢复；与 KeyUpdate 合包时仍要求 KeyUpdate 位于记录末尾，分片期间拒绝其他类型记录。票据正文按编码字段限制为最多 131337 字节，客户端重组还允许一条记录的后续数据，完整处理后释放缓冲容量；服务端仅接受 KeyUpdate，重组前将累计内容限制为五字节，仍需先解密完整记录；分配器容量和临时副本不属于此逻辑上限。GCC 16 测试覆盖最大合法票据分片及合包、扩展向量超限、客户端非法发送票据、畸形长度和票据与更新合包；独立 OpenSSL 十组验证服务端实际发送票据后仍完成更新、数据与关闭。票据恢复、PSK 和 0-RTT 尚未实现。
