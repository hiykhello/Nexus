# WireGuard 与 WARP 接入设计

状态：**P1 设计草案，未实现**。Nexus 计划实现可独立测试的 WireGuard 协议核心，并以 endpoint 接入自研网络栈或平台设备。WARP 是有条件的互操作目标，不表示 Cloudflare 已公开稳定的第三方注册接口，也不承诺可用性。协议依据为 [WireGuard 官方协议](https://www.wireguard.com/protocol/)；本文字段长度包含认证标签，所有长度和行为应与锁定的互操作目标测试。

## 职责与报文

每个 peer 持有静态公钥、可选 32 字节 PSK、允许的内部地址前缀、当前/上一代会话、接收端索引、计数器、认证后的外部 endpoint 和定时器。自身私钥来自受保护的密钥源；每次握手生成独立临时密钥。发送内部 IP 包时按目的地址的最长前缀选择 peer；接收解密后按该 peer 的 allowed IPs 检查**内部源地址**，不符合则丢弃。该映射是 WireGuard 的 cryptokey routing，不替代宿主路由或 Nexus 业务分流。

所有报文均为 UDP 数据报，前 4 字节由 1 字节类型与 3 字节保留位组成。标准 WireGuard 保留位必须为零，索引和 transport counter 用小端整数；以下为标准 wire layout：

| 类型 | 长度 | 字段顺序（不含首 4 字节） | 接收处理要点 |
| --- | --- | --- | --- |
| 1 Initiation | 148 字节 | sender index 4、ephemeral 32、encrypted static 48、encrypted timestamp 28、MAC1 16、MAC2 16 | 限长并检查 MAC，完成密钥协商与认证后按 peer 检查 TAI64N，才允许更新握手状态 |
| 2 Response | 92 字节 | sender index 4、receiver index 4、ephemeral 32、encrypted empty 16、MAC1 16、MAC2 16 | 按 receiver index 找待处理握手；校验 MAC 和认证数据，派生双向会话密钥 |
| 3 Cookie Reply | 64 字节 | receiver index 4、nonce 24、encrypted cookie 32 | 关联先前握手和 MAC1；用 XChaCha20-Poly1305 验证并缓存 cookie，随后重试 |
| 4 Transport Data | 至少 32 字节 | receiver index 4、counter 8、密文及 16 字节 tag | 按索引找有效密钥，校验认证及滑动窗口后交付内部 IP；空明文用于 keepalive/密钥确认 |

长度和字段不允许直接将网络字节解释成可能未对齐的 C++ 对象；用有界字节视图解析并验证溢出。发送端使用独立的单调递增 64 位 counter，绝不能同一密钥下重复 nonce；AEAD nonce 由 4 个零字节与小端 counter 组成。重放窗口是每个接收会话的状态，与握手时间戳分开；仅在认证成功后推进窗口，并对乱序、重复和计数耗尽测试。内部明文的填充及 IP 实际长度以协议和已验证实现为准，不能把填充当 IP 数据。

## Noise 与 peer 状态

采用 `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`，没有配置 PSK 时按协议使用 32 字节全零 PSK。初始化 chaining key 与 transcript hash，参与双方的静态密钥；Initiation 依次混入发起方临时公钥、`es` DH、加密的发起方静态公钥、`ss` DH 和加密 TAI64N；Response 混入响应方临时公钥、`ee`、`se`、PSK 后认证空消息，分离发送/接收密钥。精确的 HKDF、MAC 输入、标签与状态更新顺序按官方协议实现，不能用 `std::hash` 或简单哈希替代。

```text
空闲 → 发送 Initiation → [Cookie Reply → 重发 Initiation] → 验证 Response
     → 新密钥待确认/可发送 → Transport → 定时或阈值 rekey → 替换/过期
响应方：认证 Initiation → 发送 Response → 等待发起方首个认证 Transport → 激活
```

发起方收到有效 Response 后可发送新会话数据；响应方在收到发起方使用该密钥的首个有效 Transport 前不应主动用新会话发送。允许旧会话在规定有效期内继续接收，轮换时清除过期密钥；握手重试、速率限制、cookie 轮换、keepalive、重新握手及失效时钟采用 WireGuard 协议的具体门限并做兼容测试。高负载时先检查 MAC1，对需要地址证明的请求按规则发 Cookie Reply/验证 MAC2，避免未认证包分配大量 peer 状态。

Initiation 的 TAI64N 是 12 字节、网络序的秒与纳秒时间表示。响应方保存每个 peer 最后**成功认证**的最大值，拒绝不大于该值的握手；并发握手的比较和提交必须串行或原子化。它不是单调时钟，也不等同 transport counter：墙钟回拨可能使有效客户端握手暂时失败，需要报告时钟问题；重启后的防重放持久语义需单独决定，不宣称零代价跨重启保障。所有密钥、索引与 endpoint 更新都不得由未经认证的报文触发。

认证后的包可改变 peer 的外部 IP/端口，实现 endpoint roaming。更新须受 peer 身份、会话及重放验证约束；路由变化、旧包乱序和 NAT 重绑定期间并发发送要可预测。域名 endpoint 解析走 bootstrap/防环回路径，DNS 变化与漫游地址竞争时须保留明确优先级。允许的内部前缀重叠、peer 删除和配置热更应在编译配置时诊断。

## Cloudflare WARP 兼容层

WARP 配置应作为普通 peer 参数之上的**独立 provider profile**：本地私钥、对端公钥、分配的隧道 IPv4/IPv6、endpoint/端口、allowed IPs、MTU、keepalive 以及可选 reserved 3 字节均由用户提供或来自经授权且验证过的配置源。不得把静态公网地址、账号注册、密钥或保留位硬编码成永久有效数据。Cloudflare 当前分别列出了客户端使用 WireGuard/MASQUE 及其入口信息，账号与客户端策略可能变化，见 [Cloudflare One 客户端防火墙说明](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/)；这些资料不保证第三方 WireGuard 配置、免费账号注册或本项目兼容。

标准 profile 强制 `reserved = [0, 0, 0]`。非零值仅在显式选择、经特定服务端验证的 WARP 类兼容 profile 时允许，长度恰为 3、每项为 `0..255`；它不是 WireGuard 标准协商字段，也不能从公钥/地址推导。兼容做法是在报文完整生成后将字节 1..3 写入配置值，并在交给标准解码器前清零对应字节；接收侧必须校验来源及长度。由于这些字节也位于握手 MAC 覆盖范围内，远端必须支持并在验证 MAC 前正确还原，不能对普通 WireGuard peer 套用。非零模式默认关闭。

允许轮换的 endpoint 应先解析和探测，再安全切换；新旧路径均要通过防环回与 MTU 验证。对于 WARP 的注册/凭据刷新，仅定义外部注入与过期诊断，不伪造自动注册协议或把消费者 WARP 与组织 Zero Trust 配置混为一谈。

## 验收

- 与 WireGuard 参考实现双向握手、IPv4/IPv6、allowed IPs、重放窗口、密钥确认、重试、重连和 NAT 漫游；验证标准包长度、字节序及解析边界。
- 对握手 transcript、X25519、BLAKE2s/HMAC、ChaCha20-Poly1305、XChaCha20-Poly1305、cookie 和密钥清理使用已知答案/互操作向量；先核查所锁定的 BoringSSL libcrypto 对所需原语及 keyed BLAKE2s 的实际 API 覆盖，缺项未解决前不得宣称可用。
- 模拟时钟回拨、乱序、索引冲突、包截断、并发重放、peer 改删、MTU 黑洞与防环回；WARP profile 单独验证账户授权、endpoint、reserved 和实际链路，不影响标准模式。

