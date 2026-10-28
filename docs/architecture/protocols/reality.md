# Reality 接入设计

状态：**P0 目标的设计草案，未实现**。Reality 与自研 TLS/uTLS 边界共用；基于固定版本的 [XTLS/REALITY 服务端](https://github.com/XTLS/REALITY)和 [Xray 客户端](https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go)建立互操作目标。上游分支持续变化，本文概述不代替逐字段线规、固定提交与测试向量。

## 身份与承载

客户端需要经授权配置服务端公钥、server name、short ID 和允许的 ClientHello profile；服务端保管对应私钥、允许的 short ID/名称及受控 fallback 目标。密钥来源、解析、轮换及生命周期须显式定义。Reality 是外层握手/传输能力，VLESS 用户 UUID 是另一层身份；两者都需验证，不能仅凭观察到合法 SNI 就把请求当已认证用户。

所读 Xray 客户端在 TLS ClientHello 及 session ID 中组织认证信息，并利用密钥交换、HKDF 和 AEAD 等流程实现特定认证；client 还执行 Reality 特定的对端认证，而不是简单借用目标站的正常证书就可完成代理身份验证。具体字段、transcript、KDF、附加数据、时间窗口、证书处理和新版算法需按锁定实现逐字节核查，不能用“X25519 成功就返回认证通过”的伪代码代替验证。[客户端实现](https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go)、[服务端实现](https://github.com/XTLS/REALITY/blob/main/tls.go)。

TLS 握手、认证及不受信输入由连接 owner 串行驱动，长度、时间、并发和资源均有上限。认证失败不能交给代理协议；必要的 secret 要限期保存并清理。时钟差、重放处理、key share/profile 和错误行为以固定互操作目标为准，不假设复用同一 short ID 就代表一次重放，也不虚构固定的全局“零重放”保证。

## Fallback 与安全边界

非认证连接按配置与参考实现的语义进行 fallback 或关闭。fallback 必须限制目标、端口、超时、连接数和带宽，防止成为开放转发器或形成 TUN/出站递归；已消费的字节需要按原顺序完整交付，且关闭、半关闭、背压和失败路径须明确定义。Linux `splice()` 仅是满足文件描述符、状态和协议边界时可尝试的优化，不能默认已读取数据或仍需加密的数据可直接使用。

Reality 的网络表现取决于目标站、TLS 版本、profile、实现、路由与观测方式；不承诺字节级与任意浏览器/网站完全一致、免于主动探测或无协议特征。Fallback 也不能保证目标站总可用、认证失败时所有交互都透明。自研 TLS、libcrypto 的密码原语覆盖、证书认证与实际握手需要完整验证，不能假设第三方 libssl 已在后台完成这些工作。

## 验收

固定客户端和服务端版本，采集并验证合法/非法公钥、short ID、用户 UUID、SNI、证书认证、时钟偏差、重放及握手拆包。测试 fallback 的字节保留、目标不可达、速率限制、半关闭与防回环；对每个 ClientHello profile、IPv4/IPv6、普通 VLESS 与 Vision 分别记录互操作结果。成功握手、线上指纹和性能收益要各自测量；任何未支持的组合必须明示。
