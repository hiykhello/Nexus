# BoringSSL libcrypto 底座评估

日期：2026-10-27。本文保留最初的方案评估；后续[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)已采纳 libcrypto 并修订决策 0002。Linux 实验依赖已固定提交并验证有限静态链接，项目原语封装仍待实现，见[依赖约定](../technology/dependencies.md)。

## 建议与职责

建议 Nexus 继续实现 TLS 状态机、记录层、transcript、密钥调度流程及 ClientHello/profile，密码原语通过私有适配层使用 BoringSSL libcrypto。这样可以保留握手编码控制，同时减少原语实现和硬件适配的自研范围。这是工程判断，不是 Nexus 已完成的安全或性能验证。

libcrypto 与 libssl 是可分开的构建目标，具体依赖关系应在锁定提交核查，见[上游构建源码](https://boringssl.googlesource.com/boringssl/+/HEAD/CMakeLists.txt)。候选边界如下：

| 组件 | 建议归属 |
| --- | --- |
| 摘要、HMAC/HKDF、AEAD、密钥交换、签名和随机数 | 由 libcrypto 公共 API 提供，按所选 TLS 子集验证算法覆盖 |
| TLS wire 编码、握手/记录状态机、序号、transcript、告警 | Nexus 自研；不调用 libssl 的 TLS 引擎 |
| ClientHello 顺序、GREASE、padding、profile 与能力匹配 | Nexus 自研；底层原语不决定浏览器指纹 |
| 证书解析与链验证 | 单独评估 libcrypto 的公共 X.509 能力，不默认承诺全部自行编写 |
| 主机名、信任根、时间、吊销策略、验证错误呈现 | Nexus 的 PKI/平台策略负责装配和验证 |

使用 libcrypto 不会自动解决证书策略、随机数生命周期、nonce 唯一性、transcript/Finished 正确性和密钥擦除。调用正确的原语也不等于 TLS 引擎已经正确。

## 接入与维护成本

BoringSSL 官方明确不保证 API/ABI 稳定，也不推荐将其视为通用第三方 OpenSSL 替代品；采用方通常随程序携带自己的版本。因此候选方案应固定源码提交，并承担升级适配责任。[官方说明](https://boringssl.googlesource.com/boringssl/+/HEAD/README.md)

上游建议在更新时选取新提交并定期更新；其周期性标签不提供长期稳定分支保证。固定提交用于复现，不能演变成长期不更新密码依赖。[集成说明](https://boringssl.googlesource.com/boringssl/+/HEAD/INCORPORATING.md)

建议将 BoringSSL 原始接口的使用限制在 `nexus.thirdparty.boringssl_crypto` 与 `nexus.crypto`/`nexus.pki` 的集成边界；第三方模块按需导出类型和函数以供适配及独立消费，业务公共接口不泄漏裸句柄或宏，见[第三方 Modules 封装](../build/third-party-modules.md)。对象用 RAII 持有，按函数返回值判断成败并立即转换为 expected；不能仅用错误队列判定成败。协程跨线程恢复前先捕获本次错误上下文，避免后续操作混入诊断。[API 约定](https://boringssl.googlesource.com/boringssl/+/HEAD/API-CONVENTIONS.md)

mcpp 工作区使用固定版本的 libcrypto 源文件清单并保留必要平台及汇编构建逻辑，避免手工挑选若干算法源文件。[构建指南](https://boringssl.googlesource.com/boringssl/+/HEAD/BUILDING.md)

候选默认优先评估随程序静态链接；检查其他依赖是否又引入系统 OpenSSL 或另一份 BoringSSL，不能只看动态库列表。符号可见性、重复符号、头文件搜索顺序与跨库对象释放需要验证；上游集成说明明确指出混用多份实现存在符号冲突。

## 对现有约束的影响

后续决策已将约束修订为“允许 BoringSSL libcrypto 作为密码底座，TLS 协议和指纹仍自研；不使用 BoringSSL/OpenSSL libssl，不引入独立 OpenSSL 实现作为回退”。这确实引入 BoringSSL 依赖，不能继续写“完全不依赖 BoringSSL/OpenSSL”。

Linux 实验依赖固定上游提交 `e651545da6e26e1f4420723a3b69a78ed1b9c51d`；GCC 16 下仅构建静态 crypto 目标，已验证 SHA-256 与 AES-128-GCM 空消息已知答案及篡改拒绝。项目级 API、其他算法、平台及完整发布链接图仍待验证；接入步骤见[工作区构建](../build/mcpp-workspace.md)。

后续验证涵盖算法已知答案、错误与资源回收、随机源和 fork 行为、不同硬件路径、证书负例、TLS 互操作及最终链接输入；原语通过不替代 TLS 状态机及模糊测试。

## 当前实验模块

Linux 可选的 `nexus.crypto` 通过私有实现调用锁定的 libcrypto，对外只暴露项目类型：SHA-256/SHA-384、HKDF extract/expand、AES-128/256-GCM、ChaCha20-Poly1305 与 XChaCha20-Poly1305。AEAD 每次创建独立上下文，验证密钥和 nonce 长度，认证失败不返回明文；调用方负责同一密钥下 nonce 唯一性与算法使用限额。返回字节容器及输入密钥由调用方持有，不自动清除；可显式调用 `cleanse`，但无法保证擦除之前发生的全部副本。HKDF 限制 PRK 长度和 255 个摘要块，不能用作密码拉伸。

GCC 16 实验测试覆盖 SHA-2、[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) HKDF、AES-GCM 和 [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) ChaCha20-Poly1305 已知答案；XChaCha20-Poly1305 使用锁定上游携带的 libsodium 生成样本，四种 AEAD 均验证关联数据篡改、空消息及密钥/nonce 长度。此结果不证明完整密钥管理、密码学审计、TLS 或任何协议互操作；证书及协议仍待接入。

随机输出使用 BoringSSL `RAND_bytes`；该版本获取不到足够随机数据时会终止进程，不能保证返回可恢复错误。X25519 私钥和共享值使用不可复制对象，移动时清理源存储、析构时清理自身；调用方仍须避免自行复制借用视图并尽量缩短寿命。导入的原始密钥由调用方负责清理，返回的共享值必须经协议指定的 KDF 处理。对端长度无效或产生全零共享值时拒绝。GCC 16 已验证 [RFC 7748 第 6.1 节](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1)双方公钥和共享秘密、低阶输入拒绝、移动后源对象失效及随机生成密钥的协商；这不证明随机源的统计质量或完整协议安全。
