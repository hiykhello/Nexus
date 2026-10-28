# Linux kTLS 与数据路径设计

状态：kTLS 为[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)确定的 Linux 方向，**尚未实现或完成验证**。它接管 TLS 记录层的部分收发，不进行握手或证书验证；该机制与网卡硬件 TLS offload、`splice()` 是否减少用户态复制是不同选择。内核接口和限制以目标内核的 [kTLS 文档](https://docs.kernel.org/networking/tls.html)与头文件为准。

## 交接条件

自研 TLS 状态机完成身份校验与握手，并保有每方向协商的版本、cipher、应用密钥、IV 和下一条记录的序列号；加密/派生调用所选 libcrypto。只有确定没有未处理的用户态记录、已写出数据及对应计数后才考虑交接。对已连接 TCP socket 设置 `TCP_ULP` 为 `tls`，再使用正确版本/cipher 的 `TLS_TX` 与 `TLS_RX` 配置；`crypto_info` 的 salt/IV/seq 布局、端序和方向按实际内核接口核对。不能把握手 transcript secret、TCP sequence 或网络包数量误作 TLS record sequence。

TX 与 RX 分开启用，处理其中一个成功、另一个失败的状态：每方向明确由谁负责，只有状态可安全追踪且平台语义经验证时才能保留混合模式或回退；不能假设套接字一定支持取消已经启用的 ULP。若无法安全继续，关闭连接并明确报告，不能用旧 key/nonce 重新启动而造成重用。未启用 kTLS、前置探测失败时可以在不改变记录状态的前提下使用用户态 TLS。

## 控制消息与数据泵

kTLS 需要应用继续处理 TLS 控制记录、关闭和密钥更新，收取记录类型等使用内核定义的控制消息；TLS 1.3 KeyUpdate 的先后、双方方向、序列重置与失败都需遵守所选内核语义。内核文档记载收到 KeyUpdate 后 RX 可暂停，直到用户态提供新密钥；不能让纯 splice 泵绕过处理。未能证明控制消息正确交付的路径不启用该优化。

`splice()` 仅在 fd 类型、内核实现、方向、协议及加密边界允许时评估；通过 pipe 中转不等于保证所有内部操作或网卡路径无复制。记录 pipe 中未写出的字节：处理部分读写、EINTR/EAGAIN、背压、双向半关闭、取消和 FD 回收，不能在第二次 splice 只写出部分数据时直接覆盖/丢失剩余字节。关闭或切换时保证计数、限速与授权语义和普通转发一致。

TLS/代理 framing 仍需处理时不得绕过其封装；HTTP CONNECT 的内层 TLS 由端点完成，Nexus 无须为了使用 splice 解密该内层流量。只读条件、设备支持及缓冲所有权另有内核限制；不把某个 opt-in 选项当通用安全设置。

## 验收

覆盖不同 Linux 内核、软件/硬件能力、TLS 版本与 cipher：用户态基线、仅 TX/RX 成功、两个方向成功、启用失败和记录交接边界。用真实 TLS peer 验证 KeyUpdate、alert、close_notify、record padding、乱序读取、取消及强制错误，确保无 nonce 重用、丢失或重复数据。分别测试普通复制与 splice 的部分写入、拥塞、慢读者、字节统计、资源上限及性能；记录可用组合，未满足条件时遵循安全的回退或关闭策略。
