# 0002：自研 TUN 栈与 TLS 指纹能力

日期：2026-10-27。状态：已确定并落地。

本记录保留最初决策；其中完全排除 BoringSSL 的部分已由 [决策 0007](0007-boringssl-libcrypto-and-ktls.md) 修订，现采用静态 BoringSSL `libcrypto` 作为密码学原语底座，仍不引入第三方 `libssl`。

## 决策

- 自研用户态 TUN 栈与 TCP/IP/UDP 处理能力，不引入重型第三方通用网络栈。
- 自研 TLS 协议状态机与现代浏览器指纹编排能力，密码学原语统一收口在 BoringSSL `libcrypto`。
- 延续 C++ Modules、`mcpp`、KDL 2.0、指定解析分支、`ngcpp/proxy` 和 Corosio 的既定基线。

## 架构重点

核心设计原则已沉淀在 [核心架构原则](../design-principles/core-architecture.md) 与 [性能与数据面原则](../design-principles/performance-and-datapath.md)，重点包括组件注册分离、分阶段作用域生命周期、统一流量上下文、规则预判、设备与协议栈分离、L3/L4 双路径以及有界队列与内存预算。

## 范围与影响

- TUN 独立定义设备适配、平台网络管理、TCP/IP/UDP 状态机、NAT、流量路由与资源预算。
- TLS 独立定义协议状态机、证书与身份校验、指纹 profile、密码原语边界与异步连接适配。
- 按后续决策，依赖锁定与发布产物只链接静态 BoringSSL `libcrypto`，不通过传递依赖或可选回退引入 `libssl` 或其他第三方 TLS 协议栈。

细化文档：[组件模型](../architecture/component-model.md)、[自研 TUN 栈](../architecture/tun.md)、[自研 TLS 与指纹](../architecture/tls.md)、[验证体系与实机基线](../planning/validation.md)。
