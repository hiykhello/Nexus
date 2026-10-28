# 0002：参考 sing-box，自研 TUN 与 TLS 指纹能力

日期：2026-10-27。状态：方向已确定，实施方案待验证。来源：用户追加要求。

本记录保留最初决策；其中完全排除 BoringSSL 的部分已由[决策 0007](0007-boringssl-libcrypto-and-ktls.md)修订，现允许静态 BoringSSL libcrypto，仍不引入第三方 libssl。

## 决策

- 参考近期 sing-box 的设计，提取适用于 Nexus 的架构和工程组织方式。
- 自研 TUN 栈与相关 TCP/IP 处理能力。
- 自研 TLS 与 uTLS 类指纹能力，不依赖 BoringSSL/OpenSSL。
- 延续 C++ Modules、xmake、KDL 2.0、指定解析分支、ngcpp/proxy 和 Corosio 的既定基线。
- 当前继续以文档沉淀为交付范围。

## 参考方式

实际读取的源码版本、证据及设计判断见[sing-box 调研](../references/sing-box.md)。参考重点包括组件注册、作用域生命周期、流量上下文、路由预判、设备与协议栈分离、L3/L4 路径、队列与资源管理。

本地快照反映 sing-box 的近期开发方向，不承诺与远端最新 HEAD 或最新稳定版本一致。后续更新参考时重新记录提交及差异。

## 范围与影响

TUN 需要独立定义设备适配、平台网络管理、TCP/IP 处理、NAT、流量路由和资源预算。TLS 需要独立定义协议状态机、证书与身份、profile、密码原语及异步连接适配。

按后续决策，依赖锁定和发布产物应验证只使用指定的 BoringSSL libcrypto，不通过传递依赖或可选回退引入 libssl 或其他 TLS 实现。自研 TLS 不意味着所有密码原语均由 Nexus 实现。

## 尚未确定

首个支持平台、TCP/IP 与 TLS 协议子集、证书验证方案、指纹 profile 清单、模块名、性能目标和实现排期仍待确定；密码底座后来已按决策 0007 选定。没有承诺复现 sing-box 的全部协议、配置或平台能力。

细化草案：[组件模型](../architecture/component-model.md)、[TUN](../architecture/tun.md)、[TLS](../architecture/tls.md)、[验证路线](../planning/network-validation.md)。
