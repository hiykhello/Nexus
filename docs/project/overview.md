# 项目定位

状态：平台定位与技术方向已确定；具体产品能力为待设计内容。

## 平台目标

Nexus 是一个通用代理平台，提供可组合的代理能力，同时支持 client 和 server。协议、传输方式和部署角色应能独立演进，共享基础设施。

“通用”描述平台的扩展方向，具体支持哪些代理协议、传输协议和操作系统，需逐项确定与实现。

## 角色定义

以下为角色职责草案：

| 角色 | 主要职责 | 典型路径 |
| --- | --- | --- |
| client | 接收本地流量，根据规则选择直连或远端代理 | 本地应用 → client → 目标或 server |
| server | 接收远端代理请求，按策略连接目标并转发数据 | client → server → 目标 |

client 与 server 共享配置模型、抽象接口、协程 I/O 和转发基础设施。是否使用单一可执行文件、是否允许一个进程同时启用两个角色，尚未确定。

## 技术约束

- 项目自有 C++ 代码全面使用 Modules 组织。
- C++ 代码尽量无异常，优先以 `std::expected` 表达可失败操作，以 `std::optional` 表达正常缺失；见[编码规范](../development/cpp-guidelines.md)。
- 优先使用本机 GCC 的 C++26/C++23 能力；成员函数优先显式 this，模板优先 concept，函数优先后置返回类型，反射优先原生静态反射。断言与函数包装按[编码规范](../development/cpp-guidelines.md)选择。
- 使用 xmake 作为项目构建入口。
- 使用 KDL 2.0 编写配置，使用指定的 glaze-kdl2.0- 分支解析。
- 使用 ngcpp/proxy 表达抽象接口。
- 使用 cppalliance/corosio 作为协程与 I/O 技术基础。
- 参考近期 sing-box 的设计，自研 TUN 栈与相关 TCP/IP 处理能力。
- 自研 TLS 与 uTLS 类指纹能力，密码原语使用 BoringSSL libcrypto，不使用第三方 libssl；证书验证策略仍待确定。
- HTTP/1.1 自研，HTTPS 组合自研 HTTP 与 TLS；后续 HTTP/2 可使用 nghttp2 无 I/O 核心。
- 提供 KDL 2.0 文本规则集、BEVE 二进制规则集及双向语义转换。

## 当前工作范围

当前阶段建立可追溯的设计文档，明确依赖边界和验证问题。协议清单、命令行、管理接口、热重载、性能指标及发布平台均待后续设计。

自研方向已确定，具体协议子集与交付顺序尚未冻结。参见[参考分析](../references/sing-box.md)、[TUN 设计](../architecture/tun.md)和[TLS 设计](../architecture/tls.md)。

Linux 宿主集成已补充为设计研究方向，包括 nftables 自动分流、路由/DNS 协作和 systemd 部署体验；详见[网络适配](../platform/linux/networking.md)与[服务设计](../operations/linux-service.md)。具体首期能力和最低系统版本仍待验证。
