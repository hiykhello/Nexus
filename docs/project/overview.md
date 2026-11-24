# 项目定位

状态：平台定位与技术方向已确定，Linux 双后端内核及三端客户端基础已落地。

## 平台目标

Nexus 是一个通用代理平台，提供可组合的代理能力，同时支持 `client` 和 `server`。协议、传输方式和部署角色可独立演进并共享基础设施。

## 角色定义

| 角色 | 主要职责 | 典型路径 |
| --- | --- | --- |
| `client` | 接收本地流量，根据规则选择直连或远端代理 | 本地应用 → client → 目标或 server |
| `server` | 接收远端代理请求，按策略连接目标并转发数据 | client → server → 目标 |

`client` 与 `server` 共享配置模型、抽象接口、协程 I/O 和转发基础设施。

## 技术约束

- 项目自有 C++ 代码全面使用 C++26 Modules 组织，生产模块无统一前缀。
- C++ 代码尽量无异常，优先以 `std::expected` 表达可失败操作，以 `std::optional` 表达正常缺失；见 [编码规范](../development/cpp-guidelines.md)。
- 优先使用本机 GCC 的 C++26/C++23 能力；成员函数优先显式 `this`，模板优先 concept，函数优先后置返回类型，反射优先原生静态反射。
- 使用 `mcpp` 工作区作为项目构建入口，第三方依赖严格离线锁定。
- 使用 KDL 2.0 编写配置，使用指定的 `hiykhello/glaze-kdl` 仓库解析。
- 使用 `ngcpp/proxy` 表达抽象接口，使用 `cppalliance/corosio` 作为协程与 I/O 引擎。
- 自研 TUN 栈与用户态 TCP/IP/UDP 处理能力，核心设计原则见 [核心架构原则](../design-principles/core-architecture.md) 与 [TUN 设计](../architecture/tun.md)。
- 自研 TLS 与现代浏览器指纹能力，密码原语统一采用静态 BoringSSL `libcrypto`，不引入第三方 `libssl`；见 [TLS 设计](../architecture/tls.md)。
- HTTP/1.1 自研，HTTPS 组合自研 HTTP 与 TLS；HTTP/2 与 HTTP/3 分别基于无 I/O `nghttp2` 与 `ngtcp2`/`nghttp3`。
- 提供 KDL 2.0 文本规则集、BEVE 二进制规则集及双向语义转换。
- Linux 宿主集成覆盖原生 nftables 自动分流、策略路由、DNS 协作与 systemd 运维体验；详见 [Linux 网络集成](../platform/linux/networking.md) 与 [Linux 服务运维](../operations/linux-service.md)。
