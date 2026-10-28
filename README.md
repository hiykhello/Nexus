# Nexus

Nexus 定位为通用代理（proxy）平台，同时支持 client 与 server，全面采用 C++ Modules，以 xmake 构建。

项目已进入代码阶段：现有 C++26 Modules/xmake 构建、规则集 KDL/BEVE 互转及匹配、Linux 离线转换工具，以及实验性的 SOCKS5、Mixed、VLESS/TLS 和 SS-2022 代理链路。有限的 KDL 主配置已接入；自研 TLS 与内存网络栈已有实现和互操作测试，真实 TUN 接管和控制面仍未完成。

目前在 Linux x86_64 上使用 GCC 16.2.1 验证构建和测试；默认使用 io_uring，也可配置 epoll。网络 socket 类型不通过项目代理接口直接导出；构建与测试步骤见 [xmake 构建](docs/build/xmake.md)，转换命令和格式限制见 [规则集互转](docs/configuration/rule-sets.md)。

Linux 上可运行 `build/linux/x86_64/debug/nexus run 1080`，在 `127.0.0.1:1080` 提供无需认证的 SOCKS5 CONNECT，支持 IP 和系统解析的域名直连；追加 `kdl rules.kdl` 或 `beve rules.beve` 可按规则集阻断请求。也可用 `--config docs/configuration/examples/socks5.kdl` 启动有限的 KDL 配置。[Mixed 示例](docs/configuration/examples/mixed.kdl)在同一监听器支持 SOCKS5、HTTP CONNECT 和有限的单次 HTTP 正向代理；SOCKS5 可启用用户名密码认证。SOCKS5 UDP ASSOCIATE 和 Mixed 认证尚未接入；SS-2022 入站另有实验性 UDP 支持。详见 [SOCKS5 说明](docs/architecture/protocols/socks5-mixed.md)和[配置示例](docs/configuration/examples/README.md)。

## 已确定的技术方向

| 领域 | 选型 |
| --- | --- |
| 平台角色 | 同时支持 client 与 server |
| 代码组织 | 使用 C++ Modules；第三方依赖根据实际接口选择模块封装或私有实现 |
| C++ 规范 | 尽量无异常，优先使用 `std::expected` / `std::optional` |
| 语言能力 | 优先本机 GCC 的 C++26/C++23、显式 this、concept、后置返回类型及原生静态反射 |
| 构建系统 | xmake |
| 配置语言 | KDL 2.0 |
| 配置解析 | [glaze-kdl2.0- 的 feature/kdl2.0 分支](https://github.com/hiykhello/glaze-kdl2.0-/tree/feature/kdl2.0) |
| 抽象接口 | [ngcpp/proxy](https://github.com/ngcpp/proxy)，使用 Git 源码版本，锁定已验证提交 |
| 协程与 I/O | [cppalliance/corosio](https://github.com/cppalliance/corosio) |
| 网络栈 | 参考近期 sing-box/sing-tun，自研 TUN 与 TCP/IP 处理能力 |
| TLS 与指纹 | 自研 TLS 与 uTLS 类能力；密码原语使用静态 BoringSSL libcrypto，不使用第三方 libssl |
| HTTP / HTTPS | HTTP/1.1 自研，HTTPS 组合自研 HTTP 与 TLS；HTTP/2 接入优先级提高，固定 libnghttp2 无 I/O 核心已通过内存 smoke test |
| 规则集 | KDL 2.0 文本与 BEVE 二进制，提供双向语义转换 |

从[文档导航](docs/README.md)开始阅读。项目范围见[项目定位](docs/project/overview.md)，当前待验证事项见[实施路线](docs/planning/roadmap.md)。

设计与实现参考：[sing-box 分析](docs/references/sing-box.md)、[自研 TUN](docs/architecture/tun.md)、[自研 TLS 与指纹](docs/architecture/tls.md)。各文档区分已验证的实现与仍处于设计阶段的能力。

开发约定见[C++ 编码与错误处理规范](docs/development/cpp-guidelines.md)。

构建与依赖：[xmake 构建设计](docs/build/xmake.md)、[第三方依赖 Lua 封装](docs/build/third-party-xmake.md)、[第三方依赖 Modules 封装](docs/build/third-party-modules.md)。

性能与工程参考：[sing-box/sing-tun 性能机制](docs/references/sing-box-performance.md)、[shoes 优点提取](docs/references/shoes.md)；采用草案见[性能与资源设计](docs/architecture/performance.md)。

Linux 专项：[sing-box 集成参考](docs/references/sing-box-linux.md)、[nftables 与网络管理](docs/platform/linux/networking.md)、[systemd 服务体验](docs/operations/linux-service.md)。

DNS 与状态：[DNS、负缓存与乐观刷新](docs/architecture/dns.md)、[缓存与持久化设计](docs/architecture/state-and-cache.md)、[数据库设计](docs/architecture/database.md)、[日志设计](docs/architecture/logging.md)、[源码参考](docs/references/dns-and-persistence.md)及[验证计划](docs/planning/dns-state-validation.md)。

组件边界：[入站/出站与协议模块](docs/architecture/protocols.md)、[平台层与宿主接入](docs/platform/abstraction.md)、[sing-box 组件参考](docs/references/sing-box-components.md)。

HTTP 与规则集：[自研 HTTP/HTTPS](docs/architecture/http.md)、[KDL/BEVE 规则集互转](docs/configuration/rule-sets.md)。普通 HTTP 代理目前只处理单次请求，连接复用尚未实现；规则集支持有限的谓词类型。

协议与运行设计：[WireGuard/WARP](docs/architecture/protocols/wireguard.md)、[Hysteria 2](docs/architecture/protocols/hysteria2.md)、[SOCKS5/Mixed](docs/architecture/protocols/socks5-mixed.md)、[TUN 接管与防环回](docs/platform/tun-routing-and-loopback.md)、[Fake-IP/嗅探](docs/architecture/dns-fakeip-engine.md)及[路由热重载](docs/architecture/routing-engine.md)。

控制面采用 [Nexus 原生 API 与本地 IPC 草案](docs/architecture/control-api.md)；[KDL 配置规范](docs/configuration/spec.md)和成对 client/server 示例展示尚未实现的部署形态，不含真实凭据，不能运行。
