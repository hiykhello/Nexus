# C++ Modules 组织

状态：全面使用 C++ Modules 已确定；新模块与命名空间已确定**不再使用 `nexus.` / `nexus::` 前缀**，存量模块按第 91–96 批逐步去前缀迁移。

## 命名与去前缀约定

- **新增模块与命名空间**：直接以领域命名（沿用已落地的 `containers.byte_ring` / `containers.ring_queue` 与 `namespace containers`），例如 `logging.*`（`namespace logging`，避开 `<math.h>` 全局 `::log`）、`state.*`（`namespace state`）、`encoding.base64_key`（`namespace encoding`）。
- **存量模块迁移**：自底向上分批移除 `nexus.` 模块前缀与 `nexus::` 命名空间前缀，确保每批可独立编译验收，避免与第三方模块（如 `export module proxy.v4;`，其命名空间为 `pro::`）或 C/POSIX 全局符号冲突。迁移批次见[第 91–96 批规划](../planning/next-batches-91-96.md)。

## 组织原则

项目自有 C++ 接口通过命名模块导出，模块之间通过 `import` 表达依赖。内部实现使用模块实现单元或内部 partition，控制导出范围，保持依赖图无环。

第三方依赖也封装为可导入并导出实际所需 API 的命名模块；package 负责获取和构建，模块 target 负责 C++ 接口。是否采用上游原生模块需按锁定版本确认；头文件、宏和编译型库的链接须在各自边界处理，不能未经验证就整体重导出。业务模块可以选择是否重导出第三方模块，其消费者也可以独立导入第三方模块。各依赖的规划与验收见[第三方 Modules 封装](../build/third-party-modules.md)。

## 建议模块

| 模块名草案 | 职责 |
| --- | --- |
| `nexus.thirdparty.*` | 封装并导出各第三方库的所需 C++ 接口；每个库独立 target，nghttp2 按需启用 |
| `nexus.core` | 端点、错误和基础数据类型 |
| `nexus.config` | 类型化配置、解析入口和校验 |
| `nexus.runtime` | Corosio 与协程运行时集成 |
| `nexus.platform` | 平台窄能力契约、公共值类型与资源所有权约定 |
| `nexus.platform.linux` | Linux 原生能力实现，由装配层选择；其他后端按验证增加 |
| `nexus.transport` | 连接器、承载能力及组合；具体承载按需拆分 |
| `nexus.ingress` | 监听/注入入口与入站会话接入协调 |
| `nexus.egress` | 出站能力目录、连接计划与依赖管理 |
| `nexus.packet` | 包视图、校验、缓冲区及包设备契约 |
| `nexus.netstack` | 自研 IP、TCP、UDP、ICMP 等状态处理 |
| `nexus.tun` | TUN 设备与平台网络配置适配 |
| `nexus.crypto` | 密码原语能力边界，适配 BoringSSL libcrypto |
| `nexus.pki` | 证书、身份和信任策略 |
| `nexus.tls` | 自研 TLS 状态机、记录层与异步流适配 |
| `nexus.tls.profile` | ClientHello profile 与握手表现配置 |
| `nexus.contracts` | 基于 ngcpp/proxy 的能力契约 |
| `nexus.protocol.<name>` | 每种协议的共享编解码、client/server 状态与角色适配 |
| `nexus.http` | HTTP 公共语义与消息/流事件，供不同用途适配 |
| `nexus.http.h1` | 自研 HTTP/1.1 解析、编码及连接状态 |
| `nexus.http.h2` | 未来可选的 libnghttp2 适配，不向公共模型泄漏 C 对象 |
| `nexus.quic` | 待验证的通用 QUIC 核心和自研 TLS 适配，候选 ngtcp2/nghttp3 |
| `nexus.routing` | 路由与出口选择 |
| `nexus.rules` | 规则语义模型、校验与编译；KDL/BEVE 适配按需要拆分 |
| `nexus.dns` | 解析视图、请求/响应、上游与协议缓存语义 |
| `nexus.state` | 存储所有权、批写、持久提交与恢复能力 |
| `nexus.session` | 会话状态与转发协调 |
| `nexus.control` | 原生 HTTP/JSON、SSE 和 BEVE IPC 适配，调用窄控制服务 |
| `nexus.app` | client/server 应用装配 |

建议由 `core` 承载最小公共类型，`app` 组合其余模块；底层模块不依赖 `app`。`contracts` 中需要哪些协程返回类型，应在 Corosio 集成实验后决定，避免与 `runtime` 形成循环依赖。

`nexus.protocol.<name>` 是模块命名模式，不是可以直接 import 的名称。协议家族先按 codec/client/server 内部 partition 组织，独立裁剪有收益时再拆命名子模块；不建立一个必须 import 全部协议的公共 `nexus.protocol` 门面。协议类型化选项可在本家族定义，KDL 注册/解码与应用装配集中集成，通用解析器不依赖所有实现。

`ingress`、`egress` 承载共同机制，不 import 具体协议家族；协议适配依赖这些机制及窄契约，app 显式注册和注入。路由只依赖出站能力，协议核心不依赖路由实现、平台后端或 CLI。具体协议/承载组合与 endpoint 所有权见[协议设计](protocols.md)。

HTTP 代理协议适配复用 `http`/`http.h1`，规则下载或其他 HTTP 用途也依赖这套核心；HTTP 核心不反向 import 代理、下载器或管理端实现。HTTPS 由装配组合 TLS，不另建一份 HTTP 解析器。未来 h2 遵循同样方向，见[HTTP 设计](http.md)。

`rules` 的语义模型不依赖 KDL/BEVE 解析器，格式适配层依赖该模型与指定 Glaze 入口；离线转换工具与运行时加载器共享适配和校验。匹配器不按查询重新解析文件，二进制中保留反向导出所需语义，见[规则集转换](../configuration/rule-sets.md)。

`platform` 的能力契约与 `contracts` 按领域分工：前者面向 OS/宿主资源，后者面向通用流/数据报等能力，均不得成为所有实现的导入集合。平台后端实现契约，运行时适配负责 Corosio 句柄登记；公共异步类型的位置需实验确认无循环。详见[平台抽象](../platform/abstraction.md)。

当前 Linux 双栈 UDP socket 在 `nexus.net.udp_socket`，提供地址、发送、窥视与单次接收；SOCKS 和 UoT 使用窥视后消费，SS 按会话使用单次接收。策略、目标授权、会话和协议封包仍由各自上层负责。该边界不引入新的系统调用或分配；UoT 的上层路由和授权模型尚依赖 SOCKS 类型。

`packet` 中的包设备契约同时允许内存实现和 TUN 实现，`netstack` 不直接依赖具体平台的 TUN 设备。TLS 核心通过密码原语与证书边界处理协议，`profile` 依赖稳定的握手描述类型，核心不反向依赖具体 profile；装配层组合二者。表中的模块是职责候选，最终拆分粒度仍需编译与依赖图验证。

`dns` 定义协议有效期、解析视图与乐观刷新，`state` 通过窄存储契约提供提交和恢复，不反向依赖 DNS 路由策略。FakeIP 在普通 DNS 缓存之外管理归属；具体归属模块待接口验证，不能为了共用存储制造 `dns`、`routing` 与 `state` 的依赖环。见 [DNS](dns.md)与[持久状态](state-and-cache.md)。

`nexus.control` 只调用授权后的会话/路由/selector 服务，不反向成为数据面依赖；HTTP/JSON 与 BEVE IPC 的接口及职责见[原生控制面](control-api.md)。`nexus.quic` 的第三方模块与 TLS secret 适配、HTTP/3 与 Hysteria 请求流分流均为候选，尚未添加依赖或验证可行性，见[Hysteria 2](protocols/hysteria2.md)。

## 需要验证的模块边界

- ngcpp/proxy 的 facade、模板和宏在模块接口中的可达性与可见性。
- Corosio 及其协程依赖跨模块使用时的编译、链接和生命周期行为。
- 配置解析库的头文件与模板在模块中的接入方式。
- mcpp 对模块依赖扫描、跨工作区成员导入和增量构建的处理。
- 编译器、标准库、编译参数变化后模块产物的重建行为。
- 包设备、协议状态机和 TLS profile 的契约是否可独立编译并避免循环依赖。
- 协议家族能否分别裁剪入站/出站，且路由、公共配置读取器不导入全部协议；平台后端能否由假提供者替换而不改协议核心。
- 密码学与其他传递依赖是否满足仅引入所选 BoringSSL libcrypto、不引入第三方 libssl 或其他 TLS 实现的约束。

模块产物与具体工具链相关，不应作为跨编译器通用二进制接口。按[编码规范](../development/cpp-guidelines.md)直接使用标准库 `std::expected` 时，项目自有代码需要至少 C++23；具体标准档位和编译器版本待验证后记录，不能仅以支持 C++20 判断 Modules 已可用。

模块接口与 facade 的可失败操作优先返回 `std::expected`，正常缺失优先返回 `std::optional`。错误类型由稳定的公共模块定义，避免因错误上下文反向依赖应用层；具体 `Error` 结构仍为待设计内容。

当前语言方向优先本机 GCC 已提供的 C++26 能力；原生静态反射、显式对象参数、concept 和现代函数包装遵循[编码规范](../development/cpp-guidelines.md)。反射已通过独立编译探测，跨模块反射及成员可达性尚待验证；不要提前假定其可直接替代指定配置库的映射机制。
