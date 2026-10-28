# 文档导航

本目录保存 Nexus 的项目定义、技术约束与设计规范。

| 分类 | 文档 | 内容 |
| --- | --- | --- |
| 项目 | [项目定位](project/overview.md) | 平台目标、client/server 角色与范围 |
| 架构 | [总体架构](architecture/overview.md) | 分层、数据路径与生命周期草案 |
| 架构 | [组件模型](architecture/component-model.md) | 注册、路由上下文、生命周期与装配 |
| 架构 | [入站、出站与协议解耦](architecture/protocols.md) | 协议家族、承载组合、数据面契约和编译裁剪 |
| 架构 | [Reality 接入](architecture/protocols/reality.md) | 身份验证、客户端与服务端边界、fallback 和互操作 |
| 架构 | [VLESS / Trojan / SS-2022](architecture/protocols/vless-trojan-ss.md) | 协议边界、流控和抗重放要求 |
| 架构 | [WireGuard 与 WARP](architecture/protocols/wireguard.md) | Noise、peer 生命周期、标准模式与 WARP profile |
| 架构 | [Hysteria 2 与 QUIC](architecture/protocols/hysteria2.md) | 无 I/O QUIC 候选、HTTP/3、UDP 和拥塞控制 |
| 架构 | [SOCKS5 与 Mixed](architecture/protocols/socks5-mixed.md) | 握手、CONNECT、UDP ASSOCIATE 和资源管理 |
| 架构 | [HTTP/1.1、HTTPS 与 HTTP/2](architecture/http.md) | 自研 HTTP、TLS 组合及后续无 I/O nghttp2 接入 |
| 架构 | [具名 HTTP 客户端](architecture/http-clients.md) | tag、出口与解析依赖、生命周期和验证草案 |
| 架构 | [自研 HTTP 代理线规](architecture/http-proxy-spec.md) | 零分配 CONNECT 解析、Handoff 交接与 RFC 9298 MASQUE |
| 架构 | [C++ Modules](architecture/modules.md) | 模块组织、依赖方向与第三方边界 |
| 架构 | [源码物理目录规划](architecture/source-tree.md) | 源码工程目录结构、C++26 模块映射与 xmake 构建草案 |
| 架构 | [自研 TUN 栈](architecture/tun.md) | 设备接入、TCP/IP、L3/L4 路径与资源管理 |
| 架构 | [自研 TLS 与指纹](architecture/tls.md) | TLS 协议、ClientHello profile 和密码学边界 |
| 架构 | [uTLS 指纹编排引擎](architecture/utls-engine.md) | 现代浏览器指纹矩阵、GREASE 注入与 ML-KEM/Kyber 布局 |
| 架构 | [Linux kTLS 零拷贝架构](architecture/ktls.md) | 握手状态下沉、setsockopt 密钥注入与 splice 管道直通 |
| 评估 | [BoringSSL libcrypto 底座](architecture/boringssl-libcrypto.md) | 密码原语评估、依赖边界与接入注意事项 |
| 架构 | [并发与多线程架构](architecture/concurrency.md) | worker 所有权、监听分发、共享状态与停机 |
| 架构 | [性能与资源设计](architecture/performance.md) | 转发、批处理、加速切换、规则索引和资源预算 |
| 架构 | [DNS 与乐观缓存](architecture/dns.md) | 解析视图、TTL、负缓存、过期应答和后台刷新 |
| 架构 | [Fake-IP 与嗅探](architecture/dns-fakeip-engine.md) | 双向映射、可安全复用条件、恢复与嗅探限制 |
| 架构 | [路由匹配与热重载](architecture/routing-engine.md) | 有序规则、索引、借用生命周期和配置代次 |
| 架构 | [原生控制面与 IPC](architecture/control-api.md) | 自定义 HTTP/JSON、事件流、BEVE 本地 IPC、授权与统计 |
| 架构 | [缓存与持久状态](architecture/state-and-cache.md) | 状态分类、批写、提交语义、恢复、FakeIP 和版本 |
| 架构 | [状态数据库](architecture/database.md) | SQLite 候选、异步边界、事务、恢复与验收 |
| 架构 | [日志系统](architecture/logging.md) | stderr、文件 sink、异步背压与故障处理 |
| 架构 | [规则集二进制格式](architecture/rule-set-format.md) | BEVE、指定 Glaze 分支、文件封装与索引边界 |
| 架构 | [BEVE 状态模型](architecture/beve-schemas.md) | 规则与持久状态的逻辑字段、序列化和恢复边界 |
| 参考 | [sing-box 设计分析](references/sing-box.md) | 固定源码快照、可借鉴设计与采用方式 |
| 参考 | [sing-box 组件与平台](references/sing-box-components.md) | 注册、监听/拨号、承载、endpoint 与宿主接口 |
| 参考 | [sing-box 性能分析](references/sing-box-performance.md) | 批处理、引擎、offload、定时器与空闲回收 |
| 参考 | [sing-box Linux 集成](references/sing-box-linux.md) | nftables、策略路由、Docker/fw4、systemd 与 DNS |
| 参考 | [shoes 设计分析](references/shoes.md) | 转发公平性、splice、索引、预算和测量方法 |
| 参考 | [DNS 与持久化分析](references/dns-and-persistence.md) | sing-box 缓存、乐观刷新及 shoes 快照与地址预留 |
| 技术 | [依赖与选型](technology/dependencies.md) | 指定库职责、BoringSSL 密码底座与接入事项 |
| 工程 | [xmake 构建](build/xmake.md) | 构建约束和工具链验证计划 |
| 工程 | [xmake 第三方依赖封装](build/third-party-xmake.md) | 项目内 Lua recipe、锁定、各依赖构建边界与验证 |
| 工程 | [第三方依赖 Modules 封装](build/third-party-modules.md) | 第三方命名模块、导出接口、链接传播与验收 |
| 平台 | [Linux 网络集成](platform/linux/networking.md) | 透明接管、mark、NFQUEUE、系统配置与恢复 |
| 平台 | [平台抽象与宿主集成](platform/abstraction.md) | 窄能力、句柄所有权、事件线程与原生/宿主边界 |
| 平台 | [跨平台 TUN 接管与防环回](platform/tun-routing-and-loopback.md) | Linux、Windows、macOS 路由保护、失败恢复与验证 |
| 运维 | [Linux 服务体验](operations/linux-service.md) | systemd、目录、权限、就绪状态与诊断 |
| 开发 | [C++ 编码规范](development/cpp-guidelines.md) | expected、optional、异常边界、资源与协程错误处理 |
| 开发 | [代码文件行数规范](development/file-sizes.md) | 300 行目标、500 行上限、例外与自动检查 |
| 开发 | [C++26 实用数据结构](development/cpp26-data-structures.md) | inplace_vector、hive、flat_map、function_ref 应用规范 |
| 开发 | [上游问题与待调查现象](development/upstream-issues.md) | 依赖和工具链问题、复现范围、处理及跟踪状态 |
| 开发 | [本机 GCC 能力](development/gcc-capabilities.md) | C++23/26 特性编译探测、反射与契约边界 |
| 配置 | [KDL 2.0 配置设计](configuration/kdl.md) | 格式、解析流程与语义草案 |
| 配置 | [KDL 配置规范草案](configuration/spec.md) | 组件、协议、规则、DNS、TUN、凭据与控制面配置 |
| 配置 | [KDL/BEVE 规则集互转](configuration/rule-sets.md) | 共享语义模型、两个转换方向、错误与往返验收 |
| 配置 | [配置示例](configuration/examples/README.md) | client/server KDL 示例及其边界 |
| 决策 | [初始技术基线](decisions/0001-platform-baseline.md) | 已确定的项目方向与未决事项 |
| 决策 | [自研网络能力](decisions/0002-self-developed-network-stack.md) | 自研 TUN、TLS/uTLS 类能力及依赖约束 |
| 决策 | [C++ 错误处理](decisions/0003-cpp-error-handling.md) | 尽量无异常、优先 expected 与 optional |
| 决策 | [现代 C++ 能力](decisions/0004-modern-cpp.md) | 显式 this、concept、反射、断言与函数包装优先级 |
| 决策 | [HTTP 实现方向](decisions/0005-http-stack.md) | 自研 HTTP/1.1、HTTPS 与后续 HTTP/2 边界 |
| 决策 | [规则集格式与互转](decisions/0006-rule-set-formats.md) | KDL/BEVE 已确定及可逆语义要求 |
| 决策 | [BoringSSL 底座与 kTLS](decisions/0007-boringssl-libcrypto-and-ktls.md) | 正式采纳 libcrypto 密码底座与 Linux kTLS 卸载 |
| 决策 | [协议优先级与拒绝旧协议](decisions/0008-protocol-priorities-and-vmess-deprecation.md) | TUN、SS-2022、WireGuard 优先级提升，明确拒绝 VMess 与经典 AEAD |
| 计划 | [实施路线](planning/roadmap.md) | 技术验证顺序与验收条件 |
| 计划 | [无异常与可恢复分配](planning/fallible-allocation.md) | 内存耗尽错误传播与依赖迁移验收 |
| 计划 | [网络栈验证](planning/network-validation.md) | 协议正确性、互操作、资源与性能验证 |
| 计划 | [性能验证](planning/performance-validation.md) | 优化对照实验、指标解释与可复现证据 |
| 计划 | [Linux 集成验证](planning/linux-validation.md) | 服务生命周期、防火墙共存、DNS、崩溃恢复与优化对照 |
| 计划 | [DNS 与状态验证](planning/dns-state-validation.md) | TTL/刷新竞态、故障注入、崩溃恢复和缓存性能 |
| 接手 | [接手记录](handoff.md) | 当前进度、关键决定与下一步 |

---

## 文档状态约定

- **已确定**：用户明确给出的项目定义和技术选择，变更时需要更新决策记录。
- **设计草案**：为后续讨论提出的结构、命名或行为，不代表已冻结的接口。
- **待验证**：需要通过指定依赖源码、构建实验或运行实验确认的事项。
