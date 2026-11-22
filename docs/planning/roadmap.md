# 实施路线

当前以[功能完整度清单](feature-completion.md)保留完整范围：协议及全部拨号字段、detour、流量与 DNS 专用规则/动作、uTLS 和具名 HTTP client。先完成真实能力，再统一优化；当前执行点见[项目进度](../progress.md)。下文保留原阶段顺序，不把局部测试作为项目完成依据。

状态：建议的后续验证顺序；已建立 mcpp/C++26 Modules 基线，实现有限规则集解析、转换、顺序匹配及 Linux 离线命令，以及受限的 SOCKS5 和 HTTP CONNECT 到直连 TCP 链路。有限主配置子集已接入，代理能力范围见 [SOCKS5 说明](../architecture/protocols/socks5-mixed.md)。

## 实际编写顺序

用户已授权从设计进入代码阶段。按依赖和可验证交付排序：

1. **工程基线**：mcpp 工作区、C++ Modules、固定来源的 Glaze、文件行数检查与可重复测试；先证明干净构建和第三方模块消费。
2. **配置与规则**：KDL/BEVE 谓词规则集的有界解析、语义校验、双向转换及顺序匹配；主配置逐步实现校验，不把其他节点当成已能启动的能力。
3. **最小运行链路**：Corosio/Capy 的真实集成、取消与资源生命周期，依次打通本地 Mixed/SOCKS5、路由和 direct/block，在隔离环境测 TCP/UDP。
4. **P0 安全与接管**：逐项验证 libcrypto、TLS、VLESS/Reality 与 SS-2022；并行条件成立后接入自研网络栈、TUN、防环回、DNS/Fake-IP 和原生控制面。先以内存和隔离环境验证状态与失败处理，再评估真实系统接管。
5. **P1 扩展**：WireGuard/WARP、MASQUE、Tailscale、Hysteria 2/QUIC、AnyTLS、Trojan 与其他承载各按依赖和互操作证据推进。每完成一个纵向切片，更新支持矩阵和验证结果，不以草案或依赖编译冒充功能完成。

这些阶段可以在依赖满足时交错，但不能跳过安全边界或把 P1 候选当成已验证依赖。具体未实现部分持续记录在[项目进度](../progress.md)。

| 阶段 | 工作 | 完成依据 |
| --- | --- | --- |
| 文档基线 | 记录定位、选型、架构与未决事项 | 分类文档和决策记录可检索 |
| 架构原则沉淀 | 梳理组件注册、分阶段生命周期、自研 TUN 栈与 TLS 边界 | 见 [核心架构原则](../design-principles/core-architecture.md) |
| 性能原则沉淀 | 梳理转发公平性、加速通道、索引和资源预算 | 见 [性能与数据面原则](../design-principles/performance-and-datapath.md) |
| Linux 集成设计 | 提取 nftables、路由、DNS 与 systemd 使用体验 | 已区分参考行为、Nexus 草案与未实现功能，后续在隔离环境验证 |
| DNS 与状态设计 | 提取缓存、乐观刷新、批写、快照与恢复 | 视图、期限、提交承诺及故障策略已记录，未选择存储依赖 |
| 协议与平台边界 | 提取注册、入出站、监听/拨号和宿主提供者模式 | 已形成独立协议家族、能力组合、平台所有权与验收草案 |
| 代理链路细化 | WireGuard/WARP、MASQUE、Tailscale、Hysteria 2、AnyTLS、SOCKS5/Mixed、TUN 防环回、Fake-IP、路由、原生控制面及配置 | 各专题与成对 KDL 草案可审阅；实现、平台操作和互操作尚未验证 |
| 依赖核查 | 读取指定 KDL 分支，核对各库与 Capy 的要求 | 有来源、提交、许可证和兼容性记录 |
| 构建验证 | 使用 mcpp 验证项目及各第三方 Modules、包和静态链接边界 | 各启用依赖可通过独立模块消费，最小工程可以干净构建与增量构建 |
| 配置验证 | 确定最小 schema，解析并校验配置 | 合法配置通过，非法配置有明确错误 |
| 规则集转换 | 共享语义模型与 KDL/BEVE 两个适配器 | 两方向重读语义等价、匹配一致、失败不破坏输入/正式输出 |
| I/O 验证 | 接入 Corosio，验证连接和数据传输 | 能观察完成、失败、取消与资源回收 |
| 自研 TUN | 先验证内存包设备、传输状态机和路由，再接真实设备 | 声明支持的包序列、异常行为与回滚均有证据 |
| 自研 TLS | 验证 BoringSSL libcrypto 接入，实现并验证 TLS 与 ClientHello profile | 互操作、身份校验、线上的编码表现和依赖约束通过验证 |
| 自研 HTTP/HTTPS | HTTP/1.1 核心及自研 TLS 组合，接入实际用途 | 增量 framing、背压、身份/ALPN、CONNECT 边界与互操作通过验证 |
| 最小代理链路 | 按优先级选取协议及 client/server 组合 | 成对配置通过真实端到端转发验证 |

## 当前未决问题

- 各优先级内的具体协议/传输组合及验证顺序；是否从静态 TCP 转发实验起步。优先级与不提供的旧协议见[决策 0008](../decisions/0008-protocol-priorities-and-vmess-deprecation.md)。
- HTTP/1.1/HTTPS 的首批用途与特性范围；HTTP/2 接入优先级已提高，固定 nghttp2 版本、无 I/O 适配、TLS ALPN 和流控边界按独立切片验证。
- client/server 的程序布局及是否允许同进程组合。
- 首个支持平台、C++ 标准档位与工具链版本。
- 按当前工作区补齐可选协议和测试，重新验证锁定依赖及其发布边界；HTTP/2 入口仍待迁入。Capy/Corosio 的固定提交及已验证范围见[工作区构建](../build/mcpp-workspace.md)。
- Hysteria 2 的 ngtcp2/nghttp3 候选能否适配自研 TLS/HTTP3、Brutal 如何接入；WireGuard 与 SS-2022 所需原语（尤其 BLAKE3）的实际来源和支持情况。
- 每个第三方命名模块的公开接口清单、与上游原生模块/宏的兼容方式及真实静态库的链接传播。
- facade 的协程返回类型、所有权和错误表达方式。
- 协议家族与 KDL 适配的模块粒度、入出站/承载兼容矩阵、平台后端与宿主提供者的资源边界。
- 配置 schema、默认值、版本兼容与诊断格式。
- 谓词规则集已有 v1 schema、BEVE 封装与 Linux 转换 CLI；未来扩展逻辑规则、兼容策略和其他平台文件发布仍待决定，见[当前规则集实现](../configuration/rule-sets.md)。
- 会话取消、超时、半关闭和停止流程。
- DNS 首期传输、解析视图、负缓存/乐观策略及默认限额；持久存储格式/后端、提交保证、FakeIP 崩溃承诺与迁移方式。
- 自研 TCP/IP 栈的首期协议范围、资源预算与平台接入方式。
- libcrypto 的具体提交和密码原语覆盖、证书验证方案、TLS 协议子集与指纹 profile 清单。
- 仅引入指定的 libcrypto，排除第三方 libssl 和独立 TLS 实现的构建及传递依赖核查方式。
- C++23 标准库 `std::expected` 的 Modules 支持、公共错误类型及依赖/协程异常边界；编码规范已明确优先使用 expected 与 optional。
- 优先使用 C++26：本机 GCC 16.2.1 已通过关键特性最小编译探测；仍需验证原生反射、现代函数包装与 Modules/依赖的组合，以及契约断言的运行检查策略。

优先验证会影响模块边界和依赖关系的事项，完成实验后更新相关草案。后续扩展能力应附带对应配置与验收依据。

第三方依赖的模块封装与独立消费计划见[第三方 Modules 封装](../build/third-party-modules.md)；Glaze、Capy、Corosio 有有限项目测试，模拟静态 C 库实验不能代替真实 libcrypto 等依赖的验证。

TUN 与 TLS 的细化验证见[网络栈验证路线](network-validation.md)。两项自研工作分别推进，不要求最小代理链路等待完整通用 TCP/IP 与 TLS 能力全部完成。

性能验证见 [优化实验矩阵](performance-validation.md)，先建立正确性及普通路径基线，再逐项比较优化；热重载与多代次管理现已接入生产控制面。

配置与原生控制面已形成[字段草案](../configuration/spec.md)及[协议草案](../architecture/control-api.md)；须先实现语义校验、认证、帧预算、事件与配置代次，再验证成对配置。热重载草案仍不等于首期已实现或已冻结。

Linux 专项见[集成验证计划](linux-validation.md)，包括多实例、规则冲突、外部防火墙重建、systemd 就绪/停止、DNS 与异常恢复。当前不部署正式 unit、不修改宿主防火墙。

DNS 与状态见[专题验证计划](dns-state-validation.md)，先建立 TTL/负缓存与普通查询基线，再验证乐观刷新、清空屏障和持久故障；不要求最小代理链路等待全部 DNS 传输或磁盘能力完成。

模块解耦先按[协议验收](../architecture/protocols.md)及[平台验收](../platform/abstraction.md)建立内存/假提供者实验，再替换真实监听、连接器和平台后端；不以架构候选协议名扩大首期承诺。
