# 依赖与技术选型

状态：指定基线依赖已确定；候选方案、版本锁定和项目内接入方式待验证。上游信息核查日期：2026-10-27。

## 配置解析：glaze-kdl2.0-

- 指定仓库：<https://github.com/hiykhello/glaze-kdl2.0->。
- 指定分支：`feature/kdl2.0`。
- [完整分支入口](https://github.com/hiykhello/glaze-kdl2.0-/tree/feature/kdl2.0)。
- 项目职责：解析 KDL 2.0 配置，为类型化配置构造提供输入。

最初未能通过网页读取该分支内容；后续已只读核查本地指定分支，但仍不能据此声明完整 KDL 特性覆盖。接入必须以锁定提交的源码验证，不可直接套用其他 Glaze 版本的 API，也不可自动替换为上游默认分支。

后续核查确认 `glaze-kdl2.0-` 指定分支固定提交为 `fc646588635c42cca142562d7b3d0484cc4493b7`，项目 recipe 已锁定该提交及 MIT 许可，`nexus.thirdparty.glaze` 导出规则集所需 KDL/BEVE 接口；Linux x86_64 的 C++26 模块构建和规则集往返测试通过。完整 KDL 功能和其他工具链兼容性仍待验证。用户已确定 KDL/BEVE 规则集互转，见[格式设计](../architecture/rule-set-format.md)和[转换边界](../configuration/rule-sets.md)。

接入时需要核对：构建要求、许可证、KDL 2.0 语法覆盖、重复节点与属性行为、错误定位、类型转换及资源限制。具体支持能力以验证结果为准。

## 抽象接口：ngcpp/proxy

采用 [ngcpp/proxy](https://github.com/ngcpp/proxy) 表达运行时多态接口。上游说明其为 C++20 头文件库，支持无需实现类型继承抽象基类的多态表达。

在 Nexus 中，计划用 facade 描述组件能力，由具体组件满足契约。组件持有方式需要明确所有权和借用期限，不能假设任意 `pro::proxy` 都拥有被包装对象。

获取方式已确定为 Git 源码版本，来源为 `https://github.com/ngcpp/proxy.git`。接入时选择并记录通过本机 GCC、C++ Modules 和 facade 使用验证的完整 commit SHA；升级时显式更新该提交。默认构建不自动追随浮动 HEAD，不以发行版包或发布版本包替代用户指定的 Git 来源。项目已固定经验证的提交，具体来源与摘要见 `3rdparty/mcpp-pins.json`；Git 来源不自动要求使用 submodule。

这里的 Proxy 是 C++ 抽象库；Nexus 的 proxy 指网络代理平台。库本身不提供 Nexus 的代理协议实现。

## 协程与 I/O：cppalliance/corosio

采用 [cppalliance/corosio](https://github.com/cppalliance/corosio) 作为协程与 I/O 技术基础。上游将其描述为 C++20 协程 I/O 库，并明确依赖 [Capy](https://github.com/cppalliance/capy)。

接入时需一并核对 Corosio 与 Capy 的匹配版本、协程类型、执行器、取消与 I/O 对象的生命周期。项目依赖由 mcpp 描述符固定；升级时仍须重新验证。

Capy（`0.2.8`）与 Corosio（`0.3.12`）已锁定至本地离线验证归档，支持 Linux `epoll` 与 `io_uring` 后端。

## HTTP/1.1、HTTPS 与可选 HTTP/2

HTTP/1.1 自研，HTTPS 使用自研 HTTP 加自研 TLS，不采用第三方 HTTP/1.1 实现。HTTP/2 使用 [nghttp2](https://github.com/nghttp2/nghttp2) 的 libnghttp2 核心作无网络 I/O 协议引擎，已固定 1.70.0 发布源码及 SHA-256 并验证 Linux/GCC 16 静态核心包；不引入其工具或示例程序的 TLS/事件循环依赖。官方无 I/O 设计及内存输入/输出接口已核查，详见[HTTP 架构](../architecture/http.md)。HTTP/2 接入优先级已提高；固定 libnghttp2 核心包和内存交换 smoke test 已通过，但连接驱动、TLS ALPN 和应用适配仍未实现。

## QUIC / HTTP/3 的候选验证

无 I/O 的 [ngtcp2](https://github.com/ngtcp2/ngtcp2) 与 [nghttp3](https://github.com/ngtcp2/nghttp3) 核心已加入固定 release 包、锁文件和命名模块；配置、来源及 native ABI 校验见 [QUIC 依赖边界](../build/quic-dependencies.md)。它们配合 Nexus 自研 TLS 和既有 `libcrypto`，不编译第三方 `libssl`。

## 依赖管理约定草案

正式构建前记录每个直接依赖和必要传递依赖的来源、提交或版本、许可证及构建参数。指定分支用于追踪来源，可复现构建应进一步锁定到已验证提交。

项目通过 `3rdparty/mcpp-index` 维护固定的依赖描述符，来源与摘要另记于 `3rdparty/mcpp-pins.json`；在依赖之上提供可导出所需第三方接口的[命名模块](../build/third-party-modules.md)。必要时可验证源码 target 或 port，但不假定社区包满足 Nexus 的来源及 TLS 边界。

## 密码原语：BoringSSL libcrypto

按[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)，BoringSSL libcrypto 是密码学底座，自研 TLS 协议和指纹；只计划构建和静态链接 crypto，不引入 libssl 或独立 OpenSSL 实现。固定源码提交、平台汇编与具体构建参数仍待验证，TLS 状态机和证书策略也尚未实现。后续持续评估上游安全更新，不能把固定提交当作长期不更新的理由。

SS-2022 依赖 BLAKE3 KDF，WireGuard/WARP 及 Hysteria 还需要其他具体原语；必须先核查选定 libcrypto 公开 API 是否覆盖，缺少 BLAKE3 时其满足既有约束的来源与实现方式尚未决定，不得将其视为已有或悄悄引入另一套密码库。

## 自研能力与排除的依赖

按 [决策 0002](../decisions/0002-self-developed-network-stack.md) 及其在 [决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md) 中的修订，TUN 栈与 TLS/uTLS 类协议能力完全由 Nexus 自研，不引入第三方网络栈或第三方 `libssl`。

除选定的 BoringSSL libcrypto 外，不通过传递依赖、静态内嵌或可选回退引入其他密码库/TLS 实现；特别排除第三方 libssl 协议引擎。锁定依赖时应分别检查 Corosio 等库的 I/O 核心和可选 TLS 集成；本次尚未审计其完整依赖树，不声明现有选型已满足此约束。

证书验证策略、信任根和平台 TUN 接入所需系统组件继续待定，不能把“自研 TLS”自动等同为“所有底层组件全部自写”。详见[TLS 边界](../architecture/tls.md)与[TUN 边界](../architecture/tun.md)。
