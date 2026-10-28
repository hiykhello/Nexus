# sing-box 的协议解耦与平台边界

状态：本地源码分析，2026-10-27。快照为 `/home/yk/Code/sing-box` 的 `a6952ccf6907c18e18917fcb763a433e8e36937b`，沿用[参考基线](sing-box.md)，未运行测试或修改参考仓库。下列路径相对该仓库。

## 组件装配与协议接入

| 源码依据 | 读取到的机制 | Nexus 可借鉴点 |
| --- | --- | --- |
| `include/registry.go` | 分别装配 inbound、outbound、endpoint、DNS transport、service 与 certificate provider registry | 一个应用装配入口选择组件，路由不直接列举全部协议 |
| `adapter/inbound/registry.go`、`adapter/outbound/registry.go` | 泛型注册绑定类型化 Options、配置对象构造与运行构造器 | 一个类型标识贯通配置和组件创建，避免解析与构造清单各自漂移 |
| `adapter/inbound.go` | 最小 Inbound 为生命周期、Type、Tag，TCP/UDP 注入为附加能力 | 监听入口与已接收连接的处理可分开，不要求所有入站都监听 TCP |
| `adapter/outbound.go` | Outbound 提供 Dialer、网络能力与依赖；L3 FlowOutbound、复用等单独扩展 | 按提供的能力对接路由，特殊出口不强塞到单一字节流模型 |
| `adapter/endpoint.go` | Endpoint 同时具有生命周期和 outbound 能力，另设 manager | 长期隧道或设备型组件有独立拥有者，不必创建两个彼此争用状态的方向实例 |
| `adapter/outbound/adapter.go`、`manager.go` | detour 转为依赖，manager 按依赖启动并诊断循环/缺失 | 出站链是依赖图，构造与启动顺序不能取决于配置文件先后 |

该 registry 的 register 实际直接赋值 map，不能描述为自动拒绝重复类型；Nexus 仍建议主动报重复注册错误。Go 的 any/类型断言也是其实现细节，Nexus 不必在内部照搬不受控的动态类型容器。

## 协议、监听与拨号分别复用

`protocol/socks/inbound.go` 创建公共 `common/listener`，通过 `github.com/sagernet/sing/protocol/socks` 的握手处理提取用户/目标，再交给 ConnectionRouter。`protocol/socks/outbound.go` 则用公共 dialer 构造 SOCKS client，并适配字节流、包连接和可选 UoT。两端复用外部协议能力，但仍保留各自的配置与运行状态。

这体现了四个不同职责：接收/建立承载、处理协议、选择出口、公共转发。不能据此说 sing-box 所有协议都有完全独立的纯状态机，或它们都由 sing-box 仓库自行实现。

`common/dialer/dialer.go` 选择 default/detour，再按条件组合域名解析；协议因此无需各自实现出口接口选择、节点解析和 detour 查找。相应依赖通过 context service 查询，Nexus 可借鉴能力注入，但建议把必需依赖显式列入构造参数，避免服务缺失延迟到连接热路径。

`transport/v2ray/transport.go` 为 client/server 分别构造 HTTP、WebSocket、QUIC、gRPC 等承载，QUIC 检查 TLS 前提。这是兼容矩阵和公共构造边界，不证明每种协议都能任意组合每种承载。Nexus 也应明确每个组合是否有效。

`include/quic.go` 与 `quic_stub.go` 使用 build tag 在真实实现与“未编译”错误之间选择，保留有意义的诊断；stub 中还存在 init 注册。Nexus 可保留缺失能力诊断，但采用显式装配，避免跨 C++ Modules 的全局初始化顺序依赖。这些机制属于编译期组件装配，不能直接称作稳定 ABI 的动态插件系统。

## 平台与宿主接入

`adapter/platform.go` 集中定义平台能力，包括设备打开、出口 FD 控制、接口/默认路由监控、连接属主、Wi-Fi、通知和自动重定向等。`route/network.go` 按 UsePlatform 等开关选择平台提供的接口枚举、监控与控制路径，支持将宿主系统能力接入核心。

`protocol/tun/inbound.go` 在平台提供接口时调用 OpenInterface，否则选择原生 TUN 路径；`experimental/libbox/platform.go` 暴露 OpenTun、监控回调等宿主绑定接口。这里的 libbox API 与内部 adapter 不完全相同，说明嵌入边界可以做数据和句柄转换，而非直接暴露核心内部类型。

优点是允许 CLI 原生运行与宿主托管设备使用共同的路由/协议逻辑。局限是 PlatformInterface 较宽，含有特定部署能力，不能推导所有方法在所有平台都可用；其中也有 fd/int 和平台条件分支。Nexus 建议拆为窄平台 facade，并分别标明所有权、权限、回调线程和能力可用状态。

Linux nftables、网络恢复和服务部署的机制另见[Linux 专项](sing-box-linux.md)。本文未审计所有平台实现，不声明 Nexus 已支持 Android、Apple 或 Windows。

采用草案：[协议与入出站](../architecture/protocols.md)、[平台抽象](../platform/abstraction.md)、[Modules](../architecture/modules.md)。
