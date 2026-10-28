# sing-box 设计参考

状态：源码调研记录。Nexus 的采用方式是设计草案；自研方向见[决策 0002](../decisions/0002-self-developed-network-stack.md)。

## 调研基线

调研日期：2026-10-27。用户指定本地仓库 `/home/yk/Code/sing-box`，本次仅只读分析。

| 项目 | 实际读取的版本 |
| --- | --- |
| sing-box | `testing` 分支，`a6952ccf6907c18e18917fcb763a433e8e36937b`，提交日期 2026-10-24，工作区干净 |
| sing-tun | 由上述 `go.mod` 指定：`v0.9.7-0.20261023115453-611d83b7a57b` |
| uTLS | 上述 `go.mod` 指定 `github.com/metacubex/utls v1.8.7`；本次读取 sing-box 的接入代码，未读取该库完整实现 |

sing-tun 源码来自本机 Go 模块缓存 `/home/yk/go/pkg/mod/github.com/sagernet/sing-tun@v0.9.7-0.20261023115453-611d83b7a57b`。

已查看[在线仓库入口](https://github.com/SagerNet/sing-box)、[在线 testing 依赖清单](https://github.com/SagerNet/sing-box/blob/testing/go.mod)及[官方 TUN 文档](https://sing-box.sagernet.org/configuration/inbound/tun/)。在线内容会变化，未核对远端 HEAD 与本地提交是否一致；本文的源码结论绑定上述快照，不把 testing 等同于最新稳定版。

## 值得借鉴的设计

下表的“优势”和“Nexus 采用方式”是基于源码的设计判断，不是已测出的性能结论。源码路径相对对应仓库根目录。

| 设计 | 源码依据 | 优势判断 | Nexus 采用方式草案 |
| --- | --- | --- | --- |
| 类型注册与构造分离 | sing-box `adapter/inbound/registry.go`、`option/inbound.go`、`include/registry.go` | 配置类型与组件工厂绑定，新增组件有明确入口 | 建立配置解码与组件构造的配对注册，输出能力清单 |
| 角色与流量组件分离 | `adapter/inbound.go`、`adapter/outbound.go`、`adapter/endpoint/registry.go` | 入站、出站、L3 端点可以组合 | client/server 使用共享组件模型，角色仅约束装配 |
| 分阶段生命周期与作用域 | `adapter/lifecycle.go`、`box.go` | 子组件获得取消作用域，清理回调逆序执行 | C++ RAII 结合异步停止作用域，启动失败可回收已创建资源 |
| 统一流量上下文 | `adapter/inbound.go` 的 `InboundContext` | 不同入站向路由提供同一套源、目标、协议和跟踪信息 | 采用共享核心元数据，另外拆出嗅探结果、路由结果与匹配缓存 |
| 规则条件与动作分离 | `option/rule_action.go`、`route/route.go` | 嗅探、解析、拒绝、选路可以表达为有顺序的处理步骤 | 建立类型化动作和继续/终止语义，避免每个入站重复决策 |
| 连接建立前预判 | `adapter/router.go`、`route/route.go` 的 `PreMatch` | 已知条件可提前拒绝或选择 L3 路径 | 复用同一规则模型，信息不足时显式推迟决定 |
| TUN 设备与协议栈分离 | `protocol/tun/inbound.go`；sing-tun `stack.go` | 平台设备接入与 TCP/IP 状态机可以独立测试 | 自研设备适配层与协议栈，通过包接口连接 |
| L3 与 L4 两条路径 | `JudgeFlow`、`NewConnectionEx`、`NewPacketConnectionEx`；sing-tun `flow.go` | 可按出口能力保留包转发或转成流/数据报 | 为 L3 端口和 L4 流定义不同 facade，明确返回路径 |
| 队列、引擎与定时器组织 | sing-tun `stack_go_engine.go`、`stack_go_wheel.go` | 数据、控制事件与定时任务有统一调度位置 | 先验证单引擎正确性，再评估按流分片与时间轮 |
| 有界资源与内存设备 | sing-tun `stack_go_memory.go`、`tun_memory.go`、`udp_nat.go` | 内存 TUN 便于无特权测试，资源策略可独立验证 | 提供内存包设备、明确队列和会话预算，测试压力下的行为 |
| TLS 配置与连接实例分离 | sing-box `common/tls/client.go`、`config.go`、`utls_client.go` | 协议组件可以共享 TLS 接入方式，每条连接独立持有握手状态 | 自研 TLS 引擎与 profile 配置分离，连接状态不共享可变对象 |

## 对近期 TUN 方向的核实

本地 `docs/configuration/inbound/tun.md` 说明：从 1.15.0 起采用 sing-tun 自有 TCP/IP 栈，`stack` 选项被弃用，计划在 1.17.0 移除。对应 sing-tun `stack.go` 中空值和 `go` 都进入 `NewGo`，旧 `system`、`gvisor`、`mixed` 分支仍保留于此快照。

因此 Nexus 的参考重点是自有栈的模块边界和实现组织，无需照搬历史上的多后端选择配置。上游关于性能、能耗和内存的优势描述属于上游说明，本次未做对比实验。

自有栈中仍使用 `gtcpip/header`、`gtcpip/checksum` 等辅助代码；“自有栈”不能自动推导为每一段基础代码均从零编写。

## 对 TLS/uTLS 方向的核实

本地 `common/tls/client.go` 根据配置选择 Go、Apple、Windows 等路径，并可分派到 uTLS；`config.go` 使用 Go `crypto/tls` 类型，`utls_client.go` 导入 `crypto/x509` 和外部 `metacubex/utls`。

这证明 sing-box 在此处进行 TLS 能力集成，不能据此声称它自写了完整 TLS、证书和密码学实现，也不能由单一路径推断整个依赖树都没有 BoringSSL/OpenSSL。

Nexus 借鉴统一接入、连接隔离和 profile 思路，自行用 C++ Modules 实现拟支持的 TLS 与指纹能力。其范围见[TLS 设计](../architecture/tls.md)，密码底座按后续决策采用 BoringSSL libcrypto。

## 不直接照搬的部分

- Go 的 context 服务查找与运行时类型断言，转换为显式装配依赖、类型化配置与 ngcpp/proxy 能力接口。
- 持续扩大的单个上下文对象，拆为稳定流量标识与阶段性结果，明确修改权限。
- 历史弃用字段与多栈开关，除非 Nexus 有实际兼容需求，否则不引入。
- Go 的线程与内存组织，结合 Corosio 的执行器和 C++ 对象生命周期重新验证。

本轮提取职责和行为设计，没有复制或翻译上游实现代码。后续实现按协议规范及独立测试确定具体算法和接口。

可复核入口：[固定版本 sing-box](https://github.com/SagerNet/sing-box/tree/a6952ccf6907c18e18917fcb763a433e8e36937b)、[指定 sing-tun 提交](https://github.com/SagerNet/sing-tun/tree/611d83b7a57b)。

进一步的批处理、调度、offload、内存与 TCP/TLS 优化提取见[性能专项分析](sing-box-performance.md)，另一参考项目见[shoes 分析](shoes.md)。

Linux 专属自动分流、nftables/NFQUEUE、策略路由、Docker/fw4 兼容、systemd 与 DNS 体验见[Linux 专项](sing-box-linux.md)。
