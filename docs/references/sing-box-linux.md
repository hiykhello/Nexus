# sing-box 的 Linux 优化与系统集成

状态：源码分析。调研日期 2026-10-27，未执行服务部署、防火墙变更或性能实验。

版本沿用[参考基线](sing-box.md)：sing-box `a6952ccf6907c18e18917fcb763a433e8e36937b`，本地 `/home/yk/Code/sing-box`；sing-tun `v0.9.7-0.20261023115453-611d83b7a57b`，本地 Go 模块缓存。下文路径相对各自源码根目录，不代表远端最新状态。

## Linux 数据面与控制面协同

| 机制 | 源码依据 | 价值与适用条件 |
| --- | --- | --- |
| nftables 自动透明分流 | sing-tun `redirect_linux.go`、`redirect_nftables.go` | 自动建立规则、标记与重定向，不要求用户维护完整脚本 |
| conntrack 复用判定 | `nftablesAddPreMatchRules` | 包 mark 与连接 mark 之间保存/恢复，已识别流量可以绕过重复预判 |
| NFQUEUE 首阶段判定 | `nfqueue_linux.go`、`redirect_nftables.go` | 部分决策交给用户态，再返回 verdict/mark；受协议、已知信息和队列能力限制 |
| 内核 bypass | sing-box `docs/configuration/shared/pre-match.md`；sing-tun 的 mark/verdict 路径 | 满足条件的流量可避免进入代理转发路径，不等同于建立一个 direct 代理连接 |
| 策略路由与出口绕行 | sing-tun `tun_linux.go`、`redirect_route_linux.go` | 协调 fwmark、路由表与规则，避免自身出口再次进入 TUN |
| 本地地址集合更新 | `redirect_nftables.go` 的 `updateNetworkAddresses`、`nftablesUpdateLocalAddressSet` | 网络地址变化时更新排除集合，不依赖固定启动快照 |
| 网络命名空间 | `redirect_linux.go`、sing-box `cmd/sing-box/cmd_run_userns_linux.go` | 对特定 namespace 配置网络；rootless user namespace 路径有权限与内核条件 |
| 原生 TUN 优化 | sing-tun `tun_linux.go`、`stack_go_io_linux.go` | 多队列、virtio 包元信息、校验和/分段能力与系统调用适配 |

上游 TUN 文档推荐 Linux 使用 `auto_route` 加 `auto_redirect`，并声称比 TPROXY 更高效。本轮仅验证实现机制，不复述为已测性能结论；也不能把上层已弃用的 `gso` 配置字段与内部自动探测的 offload 能力混为一谈。

## nftables 设计的优点

`setupNFTables` 构建专有 `inet` 表，以及 output/prerouting 等不同 hook 上的处理链，集合与表达式通过库接口组织。预判链排除 TUN 输入、回复方向及已标记流量，TCP 还有 SYN 阶段筛选。这个设计让“是否需要用户态判定”和“如何转发后续数据”分工明确。

NFQUEUE 并非零成本：本地实现设置队列长度、复制包长度和 GSO 标志。不能声称所有流都严格只排队一次，或后续 UDP、ICMP、分片及状态失效无需额外处理。Nexus 借鉴时应验证实际排队比例、丢弃和超时，而非仅以启用 nftables 作为提速依据。

同一 nft 连接上的规则构造以 `Flush` 提交，但启动过程中还包括清理旧表、建立路由、更新外部防火墙等多步操作。这不证明“整个网络变更具备单次原子事务”。Nexus 需要定义分阶段提交与补偿，而非从一个 `Flush` 推断全局回滚。

## Docker 与 OpenWrt 兼容

`redirect_nftables_docker.go` 查找所支持的 `DOCKER-USER` 链，对与 TUN 相关的转发插入兼容规则，规则包含实例相关注释；通过 ruleset monitor 在相关对象变化时修复。清理逻辑按规则身份识别自身兼容项。

优点是考虑防火墙被其他服务重建后的持续运行，不只让首次启动成功。其适用范围受 Docker 防火墙后端及链结构限制，不能推导为兼容所有 Docker 版本、firewalld、Podman 或任意用户规则。

`redirect_nftables_rules_openwrt.go` 检查 `inet fw4` 与 `fw4` 程序，写入实例相关的 `/etc/nftables.d/0-<table>-auto-redirect.nft`，再执行 `fw4 reload`；清理时删除该文件并重载。因此 OpenWrt 路径实际包含持久文件和外部命令，并非全部由直接 Netlink 调用完成。

Nexus 可提取“自身对象隔离、已知外部防火墙适配、事件驱动恢复”的原则，不能把向外部链插入 accept 规则当成普遍安全或必然正确的默认做法。

## systemd 服务与安装体验

sing-box 的两个 unit 分别为 `release/config/sing-box.service` 和 `sing-box@.service`：

| 已有设计 | 具体行为 | 优点与局限 |
| --- | --- | --- |
| 普通服务与实例模板 | 普通服务读取配置目录，实例服务读取 `%i` 对应文件 | 多部署实例有统一入口，但网络表、mark 和接口仍需另外隔离 |
| 状态目录 | `StateDirectory=sing-box` 或 `sing-box-%i`，启动参数指向对应目录 | 配置和持久状态分开，实例状态不共用 |
| 自动重启 | `Restart=on-failure`、`RestartSec=10s` | 异常退出可恢复，不能代替失败原因和重启限频设计 |
| 重载入口 | `ExecReload` 向主进程发送 HUP | 用户可通过 systemctl 触发重读，但信号发送成功不代表重载完成 |
| 启动顺序 | `After=network.target nss-lookup.target network-online.target` | 表达顺序；没有对应 Wants/Requires 时不主动拉起这些目标，也不保证网络持续可用 |
| FD 上限 | `LimitNOFILE=infinity` | 避免过低服务限制；不是连接内存或 FD 预算 |

这些 unit 没有声明 `Type=notify`、watchdog、socket activation、专用 `User=` 或 capability 限制。本次不能将这些能力归为已有实现。unit 未指定 `Type` 的实际默认行为按 systemd 文档解释，Nexus 不应据“active”就认为所有网络组件已就绪。

`cmd_run.go` 收到 HUP 后先执行 `check`，校验失败则保留当前实例；通过后取消并关闭实例，再重新读取和创建。因此该快照的重载不能描述为保留全部连接的无缝更新，重建失败也不能视为自动恢复旧实例。

`.fpm_systemd` 把 unit、补全文件和 D-Bus 配置一起打包；`release/config/sing-box.postinst` 只在 systemd 环境尝试 `daemon-reload`。服务生命周期、包安装行为和 shell 补全共同构成使用体验。

## DNS 与 Linux 桌面体验

这里存在三种不同能力：

1. sing-tun `tun_linux.go` 通过原生集成设置/撤销 TUN 链路的 DNS 和域信息。
2. sing-box 的 local DNS 文档描述可用时通过 systemd-resolved D-Bus 解析，接入系统分流解析环境。
3. sing-box `service/resolved` 提供兼容 resolved 的 D-Bus 服务，用于接收其他程序的设置，是不同的运行角色。

Nexus 应先明确“使用系统 resolved”与“替代系统 resolved”的区别，优先设计链路级 DNS 及系统解析协作，替代服务能力继续单独评估。

## 可提取到 Nexus 的重点

Linux 应作为完整的宿主集成层：不仅是 TUN FD，还包括路由、fwmark、nftables、NFQUEUE、DNS、服务状态和异常恢复。以期望状态、实例所有权、依赖探测、状态诊断与可回收资源组织这些能力。

具体草案：[Linux 网络集成](../platform/linux/networking.md)、[systemd 与运维体验](../operations/linux-service.md)、[Linux 验证计划](../planning/linux-validation.md)。通用性能机制见[性能专项](sing-box-performance.md)。
