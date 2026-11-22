# Linux 服务与使用体验

状态：Nexus 部署设计草案。当前没有可安装程序、正式 CLI 或 systemd unit，本文不提供假定已可运行的命令。

## 借鉴的使用体验

普通服务、实例模板、配置目录、状态目录、信号处理、配置检查及 shell 补全作为一组完整运维能力交付，核心要点见 [多平台集成与运维原则](../design-principles/platform-and-operations.md)。Nexus 让“前台运行”和“作为系统服务运行”共享同一配置与诊断逻辑，避免部署时另写一套代理脚本。

## 目录与多实例

| 对象 | 建议路径草案 | 用途 |
| --- | --- | --- |
| 配置 | `/etc/nexus/` | KDL 配置，最终主文件与合并规则待定 |
| 持久状态 | `/var/lib/nexus/` 或实例子目录 | 用户选择、FakeIP 等按类别确认的状态 |
| 可丢弃缓存 | `/var/cache/nexus/` 或实例子目录 | 可选 DNS/规则内容磁盘缓存，与持久状态分别清理 |
| 运行状态 | `/run/nexus/` 或实例子目录 | 实例锁、运行清单及诊断端点 |
| 日志 | 默认 stderr 交给服务管理器 | 避免服务与程序重复轮转同一日志 |

建议交付单实例和 `nexus@.service` 模板，实例名称需校验和编码。网络资源分配还需满足[Linux 网络设计](../platform/linux/networking.md)中的冲突检测，不由目录布局代替。

数据类别、稳定锁、损坏处理与提交语义见[缓存和持久状态](../architecture/state-and-cache.md)。若采用 `CacheDirectory`，需与真实缓存实现及权限一起验证；服务重启不应隐式重置用户选择和 FakeIP。DNS 状态应分别报告上游可用性、fresh/stale 命中与刷新/持久化故障，见[DNS 设计](../architecture/dns.md)。

日志默认输出及文件 sink 的设计边界见[日志系统](../architecture/logging.md)，状态后端候选见[状态数据库](../architecture/database.md)；两者尚未实现。

## systemd 行为草案

| 能力 | Nexus 建议 | 前提与边界 |
| --- | --- | --- |
| 前台运行 | 一个可追踪的主进程，不自行 daemonize | 信号、退出码与资源清理一致 |
| 配置检查 | 启动前可验证 KDL、引用与已声明能力 | 区分静态校验和可能需要权限的环境探测 |
| 就绪状态 | 实现通知协议后优先评估 `Type=notify` | 接管规则、返回路径和监听实际就绪后才通知，不能先在 unit 中声明却不发送 |
| 日志 | 可读错误带组件/实例/阶段，服务模式禁用颜色 | 默认服务输出由 journal 收集不等于已实现原生结构化 journal 字段 |
| 状态目录 | 评估 `StateDirectory` / `RuntimeDirectory` 管理实例目录 | 具体权限与运行用户需和功能匹配 |
| 重启与停止 | 明确失败重启、退避、启动限频及停止期限 | 配置错误与暂时环境错误分别诊断，结束后可查未回收资源 |
| 资源限制 | FD、内存和任务限制与内部预算配合 | 不把 `LimitNOFILE=infinity` 当作容量管理 |
| 自动启动 | 软件包提供 unit，启用策略遵循发行版及用户选择 | 不把安装包自动等同于应接管宿主流量 |

`After=` 仅表达顺序，不自动引入目标依赖。若特定模式确实需要启动时网络就绪，分别评估 `Wants=network-online.target` 与顺序；服务仍需处理运行期间网络断开，不能把启动目标当作健康保证。[systemd.unit 文档](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)

`Type=notify`、watchdog、socket activation、`notify-reload` 都需要程序支持与版本验证，不能仅复制 unit 选项。具体协议依据 [systemd.service 文档](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)。本轮没有将 watchdog 或 socket activation 确定为首期功能。

## 权限与功能匹配

普通监听代理、低端口监听、TUN/路由/nftables、原始包和 namespace 操作的权限需求不同。建议按部署能力定义权限集合及专用运行用户方案，验证 `/dev/net/tun`、网络管理、D-Bus 和状态目录访问。

`CapabilityBoundingSet`、`AmbientCapabilities`、设备权限及 namespace 限制需按实际操作验证。`PrivateNetwork` 可能隔离预期宿主接管路径，不能为了增加 unit 选项而默认启用。无特权 user service 不自动拥有宿主 TUN/防火墙管理权限。

是否分离特权宿主网络管理进程尚未决定，不能为普通 client/server 默认授予所有网络权限。

## 重载语义

`SIGHUP` 热重载须先完成新配置校验，再平滑切换路由/监听器并明确区分需重启改动、保留存量连接的热更与候选失败回滚，避免仅以信号投递成功代替重载就绪。

未实现这些语义前，不在正式 unit 中宣称无缝重载，也不暴露没有处理器的 HUP 入口。若未来实现同步重载确认，再评估控制命令或 `notify-reload`，使服务管理器可观察完成与失败；热重载仍未冻结为首期功能。

## 配置与诊断体验

建议 CLI 提供以下能力，名称与参数尚未冻结：

- 静态配置检查：文件、节点/字段路径、错误原因及相互冲突的配置项。
- 环境诊断：内核、权限、TUN、nftables、NFQUEUE、resolved、当前实例资源和功能缺失原因。
- 生效计划与状态：展示将修改或已管理的接口、表、mark、规则、DNS 及回收结果；只读诊断不安装规则。
- 能力与版本：记录编译启用项、依赖版本及实际生效的 Linux 优化路径。
- shell 补全与运维说明：覆盖常见启动失败、日志位置、冲突、网络切换及退出恢复。

配置文件语法正确、环境可用、服务已就绪、流量确实按策略处理是四个不同结论，诊断应分别报告。

## 交付与验收

后续构建生成正式二进制后，再创建与真实参数匹配的 unit 和安装清单，使用 `systemd-analyze verify` 检查并在测试环境启动验证。发布 unit 的默认设置、支持的 systemd 版本及权限说明一起维护。

验收见[Linux 验证计划](../planning/linux-validation.md)。本轮没有安装、启动、重载或停止任何系统服务。
