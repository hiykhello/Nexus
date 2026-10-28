# DNS、缓存与持久化参考

状态：源码分析，调研日期 2026-10-27。未运行参考仓库的测试、基准或故障注入。

固定版本沿用 [sing-box 基线](sing-box.md)与 [shoes 基线](shoes.md)：

- sing-box：`a6952ccf6907c18e18917fcb763a433e8e36937b`，本地 `/home/yk/Code/sing-box`。
- shoes：`739e2ea91ef6a892d646a4453102277003567b7c`，本地 `/home/yk/Code/shoes`。

下文源码路径相对各自仓库；本地快照不代表远端最新稳定版。上游使用的 bbolt、JSON、Hickory、Tokio 等不因本次分析成为 Nexus 依赖。

## sing-box 的缓存层次

| 依据 | 读取到的机制 | 借鉴点与边界 |
| --- | --- | --- |
| `dns/client.go` 的 `dnsCacheKey`、`newCacheKey` | question、transport tag、有效 ECS 和环境标识共同形成内存键 | 域名相同不足以共享结果；持久键需单独审计 |
| `persistentName`、`experimental/cachefile/dns_cache.go` | transport 名编码 ECS/环境，磁盘子键含 qtype 与 qname，值含绝对过期时间和 DNS 消息 | 不能推断磁盘与内存键包含完全相同的字段，例如磁盘子键未显式存 qclass |
| `prepareExchange` | 对可缓存的简单请求合并在途查询；复杂请求绕过缓存 | 应明确适用请求集合，不能只按 qname 合并所有 DNS 流量 |
| `loadResponse`、`loadPersistentResponse` | 新鲜命中扣减 TTL；过期但在乐观窗口内返回旧响应，TTL 规范化为 1 秒 | 乐观缓存改变过期应答策略，并非把原 TTL 无限延长 |
| `backgroundRefreshDNS` | 按缓存键去重后台刷新，使用 client 生命周期上下文及查询超时；校验响应与环境后保存 | 刷新不绑定首个前台调用者寿命；去重仍不等于全局并发有界 |
| `storeCache` | 接入持久存储时走持久分支，否则走内存 LRU | 此代码不能概括为始终存在“内存 LRU + 磁盘二级缓存” |
| `cachefile/cache.go` | 保存 selector、展开状态、模式与远程规则集；部分数据通过 cache ID 分区 | 用户偏好、UI 状态、外部内容与解析缓存的丢失代价不同 |

`finishCacheKey` 防止部分环境变化后的结果写回旧视图。Nexus 可借鉴查询开始与发布时两次检查，但需要自己定义配置代次、网络变更和清空操作的屏障，不能直接照搬 hash。

`docs/configuration/dns/index.md` 在该快照中描述 optimistic 默认窗口为 3 天，且与禁用缓存、禁用过期冲突；`independent_cache` 已标记弃用。这些是该版本的行为，不是 Nexus 的默认参数或兼容承诺。

## sing-box 的批写与恢复

`experimental/cachefile/pending.go` 将 DNS、RDRC、FakeIP 和元数据合并到 pending；同键覆盖，刷盘时交换为 writing，提交一个数据库更新。读取按 pending → writing → 数据库顺序查找，因此写入期间仍可见最新待提交数据。

默认 `buffer_size` 是 1 MiB，`flush_interval` 默认关闭，见仓库 `docs/configuration/experimental/cache-file.md`。达到估算字节阈值只发送刷新信号，生产者不会因此阻塞；计算也不覆盖所有 map、key 和分配开销。因此阈值是批写触发条件，不能当作进程内存硬上限。低流量下未到阈值且未启用周期刷盘的数据可能留到显式 Flush 或关闭。

`Flush` 失败时记录警告并清除该 writing 批次，没有在此处重新并回 pending。`SaveDNSCache`、`FakeIPStore` 等调用 Flush 后返回 nil，不能据此向用户保证已持久提交；selector 的 `StoreSelected` 则直接返回数据库操作错误。Nexus 应将接受写入、读取可见、提交完成和持久性确认分开表达。

`cache.go` 检查数据库结构，部分打开错误或损坏会触发删除重建，并有运行时损坏后的重置逻辑。对可重建缓存这有恢复价值，但同一文件还保存选择与规则，不能无条件将这种策略套用到所有 Nexus 状态。

`fakeip.go` 在一次事务中维护地址 → 域名与 v4/v6 域名 → 地址索引，并在覆盖时处理旧反向关系；FakeIP bucket 直接位于数据库根，未走普通 cache ID 的 bucket helper。因此不能声称 cache ID 隔离这个文件里的所有状态。恢复元数据、地址池配置和复用策略还需结合调用方核查，数据库事务本身不证明崩溃后旧客户端地址不会误指向新域名。

`dns_cache.go` 的磁盘清理使用过期时间加 optimistic 窗口；实际应答是否过期由 DNS client 判断，不能依赖清理任务准时执行。`rdrc.go` 保存的是策略拒绝 DNS 响应的判定，不等同于 NXDOMAIN/NODATA 负缓存。该快照文档已弃用 RDRC；启用 store_dns 时清除旧 RDRC，不将其作为 Nexus 必备能力。

## shoes 的显式选择

`src/control/store.rs` 使用带 version 的有界快照、独立锁文件、私有权限，以及同目录临时文件 → 文件 sync → rename → Unix 目录 sync。读取拒绝不支持版本、超限和无效身份；Unix 路径还检查普通文件、属主与符号链接处理。各平台实际持久性仍需验证，不能由 Unix 分支推导 Windows 行为相同。

`SaveError.replaced` 区分 rename 前失败和替换后持久性不确定。`selection.rs` 的 `select` 在 save 成功后才发布内存选择；若目录同步失败，磁盘路径可能已经替换而内存仍保持旧值，所以“返回错误”不等于磁盘一定未变。该实现保存显式选择，自动选择/健康状态独立；恢复时只将仍属于有效成员的选择纳入当前视图，不把过时成员直接作为生效出口。

## shoes 的 FakeIP 持久化

`src/dns/fake_ip/persistence.rs` 的 v2 快照包含 owner、IPv4/IPv6 范围、容量、游标和映射。恢复检查兼容性、规范化域名、重复地址及可分配范围；不兼容/损坏要求显式迁移或重置，而非静默覆盖。快照读取有配置相关的大小限制，绝对上限为 256 MiB；这些数值不是 Nexus 建议值。

`pool.rs` 和 `persistence.rs` 在分配前持久化地址段预留：最多 256 个且不超过池容量一半。快照游标前移，并清除预留段可能存在的旧归属；运行期再消费预留段。它减少每次分配的同步写入，并使崩溃恢复跳过尚未 checkpoint 的预留地址。代价是可能无法恢复部分新映射；它不保证每个已经应答的域名都可在崩溃后反查，也不证明永久不会再次复用地址。

checkpoint 用 revision 避免未变化时重写；生成快照后释放状态锁再执行文件写入，成功后记录对应 revision。并发命中可能改变 LRU，因此不能把较新 revision 错标为已保存。失败时保留待保存状态。正常 shutdown checkpoint 与崩溃走不同路径。

`context.rs` 将可能阻塞的持久分配放到 blocking 任务，并以共享 semaphore 限制进入任务的数量；DNS 交换有超时。但调用方超时不表示已经开始的 blocking 文件写入停止，这仍需要生命周期和资源预算。

## DNS 能力分层

shoes 的 `hickory_resolver.rs` 将地址解析与原始 DNS exchange 分开，连接通过 proxy runtime；`composite_resolver.rs` 的 raw exchange 与地址列表查询采用不同的成功判断，并可向后续 exchange 传递同一个 deadline。这有助于避免把空答案、NXDOMAIN、截断响应和连接错误压成同一个“失败”。没有进一步审计 Hickory 的内部缓存，不据此声称 shoes 实现了与 sing-box 相同的乐观缓存。

Nexus 采用草案见 [DNS 设计](../architecture/dns.md)与[缓存及持久状态](../architecture/state-and-cache.md)，故障和性能验收见[验证计划](../planning/dns-state-validation.md)。
