# Nexus Core 审计缺陷与修复跟踪（Rounds 5–7）

本文档为七轮内核专项审计（共 **54 项：`20 P1 + 33 P2 + 1 P3`**）的后半部分，收录 Rounds 5–7 共 23 项（`7 P1 + 16 P2`）；Rounds 1–4 明细与全轮次总览见 [Part 1：Rounds 1–4](kernel-audit-findings.md)。

> **异步化架构原则（Round 7 起强制执行）**：**能异步就异步，同步路径尽可能删除。** 控制管道 I/O、多候选 DNS 探测、主机名解析与 NTP 同步等路径一律采用非阻塞/异步状态机并接入统一截止时间与 `stop_token` 取消机制，严禁在宿主主循环或关机流程中同步阻塞。

---

## 5. Round 5（5 P2，Linux 本地实测复现）

### 5.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R5 P2-1` | P2 | 文件订阅热重载 | 重载失败后原有文件订阅停止自动周期刷新 | 修复中 |
| `R5 P2-2` | P2 | 订阅模式热重载校验 | 启用订阅时更换 `selector-state-directory` 误报成功却继续写旧目录 | 修复中 |
| `R5 P2-3` | P2 | 热添加策略组切换 | 已有文件订阅的实例首次热添加手动策略组后可见但 `select` 报 `selection-unavailable` | 修复中 |
| `R5 P2-4` | P2 | 远程 DNS 规则集热重载 | 更换远程 DNS `rule-set` URL 后热重载未拉取新地址而报错 | 修复中 |
| `R5 P2-5` | P2 | 进程累计流量统计 | 监听器换代排空回收后同一进程的 `/v1/status` 累计流量倒退回 `0` | 修复中 |

### 5.2 P2 级缺陷明细

#### R5 P2-1 — 重载失败后原有文件订阅停止刷新

- **触发与影响**：文件订阅按周期（如 `1s`）自动刷新正常运行期间，提交一份移除订阅且校验失败的配置触发重载失败；随后恢复原配置并更新订阅节点内容，自动周期刷新停止直至再次手动重载。
- **涉及模块**：`src/tools/proxy_providers.cpp`、`src/tools/proxy_run.cppm`。
- **根因**：`prepare_initial` 在完整候选配置校验与发布成功之前就清空了当前活动订阅表，导致失败路径虽然保留了旧代理配置，但活跃订阅调度表已被清空。
- **修复设计**：对候选配置订阅表采用暂存与原子提交（staging + atomic commit），仅在候选配置校验和重载发布完全成功后替换活动订阅表；任意失败路径保持原活动订阅表及刷新周期不受影响。
- **回归验收**：单元测试先验证文件订阅自动刷新生效，再触发一次移除订阅且失败的重载，修改订阅文件内容后断言原自动刷新继续生效。

#### R5 P2-2 — 启用订阅时更换策略组状态目录报告成功却继续写旧目录

- **触发与影响**：启用文件订阅时将 `selector-state-directory` 从目录 `A` 改为目录 `B` 并执行热重载，控制面返回 `succeeded`，但后续 `select` 仍写入 `A/selectors.state`，重启后丢失选择。
- **涉及模块**：`src/tools/proxy_run.cppm`、`src/tools/proxy_listener_reload.cppm`。
- **根因**：启用订阅后普通重载走 `provider_refresh` 分支，该分支遗漏了 `selector_state_directory` 等不可热变更的进程级身份字段检查。
- **修复设计**：在 `provider_refresh` 分支补齐 `selector_state_directory` 及全部进程级不可热改字段的变更比对，命中变更时明确返回需要重启的错误。
- **回归验收**：单元测试在启用订阅场景下变更 `selector-state-directory` 触发重载，断言返回需重启错误而非假成功。

#### R5 P2-3 — 已有文件订阅的实例首次热添加手动策略组后可见但不可切换

- **触发与影响**：在已有文件订阅但原先无策略组的实例上首次通过热重载新增手动策略组后，`status` 可见 `group=manual selected=direct`，但执行 `select manual block` 返回 `selection-unavailable`（冷启动同样配置可正常切换）。
- **涉及模块**：`src/tools/proxy_listener_reload.cppm`、`src/tools/proxy_run.cppm`。
- **根因**：热重载仅在旧实例已持有 `group_route_files` 或新配置启用 `group_health` 时才保存切换所需路由文件，首次热添加纯手动策略组时未保存 `group_route_files` 与对应路由快照。
- **修复设计**：当新配置包含任意策略组（`!reload_config->selectors.empty()`）时亦同步保存 `group_route_files` 并初始化路由快照，使首次热添加的手动策略组立即支持切换。
- **回归验收**：单元测试对已有文件订阅的无组实例热添加手动策略组并立即执行 `select`，断言切换成功且无需重启。

#### R5 P2-4 — 更换远程 DNS `rule-set` 的 URL 无法热生效

- **触发与影响**：将远程 DNS `rule-set` 指向同一 HTTPS 服务的路径从 `/first` 改为 `/second` 后执行热重载，报错 `DNS rule-set: open input: No such file or directory`，且 HTTPS 服务端未收到新路径请求。
- **涉及模块**：`src/tools/proxy_listener_reload.cppm`、`src/tools/route_files.cpp`、`src/tools/proxy_run.cppm`。
- **根因**：热重载仅通过 `remote_rulesets.seed_cached(...)` 注入旧 URL 缓存，新 URL 未命中缓存时直接落入本地文件路径打开逻辑。
- **修复设计**：热重载执行 `load_dns_rules` 与 `load_route_files` 之前，先拉取并暂存候选配置新增或变更的远程 DNS 与路由 `rule-set` URL 写入候选输入，仅在重载发布成功后提交新缓存状态，拉取或校验失败不破坏既有规则集。
- **回归验收**：单元测试将远程 DNS `rule-set` URL 从 `/first` 切换至 `/second` 并执行热重载，断言服务端收到 `/second` 请求且新规则热生效，同时失败路径保留旧缓存。

#### R5 P2-5 — 监听器换代导致同一进程累计流量倒退

- **触发与影响**：通过代理传输数据（如 `4096B`）后仅修改监听器名称触发热重载，进程 `instance_id` 未变，待旧代监听器排空回收后 `/v1/status` 上下行累计流量回退至 `0`。
- **涉及模块**：`src/tools/proxy_host.cppm`、`src/tools/proxy_http_control.cppm`。
- **根因**：`poll_retired()` 回收并销毁已排空的 `RetiredTcpGeneration` 时，未将其最终 `rx_bytes` / `tx_bytes` 并入进程级单调累计计数器。
- **修复设计**：维护进程级已回收累计字节计数（`reclaimed_rx_bytes` / `reclaimed_tx_bytes`），在 `poll_retired()` 移除旧代前先折叠其最终字节数，并在状态统计中汇总 `reclaimed + active + draining_retired`，保证同进程累计流量单调不退且不重复计算。
- **回归验收**：单元测试在产生流量并完成监听器换代与旧代排空回收后查询状态统计，断言累计字节数保留既有总量、绝不回退且不双计。

---

## 6. Round 6（3 P1 + 6 P2，源码与本地实测复现）

### 6.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R6 P1-1` | P1 | HTTP 订阅缓存 | 订阅更换 URL 后仍按订阅名发送旧 ETag 并在 `304` 时沿用旧资源节点 | 修复中 |
| `R6 P1-2` | P1 | 远程规则集校验 | 同 URL 的多条远程规则集引用仅沿用首条校验策略，后声明的 `sha256` 未生效 | 修复中 |
| `R6 P1-3` | P1 | ACME 凭据原子提交 | ACME 可将证书与私钥不匹配的一代分步落盘并标记续签成功，TLS 拒绝未回传 | 修复中 |
| `R6 P2-1` | P2 | SS-2022 原生 UDP | 原生 UDP 规则加载对已 mmap 的 NXMM 索引规则读到空串报 `invalid NXMM file size` | 修复中 |
| `R6 P2-2` | P2 | `fixed-udp` 路由模式 | `fixed-udp` 有序规则分支跳过运行模式判断，切至 `direct` 后仍支配新流 | 修复中 |
| `R6 P2-3` | P2 | ACME 订单状态机 | 订单迟到的 `ready` 状态错过唯一 `finalize` 分支导致永远无法提交 CSR | 修复中 |
| `R6 P2-4` | P2 | SRS 派生 NXMM 缓存 | 派生目录 `cache/nxmm` 无预算回收持续增长，且 `clear-cache --rulesets` 遗漏清理 | 修复中 |
| `R6 P2-5` | P2 | Windows 控制面实例 ID | Windows 命名管道 `LocalControl::instance()` 返回固定管道名，跨重启不变 | 修复中 |
| `R6 P2-6` | P2 | Linux KDE 系统代理 | KDE 后端接受 `--pac-url` 后仅写 `ProxyType=2`，未读写/恢复 `Proxy Config Script` | 修复中 |

### 6.2 P1 级缺陷明细

#### R6 P1-1 — HTTP 订阅换 URL 后沿用上一个资源的节点

- **触发与影响**：同名 HTTP 订阅更换资源 URL 后，请求仍携带上一资源的 `ETag`；若新地址返回 `304`，内核继续复用旧 URL 的节点正文。
- **涉及模块**：`src/tools/proxy_providers.cpp`、`src/tools/proxy_providers.cppm`。
- **根因**：缓存文件仅按订阅名寻址，未将完整资源 URL 纳入缓存身份与验证器同源校验。
- **修复设计**：将缓存身份绑定至完整规范化 URL，严格校验验证器与正文同源；URL 变更时绝不发送旧 `If-None-Match` 且不复用旧正文。
- **回归验收**：单元测试将同名 HTTP 订阅切换至新 URL，断言请求不携带旧 `ETag` 且绝不复用旧节点正文。

#### R6 P1-2 — 同 URL 的远程规则集引用共用第一条引用的校验策略

- **触发与影响**：路由或 DNS 中多处引用同一远程规则集 URL 且附带不同 `sha256`（或仅后者声明 `sha256`）时，后声明的摘要约束未参与校验。
- **涉及模块**：`src/config/`（远程规则集配置校验）、`src/tools/route_files.cpp`、`src/tools/proxy_listener_reload.cppm`。
- **根因**：下载任务按 URL 收集时仅保留首条声明，后续引用绑定同 URL 缓存正文时未重新核对自身 `sha256` 约束。
- **修复设计**：配置期直接拒绝同一 URL 下的冲突 `sha256` 声明，并在每次将缓存或下载正文绑定到规则集引用时再次校验该引用的 `sha256` 约束。
- **回归验收**：单元测试验证同 URL 冲突 `sha256` 在配置期报错，且绑定阶段对每条引用强制执行独立 `sha256` 校验。

#### R6 P1-3 — ACME 可把证书与私钥不匹配的一代保存为续签成功

- **触发与影响**：ACME 签发结果若与 CSR 私钥不匹配或落盘中途失败，磁盘可能残留跨代错配 cert/key 且续签循环误判成功休眠至过期；冷启动亦先安装磁盘错配记录。
- **涉及模块**：`src/service/acme/client.cpp`、`src/service/acme/store.cpp`、`src/tools/svc_acme.cpp`。
- **根因**：签发阶段仅检查证书有效期即分两次独立替换 cert/key 文件并更新续签状态，未做公私钥配对校验，且 TLS 加载拒绝未回传至签发流程。
- **修复设计**：落盘前与冷启动加载时均校验叶证书公钥与私钥配对；cert+key 以整对原子提交消除跨代窗口；先发布激活在线 TLS 凭据并回传失败，仅在激活成功后更新续签状态。
- **回归验收**：单元测试注入公钥不匹配证书断言被拒绝（不落盘、不激活、不更新续签时间），匹配证书则原子提交并成功激活。

### 6.3 P2 级缺陷明细

#### R6 P2-1 — SS-2022 原生 UDP 遇到 NXMM 索引规则阻止实例启动

- **触发与影响**：含 NXMM 索引规则的配置通过 `nexus check`，但在启用 SS-2022 原生 UDP 启动时报错 `invalid NXMM file size`。
- **涉及模块**：`src/tools/route_files.cpp`、`src/tools/route_files_nxmm.cppm`（及原生 UDP 规则加载路径）。
- **根因**：规则加载器将 mmap 匹配器保存在 `data_mmaps[i]` 并留空 `data[i]` 字节串，原生 UDP 路径仍从空 `data[i]` 重新解析 NXMM。
- **修复设计**：让原生 UDP 与 TCP 路径共享已加载的 `data_mmaps` / `MmapMatcher` 表示，避免重复解析空字节串。
- **回归验收**：单元测试使用真实 NXMM 索引规则初始化 SS-2022 原生 UDP 路由，断言启动成功且按预期命中分流。

#### R6 P2-2 — `fixed-udp` 有序规则仍支配 `direct` 模式下的新流

- **触发与影响**：`fixed-udp` 配置有序 `block` 等规则并将运行模式切换至 `direct`（或 `global`）后，新建立的 UDP 流仍受有序规则支配。
- **涉及模块**：`src/relay/fixed_udp_inbound.cpp`。
- **根因**：`fixed-udp` 有序规则分支直接执行命中动作，跳过了运行模式决策。
- **修复设计**：与普通 UDP 入口共用运行模式决策（`direct` / `global` / `rule`），在评估有序规则前先按运行模式路由。
- **回归验收**：环回单元测试配置有序 `block` 规则后切至 `direct` 模式，断言新客户端 UDP 数据报直连到达并回显。

#### R6 P2-3 — ACME 订单迟到的 `ready` 状态无法进入 `finalize`

- **触发与影响**：ACME 订单在首轮轮询结束时仍处于 `pending`，进入第二轮后才转为 `ready` 时，客户端持续空等 `valid` 永不提交 CSR。
- **涉及模块**：`src/service/acme/client.cpp`。
- **根因**：实现拆为两段无退避循环且仅在首段结束后检查一次 `finalize`，二段不再触发 `finalize`。
- **修复设计**：改为统一的状态机驱动轮询循环（含退避间隔与总截止时间），按 `pending`/`ready`/`processing`/`valid`/`invalid` 状态流转并在 `ready` 时执行一次 `finalize`。
- **回归验收**：单元测试模拟多轮 `pending` 后才转 `ready` 的 ACME 服务端，断言 `finalize` 被正常调用且签发成功。

#### R6 P2-4 — SRS 派生缓存 `cache/nxmm` 持续增长且清规则缓存后仍保留

- **触发与影响**：SRS 编译派生的 `cache/nxmm` 文件随更新无限增长，且执行 `state clear-cache --rulesets` 或在线清理规则集缓存后仍残留磁盘。
- **涉及模块**：`src/tools/route_files_nxmm.cppm`、`src/state/ruleset_cache.cppm`、`src/state/ruleset_cache.cpp`、`src/tools/state_cli.cpp`。
- **根因**：派生 NXMM 文件未纳入规则集缓存字节预算回收，且清理路径遗漏 `cache/nxmm` 目录。
- **修复设计**：为 `cache/nxmm` 增加按规则集缓存预算淘汰最旧非活跃文件的回收机制，并将该目录纳入 CLI 与控制面 `clear-cache` 的 `rulesets` / `all` 清理范围。
- **回归验收**：单元测试验证超预算触发旧派生文件淘汰，以及 `clear-cache --rulesets` 与在线清理均完整清除 `cache/nxmm`。

#### R6 P2-5 — Windows 管道实例标识跨进程重启不变

- **触发与影响**：Windows 端重启同一配置的 Core 进程后，`LocalControl::instance()` 返回值完全相同，无法区分跨重启进程实例。
- **涉及模块**：`src/tools/control_windows.cpp`。
- **根因**：`LocalControl::instance()` 直接返回确定性的规范化命名管道路径 `pipe_utf8`。
- **修复设计**：在创建 `LocalControl` 时为每个进程实例生成独立高熵随机实例标识并由 `instance()` 返回。
- **回归验收**：单元测试验证连续创建的实例生成彼此不同的非空实例标识，且保持 Windows C++23 编译洁净。

#### R6 P2-6 — KDE 后端接受 PAC URL 后未写入该地址

- **触发与影响**：Linux KDE 系统代理后端接收 `--pac-url` 返回退出码 `0`，但实际未写入 PAC 脚本地址且禁用时未恢复原配置。
- **涉及模块**：`src/platform/system_proxy.cpp`。
- **根因**：启用路径仅写入 `ProxyType=2`，遗漏对 `Proxy Config Script` 的快照读取、写入与禁用恢复，状态查询亦未读取该键。
- **修复设计**：快照保存既有 `Proxy Config Script`，启用时同时写入 `Proxy Config Script` 与 `ProxyType=2`（任一失败即返回错误），状态查询读取该键，禁用时完整恢复或清除。
- **回归验收**：隔离 `PATH` 下的模拟 `kreadconfig6`/`kwriteconfig6` 单元测试验证启用同时写入两键、状态可读回、禁用完整恢复原值。

---

## 7. Round 7（4 P1 + 5 P2，静态审计去重于 R1–R6）

### 7.1 总览

| 编号 | 级别 | 子系统 | 缺陷摘要 | 当前状态 |
| --- | --- | --- | --- | --- |
| `R7 P1-1` | P1 | Windows TUN 初始化 | 调用 `InitializeIpInterfaceEntry` 误用 2 参函数指针而非单参 `PMIB_IPINTERFACE_ROW` | 修复中 |
| `R7 P1-2` | P1 | Darwin/Windows TUN 路由 | 排除路由缺失或出口指向 TUN 时仍安装捕获路由并报成功，引发路由环路 | 修复中 |
| `R7 P1-3` | P1 | Windows 状态持久化 | 目录句柄无写权限却调用 `FlushFileBuffers`，导致正常落盘仍报持久化未确认 / FakeIP 保存失败 | 修复中 |
| `R7 P1-4` | P1 | Windows 控制管道 | `control.poll()` 同步调用 `FlushFileBuffers`，慢客户端可直接卡死宿主主循环 | 修复中 |
| `R7 P2-1` | P2 | DHCP IPv6 DNS | 租约解析剥离链路本地地址 `%iface` 且端点构造丢失 `sin6_scope_id` | 修复中 |
| `R7 P2-2` | P2 | DHCP 多上游查询 | 多个 DHCP DNS 上游串行复用同一总截止时间，首选超时即饿死备用服务器 | 修复中 |
| `R7 P2-3` | P2 | 用户态 TCP 快速重传 | 将双向数据段或窗口更新误计为重复 ACK，违反 RFC 5681 §2 误触发快速重传 | 修复中 |
| `R7 P2-4` | P2 | NTP 异步解析与取消 | `sync_once` 同步调用 `getaddrinfo` 不受超时与 `stop_token` 覆盖，阻塞核心停机 | 修复中 |
| `R7 P2-5` | P2 | 嵌入式 NTP 时钟偏移 | 重启后新配置禁用 NTP 时仍沿用上一实例的进程级全局时钟偏移 | 修复中 |

### 7.2 P1 级缺陷明细

#### R7 P1-1 — Windows TUN `InitializeIpInterfaceEntry` 错误双参调用

- **触发与影响**：Windows TUN 接口初始化以错误的双参签名调用 `InitializeIpInterfaceEntry`，导致 ABI 不匹配、接口行未正确初始化或未定义行为。
- **涉及模块**：`src/packet/tun_network_windows.cpp`。
- **根因**：动态解析 `InitializeIpInterfaceEntry` 时错误声明为 2 参函数指针，而非单参 `PMIB_IPINTERFACE_ROW`。
- **修复设计**：直接从 Windows SDK 原型推导单参函数指针，先调用 `init_if(&iface)` 再填写 `Family` 与 `InterfaceLuid`。
- **回归验收**：静态签名/编译校验与 Windows 路由辅助单测确认调用序列为先初始化行结构再赋值字段。

#### R7 P1-2 — Darwin 与 Windows 排除路由失效时仍安装 TUN 捕获路由

- **触发与影响**：排外目标（exclude routes）未成功安装或默认出口仍指向 TUN 时继续安装捕获路由并报成功，引发代理流量回环自锁。
- **涉及模块**：`src/packet/tun_network_darwin.cpp`、`src/packet/tun_network_windows.cpp`。
- **根因**：安装捕获路由前未验证每条排除路由真实生效且出口不指向 TUN，失败时也未回滚已下发路由。
- **修复设计**：安装捕获路由前逐条确认排除路由生效且下一跳不经由 TUN；任一校验或安装失败立即回滚已装路由并返回错误。
- **回归验收**：单元测试模拟排除路由缺失或出口指向 TUN，断言拒绝安装捕获路由并完整回滚。

#### R7 P1-3 — Windows `InstanceLock` 目录句柄 `FlushFileBuffers` 权限不匹配

- **触发与影响**：Windows 平台状态快照与 FakeIP 元数据已完成文件刷盘和原子替换，仍被报告持久化未确认或保存失败。
- **涉及模块**：`src/state/lock_windows.cpp`、`src/state/file_windows.cpp`、`src/platform/os_fs_windows.cpp`。
- **根因**：目录句柄以 `FILE_LIST_DIRECTORY | SYNCHRONIZE` 打开，随后调用需要写权限的 `FlushFileBuffers` 必然触发权限拒绝错误。
- **修复设计**：修正 Windows 持久化目录提交策略（不以无写权限目录句柄调用 `FlushFileBuffers`），同时严格保留上层对真实文件刷盘与原子替换失败的错误检测。
- **回归验收**：单元测试校验 Windows 目录提交逻辑不因目录句柄权限误报失败，且文件刷盘/替换真实失败仍被准确捕获。

#### R7 P1-4 — Windows 本地控制命名管道在主循环同步 `FlushFileBuffers` 阻塞

- **触发与影响**：慢客户端或挂起客户端可让宿主主循环在 `control.poll()` 内永久卡死，阻断转发、重载与关机。
- **涉及模块**：`src/tools/control_windows.cpp`。
- **根因**：命名管道响应发送后在主循环内同步调用阻塞式 `FlushFileBuffers`。
- **修复设计**：按异步化原则彻底删除同步 `FlushFileBuffers` 阻塞路径，改用 `FILE_FLAG_OVERLAPPED` 全异步重叠 I/O 状态机并附带请求级截止时间，超时立即取消并断开慢客户端。
- **回归验收**：验证 `control_windows.cpp` 零同步阻塞调用，重叠 I/O 状态机测试覆盖请求超时断开且主循环零停顿。

### 7.3 P2 级缺陷明细

#### R7 P2-1 — DHCP DNS 租约解析丢失 IPv6 链路本地 `sin6_scope_id`

- **触发与影响**：通过 DHCPv6 获得的链路本地（`fe80::/10`）DNS 服务器因缺少接口作用域 ID 导致发包失败或错发网卡。
- **涉及模块**：`src/dns/dhcp_upstream.cpp`、`src/tools/dns_dhcp_transport.cpp`。
- **根因**：租约解析剥离了 `%iface` 区域标识，且 UDP 端点构造未填充 `sin6_scope_id`。
- **修复设计**：保留 `%zone`/接口标识并在缺省时回退 DHCP 绑定接口名，构造 IPv6 链路本地目标端点时通过 `if_nametoindex`（或数字作用域）填充 `sin6_scope_id`。
- **回归验收**：单元测试验证含 `%iface` 与无显式 `%zone` 的 `fe80::` DHCP 租约均保留作用域并正确解析为非零 `sin6_scope_id`。

#### R7 P2-2 — 多个 DHCP DNS 上游串行复用同一总截止时间饿死备选

- **触发与影响**：首选 DHCP DNS 静默丢包时，串行尝试耗尽整个查询超时预算，备用服务器从未收到查询即整体失败。
- **涉及模块**：`src/tools/dns_dhcp_transport.cpp`。
- **根因**：阻塞串行循环把完整查询截止时间全部交给第一个上游。
- **修复设计**：删除同步阻塞串行路径，改为异步错峰并发（或按候选切分预算的非阻塞异步 UDP 扇出），收到首个有效响应立即返回并取消其余在途套接字。
- **回归验收**：环回 UDP 单测中上游 #1 静默丢包、上游 #2 正常应答，断言查询在总预算内经上游 #2 快速成功。

#### R7 P2-3 — 用户态 TCP 将双向数据段或窗口更新误计为重复 ACK

- **触发与影响**：全双工收发数据或对端滑动窗口更新期间，连续收到相同 `ack` 触发虚假快速重传，吞吐骤降且拥塞窗口误减半。
- **涉及模块**：`src/tcp/send.cpp`、`src/tcp/send.cppm`（及 `src/tcp/`、`src/relay/l3_mux.cppm` 调用点）。
- **根因**：`SendQueue::on_ack` 在存在在途数据且 `ack` 未推进时无条件递增 `dup_acks_`，未遵循 RFC 5681 §2 判定条件。
- **修复设计**：向 `on_ack` 传入报文载荷/控制标志与对端通告窗口，仅当存在在途数据、载荷长度为 `0`、无 `SYN`/`FIN`、`ack == snd_una` 且通告窗口未变时才递增 `dup_acks_`。
- **回归验收**：单元测试验证 3+ 次带载荷双向数据 ACK 及窗口更新均不触发快速重传，3 次纯空同窗重复 ACK 准确触发快速重传。

#### R7 P2-4 — NTP `sync_once` 同步 `getaddrinfo` 绕过超时与取消

- **触发与影响**：NTP 域名解析卡死时无视配置超时，核心关机等待 NTP 工作线程退出时被长时间阻塞。
- **涉及模块**：`src/service/ntp/sntp.cpp`、`src/service/ntp/sntp.cppm`、`src/tools/proxy_ntp_enabled.cpp`。
- **根因**：`sync_once` 在计算截止时间前同步调用阻塞式 `getaddrinfo`，未接入 `stop_token` 取消。
- **修复设计**：删除同步阻塞解析与发包路径，入口即锁定统一截止时间并采用异步解析与异步 UDP I/O，通过 `stop_callback` 在取消或超时瞬间中止解析与套接字。
- **回归验收**：单元测试验证解析或网络挂起阶段触发 `stop_token` 或超时后迅速返回，停机零卡死。

#### R7 P2-5 — 嵌入式核心禁用 NTP 重启后沿用旧实例时钟偏移

- **触发与影响**：同一宿主进程内嵌入式核心先启用 NTP 写入非零时钟偏移，停止并以禁用 NTP 的新配置重启后，TLS 等模块仍读取残留偏移。
- **涉及模块**：`src/service/ntp/`、`src/tools/proxy_ntp_enabled.cpp`。
- **根因**：NTP 停止仅回收线程，未重置进程级全局时钟偏移，禁用启动时亦未清零。
- **修复设计**：在 NTP 服务停止以及新实例以禁用 NTP 启动时均显式将全局时钟偏移重置为 `0`。
- **回归验收**：单元测试写入非零偏移后执行停止与禁用模式启动，断言全局 NTP 偏移均归零。
