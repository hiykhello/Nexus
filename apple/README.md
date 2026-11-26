# Nexus Apple 外壳工程（Swift 6 + SwiftUI · macOS / iOS）

本目录是 Nexus 面向 **macOS 14+ 与 iOS 17+** 的原生 SwiftUI 外壳与桥接库（Swift Package Manager 结构，零第三方 SwiftPM 依赖，与主仓 `mcpp` C++26 DB-free Core 构建完全解耦），详细平台与存储设计见 [desktop-windows-macos-design.md](../docs/platform/desktop-windows-macos-design.md)、[persistence-inventory.md](../docs/architecture/persistence-inventory.md) 与 [多平台集成与运维原则](../docs/design-principles/platform-and-operations.md)。

## 模块结构

- `NexusCoreBridge`（跨 macOS / iOS 共享，Swift 6 严格并发）：
  - **统一 SQLite 3 (WAL) 本地客户端存储**（直连系统 `libsqlite3` / `import SQLite3`，零外部依赖）：
    - `NexusClientDatabase`、`NexusClientDatabaseModels`、`NexusClientDatabaseSQLite`：实现跨平台 Schema v1（`PRAGMA user_version = 1`、WAL + `BEGIN DEFERRED` 快照读、垂直拆分 `profiles` + `profile_payloads` 级联删除 `ON DELETE CASCADE`、`subscriptions`、`routing_profiles`、`workspace_meta`（`sync_revision` / `active_routing_id`）、`node_telemetry`、`traffic_ledger`、`host_kv`），默认强制 `0600` 文件与 `-wal`/`-shm` 权限，提供 `shrinkMemory()`（`PRAGMA shrink_memory; PRAGMA wal_checkpoint(PASSIVE);`）与前向版本拒绝保护；
    - `WorkspaceStore`、`HostConfigStore`、`TelemetryStore`：基于 `NexusClientDatabase` 的 Swift 6 `actor` 持久化封装，支持单飞初始化与并发去重；Core 保持完全无数据库依赖（DB-free），仅在组合与同步时交换标准 JSON/KDL 负载。
  - **Keychain 凭据隔离**：
    - `KeychainTokenStore` & `WebDavKeychainCredentials`：App Group 共享 Keychain 独占保存控制面 Bearer Token、WebDAV 密码与 E2EE 同步口令，绝不写入 SQLite 或可移植 Workspace JSON。
  - **Workspace / 订阅 / 组合 / E2EE 同步**：
    - `WorkspaceModels`、`WorkspaceNodeModels`、`WorkspaceRoutingDnsModels`、`AppleHostAndTelemetry`：完整 5 类配置模型与 Layer 3 主机适配配置（默认 `workers = 1`，无硬编码上限，兼容可选 `workers_spec` 如 `auto`/`max`/`max-<N>` 与 `workers_max`，以及可选 TUN `NEProxySettings` HTTP 代理配置）；
    - `ShareLinkParser`、`SubscriptionReplacement`（5 级无损节点 ID 保持与孤立引用清理）、`WorkspaceComposerBridge`（对接嵌入式 Core 组合/分享/加解密 C ABI）、`WebDavSyncClient`（基于 ETag/条件头与 XChaCha20-Poly1305 信封的跨端加密同步）。
  - **运行时控制、SSE 流式订阅与隧道桥接**：
    - `EmbeddedCoreBridge`：独立 `Foundation.Thread` + 无锁竞争完成盒桥接嵌入式 Core 生命周期；
    - `ControlSocketClient`：原生 POSIX `AF_UNIX` 客户端，实现 `NEXUS/1` 协议并严格校验 macOS **104 字节** `sun_path` 上限；
    - `HttpControlClient` & `HttpControlClientExtras`：Swift 6 `actor` 封装 HTTP `/v1/*`（Bearer 鉴权、`GET /v1/rules`、`GET /v1/dns/query`、`POST /v1/cache/fakeip/flush`、`POST /v1/state/clear-cache`、`POST /v1/outbounds/{tag}/probe`、`POST /v1/log-level`、`GET/PUT /v1/mode`、策略组切换/`--auto`、活跃连接）、OpenMetrics `/metrics` 解析，以及基于 `URLSession.bytes(for:)` + `SseLineParser` 的 `AsyncThrowingStream` SSE 实时流（`streamLogs` / `streamStatus` / `streamConnections` / `streamEvents`）；
    - `PeerCodeSignVerifier`：macOS 阶段 A 特权 Daemon 的纵深安全验签边界（校验 `getpeereid` UID、`LOCAL_PEERPID` 与 `csops` `CS_VALID | CS_RUNTIME` + 20 字节 CDHash 及配置文件 SHA-256 摘要）；
    - `NetworkPathWatcher`：基于 `Network.framework` `NWPathMonitor` 监控真实物理网口（过滤自身 `utunX`）、计费/受限状态并推送 `network-change`；
    - `TunnelSettingsBuilder`、`UtunPassthroughAdapter` & `NexusPacketTunnelProvider`：生成 `NEPacketTunnelNetworkSettings`（双栈地址、排除私网与 `224.0.0.251/32` mDNS/AirDrop 保护、`NEDNSSettings` `matchDomains = [""]`、可选 `NEProxySettings` HTTP/HTTPS 代理）并承载 `< 50 MiB` 内存纪律下的扩展生命周期；
    - `DaemonManager` & `LoginItemManager`：统一封装阶段 A（`SMAppService.daemon` 持久授权 / 按次提权，策略持久化于 SQLite `host_kv`，零 `UserDefaults`）与阶段 B（`NETunnelProviderManager`）生命周期。
- `NexusSharedUI`（跨 macOS / iOS 共享 SwiftUI Matte Bento 组件）：
  - `NexusThemeComponents`（Matte Bento 卡片修饰符、延迟胶囊、状态徽章、`Canvas` 实时吞吐折线图与字节格式化）、`OverviewMetricsCard`（KPI 网格 + 吞吐折线 + 物理网口诊断）、`ProxiesGroupsView`（策略组栏、延迟排序、单节点测速 + 整组测速）、`WorkspaceView`（SQLite 节点/订阅/路由与 DNS 视图 + 分享链接导入）、`RulesDnsView`（可搜索实时规则表 + 交互式 DNS 探测 + FakeIP/DNS 缓存刷新）、`ConnectionsView`（搜索/路径过滤/详情检查/确认断开全部）与 `LogsPane`（SSE 实时流/级别胶囊/动态 `setLogLevel`/暂停继续/复制导出）。
- `NexusMenuBarApp`（macOS 菜单栏常驻应用 + iOS/iPadOS 自适应主壳）：
  - `NexusAppModel`（`@MainActor @Observable` 统一状态与 SSE 生命周期）、`MenuBarPopoverView`（`.window` 风格快速面板）、`DashboardView`（`NavigationSplitView` + `Cmd+1..6` / `Cmd+R` / `Cmd+K` 快捷键）、`SettingsView`（系统代理/开机自启/TUN `NEProxySettings`/Keychain Bearer Token/诊断）与 `NexusApp`（macOS `MenuBarExtra` + `Window` + `Settings` / iOS `AdaptiveMobileRootView`）。

## 在 macOS 上运行单测与构建

```bash
./scripts/build-apple.sh
```

> 正式分发 `NEPacketTunnelProvider` System Extension（阶段 B）需在 Xcode 工程中配置 App Group、`com.apple.developer.networking.networkextension` entitlement 与 Developer ID / App Store 签名。
