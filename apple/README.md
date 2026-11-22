# Nexus Apple 外壳工程（Swift 6 + SwiftUI · macOS / iOS）

本目录是 Nexus 面向 **macOS 14+ 与 iOS 17+** 的原生 SwiftUI 外壳与桥接库（Swift Package Manager 结构，与主仓 `mcpp` C++26 构建完全解耦），详细平台设计见 [desktop-windows-macos-design.md](../docs/platform/desktop-windows-macos-design.md) 与 [多平台集成与运维原则](../docs/design-principles/platform-and-operations.md)。

## 模块结构

- `NexusCoreBridge`（跨 macOS / iOS 共享，Swift 6 严格并发）：
  - `ControlSocketClient`：原生 POSIX `AF_UNIX` 客户端，实现 `NEXUS/1` 协议并严格校验 macOS **104 字节** `sun_path` 上限；
  - `HttpControlClient`：Swift 6 `actor` 封装 HTTP `/v1/*`（Bearer 鉴权、策略组切换/`--auto`、活跃连接、清缓存）与 OpenMetrics `/metrics` 解析；
  - `PeerCodeSignVerifier`：macOS 阶段 A 特权 Daemon 的纵深安全验签边界（校验 `getpeereid` UID、`LOCAL_PEERPID` 与 `csops` `CS_VALID | CS_RUNTIME` + 20 字节 CDHash 及配置文件 SHA-256 摘要）；
  - `KeychainTokenStore`：App Group 共享 Keychain 凭据存取；
  - `NetworkPathWatcher`：基于 `Network.framework` `NWPathMonitor` 监控真实物理网口（过滤自身 `utunX`）、计费/受限状态并推送 `network-change`；
  - `TunnelSettingsBuilder` & `NexusPacketTunnelProvider`：生成 `NEPacketTunnelNetworkSettings`（双栈地址、排除私网与 `224.0.0.251/32` mDNS/AirDrop 保护、`NEDNSSettings` `matchDomains = [""]`）并承载 `< 50 MiB` 内存纪律下的扩展生命周期；
  - `DaemonManager`：统一封装阶段 A（`SMAppService.daemon`）与阶段 B（`NETunnelProviderManager`）生命周期。
- `NexusMenuBarApp`（macOS 原生菜单栏常驻应用）：
  - 基于 SwiftUI `MenuBarExtra` + `Window` 仪表盘（概览、策略组、活跃连接、KDL 配置、日志与设置）。

## 在 macOS 上运行单测与构建

```bash
./scripts/build-apple.sh
```

> 正式分发 `NEPacketTunnelProvider` System Extension（阶段 B）需在 Xcode 工程中配置 App Group、`com.apple.developer.networking.networkextension` entitlement 与 Developer ID / App Store 签名。
