# Nexus Android 客户端工程（Kotlin 2.x + Jetpack Compose Material 3）

本目录是 Nexus 的免 Root Android 客户端工程，遵循 Gradle 官方控制三件套（`gradlew` Wrapper + `*.gradle.kts` Kotlin DSL + `gradle/libs.versions.toml` Version Catalog），详细系统交互设计见 [non-root-integration-guide.md](../docs/platform/android/non-root-integration-guide.md)。

## 模块划分

- `:core-bridge`：免 Root 系统桥接层（纯 Kotlin 2.x，零 JNI）：
  - `CidrRouteCalculator`：API ≤32 CIDR 前缀减法与私有网段预设、API 33+ `IpPrefix` 排除辅助
  - `DefaultNetworkMonitor`：非 VPN 底层物理网监控、`LinkProperties` DNS/搜索域与 Private DNS 严格模式检测
  - `UdsServerSocket` / `bridge.vpn.ProtectSocketServer`：`noBackupFilesDir` 文件系统 UDS（`< 108B` 校验、零 JNI `SCM_RIGHTS` + `SO_PEERCRED` 同 UID 校验、强制关闭 FD 防泄漏）
  - `AndroidDnsBridge`：Android 10+ `DnsResolver.getInstance().rawQuery(underlyingNetwork, ...)` 原始 DNS wire 透传桥
  - `ConnectionOwnerResolver`：API 29+ `ConnectivityManager.getConnectionOwnerUid` + UID→包名 LRU 缓存
  - `NexusControlClient`：AF_UNIX `NEXUS/1` 控制与本地 HTTP `/v1/` + `/metrics` 双通道客户端
  - `CoreProcessSupervisor`：`nativeLibraryDir/libnexus.so` 原生子进程托管、配置预校验、滚动日志缓冲与指数退避重启
  - `ProfileRepository` / `ShareLinkParser`：多档案与订阅管理、分享链接解析及 `0600` 凭据隔离
  - `CoreArtifactVerifier`：内核 ELF64 / SHA-256 校验与离线规则集扫描
  - `NexusVpnService`：进程内 `VpnService` + 独立隔离原生子进程（`libnexus.so`）、`specialUse` 前台服务、`onRevoke()` 优雅退场与省电策略
- `:app`：Material 3 Adaptive Jetpack Compose UI（`NexusTheme` 深浅色与 Edge-to-Edge、`OverviewScreen` / `GroupsScreen` / `ConnectionsScreen` / `SplitTunnelScreen` / `ConfigScreen` / `LogsScreen`）、`TileService` 下拉快捷开关与 `BootReceiver`。

## 构建与预览

本机配置 JDK 与 Android SDK 后，可离线运行单元测试、构建 APK 并渲染 Compose 预览：

```bash
cd android
./gradlew --offline :core-bridge:testDebugUnitTest :app:assembleDebug
android preview render :app -- --offline
```

同步交叉编译好的 `aarch64-linux-musl` 静态内核并打包 Release APK：

```bash
./gradlew syncNexusCore -PnexusCoreBin=../target/android-arm64/nexus-cli
./gradlew :app:assembleRelease
```
