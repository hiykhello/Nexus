# Nexus Android 外壳工程（Kotlin 2.x + Gradle Wrapper / Kotlin DSL）

本目录是 Nexus 的免 Root Android 客户端工程骨架，遵循 Gradle 官方脚本控制三件套（`gradlew` Wrapper + `*.gradle.kts` Kotlin DSL + `gradle/libs.versions.toml` Version Catalog），详细系统交互设计见 [non-root-integration-guide.md](../docs/platform/android/non-root-integration-guide.md)。

## 模块划分

- `:core-bridge`：免 Root 系统桥接层（纯 Kotlin 2.x，零 JNI）：
  - `CidrRouteCalculator`：API ≤32 CIDR 前缀减法与私有网段预设、API 33+ `IpPrefix` 排除辅助
  - `DefaultNetworkMonitor`：非 VPN 底层物理网监控、`LinkProperties` DNS/搜索域与 Private DNS 严格模式检测
  - `UdsServerSocket` / `ProtectSocketServer`：`noBackupFilesDir` 文件系统 UDS（`< 108B` 校验、零 JNI `SCM_RIGHTS` 收 FD、强制 `Os.close` 防泄漏）
  - `AndroidDnsBridge`：Android 10+ `DnsResolver.getInstance().rawQuery(underlyingNetwork, ...)` 原始 DNS wire 透传桥
  - `ConnectionOwnerResolver`：API 29+ `ConnectivityManager.getConnectionOwnerUid` + UID→包名 LRU 缓存
  - `ControlSocketClient`：与 Nexus `control.sock`（`NEXUS/1` 协议）通信客户端
  - `NexusCoreProcess`：`nativeLibraryDir/libnexus.so` 原生子进程托管、滚动 stderr 采样与指数退避重启
  - `NexusVpnService`：独立 `:bg` 进程 `VpnService`、`specialUse` 前台服务、`onRevoke()` 优雅退场与防假死保护
- `:app`：Jetpack Compose Material3 UI、`TileService` 下拉快捷开关、`BootReceiver` 与 `useLegacyPackaging = true` 原生库解压配置。

## 初始化 Gradle Wrapper 与构建

本机安装 JDK 17+、Android SDK（API 37）与 Gradle 后，首次执行一次生成本地 Wrapper 脚本即可离线/CI 复用（锁定 Gradle 9.9.2 + AGP 9.4.0 内置 Kotlin + Kotlin 2.4.21 + Compose BOM 2026.11.01）：

```bash
cd android
gradle wrapper --gradle-version 9.9.2 --distribution-type bin
./gradlew :core-bridge:testDebugUnitTest
```

同步交叉编译好的 `aarch64-linux-musl` 静态内核并打包 APK：

```bash
./gradlew syncNexusCore -PnexusCoreBinary=../target/android-arm64/nexus-cli
./gradlew :app:assembleRelease
```
