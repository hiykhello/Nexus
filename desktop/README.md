# Nexus Desktop 外壳（Slint v1.19.0 · C++26/C++23 + SQLite 3 WAL）

本目录是 Nexus 面向 **Linux + macOS + Windows 桌面端**的原生轻量 GUI 外壳独立工程（与主仓 `mcpp` 构建完全解耦），基于 **Slint v1.19.0 C++ SDK**（Skia 渲染 + 原生系统托盘）、**CMake 4.5+ 官方原生 `import std;` 模块**与内置公共领域 **SQLite 3 (WAL)** 统一客户端存储，统一通过本机 HTTP `/v1` + 多路复用 RFC 6455 WebSocket `/v1/ws`（透明回退 SSE）控制面（`127.0.0.1` + 0600 Bearer Token 请求头）和 `nexus` 核心进程通信。

## 设计原则

- **全栈统一 C++26 / MSVC C++23 + `import std;`**：桥接库 `nexus-desktop-bridge` 采用标准模块（`desktop.client_db`、`desktop.workspace_store`、`desktop.workspace_composer`、`desktop.workspace_sync`、`desktop.desktop_host_config`、`desktop.telemetry_store`、`desktop.http_control`、`desktop.share_link`、`desktop.single_instance`、`desktop.system_proxy`、`desktop.core_supervisor`、`desktop.async_worker`、`desktop.ui_actions`）并链接内置静态 C 库 `nexus-sqlite3`（`3rdparty/vendor/sqlite3/sqlite3.c`）；
- **统一 SQLite 3 (WAL) 存储与零凭据落库**：工作区节点（`profiles` + `profile_payloads` 垂直分表）、订阅、路由预设、节点遥测、小时流量账本与本机选项统一持久化在私有 SQLite 数据库中，经由 `nexus workspace compose` 单一真源编译下发；WebDAV 密码与 E2EE 同步口令仅隔离存于 `0600` 凭据文件，绝不写入数据库或便携备份；
- **零 C#/.NET、零 Electron 常驻，精确私有内存指标与低内存回收**：窗口收进托盘、启动稳定或清理缓存时执行 `PRAGMA shrink_memory` / `wal_checkpoint(PASSIVE)` 与平台堆内存回收（Linux `malloc_trim(0)` / Windows `_heapmin` + `SetProcessWorkingSetSize` / macOS `malloc_zone_pressure_relief`），实时采样与系统监视器对齐的私有内存（Linux `smaps_rollup` `Private_Dirty` + `SwapPss`、Windows `PROCESS_MEMORY_COUNTERS_EX::PrivateUsage`、macOS `proc_pid_rusage` `ri_phys_footprint`）；
- **并行编译与克制哑光界面**：Slint 界面使用 `COMPILATION_UNITS 16` 分片并行编译并保持完整 Release 优化（GCC/Clang `-O3`、MSVC `/O2`），配合精简零滚动 4 行哑光 Bento 控制台（禁用 `drop-shadow-blur` / `animate drop-shadow-blur` / `backdrop-blur`），消除 Skia GPU 模糊纹理缓存膨胀并保持快速编译；
- **许可合规**：界面“关于”页内置 `AboutSlint` 署名，桌面分发兼容 GPLv3 及 Slint 免费 **Royalty-Free Desktop License**；
- **架构规范**：详见 [配置边界与统一 SQLite 存储](../docs/architecture/config-boundary.md) 与 [多平台集成与运维原则](../docs/design-principles/platform-and-operations.md)。

## 构建与自测（CMake 4.5+ & Ninja）

```bash
# 1. 无 Slint SDK 时即可离线编测 C++26 桥接库与实机联调单测（import std;）
NEXUS_CORE_BIN=/path/to/nexus ./scripts/build-desktop.sh

# 2. 接入官方 Slint v1.19.0 预编译 C++ SDK 构建完整桌面端
cmake -S desktop -B target/desktop-ui -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DSlint_DIR=/path/to/Slint-cpp-1.19.0-Linux-x86_64/lib/cmake/Slint
cmake --build target/desktop-ui

# 运行时推荐启用 Skia 后端以获得最佳 CJK 中文字体与抗锯齿体验
SLINT_BACKEND=winit-skia target/desktop-ui/nexus-desktop
```
