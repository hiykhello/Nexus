# Nexus Desktop 外壳（Slint v1.19.0 · C++26 + CMake 4.5 `import std;`）

本目录是 Nexus 面向 **Windows + Linux 桌面端**的原生轻量 GUI 外壳独立工程（与主仓 `mcpp` 构建完全解耦），基于 **Slint v1.19.0 C++ SDK**（Skia 渲染 + 原生系统托盘 + Fluent/Material 主题）与 **CMake 4.5+ 官方原生 C++26 `import std;` 模块**，通过本机 IPC（Windows Named Pipe / Linux UDS）与 HTTP `/v1` 控制面和 `nexus` 核心进程通信。

## 设计原则

- **全栈统一 C++26 + `import std;`**：桥接库 `nexus-desktop-bridge` 采用标准 C++26 模块（`desktop.ipc_client`、`desktop.http_control`、`desktop.profile_store`、`desktop.share_link`、`desktop.single_instance`、`desktop.system_proxy`、`desktop.core_supervisor`、`desktop.async_worker`）与 CMake 4.5 官方 `import std;`，与主仓代码风格一致（尾置返回、显式对象参数 `this`、零虚函数）；
- **零 C#/.NET、零 Electron 常驻**：窗口收进托盘后依赖 Slint v1.19 修复的 `winit` 事件循环零空转省电；
- **进程与构建解耦**：Linux 与 Windows 均可用 GCC 16 / Clang / MSVC + Ninja 编外壳并链接官方预编译 `Slint-cpp-1.19.0` SDK；
- **许可合规**：界面“关于”页内置 `AboutSlint` 署名，桌面分发兼容 GPLv3 及 Slint 免费 **Royalty-Free Desktop License**；
- **实战细节**：详见 [多平台集成与运维原则](../docs/design-principles/platform-and-operations.md)——内置单实例唤醒（Mutex / `$XDG_RUNTIME_DIR/nexus-desktop.sock`）、系统代理原子快照/恢复（`SystemProxySnapshot`）、多配置档案与 `0600` 密钥隔离、分享链接导入与 `nexus check` 校验热重载入口。

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
