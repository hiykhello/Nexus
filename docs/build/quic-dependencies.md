# QUIC 与 HTTP/3 依赖边界

正式包和命名模块已加入工作区，recipe 版本为 `1.25.0-nexus.1` / `1.18.0-nexus.1`；中央组合图及 Hy2 / TUIC / MASQUE CLI 的支持范围以 [支持矩阵](../planning/proxy-kernel-support-matrix.md) 为准。

| C core | 固定 release | peeled commit | archive SHA-256 |
| --- | --- | --- | --- |
| ngtcp2 | 1.25.0 | f9e9ff01ad2c8116bc09de4f644b0028a61486a6 | 2a34d2484ba17847a5d11965704e9dd0fac4c6d8efc75ffe1ec7de66d8c6b6fb |
| nghttp3 | 1.18.0 | dbfc24286138cb0b6490160e7ca87fe1ce6722a0 | aad782c23d3f01bd4bb52c8bac7a553b631ef8115fd1612703df6183449fef19 |

只编译上游 `lib/CMakeLists.txt` 列出的 46/32 个 C 源。nghttp3 的完整 release 已包含 sfparse，另记录其 commit `4b313cfd2e1b389ae632b36dcd50402307289af2` 和两个生产文件的散列。HTTP/2 与 HTTP/3 的 bundled sfparse 在当前 mcpp 对象直接链接模式下会产生 9 个同名符号；nghttp3 包由原头自动提取这些函数并通过编译定义加私有前缀，原 C 源不变，不增加运行时转发。没有上游示例、事件循环、TLS helper 或第三方 libssl；Nexus 继续拥有 UDP I/O、自研 TLS、crypto callbacks 和生命周期。

`scripts/mcpp-quic-sources.py` 检查 archive SHA、来源清单与 release version，生成兼容 Linux / Apple Darwin / Windows 64 位的 `mcpp-index` 包描述（`config.h` 宏按 `#if defined(__linux__) / defined(__APPLE__) / defined(_WIN32)` 条件分支，并同上游 lib-only CMake 实际输出比对）。生成目录在 include_dirs 中声明并标为 private，避免发布通用 config.h。所有 pins、描述、生成器、边界配置和模块正文进入既有构建期漂移 guard；`tests/mcpp_pinned_deps.py` 从原始 archive 重新生成并逐字比较。

ngtcp2 生产依赖使用锁定补丁 [pmtud-restart.patch](../../3rdparty/patches/ngtcp2/pmtud-restart.patch)。它为固定版本增加内部入口，在本地 MTU 拒绝后降低当前路径的已确认上限并重启上游 PMTU 探测；Nexus 会话按间隔重试，业务包不作为探测包。补丁与归档摘要由 pin 和 lock 固定，`tests/mcpp_pinned_deps.py` 验证补丁可无 fuzz 应用，`scripts/mcpp-verify-installed.py ngtcp2` 对安装缓存按归档加补丁核验。该内部接口只用于对应固定源码，不属于上游公开 ABI。

`scripts/mcpp-quic-modules.py` 从固定 C 头生成无前缀命名模块 `ngtcp2` / `nghttp3`（导出 `ngtcp2::` 与 `nghttp3::`）。系统包含替换为导入 `std` 后的标量类型别名，声明、callback 和版本化结构体继续取自原头；没有手抄 ABI 或新增文本 include。所需别名与宏常量由 `3rdparty/quic-boundary.json` 明确选择，正文和所选 namespace 保存在同一个命名模块，无运行时转发。

ngtcp2 的生成边界基于上游 generic sockaddr 声明，按 `__APPLE__`（含 `sin_len`/`sin6_len` 与 `af_inet6 = 30`）、`_WIN32`（`af_inet6 = 23`）和 Linux LP64（`in6_addr` 4 字节对齐与 `af_inet6 = 10`）分别对齐原 C core ABI。`tests/quic_boundary.py` 在分开的 native/generated 翻译单元实际编译运行并已覆盖 Linux x86-64 glibc 等价性；Apple Darwin 与 Windows 实机仍需对应平台 CI 验证。

`quic-native` 选择 ngtcp2 C core 和模块；`http3-core` 选择 nghttp3 及 varint；纯 `hysteria2-core` 不依赖这两库。`quic-crypto` 继续单独提供 Initial secrets、AEAD 和头保护。QUIC 和 Hy2 的当前生产接线、互操作及剩余范围以 [支持矩阵](../planning/proxy-kernel-support-matrix.md) 为准；不能用 C core 构建或内存 HTTP/3 测试代替网络验证。
