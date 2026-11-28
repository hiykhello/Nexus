# QUIC 与 HTTP/3 依赖边界

正式包和命名模块已加入工作区，当前固定版本为 `ngtcp2 1.26.0-nexus.1` / `nghttp3 1.19.0-nexus.1`；中央组合图及 Hy2 / TUIC / MASQUE 的支持范围以 [支持矩阵](../planning/proxy-kernel-support-matrix.md) 为准。

| C core | 固定 release | recipe 版本 | archive SHA-256 |
| --- | --- | --- | --- |
| ngtcp2 | 1.26.0 | `1.26.0-nexus.1` | `7804aa0fa1c39942ba322a90805824c37231f7675b08d0c3cc4332858a7b085e` |
| nghttp3 | 1.19.0 | `1.19.0-nexus.1` | `228e17f5cc3d4de7bfced9912bd09de30e7f45741cc47503cf88d3fa9209e155` |

只编译上游 `lib/CMakeLists.txt` 列出的核心 C 源；nghttp3 的 bundled sfparse 通过编译宏加私有前缀避免与 `nghttp2` 同名符号冲突。不包含上游示例、事件循环、TLS helper 或第三方 `libssl`；Nexus 拥有全部 UDP I/O、自研 TLS、密码回调与对象生命周期。

`scripts/mcpp-quic-sources.py` 校验 archive SHA-256 与源码清单并生成覆盖 Linux / Apple Darwin / Windows 64 位的 `mcpp-index` 包描述（`config.h` 按平台条件分支并保持 private）。`scripts/mcpp-quic-modules.py` 从固定 C 头生成无前缀命名模块 `ngtcp2` / `nghttp3`（导出 `ngtcp2::` 与 `nghttp3::`），所需别名与常量由 `3rdparty/quic-boundary.json` 声明。

`ngtcp2` 生产依赖保留两项锁定补丁：
- [pmtud-restart.patch](../../3rdparty/patches/ngtcp2/pmtud-restart.patch)：在本地 MTU 拒绝后降低已确认路径上限并重启上游 PMTU 探测；
- [brutal.patch](../../3rdparty/patches/ngtcp2/brutal.patch)：接入 Hysteria 2 Brutal 拥塞控制。

`quic-native` 选择 ngtcp2 C core 和模块；`http3-core` 选择 nghttp3 及 varint；纯 `hysteria2-core` 不依赖这两库；`quic-crypto` 单独提供 Initial secrets、AEAD 和头保护。
