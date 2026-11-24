# C++ Modules 组织

状态：全仓已全面切换为无前缀 C++26 命名模块与领域命名空间（`containers`、`functional`、`utility`、`encoding`、`platform`、`crypto`、`tls`、`quic`、`dns`、`rules`、`proxy` 等），第三方模块封装直接导出同名模块与命名空间（`capy`、`corosio`、`glaze`、`boringssl`、`blake3`、`nghttp2`、`ngtcp2`、`nghttp3`）。本机与跨平台构建统一采用 Clang（`llvm@23.1.6`）+ C++26 + 静态 `libc++`。

## 命名与无前缀约定

- **项目自有模块与命名空间**：统一采用领域短名，不使用 `nexus.` / `nexus::` 前缀，例如 `containers.inplace_vector`（`containers::`）、`functional`（`functional::`）、`utility`（`utility::`）、`encoding.base64`（`encoding::`）、`logging`（`logging::`）、`state.*`（`state::`）与 `platform.*`（`platform::`）。
- **第三方模块封装与测试模块**：`3rdparty/modules/` 统一导出裸库模块名与命名空间（`capy`、`corosio`、`glaze`、`boringssl`、`blake3`、`nghttp2`、`ngtcp2`、`nghttp3`）；`tests/` 下测试辅助模块统一使用 `test.*` 与 `test::`。
- **内部工作区包标识**：根工作区包与终端分发名为 `nexus`，内部各源码与测试子包（`src/*`、`tests/*`、`experiments/*`、`3rdparty/mcpp-*`）直接以职责名作为 mcpp 包名，无 `namespace = "nexus"` 前缀；仅 `3rdparty/mcpp-index` 本地 xpkg 索引条目保留 `nexus.*` 索引命名空间以配合 `pkgs/n/` 索引布局与 `mcpp.lock`。

## 核心模块与包层次

| 包目录 / 模块组 | 职责 |
| --- | --- |
| `3rdparty/modules/`（`blake3`、`boringssl`、`capy`、`corosio`、`glaze`、`nghttp2`、`ngtcp2`、`nghttp3`） | 封装并导出各第三方库的所需 C++/C ABI 接口；`corosio` 支持 Linux `uring`/`epoll`、Darwin `kqueue` 与 Windows `iocp` |
| `src/containers/`（`containers.*`） | 固定容量 `inplace_vector`（含 `erase`/`erase_if`）、`byte_ring`、`ring_queue` 与 `cache_index` |
| `src/functional/`（`functional`） | 基于 `proxy.v4` 的 `function_ref`、`move_only_function` 与 `copyable_function` |
| `src/utility/`（`utility`） | `atomic_shared_ptr`、`scope_exit` 与跨平台常量栅栏清零 `secure_zero` |
| `src/encoding/`（`encoding.*`） | Base64 编解码与 SS-2022 密钥解码 |
| `src/platform/`（`platform.*`） | OS 文件、IP 地址、进程归属、Unix Socket、网络选择、Netlink/resolved 与平台后端 |
| `src/crypto/`（`crypto`） | BoringSSL `libcrypto` AEAD / ECDH / HKDF / ML-KEM 原语包装 |
| `src/`（`protocols`） | 传输协议（TLS/uTLS、HTTP/1/2/3、QUIC、VLESS、SS-2022、Trojan、AnyTLS、Hy2、TUIC、MASQUE、WireGuard、SSH、Naive 等）、Logging 与 State |
| `src/rules/`（`policy`） | 规则语义模型、KDL/BEVE/SRS 配置解码与匹配器 |
| `src/dns/`（`dns`） | 解析视图、UDP/TCP/DoT/DoH/DoQ/DoH3 上游、乐观缓存与 FakeIP |
| `src/tun/`（`tun`） | 用户态 TUN TCP/IP 协议栈与 Linux/Darwin/Windows TUN 适配 |
| `src/relay/`（`relay-runtime`） | 入站监听、会话接管、转发调度与服务端运行时 |
| 根包 `nexus`（`src/tools/`） | CLI（`nexus`）、嵌入式 Thin C ABI（`include/nexus/core_c_api.h`）与可选 HTTP/UDS 控制面 |

## 模块解耦原则

1. 项目自有 C++ 接口通过命名模块导出，内部实现拆分为模块实现单元或私有分片（`module :private;`），保持依赖图严格无环。
2. 第三方头文件和宏仅进入对应封装模块的 Global Module Fragment，不向外泄露给业务消费者。
3. 业务可失败操作优先返回 `std::expected`，正常缺失优先返回 `std::optional`；构建期通过 `tests/mcpp_sidecar_isolation.py` 与 `tests/mcpp_pinned_deps.py` 核验依赖裁剪与模块边界。
