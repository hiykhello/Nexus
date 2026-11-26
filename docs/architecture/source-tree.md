# Nexus 源码结构与包边界说明

本文描述 Nexus 仓库当前的目录组织、mcpp 工作区划分与 C++26 模块依赖约束。

---

## 一、顶层目录结构

```text
Nexus/
├── mcpp.toml                 # mcpp 根工作区与根二进制/核心库包（nexus）配置
├── include/nexus/core_c_api.h # 面向 Apple Extension / 嵌入式宿主 Thin C ABI 头文件
├── 3rdparty/
│   ├── modules/              # 第三方 C++26 无前缀模块封装（capy/corosio/glaze/boringssl/blake3/nghttp2/ngtcp2/nghttp3）
│   ├── patches/              # 固定上游补丁（如 corosio 精确补丁）
│   ├── mcpp-index/           # 本地 mcpp xpkg 包索引覆盖（Linux / macOS / Windows 多平台元数据）
│   └── mcpp-pins.json        # 固定第三方依赖归档与校验清单
├── src/                      # 内核工作区源码与叶子基础包（均无 namespace = "nexus" 前缀）
│   ├── containers/           # containers（containers.*：inplace_vector/byte_ring/ring_queue/cache_index）
│   ├── functional/           # functional（functional：function_ref/move_only_function/copyable_function）
│   ├── utility/              # utility（utility：atomic_shared_ptr/scope_exit/secure_zero）
│   ├── encoding/             # encoding（encoding.base64 / base64_key / endian / hex / json）
│   ├── platform/             # platform（OS 文件、IP、进程归属、Unix Socket、Netlink/resolved 等）
│   ├── crypto/               # crypto（BoringSSL libcrypto 原语封装）
│   ├── rules/                # policy（配置映射与路由规则）
│   ├── dns/                  # dns（DNS 视图、UDP/TCP/DoH 查询与 FakeIP 支持）
│   ├── dns-shared/           # dns-group-core（共享 DNS 缓存核心与视图协调器）
│   ├── tun/                  # tun（包栈、TCP/UDP 与 TUN 驱动）
│   ├── relay/                # proxy-runtime（入站/出站分发、会话接管与服务端运行时）
│   ├── udp-runtime/          # ss-udp-runtime（SS-2022 UDP 入站生命周期管理）
│   ├── udp-shared/           # dns-group-udp（UDP 运行时共享 DNS 适配）
│   ├── endpoint/             # wireguard-endpoint（WireGuard / Tailscale 等端点装配）
│   └── ...                   # 各协议、状态、日志、TLS/QUIC 与 CLI/C ABI 工具子目录
├── tests/                    # 核心单元/夹具源码、test.* 测试模块、deps-tests（tests/deps/）及验证脚本
├── mcpp/                     # 独立构建视图与多平台消费者包（epoll/host-consumer/android-arm64/darwin-arm64/ios-arm64/windows-x64）
├── experiments/              # 协议互通测试向量夹具（uot-vector / vision-vector / xudp-vector）
├── scripts/                  # 代码行数检查、QUIC/BoringSSL/nghttp2 生成、XCFramework 与 pinned-guard 脚本
├── desktop/                  # Linux/macOS/Windows 桌面端与 Slint UI、C++ 桥接及 Desktop CTest
├── android/                  # Android App 与 Kotlin CoreBridge
├── apple/                    # macOS/iOS Swift Package（NexusCoreBridge，含 EmbeddedCoreBridge）及测试
├── web/                      # Web 控制台前端工程
└── docs/                     # 架构、配置、构建、开发规范与规划文档
```

---

## 二、工作区基础包与模块层次

工作区成员按叶子包到上层运行时逐级单向依赖：

1. **第三方封装模块（`3rdparty/modules/`）**：`blake3.cppm`、`boringssl.cppm`、`capy.cppm`、`corosio.cppm`、`glaze.cppm`、`nghttp2.cppm` 与由 `scripts/mcpp-quic-modules.py` 生成的 `ngtcp2.cppm` / `nghttp3.cppm` 直接导出同名无前缀命名模块及命名空间（`blake3`、`boringssl`、`capy`、`corosio`、`glaze`、`nghttp2`、`ngtcp2`、`nghttp3`）；C++ 测试辅助模块导出 `test.*`。
2. **通用容器、函数对象与工具叶子包**：
   - `containers`（`src/containers/`）：提供 `containers.inplace_vector`（定长内联顺序容器与 `containers::erase`/`erase_if`）、`containers.byte_ring`、`containers.ring_queue` 与 `containers.cache_index`。
   - `functional`（`src/functional/`）：基于 `proxy.v4` 提供 `functional::{function_ref, move_only_function, copyable_function}`（后两者为 32B SBO）。
   - `utility`（`src/utility/`）：提供 `utility::atomic_shared_ptr`、`utility::scope_exit` 与跨平台常量栅栏擦除原语 `utility::secure_zero`。
   - `encoding`（`src/encoding/`）：提供 `encoding.base64`、`encoding.base64_key`、`encoding.endian`、`encoding.hex` 与 `encoding.json`，供规则、WebSocket、配置与代理会话统一导入。
3. **平台抽象包（`platform`，`src/platform/`）**：提供 `platform.ip_address`、`platform.os_fs`、`platform.process_owner`、`platform.unix_socket`（非 Windows 条件编译）、Netlink/resolved（`platform.netlink_abi` / `platform.dbus_wire` / `platform.resolved_bus`）与各平台 TUN/批量 UDP 后端适配。
4. **核心运行时与协议目录**：
   - 协议与基础设施模块（归属 `src/`，`protocols` 包）：`acme/`、`anytls/`、`config/`、`control_api/`、`coro/`、`grpc/`、`http/`、`http2/`、`httpupgrade/`、`hysteria2/`、`logging/`、`masque/`、`memory/`、`naive/`、`net/`、`ntp/`、`openconnect/`、`openvpn/`、`packet/`、`quic/`、`reality/`、`rulefile/`、`shadowsocks/`、`shadowtls/`、`snell/`、`sniff/`、`socks5/`、`ssh/`、`state/`、`tailscale/`、`tcp/`、`tls/`、`tools/`、`trojan/`、`tuic/`、`udp/`、`uot/`、`vision/`、`vless/`、`websocket/`、`wireguard/`、`xhttp/`、`xudp/`。
   - 上层引擎与装配：`crypto`、`policy`、`dns`、`tun`、`proxy-runtime`、`ss-udp-runtime`、`wireguard-endpoint` 与 `src/tools/`（含 `core_c_api.cpp`）。

---

## 三、模块解耦保障

1. **依赖单向化**：叶子基础包（`containers`、`functional`、`utility`、`encoding`）仅向 `platform`、核心域包与测试单向输出；`crypto` 仅被 `tls` 和协议内部依赖，不向上泄漏底层头文件或宏定义。
2. **禁止跨包直含内部源码**：各子包通过各自 `mcpp.toml` 声明的命名模块接口交互，禁止通过相对路径直接将其他目录的 `.cppm`/`.hpp` 加入 `sources` 或使用 `#include`。
3. **平台条件编译隔离**：Windows/Darwin/iOS/Linux 专属实现通过 `[target.'cfg(...)'.build]` 在 `src/platform/mcpp.toml`、`src/dns/mcpp.toml`、`src/transport/mcpp.toml`、`src/crypto/mcpp.toml` 与根 `mcpp.toml` 中分拆，避免平台 API 与链接选项污染其他端。
4. **构建与依赖锁定守卫**：依赖变更后通过 `scripts/mcpp-generate-pinned-guard.py`、`tests/mcpp_pinned_deps.py` 与 `tests/mcpp_sidecar_isolation.py` 验证固定归档、模块接口、生成源码列表与 `profile-sidecar`/`profile-embedded` 特性隔离边界。
