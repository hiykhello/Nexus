# 源码工程目录规划与 C++26 模块映射

状态：设计规范。定义 Nexus 源码物理布局与 mcpp 工作区映射。

目前真实源码包括 Glaze 模块、规则集、规则文件工具、SOCKS5 解析器及 Linux 实验代理；Capy 和 Corosio 由代理私有实现使用。下图其余内容是未来布局草案，不表示对应文件已经创建。实际 target 及测试见 [mcpp 工作区](../build/mcpp-workspace.md)。

---

## 一、物理目录规划 (Source Tree Layout)

Nexus 全面采用 **C++26 命名模块（Named Modules）** 架构。源码按功能域严格划分，每个模块由接口文件（`.ixx` 或 `.cppm`）与实现单元（`.cpp`）组成：

```text
nexus/
├── mcpp.toml                     # 根工作区及应用包
├── mcpp.lock                     # 已解析依赖
├── 3rdparty/mcpp-index/          # 固定第三方依赖描述符
├── docs/                         # 完备的技术架构与设计规范文档
├── src/
│   ├── thirdparty/               # Glaze 已实现，其余模块规划中
│   │   ├── glaze.cppm           # nexus.thirdparty.glaze
│   │   ├── proxy.cppm           # nexus.thirdparty.proxy
│   │   ├── boringssl_crypto.cppm # nexus.thirdparty.boringssl_crypto
│   │   └── nghttp2.cppm         # nexus.thirdparty.nghttp2（可选）
│   ├── app/                      # 应用程序入口与拓扑装配
│   │   ├── main.cpp              # CLI 启动与服务装配
│   │   └── nexus.app.ixx         # nexus.app 模块接口
│   ├── core/                     # 核心通用类型与错误处理
│   │   ├── nexus.core.ixx        # 基本错误码、数据缓冲、状态定义
│   │   └── error.cpp
│   ├── config/                   # KDL 配置加载与解析
│   │   ├── nexus.config.ixx      # 基于 glaze-kdl2.0- 的配置映射
│   │   └── loader.cpp
│   ├── crypto/                   # 密码学算力底座适配层
│   │   ├── nexus.crypto.ixx      # 导出对 BoringSSL libcrypto 的 RAII 封装
│   │   ├── aead.cpp              # AES-GCM / ChaCha20-Poly1305 适配
│   │   ├── ecdh.cpp              # X25519 与 ML-KEM-768 后量子计算
│   │   └── x509.cpp              # 证书解析与验签
│   ├── tls/                      # 自研 TLS 1.3 协议与指纹引擎
│   │   ├── nexus.tls.ixx         # TLS 1.3 状态机与 Record Layer
│   │   ├── utls_builder.cpp      # ClientHello 浏览器指纹编排 (utls26)
│   │   ├── ktls_linux.cpp        # Linux kTLS setsockopt 密钥注入
│   │   └── reality.cpp           # Reality 握手劫持与 Fallback 反代
│   ├── http/                     # 自研轻量级微型 HTTP/1.1 代理
│   │   ├── nexus.http.ixx        # HTTP 零分配解析与 CONNECT 隧道
│   │   ├── parser.cpp            # 状态机解析器
│   │   └── masque.cpp            # RFC 9298 CONNECT-UDP 胶囊协议
│   ├── protocols/                # 主力代理协议实现
│   │   ├── vless/                # VLESS 协议与 Vision 流控
│   │   ├── trojan/               # Trojan 协议与 Web 回退
│   │   ├── shadowsocks/          # Shadowsocks 2022 AEAD
│   │   └── mixed/                # SOCKS5 / HTTP 混合入站
│   ├── routing/                  # 高性能路由与分流匹配
│   │   ├── nexus.routing.ixx     # 规则分流执行器
│   │   └── matcher.cpp           # 基于 BEVE 缓存的 GeoIP/GeoSite 匹配
│   ├── dns/                      # DNS 解析引擎
│   │   ├── nexus.dns.ixx         # 异步解析视图与乐观缓存
│   │   └── fakeip.cpp            # FakeIP 分配池与持久化
│   ├── tun/                      # 自研 TUN 设备驱动与 TCP/IP 栈
│   │   ├── nexus.tun.ixx         # L3 包设备与平台网络适配
│   │   └── netstack.cpp          # 状态机转发器
│   └── platform/linux/           # Linux 平台专属高速通道
│       ├── splice_pipe.cpp       # Linux splice 零拷贝管道数据泵
│       └── nftables.cpp          # 自动化 nftables 透明分流规则管理
```

---

## 二、工作区与模块边界

实际构建清单及功能组合见[mcpp 工作区](../build/mcpp-workspace.md)。源码按真实职责归属工作区成员；每个命名模块都由构建图中的唯一提供者提供。模块与功能选择约定见[开发规范](../development/module-feature-policy.md)。

### 自实现容器与数据结构

`src/containers/` 存放自实现通用容器和数据结构。基础模块使用 `containers.*`，由代理、DNS、路由和协议组件单向依赖。`containers.byte_ring` 提供地址稳定的定长字节存储，Hysteria 2 和 TUIC 分别决定偏移、ACK 和释放区间。`containers.ring_queue` 维护 FIFO 槽序，Shadowsocks 原生 UDP 发送队列和 Hysteria 2 重组输出继续拥有槽对象、内存和过期。槽表和独立索引按实际复用场景继续迁移。

逐项迁移时核对容量、满载行为、分配次数、地址与视图稳定性、迭代顺序以及对象销毁时机。优先保留使用方接口和现有模块入口，让调用点按实际需求迁移。验收批次与支持状态见 [支持矩阵](../planning/proxy-kernel-support-matrix.md) 与 [项目进度](../progress.md)。

---

## 三、模块解耦保障

1. **依赖单向化**：`nexus.crypto` 仅被 `nexus.tls` 和协议内部依赖，严禁向上泄漏任何 OpenSSL/BoringSSL 原生宏定义或裸指针；
2. **零循环依赖**：`nexus.routing` 只依赖出站抽象能力（Facade），不反向 `import` 任何具体协议实现；具体协议由 `nexus.app` 在启动时进行依赖注入（Dependency Injection）。
