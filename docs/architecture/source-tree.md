# 源码工程目录规划与 C++26 模块映射

状态：设计规范。定义 Nexus 源码物理布局与 xmake 构建工程映射。

目前真实源码包括 Glaze 模块、规则集、规则文件工具、SOCKS5 解析器及 Linux 实验代理；Capy 和 Corosio 由代理私有实现使用。下图其余内容是未来布局草案，不表示对应文件已经创建。实际 target 及测试见 [xmake 构建](../build/xmake.md)。

---

## 一、物理目录规划 (Source Tree Layout)

Nexus 全面采用 **C++26 命名模块（Named Modules）** 架构。源码按功能域严格划分，每个模块由接口文件（`.ixx` 或 `.cppm`）与实现单元（`.cpp`）组成：

```text
nexus/
├── xmake.lua                     # 统一构建配置 (对接 GCC 16.2+ C++26)
├── xmake/dependencies.lua        # 第三方包声明（规划）
├── 3rdparty/packages/            # 由 add_repositories 注册的项目内 package recipe
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

## 二、xmake 构建脚本设计草案

以下只展示项目入口与依赖第三方模块 target 的关系；路径、target、编译选项及依赖版本均须验证。实际 recipe 和锁文件的目录、获取与维护方式见[第三方依赖封装](../build/third-party-xmake.md)，包与命名模块的关系见[第三方 Modules 封装](../build/third-party-modules.md)。不直接引用本地工作区里的 Glaze，也不假设 `includes` 一个 Lua 文件会自动生成模块 target。

```lua
-- xmake.lua，示意而非当前可执行构建脚本
set_project("Nexus")
set_policy("package.requires_lock", true)
includes("xmake/dependencies.lua")

-- 第三方模块 target 须另行声明并绑定各自 package；以下仅表示业务依赖方向。
target("nexus_crypto")
    set_kind("static")
    add_files("src/crypto/*.cpp", "src/crypto/*.ixx", "src/crypto/*.cppm")
    add_deps("nexus-thirdparty-boringssl-crypto")

target("nexus_config")
    set_kind("static")
    add_files("src/config/*.cpp", "src/config/*.ixx", "src/config/*.cppm")
    add_deps("nexus-thirdparty-glaze")
```

示例未声明第三方模块 target，也未覆盖模块接口的公开属性、完整项目链接关系或 Linux 系统库。C++26、反射、优化、LTO 与异常等设置需按工具链和 target 验证，不能把项目选项无条件施加给第三方。

---

## 三、模块解耦保障

1. **依赖单向化**：`nexus.crypto` 仅被 `nexus.tls` 和协议内部依赖，严禁向上泄漏任何 OpenSSL/BoringSSL 原生宏定义或裸指针；
2. **零循环依赖**：`nexus.routing` 只依赖出站抽象能力（Facade），不反向 `import` 任何具体协议实现；具体协议由 `nexus.app` 在启动时进行依赖注入（Dependency Injection）。
