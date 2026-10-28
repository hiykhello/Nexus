# 接手记录

更新日期：2026-10-28。本文只记录当前状态、约束、验证证据和下一步；已完成的历史实验不在这里重复展开，专题依据见链接文档。

## 当前目标与约束

继续按[实施路线](planning/roadmap.md)交付可验证的代理能力。当前优先级是固定 HTTP/2 核心、资源边界、TLS/Corosio 驱动和独立对端互操作，然后再逐项接入正式代理路径。

- 默认验证 Linux x86_64、GCC 16.2.1、C++26 Modules 和 io_uring；改动范围允许时做增量构建，切换配置必须隔离 global/config/build 目录。
- 固定依赖：Capy `a8e93ccfec2ace5b3e35029a4b2f1b7e087c7aa2`（0.2.2）、Corosio `70adbd5aff90569aac588e78a717fecbd5b7dedc`（0.3.3）、Glaze `fc646588635c42cca142562d7b3d0484cc4493b7`；源码和提交以锁文件及 recipe 为准。
- 用户允许在自维护标准库完成前继续使用现有标准库和依赖；Capy 保留异常运行，项目业务错误优先 `expected`/`optional`。不做无异常迁移，也不启用真实系统接管。
- 第三方 socket 类型只存在私有实现单元/私有头；`src` 只放项目代码，第三方 Modules 放 `3rdparty/modules`，导出命名空间使用 `nex`。TLS 应用层不保留重复头文件实现或隐藏第三方类型的 PImpl。
- 项目动态多态优先 ngcpp/proxy；先用组合。Python 命令经 `uv run`。

## 当前已验证能力

### 工程、规则与代理

- C++26/xmake 工程、Glaze 命名模块、有限 KDL/BEVE 规则解析、双向转换、顺序匹配和 Linux 安全文件转换已通过 GCC 16 验证。
- 正式二进制统一为 `nexus`，支持 `nexus run` 与 `nexus rule convert`；有限 KDL 主配置支持单个 loopback SOCKS5 入站、direct 和可选 block/规则集。
- Linux 实验代理支持 loopback SOCKS5 CONNECT、IPv4/IPv6、系统解析的 ASCII 域名、单用户密码认证、Mixed CONNECT 和有限的单次 HTTP 正向转发；UDP ASSOCIATE、通用 HTTP 连接复用、真实 TUN、控制面仍未实现。
- 规则阻断在域名解析前及每个目标 IP 拨号前执行；会话、DNS 结果、握手和转发均有界。能力边界见[SOCKS5/Mixed](architecture/protocols/socks5-mixed.md)和[HTTP 代理线规](architecture/http-proxy-spec.md)。
- DNS 解析器已覆盖双族解析、CNAME/NXDOMAIN/NODATA 负缓存边界、具名服务器选路和受控 BIND/dnsmasq 互操作；DNSSEC、跨服务器转介和完整系统接入仍未验证。

### Capy/Corosio 升级后的使用

- 已验证 `tcp_acceptor::accept()` 值返回 API：代理 accept loop 只在成功后构造 Session，失败路径不创建半成品对象。
- 已验证 `tcp_acceptor::set_option(socket_option::reuse_port)`/`get_option`，代理不再直接使用原生 `setsockopt`；FakeIP TCP 夹具使用 acceptor 便捷构造。
- GCC 16、io_uring 下受影响目标和完整工程构建通过；I/O epoll/io_uring、SOCKS5 代理、UDP、VLESS、FakeIP chain、reuseport、accept fault、worker failure race 回归通过。epoll 结果也已独立验证。
- 仍不能把上游新增能力视为全部接入：地址工厂、协程 owner unwind、上下文 stop/drain 语义和其他便捷构造需要逐项核对。

### HTTP/2

- 固定 nghttp2 1.70.0 已作为可选 `--http2` 依赖和 `nexus.thirdparty.nghttp2` Module 接入，禁用选项时 HTTP/2 targets 缺席。
- `nexus.http2.headers` 提供单头块字段数和解压后字节上限；`nexus.http2.server` 提供无 I/O、有界并发流、请求头/DATA/结束/关闭回调、响应体所有权和总响应字节上限。
- 服务端关闭 nghttp2 自动接收窗口更新，`input_window` 同时限制连接和新流；同步接受 DATA 后显式 `session_consume`，暂停 DATA 由 `resume_input` 确认后恢复。真实内存 client/server 逐字节输入、响应 DATA、超限复位、窗口更新、回调重入和故障状态测试通过。
- 当前仍没有 TLS ALPN、Corosio socket 驱动、异步 DATA 队列、严格连接级总内存预算或独立网络对端互操作；默认不通告 h2。

### TLS 与网络栈实验

- BoringSSL 静态 libcrypto、TLS 1.3 记录/握手、证书链/名称/用途/时间校验、RSA-PSS/ECDSA/Ed25519 验证、X25519MLKEM768 实验组、KeyUpdate、close_notify 和 OpenSSL 独立互操作已有受控证据。
- `nexus.tls.corosio_client`、服务端握手和应用记录适配器已验证部分写入、期限、取消、KeyUpdate、双向背压及 owner 生命周期约束；仍需生产连接、双向并发关闭、ALPN h2 和更完整独立对端验证。
- 自研 packet/TCP/UDP 内存栈、FakeIP registry/历史实验及 SS-2022 TCP/UDP 实验链路有独立回归；真实 TUN、可信密钥/防回滚和正式 UDP 出站尚未接入。

## 构建与验证

隔离构建示例（默认 io_uring）：

```sh
export XMAKE_GLOBALDIR=/tmp/nexus-local-global
export XMAKE_CONFIGDIR=/tmp/nexus-local-config
export TMPDIR=/tmp/nexus-local-tmp
export NEXUS_GLAZE_SOURCE=file:///home/yk/Code/glaze-kdl2.0-/.git
xmake f -y -m debug --toolchain=gcc --io_uring=y
xmake build --all -r -j 1
```

常规规则、转换、I/O、代理和慢 DNS 回归命令见[构建说明](build/xmake.md)。HTTP/2 需要另建隔离配置并启用 `--http2=y`；TLS/SS-2022 需要按依赖选项启用 `--crypto=y`。socket 测试在受限沙箱中可能失败，需在已授权的二进制路径运行；这不改变源码边界。

## 本轮收口

- 已删除仓库内生成的 `build/`、`.xmake/`、`gcm.cache/` 和 `experiments/ak-fallible/build/`；`docs/build/` 是文档源目录，保留。
- 已清除 `/tmp` 下旧的 Nexus 隔离构建、探针、锁、日志和临时副本；保留固定依赖源码/安装目录，下一次工作重新创建隔离的构建目录。
- 已建立本地 Git 基线提交 `aa2e710`（`where:baseline`），远端 `origin/main` 当前不存在可追踪分支。后续每个完成并验证的切片使用简短、可定位的提交主题，例如 `where:feature`，提交前同步更新本文。

## 下一步

1. 逐项核对 Capy/Corosio 新 API：地址工厂、accept/连接失败、owner unwind、context stop/drain、取消和 io_uring/epoll 对称性；补最小回归后提交。
2. 继续 HTTP/2：完善流生命周期和连接级资源预算，处理输出/输入背压，再接 TLS ALPN 与 Corosio 应用记录；最后用独立网络对端验证。
3. 完善 TLS/Corosio 双向连接 owner、关闭/取消竞态及 h2/HTTP/1.1 ALPN 路由；保持自研 TLS 和私有 socket 边界。
4. 按路线推进普通 HTTP framing/路由、日志有界管线和文件 I/O 后端实测；SQLite 仍是待验证候选，设计文档不等于运行能力。
5. 每个切片完成后运行与范围匹配的测试、检查文档链接和源码行数，并在本文件删去已过期的临时细节。

## 仍需明确的限制

项目尚未宣称通用 HTTP/1.1 连接复用、HTTP/2 网络服务、TLS 生产入站/出站、真实 TUN、跨重启 FakeIP 安全、控制面或完整跨平台支持。设计草案、固定依赖编译和内存 smoke test 均不能替代相应运行互操作证据。
