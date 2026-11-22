# mcpp 工作区

> **2026-11-21 工作区基线更新（第 141–146 批）**：工作区已升级至 `mcpp >= 2026.11.20.1`，启用 `[workspace.dependencies]`（11 个内部测试/实验成员统一 `.workspace = true`）、`[build] target_budget = "24GiB"`、`[workspace.profile.release]`（`opt = 3`, `lto = true`, `strip = true`）、`[workspace.profile.ci]`、`[target.'cfg(...)'.build] sources` 跨平台源码路由、`[target.'cfg(not(os = "linux"))'.test]` 平台测试裁剪、`module :private;` 高频模块私有分片与 `[pack]` 发行资产打包。新增三组聚合发布特性 `profile-sidecar`（跨端非 root 核心）、`profile-linux-epoll`、`profile-linux-uring`，`mcpp/` 目录已收口为 5 个有效配置入口（`epoll`、`android-arm64`、`darwin-arm64`、`windows-x64`、`host-consumer`）。

本轮构建验收目标是 Linux x86-64。项目使用 mcpp 工作区：根包装配命令行程序，`src/proxy` 负责代理会话和服务器，`src` 提供协议和传输模块，`src/rules` 提供配置与策略，`src/dns` 提供 DNS 模型与 UDP/TCP 查询，`src/crypto` 提供密码原语，`src/platform` 提供 Linux 平台服务，`src/transport` 提供包、TCP/UDP 栈和 TUN 驱动，`src/udp-runtime` 管理 SS-2022 UDP 入站及其 DNS 生命周期；`tests`、`tests/dns`、`tests/fakeip`、`tests/http2`、`tests/proxy-faults`、`tests/tun`、`tests/tun-faults` 和 `tests/udp-runtime` 分别提供协议、DNS、FakeIP、HTTP/2、代理故障、TUN、TUN 链接故障和 SS UDP 测试。接入其余功能和恢复全部测试仍在进行中。包边界和可选 API 遵循[模块与可选功能](../development/module-feature-policy.md)。

当前本机使用 mcpp、GCC 16.2.1、C++26、系统 glibc 和已准备的离线依赖缓存。以下保留现有构建入口及验收说明，最新验证状态以 [项目进度](../progress.md) 为准。默认启用 io_uring；`crypto` 启用密码原语，`vless` 另外启用 TLS、Reality、Vision 和 VLESS 实现，`ss2022` 启用 SS-2022 TCP 及 UDP，`http2` 提供 HTTP/2 服务端会话，`http2-tls` 增加 TLS 驱动。`anytls` 和 `trojan` 提供对应生产代理路径；`wireguard` / `tailscale` 当前提供有界核心和网络夹具，`hysteria2-core` 为无 I/O 线格式。`tls` 可独立启用 TLS；`quic-tls` 在纯 `quic-transport` 之上增加共享 TLS 握手认证。`quic-native`、`quic-crypto`、`quic-transport`、`quic-tls`、`http3-core` 的边界与验证见[QUIC依赖](quic-dependencies.md)。下面的离线命令要求缓存已包含所需的固定依赖；空缓存、其他工具链与 release 仍须独立验证。

```sh
MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked build --target x86_64-linux-gnu --strict -j 1
MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked build --target x86_64-linux-gnu --strict --features crypto,vless -j 1
MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked build --target x86_64-linux-gnu --strict --features ss2022 -j 1
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked test --target x86_64-linux-gnu --strict
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked test -p nexus.protocol-tests --target x86_64-linux-gnu --strict
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked test -p nexus.dns-tests --target x86_64-linux-gnu --strict
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked test -p nexus.http2-tests --target x86_64-linux-gnu --strict
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked test -p nexus.tls-tests --target x86_64-linux-gnu --strict
MCPP_JOBS=1 MCPP_VERIFY_MODGRAPH=1 mcpp --offline --locked test -p nexus.tun-tests --target x86_64-linux-gnu --strict
```

`mcpp build --workspace --features crypto,vless` 可选择整个工作区。可执行文件位于 mcpp 报告的构建目录；测试夹具依赖的具体程序应显式传入路径。锁文件记录工作区依赖，第三方源码描述符和补丁分别位于 `3rdparty/mcpp-index` 与 `3rdparty/patches`，`src/build/mcpp_pinned_guard.cpp` 检查固定的网络依赖补丁。

BoringSSL 的 X509 修复由 mcpp 依赖边的精确补丁应用到固定上游源码，`nexus.crypto` 将其源码嵌入自身并提供项目模块门户。补丁变体的摘要进入锁文件；审计同时对照原两份修复补丁及精确补丁的输出。nghttp2、nghttp3、ngtcp2 和 BLAKE3 也由各自门户所在包嵌入。Capy 和 Corosio 的补丁迁移仍在进行，当前保持已验证的生成头方案。

拆分后的工作区已通过默认、`crypto,vless` 和单独 `ss2022` 图构建、默认 50 项及协议 20 项测试，以及独立协议对端的 Reality 双向、并发关闭和错误身份拒绝测试。`nexus.tls-tests` 独立于 Reality。包内五项测试覆盖首次 Hello 认证适配、认证策略暂存、签名协商和握手；原目录中的30项 TLS 核心测试登记为同成员的无参 bin targets（mcpp 不允许 discover 越过包根）。先 `mcpp build -p nexus.tls-tests --features io-uring,https`，再以 `python3 tests/tls_legacy_units.py <bin/tls-tests或匹配保存目录> --evidence <json>` 执行这30项，包内五项仍通过 `mcpp test -p nexus.tls-tests --features io-uring,https` 执行。七个需证书/角色参数的网络夹具分别交对应 Python 驱动，不放入无参测试发现。`nexus.protocol-tests` 的 `ss-relay` feature 生成 `shadowsocks-corosio-relay`，验证双后端 SS 双向关闭与取消；`nexus-vless-tls-test` 配合 `tests/vless_relay_interop.py` 验证普通 VLESS 的 TLS 转发和错误。DNS 网络成员的 UDP 和 TCP 回退测试覆盖 epoll 与 io_uring；其独立对端测试还覆盖解析链、缓存竞争、双栈、本地解析和 dnsmasq。DNS 查询模块的测试功能分别验证接收异常、代理注册、取消和排空。其他独立故障与网络夹具见 `tests/`；历史实验与当前交付基线见 [项目进度](../progress.md)。

网络驱动通过命令行参数或 `NEXUS_TEST_BINARY`、`NEXUS_TEST_FIXTURE_DIR` 接收本次构建产生的程序路径；使用 `tests/test_paths.py` 的驱动还可读取 mcpp 当前测试图的 `MCPP_BIN_<NAME>`，显式选择优先。按测试所需功能选择配置和夹具，避免混用不同构建的二进制。

`nexus.thirdparty-tests` 分别以 `cpo`、`allocation`、`alignment`、`crypto` 构建并运行 `cpo-module`、`allocation-probe`、`capy-frame-alignment`、`crypto-smoke`，覆盖模块与头文件 CPO 身份、分配行为、协程帧对齐和 BoringSSL 已知向量（已随上游 Capy/Corosio 收敛移除专门注入 `when_all`/构造/冷 OOM 与 `timeout` 启动抛出的测试目标与非模块化补丁）。根测试 `corosio_connect_module_probe` 根据当前功能图分别验证 epoll 与 io_uring 的连接、取消和清理。

`tests/stream_relay_chains.py <nexus>` 用 Nexus 客户端、待测服务端和独立互通出口验证 SS-2022 与 VLESS 的四种 TCP 入出站组合：分别覆盖单、双 worker 的双向大流量、上传半关闭后的延迟回复，以及活动会话停机排空。`nexus.proxy-fault-tests` 提供真实代理实现的隔离故障图：依次以 `mcpp build -p nexus.proxy-fault-tests --features relay-throw` 和 `--features relay-abandon` 构建，前者生成 `nexus-vless-relay-throw-fixture` 供 `tests/vless_relay_throw.py` 注入准备和方向协程异常，后者生成 `proxy-vless-relay-abandon-test`，通过 `NEXUS_TEST_FIXTURE_DIR` 交给 `tests/vless_relay_abandon.py` 检查挂起方向、父帧和 profile 的析构顺序。两种 feature 分开构建；钩子不进入普通生产图。

同一故障成员的 `root-launch` feature 构建 `proxy-root-launch-fault` 与 `proxy-reconfigure-fault`，分别验证单、双 worker 的两个协程启动阶段分配故障以及故障后挂起 SOCKS 会话的凭据和路由寿命。`vless-accept` feature 构建 `proxy-vless-accept-fault`，传给 `tests/vless_accept_fault.py` 验证挂起 VLESS 会话阻止配置提前替换。这些 feature 分别重建，注入回调只在故障图中编译；不能将测试对象与生产 feature 图混用。

同一成员分别选择 `relay-abandon`、`ss-abandon`、`tunnel-abandon`、`ss-tunnel-profile` 和 `vless-reconfigure`，构建对应的入站挂起帧、SS 入站、双协议活动出站、SS 工厂以及 VLESS 重配置夹具。`tests/proxy_protocol_faults.py` 可驱动需要凭据的入站与出站夹具；`tests/vless_relay_abandon.py` 需配合本地 VLESS 互通对端运行。它们检查挂起帧、隧道与借用配置的析构顺序，以及停机前后的配置替换。各图必须单独构建，测试回调不进入普通图。

`mcpp build -p nexus.proxy-preload-tests` 构建 epoll 故障夹具和 `proxy-preload-cli`；分别向 `nexus.proxy-start-shim`、`nexus.slow-resolver-shim` 请求构建得到独立共享库。`tests/proxy_start_fault.py` 接受 `proxy-start-fault` 和启动 shim；`tests/proxy_accept_faults.py` 依次接受 `proxy-worker-failure`、`proxy-accept-aborted`、`proxy-retry-stop` 和启动 shim，检查致命错误、瞬时错误、退避及停止的注入标记。`tests/proxy_failure_race.py` 和 `tests/proxy_multi_failure.py` 分别接受 worker 夹具或 epoll CLI 与启动 shim，验证并发失败及多监听器排空。`tests/reuseport.py` 接受 `reuseport` 夹具和 `epoll`，`tests/resolver_threads.py` 接受 `resolver-threads` 与慢解析器 shim。上述工作区图已通过；慢解析器驱动验证的是 Corosio 的系统解析线程池，历史代理驱动假定 `getaddrinfo` 的场景尚需按当前 DNS 路径重新验收。

以 `mcpp build -p nexus.proxy-preload-tests --features io-uring` 重建后，`proxy-init-failure`、`proxy-preload-cli` 和启动 shim 可交给 `tests/proxy_init_failure.py` 验证 ring 初始化、eventfd、提交失败及不支持的选项回退。此图的 `reuseport` 支持 `uring` 参数。两张图会覆盖同一输出目录，切换前应保存匹配的程序；accept 系统调用注入须使用单独构建的 epoll 图。启动、慢解析器、时钟、系统解析防护和 SS UDP 观察分别属于 `nexus.proxy-start-shim`、`nexus.slow-resolver-shim`、`nexus.clock-fault-shim`、`nexus.dns-system-guard-shim` 和 `nexus.ss-udp-observe-shim`，只在驱动显式设置 `LD_PRELOAD` 时加载。系统解析防护已用于 DNS bootstrap 回归，时钟和大报文观察分别通过 SS UDP 的失败排空及双监听网络测试。

`nexus.proxy-runtime` 的 `io-uring,test-start-throw` 和 `io-uring,test-session-throw` 分别生成 `launch-throw-fault` 和 `session-throw-fault`：前者检查单、双 worker 启动异常回滚和同端口重启，后者检查连续 70 次会话异常、配额恢复及其他活动会话。两张图单独构建和执行，故障回调不进入普通代理。

`nexus.dns-tests` 的普通构建生成 `dns-tcp-fixture`、`dns-resolve-fixture`、`dns-cache-fixture`、`dns-dual-fixture`、`dns-local-fixture` 和 `dns-dnsmasq-fixture`；分别传给 `tests/dns_tcp.py`、`dns_resolve.py`、`dns_cached_resolve.py`、`dns_dual_resolve.py`、`dns_local_resolve.py` 和 `dns_dnsmasq.py`。这些驱动使用本地对端；dnsmasq 测试还要求本机 `dnsmasq` 和 `dig`。原来的 `tests/dns_*.cpp` 对应源码已移到 `tests/dns/`，覆盖清单中的旧路径保留作为历史记录。

接收故障可用 `mcpp test -p nexus.dns-tests --features test-fakeip` 验证；代理查询所有权故障使用 `mcpp build -p nexus.proxy-runtime --features io-uring,test-dns-lifetime` 构建并运行 `dns-lifetime-fault`。这两个 feature 仅用于测试，调用方须提供相应钩子，不应包含在生产构建中。

`mcpp build -p nexus.proxy-runtime --features io-uring,test-dns-owner` 构建 `dns-owner-fault` 与 `borrowed-state-fault`：分别以参数 `udp`、`tcp` 运行前者，检查两个挂起查询在 worker 所有者销毁前注销；后者检查挂起握手借用的策略和凭据直到上下文析构仍有效。该图单独编译，不能与 `test-dns-lifetime` 或普通生产对象混用。

`nexus.http2-tests` 的三项常规测试覆盖会话、头与 DATA 限额及 nghttp2 内存预算。`mcpp build -p nexus.http2-tests --features tls` 生成 `http2-tls-backpressure` 和 `http2-tls-server`；后者交给 `tests/http2_tls_server.py`，通过环境变量 `NEXUS_TEST_URING=1` 选择 io_uring，默认使用 epoll。`--features test-allocator` 构建 `http2-allocator-boundary`，以测试专用回调在预算检查后注入扩容失败；生产图没有该回调。HTTP/2 会话和 TLS 驱动尚未接入根程序的网络运行时，选择 feature 不会使应用通告 h2。

`mcpp build -p nexus.tls-tests --features https` 构建使用 epoll 的 `nexus-tls-corosio-openssl-test`；增加 `io-uring` 选择对应后端。将该程序路径交给 `tests/https_response_openssl.py`，可独立验证定长、分块、空响应、截断、畸形和关闭定界的 TLS 响应。HTTPS 测试适配只在 `https` feature 中编译，不进入普通生产图。

`nexus.tun` 复用 `nexus.policy`，不重复编译规则模块。当前工作区中 48 项包、双栈 TCP/UDP 和传输常规测试已通过；`tcp-kernel-tun`、`transport-kernel-tun` 与 `transport-tun-linux-e2e` 可分别传给 `tests/tcp_kernel_tun.py`、`tests/transport_kernel_tun.py` 和 `tests/transport_tun_linux_e2e.py`，驱动在隔离网络命名空间内创建 TUN。`tests/transport_kernel_tun.py` 还需同一目录下的 `nexus-packet-tun-helper`。以 `--features test-random` 构建 `nexus.tun-tests` 后，`transport-tun-random` 可在 `unshare -Urn` 下验证随机数故障；该功能和钩子仅供测试。

`python3 scripts/mcpp-link-faults.py --suite tun --offline --home /tmp/nexus-mcpp-host-home` 按组构建并运行 11 项 TCP/UDP 分配、收发、超时和标记故障测试；可省略 `--home` 使用当前 mcpp 配置，或用 `--group` 选择一组。由于 mcpp 暂不支持目标级链接选项，`nexus.tun-fault-tests` 用同名 feature 和 profile 分组，驱动核对目标集合及每条实际链接命令中的 `--wrap` 后再运行。应使用驱动保持 feature/profile 一一对应，不要在其他测试或生产构建中选择这些 profile。普通构建不启用它们。

将 `--suite tun` 换为 `--suite udp` 可运行 SOCKS UDP 直连、入站、UoT 直连和 SS UDP 转发的链接故障测试；驱动检查每组实际链接的系统调用包装。SS 故障测试覆盖 socket 创建、选项、发送回滚、接收错误隔离和每次单独接收。UoT 直连由协议成员的 `uot-direct` 功能提供，`ss2022` 同时启用该功能，不为测试复制协议核心。

代理成员可单独选择 `mcpp build -p nexus.proxy-runtime --features io-uring,ss2022`。这个图已通过 SS-2022 的 Server API、TCP 入站与出站、单及双 worker、重放保护，以及 SOCKS UDP 经 UoT 的互通测试；它不启用 VLESS。使用 `io-uring,ss2022,vless` 组合构建后，`tests/proxy_mixed_outbounds.py` 接受 `mixed-outbounds-fixture` 路径，验证两种添加顺序、单及双 worker、路由和半关闭；反转路由的负向控制由对端拒绝。

生产 detour 使用根包 `mcpp build -p nexus --features ss2022,vless`，把该 CLI 路径分别传给 `tests/detour_network.py` 和 `tests/detour_reality.py`，验证两/三层 SS、普通 TLS、Reality、Vision 的 TCP、UoT/XUDP、半关闭、共享期限、身份拒绝和停止排空；具体边界见[配置说明](../configuration/spec.md)。单协议图可对前一个驱动加 `--protocol ss` 或 `--protocol vless`，只配置该图启用的协议，仍验证三层、HTTP CONNECT/正向和活动停机。epoll 使用既有 `mcpp build -p nexus.proxy-preload-tests --features nexus/ss2022,nexus/vless` 的 `proxy-preload-cli`，无需注入 shim；mcpp 没有 `--no-default-features`。切换前保存程序，实际后端可用 strace 核对 io_uring_setup/epoll_create1。

`tests/detour_tls_candidates.py <nexus>` 验证链内 TLS/Vision 首地址握手失败或 TCP 拒绝后的重试，以及共享期限和挂起停止。`tests/detour_failure_fanout.py <nexus> --domain --no-cache` 检查 16 层及 64 个业务地址的失败不会重复建立同一耗尽出站；加 `--fallback` 验证末地址按规则恢复 direct，`--protocol vless` 与 `--workers 2` 选择对应矩阵。工厂构造故障单独使用 `-p nexus.proxy-preload-tests --features factory-fault`，把 `detour-factory-fault` 交给 `tests/proxy_protocol_faults.py --detour-factory`；常规分配替换只在该目标生效，内部测试单元只在对应 feature 编译。详见 [拨号字段覆盖](../planning/dial-field-coverage.md)。

UoT 入站的低层客户端和故障对端通过 `mcpp build -p nexus.proxy-runtime --features io-uring,ss2022,vless,test-uot-fixture` 构建，生成 `nexus-proxy-uot-fixture` 与 `nexus-uot-fault-server`。客户端的 `nexus.proxy` 实现单元只在该测试 feature 中编译；普通生产图不包含它。网络驱动通常要求这两个可执行文件与所测 CLI 位于同一目录，测试驱动也可用 `--fixture` 指定客户端路径。

根包 `lazy-readers` 独立目标检查实际模块的按需 task owner：0/1/32 槽位、重复/提前请求、工厂异常、父取消、同槽位等待恢复和上下文放弃；只替换测试执行器，不进入生产流程。`tests/lazy_packet_readers_network.py <nexus>` 用普通组合图检查 SOCKS、Trojan 和 SS UoT 的双出站首次回复、复用与活动停机。`tests/udp_bind_port_network.py <nexus> --report <json>` 检查实际物理 UDP 源端口与空包回复、TCP 排除及 Hy2 Initial/取消；关闭图可仅选 `--cases direct`。这两个驱动固定互通对端，源码参考更新不会自动替换测试二进制。

`test-uot-write-race` 是单独的代理测试 feature，用于授权挂起和队列饱和时的观测；`io-uring,ss2022,vless,test-uot-fixture,test-uot-write-race` 构建的 `uot-proxy-fixture` 可交给 `tests/uot_write_race.py`。通过根包参数 `--features ss2022,vless,http2-tls,nexus.proxy-runtime/test-uot-write-race` 构建的测试 CLI 可运行 `tests/uot_inbound_write_race.py` 和队列饱和驱动。测试 CLI 与客户端、故障对端的路径须显式配对，不能将该 feature 用于生产程序。

XUDP 的耗尽和重连网络测试可用根包 `--features ss2022,vless,http2-tls,nexus.protocols/test-xudp-rotation` 构建专用 CLI：该测试图从 ID 65534 开始，`tests/xudp_socks_exhaustion.py` 指定 `--start 65534`，`tests/xudp_uot_exhaustion.py` 另以 `--fixture` 指定 UoT 客户端。两个驱动可分别覆盖普通、Vision 和重连时停止。 若一次选择根包与代理夹具成员，可用 `-p nexus -p nexus.proxy-runtime --features io-uring,ss2022,vless,test-uot-fixture,nexus.protocols/test-xudp-rotation`；所选 member 的 feature 用裸名称，`dependency/feature` 只用于依赖转发，且 proxy 成员需要显式启用 io-uring provider。普通生产图从 ID 1 开始，不应启用此 feature。

`mcpp build -p nexus.proxy-runtime --features test-xudp-fixture` 构建独立的代理 XUDP 客户端 `nexus-proxy-xudp-fixture`；将它传给 `tests/xudp_reality_interop.py --proxy --proxy-fixture <path>`，可验证两条 XUDP 会话经普通和 Vision Reality 代理出站。该夹具在当前工作区对独立协议对端均通过，测试实现单元只随该 feature 编译，不进入普通生产图。

根程序的 `ss2022` 功能已接入 TCP 和 UDP 入站。实际命令行 UDP 路径通过双监听、双密钥和共享 DNS 视图测试，以及单/双 worker、重放、系统 DNS、策略阻断和启动失败回滚测试。`tests/shadowsocks_udp_shared_dns.py` 和 `tests/shadowsocks_udp_config.py` 接受当前 `nexus` 二进制路径。`nexus-shadowsocks-udp-rebind-test` 为对应的重绑定和故障驱动提供入口。

`mcpp build -p nexus.ss-udp-tests` 生成 `resolve-fixture`、`resolve-owner-fixture`、`listener-fixture` 和 `cache-restart-fixture`，供 `tests/shadowsocks_udp_resolve.py`、`shadowsocks_udp_resolve_owner.py`、`shadowsocks_udp_listener.py`、`shadowsocks_udp_listener_aaaa.py` 和 `shadowsocks_udp_cache_restart.py` 使用；`ss-udp-relay` 验证会话轮转、来源过滤和零长度数据报。`test-udp-pending` 和 `test-udp-send` 是分别用于挂起及发送故障的测试功能，生产图不得启用。

`test-udp-send` 的 `listener-fixture` 可交给 `tests/shadowsocks_udp_send_stop.py <fixture> <epoll|uring> <stop|fault|task-fault|full>`；两种后端均验证停止排空、启动及协程失败和饱和队列的有序恢复。该图还可配合多监听器观察 shim 检查两个监听器的并发发送。

`mcpp build -p nexus.ss-udp-tests --features test-udp-pending` 后，分别以 `epoll` 和 `uring` 参数运行 `pending-fault`，验证挂起请求分配异常后的排空与替换。`mcpp build -p nexus.ss-udp-owner-fault-tests` 单独启用 DNS 接收注入；将 `resolve-owner-fault` 传给 `tests/shadowsocks_udp_resolve_owner.py <fixture> <epoll|uring> --fault`，验证两个并发查询的停止、到期、接收异常及缓存槽位释放。普通 `resolve-owner-fixture` 可使用同一驱动但不带 `--fault`。DNS 接收钩子与代理注册钩子使用独立编译开关，仅各自测试图提供回调。

DNS 问题规则支持见 [配置规范](../configuration/spec.md)。`nexus.dns-tests` 另提供 `dns-answer-fixture`，交给 `tests/dns_answer_resolve.py` 验证普通缓存/local 的完整规范名与 TTL、冲突及双后端取消；原 vector 接口继续使用同一组合器。`nexus.dns-group-integration` 的 `standard-lifetime,io-uring` 和 `standard-owner,io-uring` 是两张独立的普通缓存故障图，分别生成 `standard-dns-lifetime`，或 `standard-dns-owner`/`standard-borrowed-state`。前者增加 A 成功后 AAAA 的登记/接收异常、取消和上下文销毁场景；测试实现是仅 feature 编译的命名模块实现单元，不再文本包含到拨号源码。

共享 DNS 按职责拆为 `nexus.dns-group-core`（快照、视图和协调器）、`nexus.dns-group-udp`（SS UDP 适配）和联合测试夹具成员。代理始终导入 `nexus.proxy.dns_backend`；生产默认选择共享缓存和协调器，普通缓存及实验夹具使用各自的显式 feature。`nexus.proxy.request_backend` 为普通请求与实验 FakeIP 提供统一的 SOCKS 请求类型。实验通过关闭代理依赖的默认 feature 来选择测试提供者；每个边界的提供者不能放进同一构建图。测试代码及访问回调不进入默认程序。功能切换会覆盖同一构建目录中的对象，运行夹具前应重建所需配置。生产共享缓存仍需完成资源和真实性能验收。

`nexus.dns-group-experiment` 的 `group-udp-fixture` 覆盖 UDP 的 group、refresh 和 coordinator 布局；`mcpp test -p nexus.dns-group-experiment` 检查真实代理 DNS 路由的视图身份；`test-udp-start` 构建 `udp-start-fault` 检查三种布局的启动故障恢复。`mcpp build -p nexus.dns-group-core --features io-uring,test-inspect` 构建 `shared-capacity-test` 和 `coordinator-module-test`，前者检查差分、并发和分配故障，后者检查 epoll/io_uring 查询、取消及跨执行器排空；检查接口只随 `test-inspect` 编译。

`mcpp build -p nexus.dns-group-integration --features standard-proxy,io-uring` 构建 TCP 与 SS UDP 联合实验：`joint-coordinator-fixture` 可传给 `experiments/dns-shared-cache/proxy_group_network.py`（附 `--udp --coordinated`）和 `proxy_group_refresh.py`（分别指定 `tcp`、`udp`）；`coordinator-isolation-fixture` 可传给 `proxy_coordinator_isolation.py`。这些网络驱动验证共享查询、视图隔离、挂起任务排空和配置换代，不构成共享缓存的生产内存或性能验收。`joint-feature-api` 复用普通代理的 feature API 测试。用 `fakeip-proxy,io-uring` 代替 `standard-proxy,io-uring` 可构建 FakeIP 与共享 DNS 组合的 `joint-fakeip-fixture`，传给 `integration/fakeip_joint.py` 验证地址翻译、查询合并和停止排空。

同一成员的 `group-proxy,io-uring` 构建 `joint-group-fixture`，用于 `proxy_group_network.py --udp`；`refresh-proxy,io-uring` 构建 `joint-refresh-fixture`，可运行同一网络驱动及 `proxy_group_refresh.py` 的 `tcp`、`udp` 两种停止所有者场景。两者分别验证无协调器的共享缓存和刷新路径。`refresh-start-fault,io-uring` 构建 `tcp-refresh-start-fault`，验证单、双 worker 的刷新构造和启动故障回滚、重绑及资源释放。上述三种布局和协调器布局互斥，功能切换后必须重建对应夹具。

同一成员的 `capacity-group,io-uring` 和 `capacity-baseline,io-uring` 分别构建 `capacity-group-fixture` 与 `capacity-baseline-fixture`，验证真实 SOCKS/DNS 流量下的成员容量借用、回收和共享，与普通代理缓存对照。这两种布局互斥；先构建一种并将其可执行文件复制到临时目录，再构建另一种，把两个路径交给 `experiments/dns-shared-cache/proxy_shared_capacity_network.py <group> --baseline <baseline>`。两个独立进程各使用与自身构建匹配的模块对象，不混用 ABI。容量实验不启用共享访问测试钩子；联合生命周期夹具通过独立的 `test-dns-shared-access` feature 显式启用钩子。`run_proxy_shared_capacity_bench.sh <baseline> <group>` 接受同一对程序，短时驱动检查只验证入口，不代表性能验收。

`mcpp build -p nexus.fakeip-tests --features proxy,io-uring` 构建 `proxy-fakeip-fixture`，供 `tests/proxy_fakeip.py` 和 `tests/proxy_fakeip_dns_throw.py` 使用；改用 `inbound-protocols,io-uring` 后可运行 `tests/proxy_fakeip_inbounds.py`，测试 VLESS/TLS 与 SS-2022 入站。FakeIP 仍是测试功能，不代表其监听、持久化、故障或生产接入已全部迁移。

同一成员的 `lifetime,io-uring` 和 `owner,io-uring` 分别构建 `proxy-fakeip-lifetime` 与 `proxy-fakeip-owner`。前者在 epoll/io_uring 下检查异常排空和上下文析构时引脚寿命，后者检查挂起会话及 TCP/UDP DNS 查询中的引脚先于所有者释放。两种测试图单独构建；FakeIP 的测试回调和额外实现单元不进入普通生产图。
