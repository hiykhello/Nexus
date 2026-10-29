# xmake 构建设计

状态：根 `xmake.lua`、固定的 Glaze、Capy 和 Corosio recipe、规则集模块、Linux 转换工具及受限的实验代理已创建。

## 当前构建与测试

已验证环境：Linux x86_64，xmake `3.1.2+20261016`，libstdc++ `16.2.1`，C++26 Modules。GCC 16.2.1 已验证完整构建和基本 I/O；Capy 和 Corosio 头文件用于私有实现，不导出 socket 类型。当前没有确定最低版本，其他工具链和平台尚未验证。Glaze 固定 MIT 许可的 fork 提交 `fc646588635c42cca142562d7b3d0484cc4493b7`；Capy 和 Corosio 的提交与构建选项见[依赖封装](third-party-xmake.md)。默认从各 recipe 所列 Git 地址获取；`NEXUS_GLAZE_SOURCE`、`NEXUS_CAPY_SOURCE`、`NEXUS_COROSIO_SOURCE` 可指向包含相同提交的 Git 镜像，不改变锁定的提交。

在仓库根目录执行：

```sh
xmake f -y -m debug --toolchain=gcc
xmake build --all
xmake run nexus-rules-test
xmake run nexus-beve-test
xmake run nexus-match-test
xmake run nexus-socks5-test
xmake build nexus
python tests/socks_udp_proxy.py build/linux/x86_64/debug/nexus
python tests/socks_udp_lifecycle.py build/linux/x86_64/debug/nexus
python tests/socks_udp_dns.py build/linux/x86_64/debug/nexus
xmake run nexus-config-test
xmake run nexus-http-connect-test
xmake run nexus-http-forward-test
xmake run nexus-dns-message-test
xmake run nexus-dns-udp-test
xmake build nexus-dns-tcp-test
uv run --no-project python tests/dns_tcp.py build/linux/x86_64/debug/nexus-dns-tcp-test
xmake build nexus-test-slow-resolver
xmake build nexus-resolver-threads-test
uv run --no-project python tests/resolver_threads.py build/linux/x86_64/debug/nexus-resolver-threads-test build/linux/x86_64/debug/libnexus-test-slow-resolver.so
xmake build nexus-proxy-start-fault
xmake build nexus-proxy-worker-failure-test
env LD_PRELOAD=build/linux/x86_64/debug/libnexus-proxy-start-fault.so NEXUS_START_FAULT=accept build/linux/x86_64/debug/nexus-proxy-worker-failure-test 1
env LD_PRELOAD=build/linux/x86_64/debug/libnexus-proxy-start-fault.so NEXUS_START_FAULT=accept build/linux/x86_64/debug/nexus-proxy-worker-failure-test 2
uv run --no-project python tests/proxy_failure_race.py build/linux/x86_64/debug/nexus-proxy-worker-failure-test build/linux/x86_64/debug/libnexus-proxy-start-fault.so
xmake build nexus-proxy-accept-aborted-test
env LD_PRELOAD=build/linux/x86_64/debug/libnexus-proxy-start-fault.so NEXUS_START_FAULT=accept-aborted build/linux/x86_64/debug/nexus-proxy-accept-aborted-test 1
env LD_PRELOAD=build/linux/x86_64/debug/libnexus-proxy-start-fault.so NEXUS_START_FAULT=accept-aborted build/linux/x86_64/debug/nexus-proxy-accept-aborted-test 2
for mode in accept-protocol accept-netdown accept-interrupted accept-burst; do
  for workers in 1 2; do
    env LD_PRELOAD=build/linux/x86_64/debug/libnexus-proxy-start-fault.so NEXUS_START_FAULT="$mode" build/linux/x86_64/debug/nexus-proxy-accept-aborted-test "$workers" || exit $?
  done
done
xmake build nexus-proxy-retry-stop-test
env LD_PRELOAD=build/linux/x86_64/debug/libnexus-proxy-start-fault.so NEXUS_START_FAULT=accept-burst build/linux/x86_64/debug/nexus-proxy-retry-stop-test
xmake build nexus-proxy-start-fault-test
uv run --no-project python tests/proxy_start_fault.py build/linux/x86_64/debug/nexus-proxy-start-fault-test build/linux/x86_64/debug/libnexus-proxy-start-fault.so
xmake build nexus-proxy-init-failure-test
uv run --no-project python tests/proxy_init_failure.py build/linux/x86_64/debug/nexus-proxy-init-failure-test build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-proxy-start-fault.so
xmake build nexus-proxy-launch-throw-test
./build/linux/x86_64/debug/nexus-proxy-launch-throw-test
xmake build nexus-proxy-session-throw-test
./build/linux/x86_64/debug/nexus-proxy-session-throw-test
xmake build nexus-allocation-probe
(ulimit -c 0; ./build/linux/x86_64/debug/nexus-allocation-probe)
xmake build nexus-proxy-single-worker-test
./build/linux/x86_64/debug/nexus-proxy-single-worker-test
xmake build nexus-session-quota-test
./build/linux/x86_64/debug/nexus-session-quota-test
xmake build nexus-reuseport-test
uv run --no-project python tests/reuseport.py build/linux/x86_64/debug/nexus-reuseport-test epoll
uv run --no-project python tests/reuseport.py build/linux/x86_64/debug/nexus-reuseport-test uring
xmake build nexus-io-threads-test
./build/linux/x86_64/debug/nexus-io-threads-test
xmake build nexus-dns-cached-resolve-test
uv run --no-project python tests/dns_cached_resolve.py build/linux/x86_64/debug/nexus-dns-cached-resolve-test
xmake build nexus-dns-dual-resolve-test
uv run --no-project python tests/dns_dual_resolve.py build/linux/x86_64/debug/nexus-dns-dual-resolve-test
xmake build nexus-proxy-dns-lifetime-test && build/linux/x86_64/debug/nexus-proxy-dns-lifetime-test
xmake build nexus-proxy-root-fault-test && build/linux/x86_64/debug/nexus-proxy-root-fault-test
xmake build nexus-proxy-fakeip-lifetime-test && build/linux/x86_64/debug/nexus-proxy-fakeip-lifetime-test
python tests/proxy_fakeip_dns_throw.py build/linux/x86_64/debug/nexus-proxy-fakeip-fixture
xmake build nexus-proxy-fakeip-owner-test
build/linux/x86_64/debug/nexus-proxy-fakeip-owner-test
xmake build nexus-dns-system-guard
uv run --no-project python tests/proxy_dns.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/proxy_dns_routing.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so 1
uv run --no-project python tests/proxy_dns_routing.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so 2
uv run --no-project python tests/proxy_dns_bootstrap.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/proxy_dns_edns.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/proxy_multi_inbound.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/proxy_route_order.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/proxy_route_candidates.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/proxy_pending_connect.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/proxy_candidate_cancel.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/proxy_tunnel_dial_cancel.py build/linux/x86_64/debug/nexus
# With --ss2022=y, exercise the SS-2022 outbound as well:
uv run --no-project python tests/proxy_tunnel_dial_cancel.py build/linux/x86_64/debug/nexus ss
# 下列 TLS 测试目标需启用 --crypto=y
xmake build nexus-vless-tls-write-overlap-test
build/linux/x86_64/debug/nexus-vless-tls-write-overlap-test
xmake build nexus-vless-tls-corosio-inbound-fixture
uv run --no-project python tests/vless_tls_corosio_inbound.py build/linux/x86_64/debug/nexus-vless-tls-corosio-inbound-fixture
uv run --no-project python tests/vless_tls_inbound_failures.py build/linux/x86_64/debug/nexus-vless-tls-corosio-inbound-fixture
uv run --no-project python tests/vless_proxy_inbound.py build/linux/x86_64/debug/nexus 1
uv run --no-project python tests/vless_inbound_hrr.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_inbound_hrr.py build/linux/x86_64/debug/nexus hybrid
uv run --no-project python tests/vless_inbound_hrr.py build/linux/x86_64/debug/nexus hybrid-retry
uv run --no-project python tests/vless_proxy_inbound.py build/linux/x86_64/debug/nexus 2 chain pem
uv run --no-project python tests/vless_proxy_inbound.py build/linux/x86_64/debug/nexus 2 chain pem longchain
uv run --no-project python tests/vless_proxy_inbound.py build/linux/x86_64/debug/nexus 2 chain pem hybrid
uv run --no-project python tests/vless_hybrid_outbound.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_hybrid_openssl.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_hybrid_openssl.py build/linux/x86_64/debug/nexus x25519-mlkem768-only
uv run --no-project python tests/vless_hybrid_outbound.py build/linux/x86_64/debug/nexus strict
uv run --no-project python tests/vless_hybrid_outbound.py build/linux/x86_64/debug/nexus forged-retry
uv run --no-project python tests/vless_hybrid_outbound.py build/linux/x86_64/debug/nexus forged-final
uv run --no-project python tests/vless_hybrid_outbound.py build/linux/x86_64/debug/nexus bootstrap build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/vless_hybrid_outbound.py build/linux/x86_64/debug/nexus bootstrap-chain build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/vless_candidate_retry.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_candidate_retry.py build/linux/x86_64/debug/nexus blocked
uv run --no-project python tests/vless_candidate_retry.py build/linux/x86_64/debug/nexus-vless-relay-throw-fixture partial
uv run --no-project python tests/vless_candidate_retry.py build/linux/x86_64/debug/nexus stop
uv run --no-project python tests/vless_bootstrap_failure.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/vless_bootstrap_deadline.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/vless_bootstrap_concurrent.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
uv run --no-project python tests/vless_proxy_inbound.py build/linux/x86_64/debug/nexus 2 chain largecert
# 此场景需要 /etc/ssl/certs/ca-certificates.crt 包含超过 64 个证书
uv run --no-project python tests/vless_proxy_inbound.py build/linux/x86_64/debug/nexus 2 chain pem systembundle
uv run --no-project python tests/vless_certificate_chain_limits.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_proxy_inbound_failures.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_proxy_inbound_limits.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_proxy_concurrent.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/vless_proxy_slow_dns.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-test-slow-resolver.so
# 需要 --crypto=y --ss2022=y，验证两类出站的阻塞系统解析停止
xmake build nexus-shadowsocks-singbox-fixture
uv run --no-project python tests/tunnel_system_dns_stop.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-test-slow-resolver.so build/linux/x86_64/debug/nexus-shadowsocks-singbox-fixture
xmake build nexus-vless-relay-throw-fixture
uv run --no-project python tests/vless_relay_throw.py build/linux/x86_64/debug/nexus-vless-relay-throw-fixture
xmake build nexus-tls-corosio-server-test
uv run --no-project python tests/tls_corosio_server.py build/linux/x86_64/debug/nexus-tls-corosio-server-test
xmake build nexus-tls-server-handshake-io-test
uv run --no-project python tests/tls_server_handshake_io.py build/linux/x86_64/debug/nexus-tls-server-handshake-io-test
xmake build nexus-tls-server-flight-test
uv run --no-project python tests/tls_server_flight_openssl.py build/linux/x86_64/debug/nexus-tls-server-flight-test
xmake build nexus-tls-server-credential-test
xmake build nexus-vless-server-profile-test
uv run --no-project python tests/tls_server_credential_openssl.py build/linux/x86_64/debug/nexus-tls-server-credential-test build/linux/x86_64/debug/nexus-vless-server-profile-test
xmake build nexus-tls-server-keys-test
./build/linux/x86_64/debug/nexus-tls-server-keys-test
uv run --no-project python tests/tls_server_keys_openssl.py build/linux/x86_64/debug/nexus-tls-server-keys-test TLS_AES_128_GCM_SHA256
xmake build nexus-tls-server-negotiation-test
./build/linux/x86_64/debug/nexus-tls-server-negotiation-test
uv run --no-project python tests/tls_client_hello_openssl.py build/linux/x86_64/debug/nexus-tls-server-negotiation-test
xmake build nexus-tls-client-hello-stream-test
./build/linux/x86_64/debug/nexus-tls-client-hello-stream-test
uv run --no-project python tests/tls_client_hello_openssl.py build/linux/x86_64/debug/nexus-tls-client-hello-stream-test
xmake build nexus-vless-inbound-fixture
uv run --no-project python tests/vless_inbound_singbox.py build/linux/x86_64/debug/nexus-vless-inbound-fixture
xmake build nexus-vless-corosio-state-test nexus-vless-corosio-relay-test nexus-vless-corosio-inbound-fixture
./build/linux/x86_64/debug/nexus-vless-corosio-state-test
./build/linux/x86_64/debug/nexus-vless-corosio-relay-test
uv run --no-project python tests/vless_corosio_inbound.py build/linux/x86_64/debug/nexus-vless-corosio-inbound-fixture
xmake build nexus-proxy-start-fault
uv run --no-project python tests/proxy_multi_failure.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-proxy-start-fault.so
uv run --no-project python tests/proxy_dns_edns_dnsmasq.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-dns-system-guard.so
xmake build nexus-dns-resolve-test
uv run --no-project python tests/dns_resolve.py build/linux/x86_64/debug/nexus-dns-resolve-test
xmake build nexus-dns-dnsmasq-test
uv run --no-project python tests/dns_dnsmasq.py build/linux/x86_64/debug/nexus-dns-dnsmasq-test
uv run --no-project python tests/dns_bind.py build/linux/x86_64/debug/nexus-dns-dnsmasq-test
xmake run nexus-cpo-module-test
xmake run nexus-packet-test
xmake run nexus-tcp-packet-test
xmake run nexus-tcp-receive-test
xmake run nexus-tcp-send-test
xmake run nexus-tcp-memory-test
xmake run nexus-tcp-handshake-test
xmake run nexus-tcp-connection-test
xmake run nexus-tcp-persist-memory-test
xmake run nexus-tcp-table-test
xmake run nexus-tcp-dispatch-test
xmake run nexus-tcp-engine-test
xmake run nexus-tcp-service-test
xmake run nexus-tcp-window-test
xmake run nexus-tcp-route-test
xmake run nexus-tcp-direct-test
xmake run nexus-tcp-direct-packets-test
xmake run nexus-packet6-test
xmake run nexus-udp-test
xmake run nexus-udp-route-test
xmake run nexus-udp-direct-test
xmake run nexus-udp-direct6-test
xmake run nexus-udp-direct-fault-test
xmake run nexus-udp-engine-test
xmake run nexus-udp-engine-fault-test
xmake run nexus-udp-loopback-test
xmake run nexus-udp-async-test
xmake run nexus-io-test
xmake run nexus-proxy-test
xmake run nexus-proxy-limits-test
tests/cli.sh build/linux/x86_64/debug/nexus
tests/rule_convert.sh build/linux/x86_64/debug/nexus
xmake run nexus-http-response-test
uv run --no-project python tests/http_forward.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/http_upload.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/http_expect.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/proxy_config.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/mixed.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/socks_auth.py build/linux/x86_64/debug/nexus
uv run --no-project python tests/mapped_policy.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-test-slow-resolver.so
uv run --no-project python tests/address_fallback.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-test-slow-resolver.so
uv run --no-project python tests/proxy_candidate_limit.py build/linux/x86_64/debug/nexus build/linux/x86_64/debug/libnexus-test-slow-resolver.so
# 加密构建加 --crypto，额外验证直连与失败的 VLESS 候选交错
scripts/check-source-lines.sh
```

HTTP/2 核心可选实验（固定 nghttp2 1.70.0；测试逐字节输入、头块限额和流复位隔离；尚未接生产网络会话。使用单独的配置和构建目录，实验结束后恢复原配置）：

```sh
xmake f -y -m debug --toolchain=gcc --http2=y --io_uring=n --builddir=/tmp/nexus-http2-build
xmake build nexus-nghttp2-memory-test
xmake run nexus-nghttp2-memory-test
xmake build nexus-http2-server-test
xmake run nexus-http2-server-test
xmake build nexus-http2-memory-budget-test
xmake run nexus-http2-memory-budget-test
xmake build nexus-http2-allocator-boundary-test
xmake run nexus-http2-allocator-boundary-test
# TLS 组合测试另需 --crypto=y、支持 HTTP/2 的 curl，使用对应配置的 builddir
xmake build nexus-http2-tls-server-test
python3 tests/http2_tls_server.py /tmp/nexus-http2-build/linux/x86_64/debug/nexus-http2-tls-server-test
```

Linux 上还可用受控的解析器替身验证慢 DNS 的取消和停止：

```sh
env LD_PRELOAD=build/linux/x86_64/debug/libnexus-test-slow-resolver.so NEXUS_TEST_SLOW_RESOLVER=1 build/linux/x86_64/debug/nexus-proxy-test 2
```

该替身仅供测试，不用于服务器运行；它也为 `nexus-mapped.test` 提供 IPv4 映射 IPv6 地址，供阻断策略测试。它会阻塞解析至握手超时后，检查客户端断开、其他会话继续以及停止等待解析返回。`nexus-proxy-limits-test` 还会等待握手超时，检查 64 个会话上限和回收。

示例中的测试脚本路径针对已验证的 Linux x86_64 debug 输出。xmake 默认使用其全局目录；需要隔离缓存时，可为上述命令设置独立的 `XMAKE_GLOBALDIR` 和 `XMAKE_CONFIGDIR`。已有 `nexus-thirdparty-glaze`、`nexus-rules`、`nexus-socks5`、`nexus-config`，以及 Linux 的 `nexus-rulefile`、`nexus-proxy` 和统一的 `nexus` target；测试目标不属于默认构建，但包含在 `--all` 中。I/O、UDP 回环和代理测试需要允许本地 socket 与 loopback；限制这些调用的沙箱中会失败。

`nexus.module_tracking` 为自身及传递依赖的 `.cppm`/`.ixx` 文件加入内容指纹，修复已复现的模块单独构建后消费者未重编译；接口文本变化会保守触发相关 target 重编译。隔离回归可运行 `uv run --no-project python tests/module_incremental.py`，其他依赖和限制见[问题记录](../development/upstream-issues.md)。

本机曾在模块接口变更后遇到增量构建下游对象未更新。临时副本构建曾导致主工程读取副本 BMI；一次无异常副本实验即使隔离了项目构建目录、`XMAKE_GLOBALDIR` 和 `XMAKE_CONFIGDIR` 仍发生同类问题。两套构建共享 `/tmp/.xmake1000` 下的模块映射文件；为每套构建设置不同且预先创建的 `TMPDIR` 后，观察到映射文件分别写入各自目录，普通与 `-fno-exceptions` SOCKS5 目标交替构建和测试通过。该实验支持临时目录共享是一个污染途径，不能证明此前所有故障同源或覆盖所有缓存。隔离实验应同时隔离项目、build、`XMAKE_GLOBALDIR`、`XMAKE_CONFIGDIR` 和 `TMPDIR`；发生污染后重建受影响模块及消费者。日常使用增量构建；发布验证可另做干净构建。

CLI 命令枚举使用 GCC 16 原生反射生成名称查找与帮助列表；`nexus` target 显式启用 `-freflection`，用于编译和模块扫描。当前构建只验证 GCC 16。

Linux 默认启用系统 liburing 并使用 io_uring（需要 pkg-config 可找到版本不低于 2.5，且运行环境允许 io_uring）。I/O 测试依次覆盖 epoll 和 io_uring：

```sh
xmake f -y -m debug --toolchain=gcc --io_uring=y
xmake build -r nexus-io-test
xmake run nexus-io-test

# Corosio Module 地址/组合连接边界（覆盖 epoll 与 io_uring）
xmake build nexus-corosio-endpoint-test nexus-corosio-connect-test nexus-capy-quitter-test nexus-capy-when-all-startup-test
xmake run nexus-corosio-endpoint-test
xmake run nexus-corosio-connect-test
xmake run nexus-capy-quitter-test
xmake run nexus-capy-when-all-startup-test
```

可用 `xmake f -y -m debug --toolchain=gcc --io_uring=n` 显式选择 epoll；切换配置后应重建相关 target。本机以系统 liburing 2.15 验证；测试不是对所有内核或并发场景的保证。源码依赖仅分别禁用系统包查找，liburing 作为系统依赖解析，不下载替代副本。

## 构建目标

xmake 作为 Nexus 的统一构建入口，管理项目自有 C++ Modules、第三方依赖接入和后续测试目标。client/server 的可执行文件布局尚未确定，当前不预设必须拆成两个程序。

项目若使用 Python 辅助脚本，通过 `uv run` 调用并按项目环境管理其 Python 依赖；当前没有正式 Python 工程或 Python 运行代码。独立文档检查脚本可在临时目录离线运行，不应隐式修改用户全局环境。

构建描述应体现模块依赖和组件边界，不依靠手工排序编译模块。依赖自身的构建流程如需适配，应封装在 xmake 的依赖接入层。

第三方依赖用项目内 xmake package recipe 封装，通过 `add_repositories("nexus-repo 3rdparty")` 注册，分别管理来源、提交、编译方式和传递依赖。Glaze 提供命名模块；Capy 和 Corosio 在私有实现中使用，不直接导出其网络类型。其余依赖仍在规划。目录、Lua 示例和各库边界见[第三方依赖封装](third-party-xmake.md)，模块 target 和验收见[第三方 Modules 封装](third-party-modules.md)。ngcpp/proxy 按用户要求从 Git 源码获取，并锁定已验证完整提交；依赖更新与普通构建分开，不在每次构建时解析浮动 HEAD。

TLS 所有者取消专项启用 `--crypto=y`，构建 `nexus-tls-corosio-connection-test` 后运行该二进制；启用 io_uring 时测试同时覆盖 epoll 和 io_uring。测试使用本地 socket，可能需要在受限沙箱外运行。

自研 TUN、TCP/IP、TLS 与 profile 应可单独构建验证，内存包设备与内存传输用于状态机实验。构建时记录被启用的能力，配置引用未编译能力时应明确报错。

协议家族、方向、承载和平台后端的依赖显式列入 target/模块图，按[协议设计](../architecture/protocols.md)裁剪；装配清单与能力诊断保持一致。验证仅编译某个入站或出站时不会通过公共模块又带入全部实现；平台选择在装配和后端边界完成，不在所有协议中散布 OS 条件。

HTTP/1.1 核心自研，HTTPS 复用 TLS target；HTTP/2 若启用，仅接 libnghttp2 核心，核查没有带入工具/示例的 TLS 或事件循环依赖。规则集转换与顺序匹配共用模型和 KDL/BEVE 适配，离线转换目标不链接平台接管组件。HTTP 和未来运行时 target 与开关仍未创建。

Hysteria 2 的 ngtcp2/nghttp3 核心及其项目第三方模块只是[候选验证](../architecture/protocols/hysteria2.md)，尚未纳入正式 package/target；若评估，须禁用现成 TLS crypto helper，核查最终链接及自研 TLS 回调。SS-2022 实验使用单独固定的官方 BLAKE3 C 实现；libcrypto 本身不提供该接口。

按[决策 0007](../decisions/0007-boringssl-libcrypto-and-ktls.md)，允许固定提交的 BoringSSL libcrypto 静态库作为密码底座，不引入 libssl、独立 OpenSSL 或其他第三方 TLS 协议实现，包括默认启用的可选功能及静态内嵌组件。需要核对 package recipe、实际编译源文件、链接输入与最终产物，相关检查目前尚未执行。

## 工具链验证记录要求

| 项目 | 需要记录的内容 |
| --- | --- |
| xmake | 具体版本与模块相关配置 |
| 编译器 | 实现、版本及模块扫描工具 |
| 标准库 | 实现及版本 |
| C++ 标准 | 经全部依赖及模块实验验证的标准档位 |
| 平台 | 操作系统、架构与系统依赖 |
| 依赖 | 固定提交、编译参数与构建方式 |

不提前声明最低工具链版本或跨平台兼容范围；支持列表应来自实测。

按[C++ 编码规范](../development/cpp-guidelines.md)直接采用标准库 `std::expected`，项目自有代码至少需要 C++23，并验证对应标准库实现。尽量无异常是代码设计要求，当前不等同于对所有 target 设置 `-fno-exceptions`；需先核查依赖、协程及分配失败路径，具体编译参数尚未确定。

后续语言方向已追加为优先 C++26，使用本机 GCC 已提供的能力。当前 GCC 16.2.1 的显式对象参数、concept、后置返回类型、expected/optional、三种现代函数包装、反射与契约断言均通过最小编译探测，见[能力记录](../development/gcc-capabilities.md)。反射实验使用 `-freflection`；正式 xmake 需验证该选项在模块扫描和编译阶段的一致性，并明确 `contract_assert` 的运行检查策略。函数级 `pre`/`post` 契约不采用。

## 首轮验证顺序

1. 用 xmake 构建两个互相导入的项目模块及入口。
2. 按[第三方依赖封装](third-party-xmake.md)及[第三方 Modules 封装](third-party-modules.md)逐一验证指定配置库、ngcpp/proxy、Corosio、Capy 和 BoringSSL libcrypto 的包与模块；HTTP/2 启用时再验证 nghttp2。
3. 验证模块之间传递配置类型、facade 和异步结果所需的最小边界。
4. 检查干净构建、增量构建和模块接口修改后的重建。
5. 记录成功组合与失败原因，持续更新 `xmake.lua` 和构建命令文档。

当前规则集和 I/O 测试目标已在所列 Linux GCC 工具链验证；其他依赖目标和跨平台构建仍需逐一验证。

参考：[xmake 官方文档](https://xmake.io/)。具体模块配置语法以采用版本为准。

SS-2022 密钥派生实验使用 `--ss2022=y --crypto=y`，运行 `nexus-blake3-test` 和 `nexus-shadowsocks-key-test`。BLAKE3 1.8.4 固定完整提交、静态构建并使用 portable 实现；`NEXUS_BLAKE3_SOURCE` 可指定等价的本地 Git 源。默认关闭此选项；它尚未接入代理协议或正式可执行文件。

### Linux TUN 组合驱动验证

构建 `nexus-transport-tun-linux-test`、`nexus-transport-tun-linux-e2e-test` 后，分别运行：

```sh
unshare -Urn build/linux/x86_64/debug/nexus-transport-tun-linux-test
python3 tests/transport_tun_linux_e2e.py build/linux/x86_64/debug/nexus-transport-tun-linux-e2e-test
python3 tests/transport_tun_linux_stop.py build/linux/x86_64/debug/nexus-transport-tun-linux-e2e-test
xmake build nexus-transport-tun-random-test
unshare -Urn build/linux/x86_64/debug/nexus-transport-tun-random-test
xmake build nexus-direct-socket-mark-failure-test
build/linux/x86_64/debug/nexus-direct-socket-mark-failure-test
```

测试需要 Linux 用户与网络命名空间、`/dev/net/tun` 和 `ip`。端到端测试在临时命名空间配置策略路由，验证标记出口且拒绝未标记目标。端到端夹具在两个临时网络命名空间中配置 TUN 和回环出口，验证 IPv4 TCP、IPv4/IPv6 UDP 往返及 IPv6 选项头，并在驱动仍存活时停止三个 TCP 和两个 UDP 流、回收出口 socket 与 TUN；它不修改宿主路由，也不验证正式系统接管、出口防环回或生产调度。
