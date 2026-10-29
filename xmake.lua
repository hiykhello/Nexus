set_project("Nexus")
set_version("0.1.0")
set_languages("c++26")
set_policy("build.c++.modules", true)
set_policy("package.requires_lock", true)
includes("build_config/module_tracking.lua")
add_rules("mode.debug", "mode.release", "nexus.module_tracking")
option("crypto")
    set_default(false)
    set_showmenu(true)
    set_description("Enable experimental pinned BoringSSL libcrypto")
option_end()
includes("build_config/http2_require.lua")
includes("build_config/shadowsocks_require.lua")
option("io_uring")
    set_default(true)
    set_showmenu(true)
    set_description("Build Corosio with system liburing on Linux")
option_end()
add_repositories("nexus-repo 3rdparty")
add_requires("nexus-glaze-kdl 0.1.0", {system = false})
if is_plat("linux") and has_config("crypto") then
    add_requires("nexus-boringssl-crypto 0.1.0", {system = false})
end
if is_plat("linux") then
    add_requires("nexus-ngcpp-proxy 0.1.0", {system = false})
    add_requires("nexus-capy 0.2.4", {system = false})
    add_requires("nexus-corosio 0.3.5", {system = false, configs = {uring = has_config("io_uring")}})
end

includes("build_config/network_modules.lua")
includes("build_config/tls.lua")
includes("build_config/vless.lua")
includes("build_config/shadowsocks.lua")

target("nexus-thirdparty-glaze")
    set_kind("static")
    add_files("3rdparty/modules/glaze.cppm", {public = true})
    add_packages("nexus-glaze-kdl", {public = true})

includes("build_config/http2.lua")

target("nexus-rules")
    set_kind("static")
    add_files("src/rules/rules.cppm", {public = true})
    add_files("src/rules/validate.cpp", "src/rules/kdl.cpp", "src/rules/beve.cpp", "src/rules/beve_profile.cpp", "src/rules/matcher.cpp")
    add_deps("nexus-thirdparty-glaze")
    if is_plat("windows") then
        add_syslinks("ws2_32")
    end

target("nexus-socks5")
    set_kind("static")
    add_files("src/socks5/socks5.cppm", {public = true})
    add_files("src/socks5/parse.cpp")

target("nexus-config")
    set_kind("static")
    add_files("src/config/config.cppm", {public = true})
    add_files("src/config/config.cpp")
    add_deps("nexus-thirdparty-glaze")
    if is_plat("windows") then
        add_syslinks("ws2_32")
    end

target("nexus-rules-test")
    set_kind("binary")
    set_default(false)
    set_rundir("$(projectdir)")
    add_files("tests/rules_kdl.cpp")
    add_deps("nexus-rules", "nexus-thirdparty-glaze")

target("nexus-beve-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/rules_beve.cpp")
    add_deps("nexus-rules")

target("nexus-match-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/rules_match.cpp")
    add_deps("nexus-rules")

target("nexus-socks5-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/socks5.cpp")
    add_deps("nexus-socks5")

target("nexus-config-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/config.cpp")
    add_deps("nexus-config")

if is_plat("linux") then
    target("nexus-session-quota")
        set_kind("static")
        add_files("src/proxy/session_quota.cppm", {public = true})

    target("nexus-thirdparty-proxy")
        set_kind("static")
        add_packages("nexus-ngcpp-proxy", {public = true})
        on_load(function (target)
            local package = target:pkg("nexus-ngcpp-proxy")
            target:add("files", path.join(package:installdir(), "include/proxy/v4/proxy.ixx"), {public = true})
        end)

    target("nexus-proxy")
        set_kind("static")
        add_files("src/proxy/proxy.cppm", {public = true})
        add_files("src/proxy/proxy.cpp", "src/proxy/session.cpp", "src/proxy/dial.cpp", "src/proxy/http_forward.cpp")
        add_packages("nexus-corosio", "nexus-capy", "nexus-ngcpp-proxy", {public = true})
        add_deps("nexus-session-quota", "nexus-socks5", "nexus-rules", "nexus-http-connect", "nexus-thirdparty-proxy", "nexus-thirdparty-corosio", "nexus-dns-cache")
        if has_config("crypto") and has_config("ss2022") then
            add_defines("NEXUS_ENABLE_SS2022", {public = true})
            add_files("src/proxy/shadowsocks.cpp", "src/proxy/shadowsocks_inbound.cpp")
            add_deps("nexus-shadowsocks-corosio-relay", "nexus-shadowsocks-corosio-inbound")
        end
        if has_config("crypto") then
            add_defines("NEXUS_ENABLE_VLESS", {public = true})
            add_files("src/proxy/vless.cpp", "src/proxy/vless_inbound.cpp")
            add_deps("nexus-vless-corosio-client", "nexus-vless-tls-server", "nexus-vless-server-profile", "nexus-tls-corosio-server-handshake", "nexus-config", "nexus-rulefile")
        end

    target("nexus")
        set_kind("binary")
        add_files("src/tools/main.cpp", "src/tools/proxy_server.cpp", "src/tools/rule_convert.cpp")
        add_cxxflags("-freflection", {force = true})
        add_deps("nexus-proxy", "nexus-rulefile", "nexus-config", "nexus-rules")
        if has_config("crypto") and has_config("ss2022") then
            add_deps("nexus-shadowsocks-udp-dispatch", "nexus-dns-cache")
        end

    target("nexus-io-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/io.cpp")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-proxy-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/proxy.cpp")
        add_deps("nexus-proxy", "nexus-rulefile")

    target("nexus-proxy-limits-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/proxy_limits.cpp")
        add_deps("nexus-proxy")

    target("nexus-test-slow-resolver")
        set_kind("shared")
        set_default(false)
        add_files("tests/slow_resolver.c")
        add_syslinks("dl")

    target("nexus-test-clock-fault")
        set_kind("shared")
        set_default(false)
        add_files("tests/clock_fault.c")

    target("nexus-rulefile")
        set_kind("static")
        add_files("src/rulefile/rulefile.cppm", {public = true})
        add_files("src/rulefile/posix.cpp")
        add_deps("nexus-rules")

end

target("nexus-http-connect")
    set_kind("static")
    add_files("src/http/connect.cppm", {public = true})
    add_files("src/http/connect.cpp", "src/http/forward.cpp", "src/http/chunk.cpp", "src/http/response.cpp")
    if is_plat("windows") then
        add_syslinks("ws2_32")
    end

target("nexus-http-connect-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/http_connect.cpp")
    add_deps("nexus-http-connect")

target("nexus-http-forward-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/http_forward.cpp")
    add_deps("nexus-http-connect")

target("nexus-packet")
    set_kind("static")
    add_files("src/packet/packet.cppm", {public = true})
    add_files("src/packet/ipv4.cpp", "src/packet/ipv6.cpp", "src/packet/tcp4.cpp", "src/packet/memory.cpp")

target("nexus-packet-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/packet.cpp")
    add_deps("nexus-packet")

if is_plat("linux") then
    target("nexus-packet-tun-linux")
        set_kind("static")
        add_files("src/packet/tun_linux.cppm", {public = true})
        add_files("src/packet/tun_linux.cpp")

    target("nexus-packet-tun-helper")
        set_kind("binary")
        set_default(false)
        add_files("tests/tun_linux_helper.cpp")
        add_deps("nexus-packet-tun-linux")

    target("nexus-packet-tun-linux-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/packet_tun_linux.cpp")
        add_deps("nexus-packet-tun-linux", "nexus-packet-fd")

    target("nexus-packet-fd")
        set_kind("static")
        add_files("src/packet/fd.cppm", {public = true})
        add_files("src/packet/fd.cpp")
        add_deps("nexus-packet")

    target("nexus-packet-fd-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/packet_fd.cpp")
        add_deps("nexus-packet-fd")
end

target("nexus-packet-switch")
    set_kind("static")
    add_files("src/packet/switch.cppm", {public = true})
    add_files("src/packet/switch.cpp")
    add_deps("nexus-packet")

target("nexus-packet-switch-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/packet_switch.cpp")
    add_deps("nexus-packet-switch")

target("nexus-tcp-packet-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_packet.cpp")
    add_deps("nexus-packet")

target("nexus-tcp-receive")
    set_kind("static")
    add_files("src/tcp/receive.cppm", {public = true})
    add_files("src/tcp/receive.cpp")

target("nexus-tcp-receive-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_receive.cpp")
    add_deps("nexus-tcp-receive")

target("nexus-tcp-send")
    set_kind("static")
    add_files("src/tcp/send.cppm", {public = true})
    add_files("src/tcp/send.cpp")

target("nexus-tcp-send-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_send.cpp")
    add_deps("nexus-tcp-send")

target("nexus-tcp-memory-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_memory.cpp")
    add_deps("nexus-tcp-send", "nexus-tcp-receive", "nexus-packet")

target("nexus-tcp-handshake")
    set_kind("static")
    add_files("src/tcp/handshake.cppm", {public = true})
    add_files("src/tcp/handshake.cpp")
    add_deps("nexus-packet")

target("nexus-tcp-handshake-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_handshake.cpp")
    add_deps("nexus-tcp-handshake", "nexus-tcp-receive")

target("nexus-tcp-connection")
    set_kind("static")
    add_files("src/tcp/connection.cppm", {public = true})
    add_files("src/tcp/connection.cpp")
    add_deps("nexus-tcp-handshake", "nexus-tcp-receive", "nexus-tcp-send", "nexus-packet")

target("nexus-tcp-connection-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_connection.cpp")
    add_deps("nexus-tcp-connection")

target("nexus-tcp-persist-memory-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_persist_memory.cpp")
    add_deps("nexus-tcp-connection", "nexus-tcp-receive")

target("nexus-tcp-table")
    set_kind("static")
    add_files("src/tcp/table.cppm", {public = true})
    add_files("src/tcp/table.cpp")
    add_deps("nexus-tcp-connection")

target("nexus-tcp-table-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_table.cpp")
    add_deps("nexus-tcp-table")

target("nexus-tcp-dispatch")
    set_kind("static")
    add_files("src/tcp/dispatch.cppm", {public = true})
    add_files("src/tcp/dispatch.cpp", "src/tcp/route.cpp")
    add_deps("nexus-tcp-table", "nexus-rules")

target("nexus-tcp-dispatch-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_dispatch.cpp")
    add_deps("nexus-tcp-dispatch")

target("nexus-tcp-engine")
    set_kind("static")
    add_files("src/tcp/engine.cppm", {public = true})
    add_files("src/tcp/engine.cpp", "src/tcp/service.cpp", "src/tcp/read.cpp")
    add_deps("nexus-tcp-dispatch")

target("nexus-tcp-engine-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_engine.cpp")
    add_deps("nexus-tcp-engine")

target("nexus-tcp-service-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_service.cpp")
    add_deps("nexus-tcp-engine")

target("nexus-tcp-window-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_window.cpp")
    add_deps("nexus-tcp-engine")

target("nexus-tcp-reset-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_reset.cpp")
    add_deps("nexus-tcp-engine")

target("nexus-tcp-route-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/tcp_route.cpp")
    add_deps("nexus-tcp-engine")

if is_plat("linux") then
    target("nexus-tcp-direct")
        set_kind("static")
        add_files("src/tcp/direct.cppm", {public = true})
        add_files("src/tcp/direct.cpp")
        add_deps("nexus-tcp-engine")

    target("nexus-tcp-kernel-tun-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/tcp_kernel_tun.cpp")
        add_deps("nexus-tcp-engine", "nexus-packet-fd")

    target("nexus-tcp-stack")
        set_kind("static")
        add_files("src/tcp/stack.cppm", {public = true})
        add_files("src/tcp/stack.cpp")
        add_deps("nexus-tcp-direct")

    target("nexus-tcp-stack-multi-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/tcp_stack_multi.cpp")
        add_deps("nexus-tcp-stack")

    target("nexus-tcp-stack-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/tcp_stack.cpp")
        add_deps("nexus-tcp-stack")

    target("nexus-tcp-direct-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/tcp_direct.cpp")
        add_deps("nexus-tcp-direct")

    target("nexus-tcp-direct-packets-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/tcp_direct_packets.cpp")
        add_deps("nexus-tcp-direct")
end

target("nexus-udp")
    set_kind("static")
    add_files("src/udp/udp.cppm", {public = true})
    add_files("src/udp/udp.cpp", "src/udp/bridge.cpp")
    add_deps("nexus-packet")

target("nexus-udp-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/udp.cpp")
    add_deps("nexus-udp")

if is_plat("linux") then
    target("nexus-udp-loopback-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/udp_loopback.cpp")
        add_deps("nexus-udp-route", "nexus-rules")
end

if is_plat("linux") then
    target("nexus-udp-async-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/udp_async.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-udp")
end

target("nexus-udp-route")
    set_kind("static")
    add_files("src/udp/route.cppm", {public = true})
    add_files("src/udp/route.cpp")
    add_deps("nexus-udp", "nexus-rules")

target("nexus-udp-route-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/udp_route.cpp")
    add_deps("nexus-udp-route", "nexus-rules")

target("nexus-packet6-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/packet6.cpp")
    add_deps("nexus-packet")

target("nexus-cpo-module-test")
    set_kind("binary")
    set_default(false)
    add_files("tests/cpo_module.cppm", "tests/cpo_module.cpp", "tests/cpo_header.cpp")
    add_packages("nexus-capy", "nexus-corosio")

if is_plat("linux") then
    target("nexus-udp-direct")
        set_kind("static")
        add_files("src/udp/direct.cppm", {public = true})
        add_files("src/udp/direct.cpp", "src/udp/direct6.cpp")
        add_deps("nexus-udp-route", "nexus-rules")

    target("nexus-udp-direct-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/udp_direct.cpp")
        add_deps("nexus-udp-direct", "nexus-rules")

    target("nexus-udp-direct6-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/udp_direct6.cpp")
        add_deps("nexus-udp-direct", "nexus-rules")

    target("nexus-udp-engine")
        set_kind("static")
        add_files("src/udp/engine.cppm", {public = true})
        add_files("src/udp/engine.cpp")
        add_deps("nexus-udp-direct", "nexus-rules")
end

if is_plat("linux") then
    target("nexus-transport-kernel-tun-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/transport_kernel_tun.cpp")
        add_deps("nexus-transport-memory", "nexus-packet-fd")

    target("nexus-transport-fd-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/transport_fd.cpp")
        add_deps("nexus-transport-memory", "nexus-packet-fd")

    target("nexus-transport-memory-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/transport_memory.cpp")
        add_deps("nexus-transport-memory")

    target("nexus-transport-memory")
        set_kind("static")
        add_files("src/transport/memory.cppm", {public = true})
        add_files("src/transport/memory.cpp")
        add_deps("nexus-packet-switch", "nexus-tcp-stack", "nexus-udp-engine")
end

if is_plat("linux") then
    target("nexus-udp-engine-test")
        set_kind("binary")
        set_default(false)
        add_files("tests/udp_engine.cpp")
        add_deps("nexus-udp-engine", "nexus-rules")
end
includes("build_config/udp_faults.lua")
includes("build_config/tcp_faults.lua")
includes("build_config/dns.lua")
includes("build_config/concurrency.lua")
