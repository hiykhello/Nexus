target("nexus-dns-message")
    set_kind("static")
    add_files("$(projectdir)/src/dns/message.cppm", {public = true})
    add_files("$(projectdir)/src/dns/message.cpp")

target("nexus-dns-message-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_message.cpp")
    add_deps("nexus-dns-message")

if is_plat("linux") then
    target("nexus-proxy-fakeip-experiment")
        set_kind("static")
        set_default(false)
        add_defines("NEXUS_TEST_FAKEIP", {public = true})
        add_files("$(projectdir)/src/proxy/proxy.cppm", {public = true})
        add_files("$(projectdir)/src/proxy/proxy.cpp", "$(projectdir)/src/proxy/session.cpp",
                  "$(projectdir)/src/proxy/dial.cpp", "$(projectdir)/src/proxy/http_forward.cpp")
        add_packages("nexus-corosio", "nexus-capy", "nexus-ngcpp-proxy", {public = true})
        add_deps("nexus-session-quota", "nexus-socks5", "nexus-rules", "nexus-http-connect", "nexus-thirdparty-proxy", "nexus-dns-cache", "nexus-dns-fakeip-request")
        if has_config("crypto") and has_config("ss2022") then
            add_defines("NEXUS_ENABLE_SS2022", {public = true})
            add_files("$(projectdir)/src/proxy/shadowsocks.cpp", "$(projectdir)/src/proxy/shadowsocks_inbound.cpp")
            add_deps("nexus-shadowsocks-corosio-relay", "nexus-shadowsocks-corosio-inbound")
        end
        if has_config("crypto") then
            add_defines("NEXUS_ENABLE_VLESS", {public = true})
            add_files("$(projectdir)/src/proxy/vless.cpp", "$(projectdir)/src/proxy/vless_inbound.cpp")
            add_deps("nexus-vless-corosio-client", "nexus-vless-tls-server", "nexus-vless-server-profile", "nexus-tls-corosio-server-handshake", "nexus-config", "nexus-rulefile")
        end

    target("nexus-proxy-fakeip-abandon-experiment")
        set_kind("static")
        set_default(false)
        add_defines("NEXUS_TEST_FAKEIP", "NEXUS_TEST_FAKEIP_ABANDON", {public = true})
        add_files("$(projectdir)/src/proxy/proxy.cppm", {public = true})
        add_files("$(projectdir)/src/proxy/proxy.cpp", "$(projectdir)/src/proxy/session.cpp",
                  "$(projectdir)/src/proxy/dial.cpp", "$(projectdir)/src/proxy/http_forward.cpp")
        add_packages("nexus-corosio", "nexus-capy", "nexus-ngcpp-proxy", {public = true})
        add_deps("nexus-session-quota", "nexus-socks5", "nexus-rules", "nexus-http-connect", "nexus-thirdparty-proxy", "nexus-dns-cache", "nexus-dns-fakeip-request")
        if has_config("crypto") and has_config("ss2022") then
            add_defines("NEXUS_ENABLE_SS2022", {public = true})
            add_files("$(projectdir)/src/proxy/shadowsocks.cpp", "$(projectdir)/src/proxy/shadowsocks_inbound.cpp")
            add_deps("nexus-shadowsocks-corosio-relay", "nexus-shadowsocks-corosio-inbound")
        end
        if has_config("crypto") then
            add_defines("NEXUS_ENABLE_VLESS", {public = true})
            add_files("$(projectdir)/src/proxy/vless.cpp", "$(projectdir)/src/proxy/vless_inbound.cpp")
            add_deps("nexus-vless-corosio-client", "nexus-vless-tls-server", "nexus-vless-server-profile", "nexus-tls-corosio-server-handshake", "nexus-config", "nexus-rulefile")
        end

    target("nexus-proxy-fakeip-owner-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/proxy_fakeip_owner.cpp")
        add_deps("nexus-proxy-fakeip-abandon-experiment")

    target("nexus-proxy-fakeip-fixture")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/proxy_fakeip_fixture.cpp")
        add_deps("nexus-proxy-fakeip-experiment", "nexus-dns-message")

    target("nexus-proxy-fakeip-lifetime-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/proxy_fakeip_lifetime.cpp", "$(projectdir)/tests/proxy_fakeip_lifetime_impl.cpp")
        add_deps("nexus-proxy-fakeip-experiment", "nexus-dns-message", "nexus-thirdparty-corosio")

    target("nexus-dns-udp-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_udp.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-message")
end

if is_plat("linux") then
    target("nexus-dns-tcp-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_tcp.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-message")
end

if is_plat("linux") then
    target("nexus-dns-resolve-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_resolve.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-message")
end

if is_plat("linux") then
    target("nexus-dns-dnsmasq-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_dnsmasq.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-message")
end

target("nexus-dns-cache")
    set_kind("static")
    add_files("$(projectdir)/src/dns/cache.cppm", {public = true})
    add_files("$(projectdir)/src/dns/cache.cpp")
    add_deps("nexus-dns-message")

target("nexus-dns-cache-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_cache.cpp")
    add_deps("nexus-dns-cache")

target("nexus-dns-fakeip")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip.cppm", {public = true})
    add_files("$(projectdir)/src/dns/fakeip.cpp")

target("nexus-dns-fakeip-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip.cpp")
    add_deps("nexus-dns-fakeip")

target("nexus-dns-fakeip-response")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip_response.cppm", {public = true})
    add_files("$(projectdir)/src/dns/fakeip_response.cpp")
    add_deps("nexus-dns-fakeip")

target("nexus-dns-fakeip-response-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip_response.cpp")
    add_deps("nexus-dns-fakeip-response", "nexus-dns-message")

target("nexus-dns-fakeip-target")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip_target.cppm", {public = true})
    add_files("$(projectdir)/src/dns/fakeip_target.cpp")
    add_deps("nexus-dns-fakeip")

target("nexus-dns-fakeip-target-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip_target.cpp")
    add_deps("nexus-dns-fakeip-target", "nexus-dns-fakeip-response", "nexus-dns-message")

target("nexus-dns-fakeip-registry")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip_registry.cppm", {public = true})
    add_files("$(projectdir)/src/dns/fakeip_registry.cpp")
    add_deps("nexus-dns-fakeip-target", "nexus-dns-fakeip-response")

target("nexus-dns-fakeip-registry-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip_registry.cpp")
    add_deps("nexus-dns-fakeip-registry", "nexus-dns-fakeip-response", "nexus-dns-message")

target("nexus-dns-fakeip-request")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip_request.cppm", {public = true})
    add_files("$(projectdir)/src/dns/fakeip_request.cpp")
    add_deps("nexus-dns-fakeip-shared", "nexus-socks5")

target("nexus-dns-fakeip-request-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip_request.cpp")
    add_deps("nexus-dns-fakeip-request", "nexus-dns-message")

target("nexus-dns-fakeip-shared")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip_shared.cppm", {public = true})
    add_deps("nexus-dns-fakeip-registry")

target("nexus-dns-fakeip-shared-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip_shared.cpp")
    add_deps("nexus-dns-fakeip-shared", "nexus-dns-message")

if is_plat("linux") then
    target("nexus-dns-fakeip-udp-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_fakeip_udp.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-fakeip-shared", "nexus-dns-message")

    target("nexus-dns-fakeip-chain-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_fakeip_chain.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-fakeip-request", "nexus-dns-message")

    target("nexus-dns-cached-resolve-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_cached_resolve.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-cache")

    target("nexus-dns-system-guard")
        set_kind("shared")
        set_default(false)
        add_files("$(projectdir)/tests/proxy_dns_system_guard.c")

    target("nexus-dns-dual-resolve-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_dual_resolve.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-dns-cache")
end

target("nexus-dns-fakeip-recovery")
    set_kind("static")
    set_default(false)
    add_files("$(projectdir)/src/dns/fakeip_recovery.cppm", {public = true})
    add_files("$(projectdir)/src/dns/fakeip_recovery.cpp")
    add_deps("nexus-dns-fakeip-shared")

target("nexus-dns-fakeip-recovery-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/dns_fakeip_recovery.cpp")
    add_deps("nexus-dns-fakeip-recovery", "nexus-dns-message")

if has_config("crypto") then
    target("nexus-dns-fakeip-history")
        set_kind("static")
        set_default(false)
        add_files("$(projectdir)/src/dns/fakeip_history.cppm", {public = true})
        add_files("$(projectdir)/src/dns/fakeip_history.cpp")
        add_deps("nexus-dns-fakeip-recovery", "nexus-crypto")

    target("nexus-dns-fakeip-history-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_fakeip_history.cpp")
        add_deps("nexus-dns-fakeip-history")
end

if is_plat("linux") and has_config("crypto") then
    target("nexus-proxy-fakeip-recovery-fixture")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/proxy_fakeip_recovery_fixture.cpp")
        add_deps("nexus-proxy-fakeip-experiment", "nexus-dns-fakeip-history-store", "nexus-dns-message")

    target("nexus-dns-fakeip-history-fixture")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/experiments/fakeip-history/fixture.cpp")
        add_deps("nexus-dns-fakeip-history", "nexus-dns-message")
end

if has_config("crypto") then
    target("nexus-dns-fakeip-history-store")
        set_kind("static")
        set_default(false)
        add_files("$(projectdir)/src/dns/fakeip_history_store.cppm", {public = true})
        add_files("$(projectdir)/src/dns/fakeip_history_store.cpp")
        add_deps("nexus-dns-fakeip-history")

    target("nexus-dns-fakeip-history-store-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_fakeip_history_store.cpp")
        add_deps("nexus-dns-fakeip-history-store", "nexus-dns-message")
end

if has_config("crypto") then
    target("nexus-dns-fakeip-history-store-fault-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/dns_fakeip_history_store_fault.cpp")
        add_deps("nexus-dns-fakeip-history-store")
end
