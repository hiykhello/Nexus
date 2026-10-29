if is_plat("linux") and has_config("ss2022") then
    target("nexus-thirdparty-blake3")
        set_kind("static")
        set_policy("build.c++.modules.std", false)
        add_files("../3rdparty/modules/blake3.cppm", {public = true})
        add_packages("nexus-blake3", {public = true})

    target("nexus-blake3-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/blake3.cpp")
        add_deps("nexus-thirdparty-blake3")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-key")
        set_kind("static")
        add_files("../src/shadowsocks/key.cppm", {public = true})
        add_files("../src/shadowsocks/key.cpp")
        add_files("../src/shadowsocks/chunk.cppm", {public = true})
        add_files("../src/shadowsocks/chunk.cpp")
        add_files("../src/shadowsocks/header.cppm", {public = true})
        add_files("../src/shadowsocks/header.cpp")
        add_files("../src/shadowsocks/replay.cppm", {public = true})
        add_files("../src/shadowsocks/replay.cpp")
        add_files("../src/shadowsocks/request.cppm", {public = true})
        add_files("../src/shadowsocks/request.cpp")
        add_files("../src/shadowsocks/response.cppm", {public = true})
        add_files("../src/shadowsocks/response.cpp")
        add_files("../src/shadowsocks/frame.cppm", {public = true})
        add_files("../src/shadowsocks/frame.cpp")
        add_files("../src/shadowsocks/udp_cipher.cppm", {public = true})
        add_files("../src/shadowsocks/udp_cipher.cpp")
        add_files("../src/shadowsocks/udp_packet.cppm", {public = true})
        add_files("../src/shadowsocks/udp_packet.cpp")
        add_packages("nexus-boringssl-crypto")
        add_deps("nexus-thirdparty-blake3", "nexus-crypto")

    target("nexus-shadowsocks-key-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_key.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-chunk-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_chunk.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-header-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_header.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-replay-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_replay.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-request-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_request.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-response-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_response.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-frame-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_frame.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-singbox-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_singbox_fixture.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-singbox-client")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_singbox_client.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-probe-close-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_probe_close.cpp")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-corosio-server")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/corosio_server.cppm", {public = true})
        add_deps("nexus-shadowsocks-key", "nexus-crypto", "nexus-thirdparty-capy", "nexus-thirdparty-corosio")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-shadowsocks-corosio-server-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_corosio_server.cpp")
        add_deps("nexus-shadowsocks-corosio-server")
        add_packages("nexus-corosio", "nexus-capy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-corosio-client")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/corosio_client.cppm", {public = true})
        add_deps("nexus-shadowsocks-key", "nexus-crypto", "nexus-thirdparty-capy", "nexus-thirdparty-corosio")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-shadowsocks-corosio-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_corosio.cpp")
        add_deps("nexus-shadowsocks-corosio-client")
        add_packages("nexus-corosio", "nexus-capy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-corosio-inbound")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/corosio_inbound.cppm", {public = true})
        add_deps("nexus-shadowsocks-corosio-server", "nexus-shadowsocks-corosio-client")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-shadowsocks-corosio-inbound-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_corosio_inbound.cpp")
        add_deps("nexus-shadowsocks-corosio-inbound")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-shadowsocks-corosio-inbound-singbox")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_corosio_inbound_singbox.cpp")
        add_deps("nexus-shadowsocks-corosio-inbound")
        add_packages("nexus-corosio", "nexus-capy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-corosio-relay")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/corosio_relay.cppm", {public = true})
        add_deps("nexus-shadowsocks-corosio-client")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-shadowsocks-corosio-relay-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_corosio_relay.cpp")
        add_deps("nexus-shadowsocks-corosio-relay")
        add_packages("nexus-corosio", "nexus-capy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-corosio-singbox")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_corosio_singbox.cpp")
        add_deps("nexus-shadowsocks-corosio-relay")
        add_packages("nexus-corosio", "nexus-capy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-replay-wire")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_replay_wire.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-inbound-proxy-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_inbound_proxy_fixture.cpp")
        add_deps("nexus-proxy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-proxy-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_proxy_fixture.cpp")
        add_deps("nexus-proxy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-replay")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_replay.cppm", {public = true})

    target("nexus-shadowsocks-udp-replay-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_replay.cpp")
        add_deps("nexus-shadowsocks-udp-replay")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-cipher-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_cipher.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-packet-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_packet.cpp")
        add_deps("nexus-shadowsocks-key", "nexus-shadowsocks-udp-replay")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-singbox-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_singbox.cpp")
        add_deps("nexus-shadowsocks-udp-client")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-client")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_client.cppm", {public = true})
        add_files("../src/shadowsocks/udp_client.cpp")
        add_deps("nexus-shadowsocks-key", "nexus-shadowsocks-udp-replay")
    target("nexus-shadowsocks-udp-client-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_client.cpp")
        add_deps("nexus-shadowsocks-udp-client")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-sessions")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_sessions.cppm", {public = true})
        add_files("../src/shadowsocks/udp_sessions.cpp")
        add_deps("nexus-shadowsocks-key", "nexus-shadowsocks-udp-replay", "nexus-shadowsocks-udp-id-reservation")
    target("nexus-shadowsocks-udp-sessions-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_sessions.cpp")
        add_deps("nexus-shadowsocks-udp-sessions")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-inbound-singbox-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_inbound_singbox.cpp")
        add_deps("nexus-shadowsocks-udp-sessions")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-relay")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_relay.cppm", {public = true})
        add_files("../src/shadowsocks/udp_relay.cpp")
        add_deps("nexus-shadowsocks-udp-sessions")
    target("nexus-shadowsocks-udp-relay-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_relay.cpp")
        add_deps("nexus-shadowsocks-udp-relay")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-server")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_server.cppm", {public = true})
        add_files("../src/shadowsocks/udp_server.cpp")
        add_deps("nexus-shadowsocks-udp-relay")
    target("nexus-shadowsocks-udp-server-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_server.cpp")
        add_deps("nexus-shadowsocks-udp-server")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-server-singbox-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_server_singbox.cpp")
        add_deps("nexus-shadowsocks-udp-dispatch")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-route")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_route.cppm", {public = true})
        add_files("../src/shadowsocks/udp_route.cpp")
        add_deps("nexus-shadowsocks-udp-server", "nexus-rules")
    target("nexus-shadowsocks-udp-route-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_route.cpp")
        add_deps("nexus-shadowsocks-udp-route")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-dispatch")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_dispatch.cppm", {public = true})
        add_files("../src/shadowsocks/udp_dispatch.cpp")
        add_deps("nexus-shadowsocks-udp-route")
    target("nexus-shadowsocks-udp-dispatch-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_dispatch.cpp")
        add_deps("nexus-shadowsocks-udp-dispatch")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-resolve-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_resolve.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-shadowsocks-udp-dispatch", "nexus-dns-cache")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-resolve-owner-test")
        set_kind("binary")
        set_default(false)
        add_defines("NEXUS_TEST_DNS_LIFETIME")
        add_files("../tests/shadowsocks_udp_resolve_owner.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-shadowsocks-udp-dispatch", "nexus-dns-cache")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-listener-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_listener.cpp")
        add_packages("nexus-corosio", "nexus-capy")
        add_deps("nexus-shadowsocks-udp-dispatch", "nexus-dns-cache", "nexus-proxy")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-test-shadowsocks-udp-observe")
        set_kind("shared")
        set_default(false)
        add_files("../tests/shadowsocks_udp_observe.c")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-relay-fault-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_relay_fault.cpp")
        add_ldflags("-Wl,--wrap=recvfrom")
        add_deps("nexus-shadowsocks-udp-relay")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-rebind-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_rebind.cpp")
        add_deps("nexus-shadowsocks-key")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-shadowsocks-udp-id-reservation")
        set_kind("static")
        set_default(false)
        add_files("../src/shadowsocks/udp_id_reservation.cppm", {public = true})
    target("nexus-shadowsocks-udp-id-reservation-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/shadowsocks_udp_id_reservation.cpp")
        add_deps("nexus-shadowsocks-udp-id-reservation")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-sqlite-replay-experiment")
        set_kind("binary")
        set_default(false)
        add_files("../experiments/sqlite-replay/session_fixture.cpp")
        add_deps("nexus-shadowsocks-udp-sessions")
        add_syslinks("sqlite3")
end

if is_plat("linux") and has_config("ss2022") and has_config("crypto") then
    target("nexus-beve-snapshot-experiment")
        set_kind("binary")
        set_default(false)
        add_files("../experiments/beve-state/snapshot_fixture.cpp")
        add_deps("nexus-thirdparty-glaze", "nexus-shadowsocks-udp-sessions")
end
