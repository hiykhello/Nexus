target("nexus-vless")
    set_kind("static")
    add_files("../src/vless/vless.cppm", {public = true})
    add_files("../src/vless/vless.cpp")

target("nexus-vless-test")
    set_kind("binary")
    set_default(false)
    add_files("../tests/vless.cpp")
    add_deps("nexus-vless")

if is_plat("linux") then
    target("nexus-vless-corosio-server")
        set_kind("static")
        set_default(false)
        add_files("../src/vless/corosio_server.cppm", {public = true})
        add_deps("nexus-vless", "nexus-thirdparty-capy", "nexus-thirdparty-corosio")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-vless-inbound-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/vless_inbound_fixture.cpp")
        add_deps("nexus-vless")

    target("nexus-vless-corosio-inbound-fixture")
        set_kind("binary")
        set_default(false)
        add_files("../tests/vless_corosio_inbound.cpp")
        add_deps("nexus-vless-corosio-server")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-vless-corosio-state-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/vless_corosio_state.cpp")
        add_deps("nexus-vless-corosio-server")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-vless-corosio-relay-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/vless_corosio_relay.cpp")
        add_deps("nexus-vless-corosio-server")
        add_packages("nexus-corosio", "nexus-capy")
end

if is_plat("linux") and has_config("crypto") then
    target("nexus-vless-corosio-client")
        set_kind("static")
        set_default(false)
        add_files("../src/vless/corosio_client.cppm", {public = true})
        add_deps("nexus-vless", "nexus-tls-corosio-client")
        add_packages("nexus-corosio", "nexus-capy")

    target("nexus-vless-server-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/vless_server.cpp")
        add_deps("nexus-proxy")

    target("nexus-vless-tls-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/vless_tls.cpp")
        add_deps("nexus-vless-corosio-client", "nexus-config", "nexus-rulefile")
        add_packages("nexus-corosio", "nexus-capy")
end
