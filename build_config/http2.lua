target("nexus-http-response-test")
    set_kind("binary")
    set_default(false)
    add_files("$(projectdir)/tests/http_response.cpp")
    add_deps("nexus-http-connect")

if has_config("http2") then
    target("nexus-thirdparty-nghttp2")
        set_kind("static")
        set_policy("build.c++.modules.std", false)
        add_files("$(projectdir)/3rdparty/modules/nghttp2.cppm", {public = true})
        add_packages("nexus-nghttp2", {public = true})

    target("nexus-http2-headers")
        set_kind("static")
        add_files("$(projectdir)/src/http2/headers.cppm", {public = true})

    target("nexus-http2-server")
        set_kind("static")
        add_files("$(projectdir)/src/http2/server.cppm", {public = true})
        add_deps("nexus-http2-headers", "nexus-thirdparty-nghttp2", {public = true})

    target("nexus-http2-server-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/http2_server.cpp")
        add_deps("nexus-http2-server", "nexus-thirdparty-nghttp2")

    target("nexus-http2-memory-budget-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/http2_memory_budget.cpp")
        add_deps("nexus-http2-server", "nexus-thirdparty-nghttp2")

    if is_plat("linux") and has_config("crypto") then
        target("nexus-http2-tls-server")
            set_kind("static")
            add_files("$(projectdir)/src/http2/tls_server.cppm", {public = true})
            add_deps("nexus-http2-server", "nexus-tls-corosio-application", "nexus-thirdparty-capy", "nexus-thirdparty-corosio")

        target("nexus-http2-tls-server-test")
            set_kind("binary")
            set_default(false)
            add_files("$(projectdir)/tests/http2_tls_server.cpp")
            add_deps("nexus-http2-tls-server", "nexus-tls-corosio-server-handshake")
            add_packages("nexus-corosio", "nexus-capy")
    end

    target("nexus-nghttp2-memory-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/nghttp2_memory.cpp")
        add_deps("nexus-thirdparty-nghttp2", "nexus-http2-headers")
end
