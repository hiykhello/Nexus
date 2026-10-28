if is_plat("linux") then
    target("nexus-thirdparty-capy")
        set_kind("static")
        set_default(false)
        -- These wrappers include upstream headers and do not import std. Avoid
        -- generating separate std BMIs that conflict in downstream targets.
        set_policy("build.c++.modules.std", false)
        add_files("../3rdparty/modules/capy.cppm", {public = true})
        add_packages("nexus-capy", {public = true})

    target("nexus-thirdparty-corosio")
        set_kind("static")
        set_default(false)
        set_policy("build.c++.modules.std", false)
        add_files("../3rdparty/modules/corosio.cppm", {public = true})
        add_packages("nexus-corosio", "nexus-capy", {public = true})

    target("nexus-thirdparty-network-test")
        set_kind("binary")
        set_default(false)
        add_files("../tests/network_modules.cpp")
        add_deps("nexus-thirdparty-capy", "nexus-thirdparty-corosio")

end
