package("nexus-glaze-kdl")
    set_homepage("https://github.com/hiykhello/glaze-kdl2.0-")
    set_description("Pinned Glaze fork with KDL 2.0 and BEVE support")
    set_license("MIT")
    set_kind("library", {headeronly = true})
    -- An explicit local mirror supports offline builds; the commit is unchanged.
    add_urls(os.getenv("NEXUS_GLAZE_SOURCE") or "https://github.com/hiykhello/glaze-kdl2.0-.git")
    add_versions("0.1.0", "fc646588635c42cca142562d7b3d0484cc4493b7")

    on_install(function (package)
        os.cp("include/*", package:installdir("include"))
        os.cp("LICENSE", package:installdir("share/licenses/nexus-glaze-kdl"))
    end)

    on_test(function (package)
        local opts = {configs = {languages = "c++26"}}
        assert(package:has_cxxincludes("glaze/kdl.hpp", opts))
        assert(package:has_cxxincludes("glaze/beve.hpp", opts))
    end)
package_end()
