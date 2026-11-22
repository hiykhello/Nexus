-- The same Glaze fork and commit as the xmake recipe. The archive checksum
-- pins the bytes independently of GitHub's branch state.
package = {
    spec = "1",
    namespace = "nexus",
    name = "glaze-kdl",
    description = "Nexus pinned Glaze KDL and BEVE headers",
    licenses = { "MIT" },
    repo = "https://github.com/hiykhello/glaze-kdl2.0-",
    type = "package",
    xpm = {
        linux = {
            ["0.1.0"] = {
                url = "https://github.com/hiykhello/glaze-kdl2.0-/archive/fc646588635c42cca142562d7b3d0484cc4493b7.tar.gz",
                sha256 = "f238db70dee9ef25d0898a0da062209453225832d0d82f10d1fb11037c81ef3b",
            },
        },
    },
    mcpp = {
        language = "c++23",
        import_std = false,
        include_dirs = { "*/include" },
        generated_files = {
            ["mcpp_generated/nexus_glaze_kdl_anchor.c"] = "int nexus_glaze_kdl_headers_anchor(void) { return 0; }\n",
        },
        sources = { "mcpp_generated/nexus_glaze_kdl_anchor.c" },
        targets = { ["glaze-kdl"] = { kind = "lib" } },
        deps = {},
    },
}
