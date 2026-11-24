-- Pinned Glaze KDL/BEVE fork commit (hiykhello/glaze-kdl). The archive checksum
-- pins the bytes independently of GitHub's branch state.
package = {
    spec = "1",
    namespace = "nexus",
    name = "glaze-kdl",
    description = "Nexus pinned Glaze KDL and BEVE headers",
    licenses = { "MIT" },
    repo = "https://github.com/hiykhello/glaze-kdl",
    type = "package",
    xpm = {
        linux = {
            ["0.1.1"] = {
                url = "https://github.com/hiykhello/glaze-kdl/archive/4e3230a6c1a3e665a6d81ca18e804291f894e876.tar.gz",
                sha256 = "d3f83cf958aed10f7e27dc672cb05d755773ce5572eed90c20a463b46b4a66c4",
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
