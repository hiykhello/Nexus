-- Pinned Beman Project reference implementation of C++26 P0843 std::inplace_vector.
-- Archive checksum pins the bytes independently of GitHub's branch state.
package = {
    spec = "1",
    namespace = "nexus",
    name = "beman-inplace-vector",
    description = "Nexus pinned Beman inplace_vector (C++26 P0843)",
    licenses = { "Apache-2.0 WITH LLVM-exception" },
    repo = "https://github.com/bemanproject/inplace_vector",
    type = "package",
    xpm = {
        linux = {
            ["0.1.0"] = {
                url = "https://github.com/bemanproject/inplace_vector/archive/c7fe76da307f0d6fda5023b2d2ebef7e3f7b18d1.tar.gz",
                sha256 = "336fcdc77875fa75dc1e503b4dbbfc64f3483abce70d2e1669bb26f64e9ac2f3",
            },
        },
    },
    mcpp = {
        language = "c++23",
        import_std = false,
        include_dirs = { "*/include" },
        generated_files = {
            ["mcpp_generated/nexus_beman_inplace_vector_anchor.c"] = "int nexus_beman_inplace_vector_headers_anchor(void) { return 0; }\n",
        },
        sources = { "mcpp_generated/nexus_beman_inplace_vector_anchor.c" },
        targets = { ["beman-inplace-vector"] = { kind = "lib" } },
        deps = {},
    },
}
