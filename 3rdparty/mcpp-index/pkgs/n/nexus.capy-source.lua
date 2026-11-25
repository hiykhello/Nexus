-- Pinned upstream source; Nexus consumers apply the verified exact patch.
package = {
  spec = "1", namespace = "nexus", name = "capy-source", licenses = { "BSL-1.0" },
  description = "Pinned upstream source for Nexus", repo = "https://github.com/cppalliance/capy", type = "package",
  xpm = { linux = { ["0.2.9"] = { url = "https://github.com/cppalliance/capy/archive/93e5f15ab964a64f80fa2d10e4860ae02319831f.tar.gz", sha256 = "2f22efe35fb222e01c790c595d4f617c17408af681f94a006b7960fba14fb48a" } } },
  mcpp = { language = "c++23", import_std = false,
    include_dirs = { "*/include", "*" }, private_include_dirs = { "*" },
    sources = { "*/src/**/*.cpp" }, defines = { "BOOST_CAPY_NO_LIB", "BOOST_CAPY_STATIC_LINK" }, cxxflags = { "-DBOOST_CAPY_SOURCE" }, ldflags = { "-lpthread" },
    targets = { ["capy"] = { kind = "lib" } }, deps = {} },
}
