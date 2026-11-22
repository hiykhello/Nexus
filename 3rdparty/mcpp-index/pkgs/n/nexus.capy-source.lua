-- Pinned upstream source; Nexus consumers apply the verified exact patch.
package = {
  spec = "1", namespace = "nexus", name = "capy-source", licenses = { "BSL-1.0" },
  description = "Pinned upstream source for Nexus", repo = "https://github.com/cppalliance/capy", type = "package",
  xpm = { linux = { ["0.2.8"] = { url = "https://github.com/cppalliance/capy/archive/6a9569060f999453e1f7b59cc9ae31c808c0778b.tar.gz", sha256 = "e08c47c3c91c1a6f5f37d3af450695a8e4fd8e573b1b53276e07643171db6f35" } } },
  mcpp = { language = "c++23", import_std = false,
    include_dirs = { "*/include", "*" }, private_include_dirs = { "*" },
    sources = { "*/src/**/*.cpp" }, defines = { "BOOST_CAPY_NO_LIB", "BOOST_CAPY_STATIC_LINK" }, cxxflags = { "-DBOOST_CAPY_SOURCE" }, ldflags = { "-lpthread" },
    targets = { ["capy"] = { kind = "lib" } }, deps = {} },
}
