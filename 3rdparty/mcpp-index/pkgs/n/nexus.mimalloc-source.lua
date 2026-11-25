-- Unmodified upstream mimalloc source, pinned archive.
-- Compiled as C++ (upstream MI_USE_CXX=ON) with -fno-builtin-malloc so global
-- operator new/new[] overrides throw std::bad_alloc on OOM instead of abort().
package = {
  spec = "1", namespace = "nexus", name = "mimalloc-source",
  description = "Pinned mimalloc static global-override allocator", licenses = { "MIT" },
  repo = "https://github.com/microsoft/mimalloc", type = "package",
  archs = { "x86_64", "arm64", "aarch64" },
  xpm = { linux = { ["3.6.1"] = {
    url = "https://github.com/microsoft/mimalloc/archive/refs/tags/v3.6.1.tar.gz",
    sha256 = "2672e6a99d4579fb4bb32d9de0d63aa424ce600d31fbfaf06eb74d940d2e07a6",
  } } },
  mcpp = { language = "c++26", import_std = false,
    include_dirs = { "*/include", "*/src" }, private_include_dirs = { "*/src" },
    defines = { "MI_MALLOC_OVERRIDE=1", "MI_LIBC_MUSL=1", "_DEFAULT_SOURCE" },
    cxxflags = { "-fno-builtin-malloc" },
    generated_files = {
      ["mcpp_generated/mimalloc_static.cpp"] = "#include \"static.c\"\n",
    },
    sources = { "mcpp_generated/mimalloc_static.cpp" },
    targets = { ["mimalloc-source"] = { kind = "lib" } }, deps = {},
    linux = { ldflags = { "-lpthread", "-lrt" } },
  },
}
