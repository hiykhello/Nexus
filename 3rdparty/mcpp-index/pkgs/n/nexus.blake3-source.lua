-- Official BLAKE3 C implementation at the pinned upstream revision.
-- BLAKE3_SIMD_TYPE=none in upstream CMake selects these three files and macros.
package = {
  spec = "1", namespace = "nexus", name = "blake3-source",
  description = "Pinned portable BLAKE3 C sources", licenses = { "Apache-2.0", "CC0-1.0" },
  repo = "https://github.com/BLAKE3-team/BLAKE3", type = "package",
  archs = { "x86_64", "arm64", "aarch64" },
  xpm = { linux = { ["1.8.7"] = {
    url = "https://github.com/BLAKE3-team/BLAKE3/archive/f3149ec5bb5449af877ba20377a11008ff499fa2.tar.gz",
    sha256 = "92acc8eaef2623ee54bf527454fcc56255cd0a9bfe153ca3e722d367c74b1c4a",
  } } },
  mcpp = { language = "c++23", import_std = false,
    include_dirs = { "*/c" },
    defines = { "BLAKE3_NO_SSE2", "BLAKE3_NO_SSE41",
                "BLAKE3_NO_AVX2", "BLAKE3_NO_AVX512" },
    generated_files = {
      ["mcpp_generated/blake3_neon_guard.c"] = "#if defined(__aarch64__) || defined(_M_ARM64)\n#include \"blake3_neon.c\"\n#else\ntypedef int blake3_neon_guard_unused;\n#endif\n",
    },
    sources = { "*/c/blake3.c", "*/c/blake3_dispatch.c", "*/c/blake3_portable.c", "mcpp_generated/blake3_neon_guard.c" },
  },
}
