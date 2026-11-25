#include <mimalloc.h>

// Explicitly anchors mimalloc's static allocator unit so LTO and --gc-sections
// never strip the global malloc/free/operator new override symbols.
extern "C" __attribute__((used)) int nexus_mimalloc_version_anchor() noexcept {
    return mi_version();
}
