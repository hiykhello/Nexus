module;
#include <blake3.h>
export module nexus.thirdparty.blake3;
export namespace nex::blake3 {
    using ::blake3_hasher;
    using ::blake3_hasher_init_derive_key_raw;
    using ::blake3_hasher_update;
    using ::blake3_hasher_finalize;
    using ::blake3_version;
}
