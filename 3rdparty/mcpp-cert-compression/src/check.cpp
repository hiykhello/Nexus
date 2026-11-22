#include <brotli/decode.h>
#include <zstd.h>

static_assert(BROTLI_DECODER_RESULT_SUCCESS == 1);
static_assert(ZSTD_VERSION_NUMBER >= 10400);
