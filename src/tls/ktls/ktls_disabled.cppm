export module tls.ktls;

export namespace tls {
    enum class KtlsStatus { ok, unavailable, invalid_state, would_block, fatal_error };
}
