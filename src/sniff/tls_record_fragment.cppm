export module tls.record_fragment;
import std;

export namespace tls {
    // Returns true if wire starts with a complete plaintext TLS Handshake (0x16)
    // record containing a ClientHello (handshake type 0x01).
    [[nodiscard]] constexpr auto is_tls_client_hello_record(std::span<std::uint8_t const> wire) noexcept -> bool {
        if (wire.size() < 10) return false;
        if (wire[0] != 0x16 || wire[1] != 0x03 || wire[2] > 0x03) return false;
        auto rec_len = (std::size_t{wire[3]} << 8) | wire[4];
        if (rec_len < 5 || 5 + rec_len > wire.size()) return false;
        return wire[5] == 0x01;
    }

    // Splits a single TLS plaintext ClientHello record into multiple RFC-compliant
    // TLS plaintext handshake records with bounded pseudorandom fragment sizes.
    // Any bytes following the first TLS record are appended verbatim.
    // Non-ClientHello input is returned unchanged.
    [[nodiscard]] inline auto fragment_tls_client_hello(
        std::span<std::uint8_t const> wire,
        std::size_t min_len = 16,
        std::size_t max_len = 64,
        std::uint64_t seed = 0x9e3779b97f4a7c15ULL) -> std::vector<std::uint8_t> {
        if (!is_tls_client_hello_record(wire)) return {wire.begin(), wire.end()};
        if (min_len == 0) min_len = 1;
        if (max_len < min_len) max_len = min_len;
        if (max_len > 16384) max_len = 16384;
        auto rec_len = (std::size_t{wire[3]} << 8) | wire[4];
        auto payload = wire.subspan(5, rec_len);
        auto tail = wire.subspan(5 + rec_len);
        if (payload.size() <= min_len) return {wire.begin(), wire.end()};

        std::vector<std::uint8_t> out;
        out.reserve(wire.size() + (payload.size() / min_len + 1) * 5);
        std::uint64_t state = seed ? seed : 0x517cc1b727220a95ULL;
        auto next_u64 = [&]() noexcept -> std::uint64_t {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            return state * 0x2545f4914f6cdd1dULL;
        };
        std::size_t off = 0;
        std::uint8_t ver_minor = wire[2];
        while (off < payload.size()) {
            auto rem = payload.size() - off;
            std::size_t span = max_len - min_len + 1;
            std::size_t chunk = min_len + static_cast<std::size_t>(next_u64() % span);
            if (chunk > rem) chunk = rem;
            // Ensure at least 2 records if we started larger than min_len.
            if (off == 0 && chunk == rem && rem > 1) chunk = std::max<std::size_t>(1, rem / 2);
            out.push_back(0x16);
            out.push_back(0x03);
            out.push_back(ver_minor);
            out.push_back(static_cast<std::uint8_t>(chunk >> 8));
            out.push_back(static_cast<std::uint8_t>(chunk & 0xff));
            out.insert(out.end(), payload.begin() + static_cast<std::ptrdiff_t>(off),
                payload.begin() + static_cast<std::ptrdiff_t>(off + chunk));
            off += chunk;
        }
        out.insert(out.end(), tail.begin(), tail.end());
        return out;
    }
}
