// Browser TLS ClientHello extension builder & CSPRNG helper.
export module tls.browser_extensions;
import std;
import crypto;
import tls.fingerprint;
import tls.browser_profiles;

export namespace tls::detail {
    class Random {
        std::array<std::uint8_t, 64> bytes_{};
        std::size_t offset_ = 64;
    public:
        auto sample(std::uint16_t bound) -> std::optional<std::uint16_t> {
            if (!bound) return {};
            auto limit = 65536u - (65536u % bound);
            for (;;) {
                if (offset_ == bytes_.size()) {
                    if (!crypto::random_bytes(bytes_)) return {};
                    offset_ = 0;
                }
                auto value = (std::uint32_t{bytes_[offset_]} << 8) | bytes_[offset_ + 1];
                offset_ += 2;
                if (value < limit) return static_cast<std::uint16_t>(value % bound);
            }
        }
        auto grease() -> std::optional<std::uint16_t> {
            auto value = sample(16);
            if (!value) return {};
            return static_cast<std::uint16_t>(0x0a0a + 0x1010 * (*value));
        }
    };

    inline auto chrome155_trust_anchors_payload() -> std::vector<std::uint8_t> {
        // Chrome 155 Root Store Trust Anchor IDs in lexicographic order (draft-ietf-tls-trust-anchor-ids).
        constexpr std::array<std::uint8_t, 8> prefix_a_tails{0x01, 0x06, 0x0d, 0x0e, 0x0f, 0x12, 0x13, 0x14};
        constexpr std::array<std::uint8_t, 9> prefix_b_tails{0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x12, 0x13};
        constexpr std::array<std::uint8_t, 11> prefix_c_tails{0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f};
        std::vector<std::uint8_t> out{0, 0};
        out.reserve(186);
        for (auto t : prefix_a_tails) out.append_range(std::array<std::uint8_t, 6>{5, 0x82, 0xdf, 0x13, 0x02, t});
        for (auto t : prefix_b_tails) out.append_range(std::array<std::uint8_t, 9>{8, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, t});
        for (auto t : prefix_c_tails) out.append_range(std::array<std::uint8_t, 5>{4, 0xd6, 0x79, 0x09, t});
        auto list_len = out.size() - 2;
        out[0] = static_cast<std::uint8_t>(list_len >> 8);
        out[1] = static_cast<std::uint8_t>(list_len & 0xff);
        return out;
    }

    inline auto add_browser_extensions(ClientHello& hello, BrowserPresetSpec const& spec,
        std::span<std::string_view const> alpn, HandshakeTransport transport,
        bool real_ech, bool allow_tls12, Random& random) -> bool {
        hello.extensions.push_back({5, {1, 0, 0, 0, 0}});
        hello.extensions.push_back({18, {}});
        if (spec.delegated_credentials) hello.extensions.push_back({34, {0, 8, 4, 3, 5, 3, 6, 3, 8, 7}});
        if (transport == HandshakeTransport::tcp && spec.alps_h2 && std::ranges::contains(alpn, std::string_view("h2")))
            hello.extensions.push_back({0x44cd, {0, 3, 2, 'h', '2'}});
        if (spec.trust_anchors) hello.extensions.push_back({0xca34, chrome155_trust_anchors_payload()});
        if (spec.grease_ech && !real_ech) {
            auto size = random.sample(4);
            if (!size) return false;
            auto payload = 128u + 32u * (*size);
            Extension ech{0xfe0d, {0, 0, 1, 0, 1, 0, 0, 32}};
            ech.data.resize(42 + payload);
            if (!crypto::random_bytes(std::span(ech.data).subspan(5, 1)) ||
                !crypto::random_bytes(std::span(ech.data).subspan(8, 32)) ||
                !crypto::random_bytes(std::span(ech.data).subspan(42)))
                return false;
            ech.data[40] = static_cast<std::uint8_t>(payload >> 8);
            ech.data[41] = static_cast<std::uint8_t>(payload);
            hello.extensions.push_back(std::move(ech));
        }
        if (transport == HandshakeTransport::quic) return true;
        hello.extensions.push_back({11, {1, 0}});
        hello.extensions.push_back({23, {}});
        hello.extensions.push_back({35, {}});
        hello.extensions.push_back({0xff01, {0}});
        if (!allow_tls12) return true;
        hello.cipher_suites.append_range(spec.tls12_ciphers);
        for (auto& extension : hello.extensions)
            if (extension.type == 43) extension.data = {4, 3, 4, 3, 3};
        return true;
    }
}
