// Single source of truth for TLS uTLS fingerprint identities, version aliases, and external normalization.
export module utility.tls_fingerprint;
import std;

export namespace utility {
    enum class TlsFingerprintId : std::uint8_t {
        native, tls13_grease, tls13_randomized,
        chrome, firefox, safari, ios, android, edge, random, tls12
    };

    struct TlsFingerprintAlias {
        std::string_view name;
        TlsFingerprintId id;
    };

    struct TlsFingerprintBaseline {
        TlsFingerprintId id;
        std::string_view canonical;
        std::string_view baseline;
    };

    inline constexpr auto tls_fingerprint_baselines = std::to_array<TlsFingerprintBaseline>({
        {TlsFingerprintId::native, "native", "native"},
        {TlsFingerprintId::tls13_grease, "tls13-grease", "tls13-grease"},
        {TlsFingerprintId::tls13_randomized, "tls13-randomized", "tls13-randomized"},
        {TlsFingerprintId::chrome, "chrome", "chrome-158"},
        {TlsFingerprintId::firefox, "firefox", "firefox-161"},
        {TlsFingerprintId::safari, "safari", "safari-26.3"},
        {TlsFingerprintId::ios, "ios", "ios-26.3"},
        {TlsFingerprintId::android, "android", "android-16"},
        {TlsFingerprintId::edge, "edge", "edge-158"},
        {TlsFingerprintId::random, "random", "random"},
        {TlsFingerprintId::tls12, "tls12", "tls12"},
    });

    // Strict canonical names plus supported versioned aliases for KDL configs and tls::parse_fingerprint.
    inline constexpr auto tls_fingerprint_aliases = std::to_array<TlsFingerprintAlias>({
        {"native", TlsFingerprintId::native},
        {"tls13-grease", TlsFingerprintId::tls13_grease},
        {"tls13-randomized", TlsFingerprintId::tls13_randomized},
        {"chrome", TlsFingerprintId::chrome},
        {"chrome-133", TlsFingerprintId::chrome},
        {"chrome-155", TlsFingerprintId::chrome},
        {"chrome-158", TlsFingerprintId::chrome},
        {"firefox", TlsFingerprintId::firefox},
        {"firefox-135", TlsFingerprintId::firefox},
        {"firefox-148", TlsFingerprintId::firefox},
        {"firefox-161", TlsFingerprintId::firefox},
        {"safari", TlsFingerprintId::safari},
        {"safari-18", TlsFingerprintId::safari},
        {"safari-26", TlsFingerprintId::safari},
        {"safari-26.3", TlsFingerprintId::safari},
        {"ios", TlsFingerprintId::ios},
        {"ios-14", TlsFingerprintId::ios},
        {"ios-18", TlsFingerprintId::ios},
        {"ios-26", TlsFingerprintId::ios},
        {"ios-26.3", TlsFingerprintId::ios},
        {"android", TlsFingerprintId::android},
        {"android-11", TlsFingerprintId::android},
        {"android-16", TlsFingerprintId::android},
        {"edge", TlsFingerprintId::edge},
        {"edge-133", TlsFingerprintId::edge},
        {"edge-155", TlsFingerprintId::edge},
        {"edge-158", TlsFingerprintId::edge},
        {"random", TlsFingerprintId::random},
        {"tls12", TlsFingerprintId::tls12},
    });

    [[nodiscard]] constexpr auto parse_tls_fingerprint_id(std::string_view name) noexcept -> std::optional<TlsFingerprintId> {
        for (auto const& entry : tls_fingerprint_aliases)
            if (entry.name == name) return entry.id;
        return std::nullopt;
    }

    [[nodiscard]] constexpr auto tls_fingerprint_id_name(TlsFingerprintId id) noexcept -> std::string_view {
        for (auto const& entry : tls_fingerprint_baselines)
            if (entry.id == id) return entry.canonical;
        return "native";
    }

    [[nodiscard]] constexpr auto tls_fingerprint_baseline(TlsFingerprintId id) noexcept -> std::string_view {
        for (auto const& entry : tls_fingerprint_baselines)
            if (entry.id == id) return entry.baseline;
        return "native";
    }

    namespace detail {
        [[nodiscard]] constexpr auto is_ascii_space(char c) noexcept -> bool {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }
        [[nodiscard]] constexpr auto is_ascii_digit(char c) noexcept -> bool {
            return c >= '0' && c <= '9';
        }
        [[nodiscard]] constexpr auto to_lower_ascii(char c) noexcept -> char {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }
        [[nodiscard]] constexpr auto matches_versioned_family(std::string_view s, std::string_view family) noexcept -> bool {
            if (s == family) return true;
            if (!s.starts_with(family)) return false;
            auto rest = s.substr(family.size());
            if (rest.empty()) return true;
            if (rest.front() == '-' || rest.front() == '_') rest.remove_prefix(1);
            if (rest.empty()) return false;
            return rest == "auto" || is_ascii_digit(rest.front());
        }
    }

    // Permissive normalizer for external subscription imports (sing-box, Clash/Mihomo, share URIs).
    // Returns a canonical Nexus fingerprint name or empty string_view if unsupported.
    [[nodiscard]] constexpr auto normalize_external_tls_fingerprint(std::string_view raw) noexcept -> std::string_view {
        while (!raw.empty() && detail::is_ascii_space(raw.front())) raw.remove_prefix(1);
        while (!raw.empty() && detail::is_ascii_space(raw.back())) raw.remove_suffix(1);
        if (raw.empty() || raw.size() > 48) return {};

        std::array<char, 48> buf{};
        for (std::size_t i = 0; i < raw.size(); ++i) {
            char c = detail::to_lower_ascii(raw[i]);
            buf[i] = (c == '_') ? '-' : c;
        }
        std::string_view norm(buf.data(), raw.size());

        if (auto exact = parse_tls_fingerprint_id(norm)) return tls_fingerprint_id_name(*exact);
        if (norm == "randomized" || norm == "randomized-alpn" || norm == "randomized-no-alpn") return "random";
        if (detail::matches_versioned_family(norm, "chrome")) return "chrome";
        if (detail::matches_versioned_family(norm, "firefox")) return "firefox";
        if (detail::matches_versioned_family(norm, "safari")) return "safari";
        if (detail::matches_versioned_family(norm, "edge")) return "edge";
        if (detail::matches_versioned_family(norm, "ios")) return "ios";
        if (detail::matches_versioned_family(norm, "android")) return "android";
        return {};
    }
}
