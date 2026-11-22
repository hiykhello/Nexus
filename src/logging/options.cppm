export module logging.options;
import std;

export namespace logging {
    enum class Level : std::uint8_t { trace, debug, info, warn, error, fatal, off };
    enum class Domain : std::uint8_t { core, net, tls, quic, dns, route, tun, proxy, control, state };
    enum class Privacy : std::uint8_t { redacted, verbose };
    enum class Format : std::uint8_t { text, jsonl };
    enum class Timestamp : std::uint8_t { rfc3339, monotonic, none };
    enum class SinkKind : std::uint8_t { stderr, file, off, journald };

    inline constexpr std::array<std::string_view, 10> domain_names{
        "core", "net", "tls", "quic", "dns", "route", "tun", "proxy", "control", "state"
    };
    inline constexpr std::array<std::string_view, 7> level_names{
        "trace", "debug", "info", "warn", "error", "fatal", "off"
    };
    inline constexpr auto domain_count = domain_names.size();
    inline constexpr auto level_count = level_names.size() - 1;

    constexpr auto name(Domain domain) noexcept -> std::string_view {
        return domain_names[std::to_underlying(domain)];
    }
    constexpr auto name(Level level) noexcept -> std::string_view {
        return level_names[std::to_underlying(level)];
    }
    constexpr auto parse_level(std::string_view text) noexcept -> std::optional<Level> {
        auto value = std::ranges::find(level_names, text);
        if (value == level_names.end()) return {};
        return static_cast<Level>(value - level_names.begin());
    }
    constexpr auto parse_domain(std::string_view text) noexcept -> std::optional<Domain> {
        auto value = std::ranges::find(domain_names, text);
        if (value == domain_names.end()) return {};
        return static_cast<Domain>(value - domain_names.begin());
    }

    struct Output {
        Format format = Format::text;
        Timestamp timestamp = Timestamp::rfc3339;
        auto operator==(Output const&) const -> bool = default;
    };
    struct Settings {
        Output output{};
        Privacy privacy = Privacy::redacted;
        std::size_t ring_capacity = 0;
        auto operator==(Settings const&) const -> bool = default;
    };
    struct Destination {
        SinkKind kind;
        std::string path;
        std::uint64_t max_size_bytes = 0;
        std::size_t max_files = 1; // Includes the active file.
        auto operator==(Destination const&) const -> bool = default;
    };
    struct Config {
        Settings settings{Output{}, Privacy::redacted, 2048};
        Level level = Level::info;
        Level ring_level = Level::trace;
        std::array<std::optional<Level>, domain_count> domains{};
        std::vector<Destination> sinks{{SinkKind::stderr, {}}};
    };
}
