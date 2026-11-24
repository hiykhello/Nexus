// Rule-set cache key, validation & option helpers for rule fetch CLI.
export module cli.rule_fetch_cache;
import std;
import cli.rule_fetch_url;
import config;
import crypto;
import http.connect;
import platform.ip_address;
import rulefile;
import rules.rule_input;
import state.core;
import state.file;
import state.ruleset_cache;

export namespace cli::rule_fetch_detail {
    inline auto rule_digest(std::string_view data) -> std::optional<std::array<std::uint8_t, 32>> {
        auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(data.data()), data.size());
        auto digest = ::crypto::digest(::crypto::Hash::sha256, bytes);
        std::array<std::uint8_t, 32> result;
        if (!digest || digest->size() != result.size()) return {};
        std::ranges::copy(*digest, result.begin());
        return result;
    }

    inline auto parse_sha256(std::string_view text) -> std::optional<std::array<std::uint8_t, 32>> {
        std::array<std::uint8_t, 32> result{};
        if (text.size() != result.size() * 2) return {};
        for (auto& byte : result) {
            unsigned value = 0;
            auto end = text.data() + 2;
            auto [parsed, error] = std::from_chars(text.data(), end, value, 16);
            if (error != std::errc{} || parsed != end) return {};
            byte = static_cast<std::uint8_t>(value);
            text.remove_prefix(2);
        }
        return result;
    }

    struct FetchOptions {
        std::optional<std::array<std::uint8_t, 32>> pin;
        std::optional<::state::RulesetCache> cache;
        std::filesystem::path cache_root;
        bool offline = false;
        std::optional<std::uint64_t> max_bytes;
    };

    inline auto fetch_options(int argc, char** argv) -> std::expected<FetchOptions, std::string> {
        FetchOptions options;

        for (int i = 6; i < argc; ++i) {
            auto name = std::string_view(argv[i]);
            if (name == "--offline-cache" && !options.offline) {
                options.offline = true;
                continue;
            }
            if (i + 1 == argc) return std::unexpected("missing rule fetch option value");
            auto value = std::string_view(argv[++i]);
            if (name == "--sha256" && !options.pin) {
                options.pin = parse_sha256(value);
                if (!options.pin) return std::unexpected("SHA-256 pin must contain 64 hexadecimal digits");
            } else if (name == "--cache-dir" && options.cache_root.empty()) {
                options.cache_root = value;
                if (!options.cache_root.is_absolute()) return std::unexpected("cache directory must be absolute");
            } else if (name == "--ruleset-cache-max-bytes" && !options.max_bytes) {
                std::uint64_t bytes = 0;
                auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), bytes);
                if (error != std::errc{} || end != value.end() || !bytes)
                    return std::unexpected("invalid ruleset-cache-max-bytes");
                options.max_bytes = bytes;
            } else return std::unexpected("unknown or repeated rule fetch option");
        }
        if (options.offline && !options.pin) return std::unexpected("--offline-cache requires --sha256");
        return options;
    }

    inline auto cache_error(::state::StateError const& error) -> int {
        std::cerr << "ruleset cache: " << ::state::describe(error.stage);
        if (error.os) std::cerr << " (errno=" << error.os.value() << "): " << error.os.message();
        if (error.preceding) std::cerr << " after " << ::state::describe(*error.preceding);
        std::cerr << '\n';
        return 1;
    }

    inline auto canonical_url(Url const& url) -> std::string {
        auto const& peer = url.destination;
        std::string host;
        if (peer.kind != http::HostKind::domain) {
            bool v6 = peer.kind == http::HostKind::ipv6;
            auto address = platform::format_ip_address(std::span(peer.address).first(v6 ? 16u : 4u));
            if (!address) return {};
            host = v6 ? std::format("[{}]", *address) : std::move(*address);
        } else {
            host = peer.host;
            std::ranges::transform(host, host.begin(), [](char ch) {
                return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
            });
        }
        if (peer.port != 443) host += std::format(":{}", peer.port);
        return "https://" + host + url.target;
    }

    inline auto cache_key(Url const& url, ::rules::InputFormat format, std::string_view source, std::string_view client)
        -> std::optional<::state::RulesetKey> {
        using Format = ::rules::InputFormat;
        ::state::RuleFormat type = ::state::RuleFormat::srs;
        switch (format) {
        case Format::kdl: type = ::state::RuleFormat::kdl; break;
        case Format::beve: type = ::state::RuleFormat::beve; break;
        case Format::srs: type = ::state::RuleFormat::srs; break;
        case Format::nxmm: type = ::state::RuleFormat::nxmm; break;
        case Format::json: type = ::state::RuleFormat::json; break;
        case Format::domain_list: type = ::state::RuleFormat::domain_list; break;
        case Format::ipcidr_list: type = ::state::RuleFormat::ipcidr_list; break;
        case Format::classical: type = ::state::RuleFormat::classical; break;
        case Format::adguard: type = ::state::RuleFormat::adguard; break;
        }
        // Bump when accepted rule semantics change. Separate representations
        // that can depend on the named client's request headers and settings.
        constexpr unsigned parser_version = 1;
        auto scope = rule_digest(std::format("{}\n{}\n{}", client.size(), client, source));
        auto canonical = canonical_url(url);
        if (!scope || canonical.empty()) return {};
        ::state::RulesetKey key{std::move(canonical), type, parser_version};
        std::ranges::copy(std::as_bytes(std::span(*scope)), key.scope.begin());
        return key;
    }

    inline auto cache_path_conflict(std::filesystem::path const& root, std::filesystem::path const& path) -> bool {
        if (path.empty()) return false;
        std::error_code error;
        auto directory = std::filesystem::weakly_canonical(root / "rulesets", error);
        if (error) return true;
        auto absolute = std::filesystem::absolute(path, error);
        if (error) return true;
        auto other = std::filesystem::weakly_canonical(absolute, error);
        if (error) return true;
        auto common = std::ranges::mismatch(directory, other);
        return common.in1 == directory.end() || common.in2 == other.end();
    }

    inline auto epoch_seconds() -> std::uint64_t {
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return static_cast<std::uint64_t>(std::max<std::int64_t>(0, seconds));
    }

    inline auto offline_error(std::string_view message) noexcept -> bool {
        return message == "HTTPS resolution, connection or certificate verification failed" ||
            message == "HTTP/3 resolution failed" || message == "HTTP/3 handshake failed" ||
            message == "HTTP/3 outbound packet connection failed";
    }

    inline auto validate_download(std::string_view body, ::rules::InputFormat format,
                           std::optional<std::array<std::uint8_t, 32>> const& pin)
        -> std::expected<void, std::string> {
        if (pin) {
            auto digest = rule_digest(body);
            if (!digest || !::crypto::constant_time_equal(*digest, *pin))
                return std::unexpected("downloaded rule SHA-256 does not match");
        }
        auto parsed = ::rules::parse_rule_input(body, format);
        if (!parsed) return std::unexpected("invalid downloaded rule set: " + parsed.error().message);
        if (parsed->rules.empty()) return std::unexpected("downloaded rule set is empty");
        return {};
    }

    inline auto publish_rules(char const* path, std::string_view body) -> int {
        auto published = ::rulefile::replace_file(path, body);
        if (published) return 0;
        std::cerr << published.error() << '\n';
        return 1;
    }

    inline auto configure_rule_cache(FetchOptions& options, config::Config const& config)
        -> std::expected<void, std::string> {
        if (options.cache_root.empty() && config.state) options.cache_root = config.state->cache_directory;
        if (options.cache_root.empty()) {
            if (options.offline || options.max_bytes) return std::unexpected("cache options require a cache directory");
            return {};
        }
        ::state::RulesetCacheLimits limits;
        if (options.max_bytes) limits.max_bytes = *options.max_bytes;
        else if (config.state) limits.max_bytes = config.state->ruleset_cache_max_bytes;
        auto ready = ::state::ensure_private_directory(options.cache_root);
        if (!ready) return std::unexpected(std::string(::state::describe(ready.error().stage)));
        options.cache.emplace(options.cache_root, limits);
        return {};
    }
}
