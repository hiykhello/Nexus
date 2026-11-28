export module cli.route_files;
import std;
import config;
import relay;
import rules;
export import rules.rule_input;
import state.core;

export namespace cli {
    [[nodiscard]] inline auto current_unix_seconds() noexcept -> std::uint64_t {
        auto s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return static_cast<std::uint64_t>(std::max<std::int64_t>(0, s));
    }

    // Returns remaining refresh cooldown in ms ONLY if fetched_at_unix > 0, now_unix >= fetched_at_unix
    // (protects against future clock skew), and elapsed_ms < interval_ms.
    [[nodiscard]] constexpr auto compute_remaining_refresh_ms(
        std::uint64_t fetched_at_unix, std::uint64_t now_unix, std::uint32_t interval_ms) noexcept
        -> std::optional<std::uint64_t> {
        if (fetched_at_unix == 0 || interval_ms == 0 || now_unix < fetched_at_unix) return std::nullopt;
        std::uint64_t const elapsed_s = now_unix - fetched_at_unix;
        if (elapsed_s > (std::numeric_limits<std::uint64_t>::max() / 1000u)) return std::nullopt;
        std::uint64_t const elapsed_ms = elapsed_s * 1000u;
        if (elapsed_ms >= static_cast<std::uint64_t>(interval_ms)) return std::nullopt;
        return static_cast<std::uint64_t>(interval_ms) - elapsed_ms;
    }

    [[nodiscard]] inline auto http_client_signature(config::Config const& cfg, std::string_view requested) -> std::string {
        std::string_view name = requested.empty() ? std::string_view(cfg.default_http_client) : requested;
        std::string raw;
        auto push = [&](std::string_view s) {
            raw += std::to_string(s.size());
            raw.push_back(':');
            raw.append(s);
            raw.push_back(';');
        };
        push(name);
        auto it = std::ranges::find(cfg.http_clients, name, &config::NamedHttpClient::name);
        if (it == cfg.http_clients.end()) {
            push("<missing>");
        } else {
            auto const& c = *it;
            push(c.outbound); push(c.resolver); push(c.ca_file); push(c.ech_config_file);
            raw += std::format("p={};f={};k={};mb={};mr={};mtu={};rsl={};pmtu={};",
                static_cast<unsigned>(c.protocol), static_cast<unsigned>(c.fingerprint),
                static_cast<unsigned>(c.key_exchange), c.max_bytes, c.max_redirects,
                c.max_udp_payload.value_or(0), c.record_size_limit.value_or(0),
                c.disable_path_mtu_discovery.has_value() ? (*c.disable_path_mtu_discovery ? 2 : 1) : 0);
            for (auto const& [hk, hv] : c.headers) { push(hk); push(hv); }
        }
        auto fp = ::state::fingerprint(std::as_bytes(std::span(raw)));
        static constexpr char kHex[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(fp.size() * 2);
        for (auto b : fp) {
            auto v = std::to_integer<std::uint8_t>(b);
            hex.push_back(kHex[v >> 4]);
            hex.push_back(kHex[v & 0x0fu]);
        }
        return hex;
    }

    auto set_working_directory(std::filesystem::path directory) -> void;
    auto restore_working_directory(std::optional<std::filesystem::path> directory) -> void;
    [[nodiscard]] auto working_directory() -> std::optional<std::filesystem::path>;
    [[nodiscard]] auto read_config_source(std::string_view path,bool is_directory=false,
        std::string_view host_override_path={}) -> std::expected<std::string,std::string>;

    struct ManagedRulesetFetchResult {
        std::string body;
        std::string etag;
        bool unchanged = false;
        std::uint64_t fetched_at = 0;
        std::uint64_t remaining_ms = 0;
        bool from_fresh_cache = false;
    };
    struct FreshRulesetCacheHit {
        std::string body;
        std::string etag;
        std::uint64_t fetched_at = 0;
        std::uint64_t remaining_ms = 0;
    };
    using ManagedRulesetFetcher = std::expected<ManagedRulesetFetchResult,std::string> (*)(
        config::Config const&,std::string_view,config::BlockRules const&,std::string_view,bool,std::stop_token,void*);
    using ManagedRulesetCacheProbe = std::optional<FreshRulesetCacheHit> (*)(
        config::Config const&,std::string_view,config::BlockRules const&,std::uint64_t);
    using ManagedHttpPoolFactory = std::shared_ptr<void> (*)();
    auto register_managed_ruleset_fetcher(ManagedRulesetFetcher fetcher) noexcept -> void;
    auto register_managed_ruleset_cache_probe(ManagedRulesetCacheProbe probe) noexcept -> void;
    auto register_managed_http_pool_factory(ManagedHttpPoolFactory factory) noexcept -> void;
    auto ensure_http_fetchers_registered() noexcept -> void;
    [[nodiscard]] auto create_managed_http_pool() noexcept -> std::shared_ptr<void>;
    [[nodiscard]] auto verify_remote_ruleset_sha256(config::BlockRules const& spec, std::string_view body)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto probe_fresh_managed_ruleset_cache(config::Config const& config, std::string_view config_source,
        config::BlockRules const& spec, std::uint64_t now_unix = current_unix_seconds())
        -> std::optional<FreshRulesetCacheHit>;
    [[nodiscard]] auto fetch_managed_ruleset(config::Config const& config,std::string_view config_source,
        config::BlockRules const& spec,std::string_view previous_etag={},bool offline_fallback=true,
        std::stop_token stop={},void* client_pool=nullptr) -> std::expected<ManagedRulesetFetchResult,std::string>;

    class RuleFileInput {
        std::filesystem::path config_path_;
        std::filesystem::path cache_dir_;
        std::map<std::string,std::string,std::less<>> files_;
        std::map<std::string,std::shared_ptr<rules::MmapMatcher const>,std::less<>> mmaps_;
        bool allow_unfetched_remote_=false;
    public:
        explicit RuleFileInput(std::string_view config_path,bool allow_unfetched_remote=false)
            : config_path_(config_path),allow_unfetched_remote_(allow_unfetched_remote) {}
        auto seed(std::string key,std::string content) -> void { files_.insert_or_assign(std::move(key),std::move(content)); }
        auto set_cache_dir(std::filesystem::path dir) -> void { cache_dir_=std::move(dir); }
        [[nodiscard]] auto cache_dir() const noexcept -> std::filesystem::path const& { return cache_dir_; }
        [[nodiscard]] auto allows_unfetched_remote() const noexcept -> bool { return allow_unfetched_remote_; }
        [[nodiscard]] auto read(std::string const& path) -> std::expected<std::string_view,std::string>;
        [[nodiscard]] auto open_mapped(std::string const& path,
            std::size_t max_bytes = rules::max_input_bytes) -> std::expected<std::shared_ptr<rules::MmapMatcher const>,std::string>;
    };

    struct RouteFiles {
        std::vector<std::string> data;
        std::vector<std::shared_ptr<rules::MmapMatcher const>> data_mmaps;
        std::vector<std::size_t> indices;
        std::vector<rules::ProgramRule> ordered;
        std::vector<std::pair<std::string, std::vector<std::string>>> tun_cidrs;
    };

    [[nodiscard]] auto relay_rule_format(config::RuleFormat format) noexcept -> relay::RuleFormat;
    [[nodiscard]] auto rule_input_format(config::RuleFormat format) noexcept -> rules::InputFormat;

    struct ProjectedRoutes {
        std::vector<rules::ProgramRule> ordered;
        std::shared_ptr<rules::OutboundDistribution const> distribution;
        std::size_t default_outbound;

        [[nodiscard]] auto program(config::Config const&) const -> std::optional<relay::OrderedRuleInput>;
        auto compile(config::Config const&,std::string_view inbound)
            const -> std::expected<relay::RouteSnapshot,std::string>;
    };

    auto project_routes(config::Config const&,RouteFiles const&) -> ProjectedRoutes;
    auto outbound_names(config::Config const&) -> std::vector<std::string>;
    auto load_route_files(config::Config const&,RuleFileInput&) -> std::expected<RouteFiles,std::string>;
    auto load_route_files(config::Config const&,std::string_view config_path,bool allow_unfetched_remote=false) -> std::expected<RouteFiles,std::string>;
    auto apply_tun_route_sets(config::TunInbound&,RouteFiles const&) -> std::expected<void,std::string>;
}
