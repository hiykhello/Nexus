export module cli.route_files;
import std;
import config;
import relay;
import rules;
export import rules.rule_input;

export namespace cli {
    auto set_working_directory(std::filesystem::path directory) -> void;
    auto restore_working_directory(std::optional<std::filesystem::path> directory) -> void;
    [[nodiscard]] auto working_directory() -> std::optional<std::filesystem::path>;
    [[nodiscard]] auto read_config_source(std::string_view path,bool is_directory=false,
        std::string_view host_override_path={}) -> std::expected<std::string,std::string>;

    struct ManagedRulesetFetchResult {
        std::string body;
        std::string etag;
        bool unchanged = false;
    };
    using ManagedRulesetFetcher = std::expected<ManagedRulesetFetchResult,std::string> (*)(
        config::Config const&,std::string_view,config::BlockRules const&,std::string_view,bool,std::stop_token,void*);
    using ManagedHttpPoolFactory = std::shared_ptr<void> (*)();
    auto register_managed_ruleset_fetcher(ManagedRulesetFetcher fetcher) noexcept -> void;
    auto register_managed_http_pool_factory(ManagedHttpPoolFactory factory) noexcept -> void;
    auto ensure_http_fetchers_registered() noexcept -> void;
    [[nodiscard]] auto create_managed_http_pool() noexcept -> std::shared_ptr<void>;
    [[nodiscard]] auto verify_remote_ruleset_sha256(config::BlockRules const& spec, std::string_view body)
        -> std::expected<void, std::string>;
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
        [[nodiscard]] auto open_mapped(std::string const& path) -> std::expected<std::shared_ptr<rules::MmapMatcher const>,std::string>;
    };

    struct RouteFiles {
        std::vector<std::string> data;
        std::vector<std::shared_ptr<rules::MmapMatcher const>> data_mmaps;
        std::vector<std::size_t> indices;
        std::vector<rules::ProgramRule> ordered;
        std::vector<std::pair<std::string, std::vector<std::string>>> tun_cidrs;

        auto indexed(config::Config const&) const -> std::vector<relay::IndexedRouteRule>;
    };

    [[nodiscard]] auto relay_rule_format(config::RuleFormat format) noexcept -> relay::RuleFormat;
    [[nodiscard]] auto rule_input_format(config::RuleFormat format) noexcept -> rules::InputFormat;

    struct ProjectedRoutes {
        std::vector<relay::IndexedRouteRule> indexed;
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
