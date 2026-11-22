export module cli.route_files;
import std;
import config;
import proxy;
import rules;

export namespace cli {
    auto set_working_directory(std::filesystem::path directory) -> void;
    [[nodiscard]] auto working_directory() noexcept -> std::optional<std::filesystem::path> const&;
    [[nodiscard]] auto read_config_source(std::string_view path,bool is_directory=false) -> std::expected<std::string,std::string>;

    struct ManagedRulesetFetchResult {
        std::string body;
        std::string etag;
        bool unchanged = false;
    };
    using ManagedRulesetFetcher = std::expected<ManagedRulesetFetchResult,std::string> (*)(
        config::Config const&,std::string_view,config::BlockRules const&,std::string_view,bool);
    auto register_managed_ruleset_fetcher(ManagedRulesetFetcher fetcher) noexcept -> void;
    [[nodiscard]] auto fetch_managed_ruleset(config::Config const& config,std::string_view config_source,
        config::BlockRules const& spec,std::string_view previous_etag={},bool offline_fallback=true)
        -> std::expected<ManagedRulesetFetchResult,std::string>;

    class RuleFileInput {
        std::filesystem::path config_path_;
        std::map<std::string,std::string,std::less<>> files_;
        bool allow_unfetched_remote_=false;
    public:
        explicit RuleFileInput(std::string_view config_path,bool allow_unfetched_remote=false)
            : config_path_(config_path),allow_unfetched_remote_(allow_unfetched_remote) {}
        auto seed(std::string key,std::string content) -> void { files_.insert_or_assign(std::move(key),std::move(content)); }
        [[nodiscard]] auto allows_unfetched_remote() const noexcept -> bool { return allow_unfetched_remote_; }
        [[nodiscard]] auto read(std::string const& path) -> std::expected<std::string_view,std::string>;
    };

    struct RouteFiles {
        std::vector<std::string> data;
        std::vector<std::size_t> indices;
        std::vector<rules::ProgramRule> ordered;

        auto indexed(config::Config const&) const -> std::vector<proxy::IndexedRouteRule>;
    };

    struct ProjectedRoutes {
        std::vector<proxy::IndexedRouteRule> indexed;
        std::vector<rules::ProgramRule> ordered;
        std::shared_ptr<rules::OutboundDistribution const> distribution;
        std::size_t default_outbound;

        [[nodiscard]] auto program(config::Config const&) const -> std::optional<proxy::OrderedRuleInput>;
        auto compile(config::Config const&,std::string_view inbound)
            const -> std::expected<proxy::RouteSnapshot,std::string>;
    };

    auto project_routes(config::Config const&,RouteFiles const&) -> ProjectedRoutes;
    auto outbound_names(config::Config const&) -> std::vector<std::string>;
    auto load_route_files(config::Config const&,RuleFileInput&) -> std::expected<RouteFiles,std::string>;
    auto load_route_files(config::Config const&,std::string_view config_path,bool allow_unfetched_remote=false) -> std::expected<RouteFiles,std::string>;
}
