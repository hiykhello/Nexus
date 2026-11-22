export module dns.corosio_local;
import std;
export import dns.corosio_cached;
export import dns.local_config;

export namespace dns::detail {
    // The caller owns an immutable configuration snapshot and retains this
    // object and the snapshot until completion, including after cancellation.
    template<class Lookup>
    class BasicLocalAddressResolver {
        using Clock=std::chrono::steady_clock;
        Lookup& lookup_;
        LocalConfig const& config_;
        std::span<LocalHost const> hosts_;
        AddressStrategy strategy_;
        bool started_=false, canceled_=false, valid_=true;
        std::size_t offset_;
        static auto allowed(LocalServer const& ip, AddressStrategy strategy) -> bool {
            return strategy!=AddressStrategy::ipv4_only && strategy!=AddressStrategy::ipv6_only ? true :
                ip.ipv6==(strategy==AddressStrategy::ipv6_only);
        }
        static auto convert(LocalServer const& ip) -> Address {
            Address result{}; result.size=ip.ipv6 ? 16 : 4; result.bytes=ip.address; return result;
        }
        static auto endpoint(LocalServer const& server) -> dns_io::endpoint {
            if (server.ipv6) return {dns_io::ipv6_address(server.address),server.port};
            dns_io::ipv4_address::bytes_type bytes{};
            std::copy_n(server.address.begin(),4,bytes.begin());
            return {dns_io::ipv4_address(bytes),server.port};
        }
    public:
        BasicLocalAddressResolver(Lookup& lookup, LocalConfig const& config,
            std::span<LocalHost const> hosts, AddressStrategy strategy, std::size_t rotation=0,bool valid=true)
            : lookup_(lookup),config_(config),hosts_(hosts),strategy_(strategy),valid_(valid),offset_(rotation) {}
        auto cancel() noexcept -> void { canceled_=true; lookup_.cancel(); }
        template<bool Full>
        auto resolve_impl(std::string input,Clock::time_point deadline) -> dns_capy::task<std::expected<AddressResult<Full>,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            if (!valid_) co_return std::unexpected(ResolveError::state);
            if (Clock::now()>=deadline) co_return std::unexpected(ResolveError::timeout);
            if (auto literal=parse_local_address(input)) {
                if (!allowed(*literal,strategy_)) co_return std::unexpected(ResolveError::no_data);
                if constexpr (Full) co_return AddressAnswer{input,{input},{convert(*literal)},{}};
                else co_return std::vector<Address>{convert(*literal)};
            }
            auto normalized=normalize_local_name(input);
            if (!normalized) co_return std::unexpected(ResolveError::protocol);
            bool host_known=false; std::vector<Address> result;
            for (auto const& host:hosts_) {
                if (host.name!=*normalized) continue;
                host_known=true;
                if (!allowed(host.address,strategy_)) continue;
                if (result.size()==64) co_return std::unexpected(ResolveError::limit);
                result.push_back(convert(host.address));
            }
            if (host_known) {
                if (result.empty()) co_return std::unexpected(ResolveError::no_data);
                bool prefer_v6=strategy_==AddressStrategy::prefer_ipv6;
                std::stable_partition(result.begin(),result.end(),[prefer_v6](auto const& addr) { return (addr.size==16)==prefer_v6; });
                if constexpr (Full) co_return AddressAnswer{*normalized,{*normalized},std::move(result),{}};
                else co_return result;
            }
            if (config_.servers.empty() || config_.servers.size()>3 || !config_.attempts || config_.attempts>5 ||
                !config_.timeout_seconds || config_.timeout_seconds>30) co_return std::unexpected(ResolveError::state);
            if (config_.search.size()>6 || config_.ndots>15) co_return std::unexpected(ResolveError::state);
            auto candidates=local_search_candidates(config_,input,*normalized);
            auto last=ResolveError::transport;
            auto start=config_.rotate ? offset_%config_.servers.size() : 0;
            for (auto const& candidate:candidates) {
                for (std::uint32_t attempt=0;attempt<config_.attempts;++attempt) {
                    for (std::size_t index=0;index<config_.servers.size();++index) {
                        if (canceled_) co_return std::unexpected(ResolveError::canceled);
                        auto now=Clock::now(); if (now>=deadline) co_return std::unexpected(ResolveError::timeout);
                        auto const& server=config_.servers[(start+index)%config_.servers.size()];
                        if (!server.port) co_return std::unexpected(ResolveError::state);
                        auto attempt_deadline=std::min(deadline,now+std::chrono::seconds(config_.timeout_seconds));
                        std::expected<AddressResult<Full>,ResolveError> resolved;
                        if constexpr (Full) resolved=co_await lookup_.resolve_answer(endpoint(server),config_.use_tcp,strategy_,candidate,attempt_deadline);
                        else resolved=co_await lookup_.resolve(endpoint(server),config_.use_tcp,strategy_,candidate,attempt_deadline);
                        lookup_.finish();
                        if (canceled_) co_return std::unexpected(ResolveError::canceled);
                        if (resolved) co_return std::move(*resolved);
                        last=resolved.error();
                        if (last==ResolveError::name_not_found || last==ResolveError::no_data) break;
                        if (last!=ResolveError::transport && last!=ResolveError::timeout &&
                            last!=ResolveError::server_failure && last!=ResolveError::refused) co_return std::unexpected(last);
                    }
                    if (last==ResolveError::name_not_found || last==ResolveError::no_data) break;
                }
                if (last!=ResolveError::name_not_found && last!=ResolveError::no_data) co_return std::unexpected(last);
            }
            co_return std::unexpected(last);
        }
        auto resolve(std::string input,Clock::time_point deadline)
            -> dns_capy::task<std::expected<std::vector<Address>,ResolveError>> {
            return resolve_impl<false>(std::move(input),deadline);
        }
        auto resolve_answer(std::string input,Clock::time_point deadline)
            -> dns_capy::task<std::expected<AddressAnswer,ResolveError>> {
            // Retain the successful search candidate's terminal name.
            return resolve_impl<true>(std::move(input),deadline);
        }
    };

    class LocalDefaultLookup {
        dns_io::io_context& context_;
        AddressCache unused_cache_{0};
        std::unique_ptr<DualAddressResolver> active_;
        std::optional<ClientSubnet> subnet_;
    public:
        explicit LocalDefaultLookup(dns_io::io_context& context,std::optional<ClientSubnet> subnet={}) : context_(context),subnet_(subnet) {}
        auto cancel() noexcept -> void { if (active_) active_->cancel(); }
        auto resolve(dns_io::endpoint endpoint,bool tcp,AddressStrategy strategy,std::string const& name,
                     std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<std::vector<Address>,ResolveError>>;
        auto resolve_answer(dns_io::endpoint endpoint,bool tcp,AddressStrategy strategy,std::string const& name,
                            std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<AddressAnswer,ResolveError>>;
        auto finish() noexcept -> void { active_.reset(); }
    };

    // Compatibility wrapper for consumers without a shared generation.
    class LocalAddressResolver {
        LocalDefaultLookup lookup_;
        BasicLocalAddressResolver<LocalDefaultLookup> resolver_;
    public:
        LocalAddressResolver(dns_io::io_context& context,LocalConfig const& config,
            std::span<LocalHost const> hosts,AddressStrategy strategy,std::size_t rotation=0,std::optional<ClientSubnet> subnet={})
            : lookup_(context,subnet),resolver_(lookup_,config,hosts,strategy,rotation,!subnet || valid_client_subnet(*subnet)) {}
        auto cancel() noexcept -> void { resolver_.cancel(); }
        auto resolve(std::string input,std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<std::vector<Address>,ResolveError>>;
        auto resolve_answer(std::string input,std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<AddressAnswer,ResolveError>>;
    };
}
