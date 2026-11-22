export module dns.response_query;
import std;
import dns.message;
import dns.local_config;
import dns.cache;
import dns.response_cache;
import dns.response_match;
import dns.corosio_query;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace dns::detail {
    // A complete client query has option-dependent semantics. Until a
    // message-aware cache/coalescer exists, each exchange is independent.
    class MessageQuery {
        using Clock=std::chrono::steady_clock;
        dns_io::io_context& context_;
        FallbackQuery transport_;
        std::optional<FallbackQuery> retry_;
        bool tcp_only_;
        ProtectedQuery const* protection_;
        bool started_=false,canceled_=false;
    public:
        explicit MessageQuery(dns_io::io_context& context,bool tcp_only,ProtectedQuery const* protection=nullptr)
            : context_(context),transport_(context,tcp_only,nullptr,protection),tcp_only_(tcp_only),protection_(protection) {}
        MessageQuery(MessageQuery const&)=delete;
        auto operator=(MessageQuery const&) -> MessageQuery& = delete;
        auto cancel() noexcept -> void {canceled_=true;transport_.cancel();if(retry_)retry_->cancel();}
        auto run(dns_io::endpoint upstream,QueryMessage query,Clock::time_point deadline)
            -> dns_capy::task<std::expected<Bytes,ResolveError>> {
            co_return co_await run_borrowed(upstream,query,deadline);
        }
        // The caller retains the immutable query until completion, including cancellation.
        auto run_borrowed(dns_io::endpoint upstream,QueryMessage const& query,Clock::time_point deadline)
            -> dns_capy::task<std::expected<Bytes,ResolveError>> {
            if(std::exchange(started_,true)) co_return std::unexpected(ResolveError::state);
            if(canceled_) co_return std::unexpected(ResolveError::canceled);
            if(Clock::now()>=deadline) co_return std::unexpected(ResolveError::timeout);
            if(!upstream.port()) co_return std::unexpected(ResolveError::state);
            if(query.edns) {
                auto subnet=query_client_subnet(*query.edns);
                if(!subnet) co_return std::unexpected(ResolveError::protocol);
            }
            auto id=random_id();if(!id) co_return std::unexpected(id.error());
            auto response=co_await transport_.query_borrowed(upstream,query,deadline,*id);
            if(canceled_) co_return std::unexpected(ResolveError::canceled);
            if(!response) co_return std::unexpected(response.error()==UdpError::budget_exhausted ? ResolveError::budget_exhausted : response.error()==UdpError::timeout ? ResolveError::timeout :
                response.error()==UdpError::canceled ? ResolveError::canceled :
                response.error()==UdpError::transport ? ResolveError::transport : ResolveError::protocol);
            if(!validate_response_ecs(query,*response))co_return std::unexpected(ResolveError::protocol);
            if(response->rcode==5 && query.edns && std::ranges::any_of(query.edns->options,[](auto const& option){return option.code==8;})) {
                auto retry_query=query;
                if(!set_query_client_subnet(retry_query,{}))co_return std::unexpected(ResolveError::protocol);
                auto retry_id=random_id();if(!retry_id)co_return std::unexpected(retry_id.error());retry_query.id=*retry_id;
                retry_.emplace(context_,tcp_only_,nullptr,protection_);
                response=co_await retry_->query_borrowed(upstream,retry_query,deadline);retry_.reset();
                if(canceled_)co_return std::unexpected(ResolveError::canceled);
                if(!response)co_return std::unexpected(response.error()==UdpError::budget_exhausted ? ResolveError::budget_exhausted : response.error()==UdpError::timeout ? ResolveError::timeout :
                    response.error()==UdpError::canceled ? ResolveError::canceled :
                    response.error()==UdpError::transport ? ResolveError::transport : ResolveError::protocol);
                if(!validate_response_ecs(retry_query,*response))co_return std::unexpected(ResolveError::protocol);
            }
            auto wire=complete_response_ecs(query,*response);
            if(!wire) co_return std::unexpected(ResolveError::protocol);
            co_return std::move(*wire);
        }
        auto run_borrowed(dns_io::endpoint,QueryMessage&&,Clock::time_point) -> dns_capy::task<std::expected<Bytes,ResolveError>> = delete;
        auto run_borrowed(dns_io::endpoint,QueryMessage const&&,Clock::time_point) -> dns_capy::task<std::expected<Bytes,ResolveError>> = delete;
    };
    struct LocalResponseHosts { std::string question; std::optional<Response> response; };
    // Produce a local hosts answer for response-stage policy. It is synthetic
    // by definition, TTL zero, and never inserted into the wire cache.
    inline auto local_hosts_response(LocalSnapshot const& snapshot,std::string_view name,std::uint16_t type)
        -> std::expected<LocalResponseHosts,ResolveError> {
        auto normalized=normalize_local_name(name);if (!normalized || (type!=1 && type!=28)) return std::unexpected(ResolveError::protocol);
        bool known=false;std::vector<LocalServer> hosts;
        for (auto const& host:snapshot.hosts) if (host.name==*normalized) {
            known=true;if (host.address.ipv6==(type==28)) hosts.push_back(host.address);
        }
        if (!known) return LocalResponseHosts{std::move(*normalized),{}};
        if (hosts.size()>64) return std::unexpected(ResolveError::limit);
        auto id=random_id();if (!id) return std::unexpected(id.error());
        auto wire=make_query(*id,{*normalized,type});if (!wire) return std::unexpected(ResolveError::protocol);
        (*wire)[2]=0x81;(*wire)[3]=0x80;(*wire)[6]=static_cast<std::uint8_t>(hosts.size()>>8);(*wire)[7]=static_cast<std::uint8_t>(hosts.size());
        for (auto const& host:hosts) {
            wire->insert(wire->end(),{0xc0,0x0c,static_cast<std::uint8_t>(type>>8),static_cast<std::uint8_t>(type),0,1,0,0,0,0,0,static_cast<std::uint8_t>(type==1 ? 4 : 16)});
            wire->insert(wire->end(),host.address.begin(),host.address.begin()+(type==1 ? 4 : 16));
        }
        auto response=parse_owned_response(std::move(*wire),*id,{*normalized,type});if (!response) return std::unexpected(ResolveError::protocol);
        return LocalResponseHosts{std::move(*normalized),std::move(*response)};
    }
    inline auto local_response_candidates(LocalConfig const& config,std::string_view input,std::string const& normalized)
        -> std::expected<std::vector<std::string>,ResolveError> {
        if (config.servers.empty() || config.servers.size()>3 || !config.attempts || config.attempts>5 || !config.timeout_seconds ||
            config.timeout_seconds>30 || config.search.size()>6 || config.ndots>15) return std::unexpected(ResolveError::state);
        return local_search_candidates(config,input,normalized);
    }
    // One transaction and one executor. Cache view identifies endpoint,
    // transport, EDNS and configuration epoch. Cancellation is serialized
    // with run and the owner stays alive until it returns.
    class ResponseQuery {
        using Clock=std::chrono::steady_clock;
        dns_io::io_context& context_;
        ResponseCache& cache_;
        std::optional<FallbackQuery> active_;
        bool started_=false,canceled_=false;
        static auto millis(Clock::time_point time) noexcept -> std::uint64_t {
            auto value=std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
            return value<0 ? 0 : static_cast<std::uint64_t>(value);
        }
    public:
        ResponseQuery(dns_io::io_context& context,ResponseCache& cache) noexcept : context_(context),cache_(cache) {}
        ResponseQuery(ResponseQuery const&)=delete;
        auto cancel() noexcept -> void { canceled_=true;if (active_) active_->cancel(); }
        auto run(dns_io::endpoint upstream,std::uint64_t view,Question question,Clock::time_point deadline,
                 bool tcp=false,bool edns=false,bool disable_cache=false,std::optional<ClientSubnet> subnet={},
                 ProtectedQuery const* protection=nullptr)
            -> dns_capy::task<std::expected<Response,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            if (subnet && !valid_client_subnet(*subnet)) co_return std::unexpected(ResolveError::state);
            // This cache's key does not independently encode ECS. Coordinated
            // callers can publish under their subnet-specific view instead.
            if (subnet) disable_cache=true;
            auto start=Clock::now();if (start>=deadline) co_return std::unexpected(ResolveError::timeout);
            auto id=random_id();if (!id) co_return std::unexpected(id.error());
            CacheKey key{view,question.name,question.type};
            if (!disable_cache) {
                auto found=cache_.lookup(key,millis(start),*id,edns);
                if (found && *found) co_return std::move(**found);
            }
            std::optional<CacheToken> token;
            if (!disable_cache) { auto value=cache_.begin(key,edns);if (value) token=*value; }
            struct Registration {
                ResponseCache& cache;std::optional<CacheToken>& token;
                ~Registration() { if (token) (void)cache.cancel(*token); }
            } registration{cache_,token};
            bool extended=edns || subnet.has_value();
            for (;;) {
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                if (Clock::now()>=deadline) co_return std::unexpected(ResolveError::timeout);
                active_.emplace(context_,tcp,nullptr,protection);
                QueryMessage query{*id,0x0100,question,extended ? std::optional<QueryEdns>{QueryEdns{1232,0,false,{}}} : std::nullopt};
                if(subnet && !set_query_client_subnet(query,subnet))co_return std::unexpected(ResolveError::protocol);
                auto response=co_await active_->query_borrowed(upstream,query,deadline);
                active_.reset();
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                if (!response) co_return std::unexpected(response.error()==UdpError::budget_exhausted ? ResolveError::budget_exhausted : response.error()==UdpError::timeout ? ResolveError::timeout :
                    response.error()==UdpError::canceled ? ResolveError::canceled :
                    response.error()==UdpError::transport ? ResolveError::transport : ResolveError::protocol);
                if (extended && response->rcode==1 && !response->edns) {
                    if(subnet)co_return std::unexpected(ResolveError::protocol);
                    extended=false;id=random_id();if (!id) co_return std::unexpected(id.error());continue;
                }
                if (response->edns ? (!extended || response->edns->version || response->edns->flags || response->edns->option_count>(subnet ? 1u : 0u))
                                   : (extended && !subnet)) co_return std::unexpected(ResolveError::protocol);
                if(subnet) {
                    if(!validate_response_ecs(query,*response))co_return std::unexpected(ResolveError::protocol);
                    if(response->edns && response->edns->option_count) {
                        auto opt=std::ranges::find(response->records,std::uint16_t{41},&Record::type);
                        if(opt==response->records.end() || opt->data_length<4 || response->wire[opt->data_offset]!=0 || response->wire[opt->data_offset+1]!=8)
                            co_return std::unexpected(ResolveError::protocol);
                    }
                }
                auto now=Clock::now();auto elapsed=std::chrono::ceil<std::chrono::seconds>(now-start).count();
                if (!age_response(*response,elapsed<0 ? 0 : static_cast<std::uint64_t>(elapsed),*id))
                    co_return std::unexpected(ResolveError::protocol);
                if (token && cache_.publish(key,*response,millis(now),*token)) token.reset();
                co_return std::move(*response);
            }
        }
    };
}
