export module dns.local_response;
import std;
import dns.response_query;
import dns.local_config;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace dns::detail {
    struct LocalResponseSelection { Response response;dns_io::endpoint upstream;bool tcp;std::string question;bool local=true;std::shared_ptr<ProtectedQuery const> protection{}; };
    // Origin and budget stay with the response selected by a later respond.
    struct EvaluatedResponseMeta {
        dns_io::endpoint upstream;bool tcp;std::string question;bool local,empty;
        std::chrono::steady_clock::time_point deadline;
        std::optional<ClientSubnet> subnet;
        std::shared_ptr<ProtectedQuery const> protection{};
    };
    // Adapter owns cancellation and returns a complete response from its
    // generation-scoped view. The same algorithm serves stream and datagram
    // callers without introducing an additional forwarding coroutine.
    template<class Lookup>
    class BasicLocalResponseResolver {
        using Clock=std::chrono::steady_clock;
        Lookup& lookup_;
        std::shared_ptr<LocalSnapshot const> snapshot_;
        std::size_t rotation_;
        std::optional<ClientSubnet> subnet_;
        bool canceled_=false,started_=false;
        std::size_t* next_rotation_=nullptr;
    public:
        BasicLocalResponseResolver(Lookup& lookup,std::shared_ptr<LocalSnapshot const> snapshot,std::size_t rotation,std::size_t* next_rotation=nullptr,std::optional<ClientSubnet> subnet={})
            : lookup_(lookup),snapshot_(std::move(snapshot)),rotation_(rotation),subnet_(subnet),next_rotation_(next_rotation) {}
        auto cancel() noexcept -> void { canceled_=true;lookup_.cancel(); }
        auto resolve(std::string const& name,std::uint16_t type,Clock::time_point deadline,bool disabled,
                     std::optional<std::string_view> fixed_candidate={})
            -> dns_capy::task<std::expected<LocalResponseSelection,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            if (!snapshot_) co_return std::unexpected(ResolveError::state);
            bool address_query = type == 1 || type == 28;
            std::optional<std::string> normalized;
            if (!address_query) normalized = normalize_local_name(name);
            if (address_query) {
                auto hosts = local_hosts_response(*snapshot_, name, type);
                if (!hosts) co_return std::unexpected(hosts.error());
                if (hosts->response) co_return LocalResponseSelection{std::move(*hosts->response), {}, false, std::move(hosts->question)};
                normalized = std::move(hosts->question);
            }
            if (!type || !normalized) co_return std::unexpected(ResolveError::protocol);
            auto const& config=snapshot_->config;auto candidates=local_response_candidates(config,name,*normalized);
            if (fixed_candidate && candidates) {
                auto canonical=normalize_local_name(*fixed_candidate);
                if (!canonical || std::ranges::find(*candidates,*canonical)==candidates->end()) co_return std::unexpected(ResolveError::protocol);
                candidates->assign(1,std::move(*canonical));
            }
            if (!candidates) co_return std::unexpected(candidates.error());
            auto rotation=config.rotate ? rotation_%config.servers.size() : 0;
            if (config.rotate && next_rotation_) *next_rotation_=rotation_;
            std::optional<LocalResponseSelection> last_negative;auto last=ResolveError::transport;
            for (auto const& candidate:*candidates) {
                bool negative=false;
                for (std::uint32_t attempt=0;attempt<config.attempts;++attempt) {
                    for (std::size_t index=0;index<config.servers.size();++index) {
                        if (canceled_) co_return std::unexpected(ResolveError::canceled);
                        auto now=Clock::now();if (now>=deadline) co_return std::unexpected(ResolveError::timeout);
                        auto const& server=config.servers[(rotation+index)%config.servers.size()];
                        dns_io::endpoint upstream;
                        if (server.ipv6) upstream={dns_io::ipv6_address(server.address),server.port};
                        else { dns_io::ipv4_address::bytes_type bytes{};std::copy_n(server.address.begin(),4,bytes.begin());upstream={dns_io::ipv4_address(bytes),server.port}; }
                        auto response=co_await lookup_.resolve(snapshot_,upstream,candidate,type,std::min(deadline,now+std::chrono::seconds(config.timeout_seconds)),config.use_tcp,disabled);
                        if (canceled_) co_return std::unexpected(ResolveError::canceled);
                        if (!response) { last=response.error();if (last==ResolveError::transport || last==ResolveError::timeout) continue;co_return std::unexpected(last); }
                        auto id=static_cast<std::uint16_t>((std::uint16_t(response->wire[0])<<8)|response->wire[1]);
                        if (response->rcode==3) {
                            if (address_query && !parse_nxdomain_alias(response->wire,id,{candidate,type},subnet_.has_value(),subnet_)) co_return std::unexpected(ResolveError::protocol);
                            last_negative=LocalResponseSelection{std::move(*response),upstream,config.use_tcp,candidate};negative=true;break;
                        }
                        if (response->rcode==2 || response->rcode==5) { last=response->rcode==2 ? ResolveError::server_failure : ResolveError::refused;continue; }
                        if (response->rcode!=0) co_return std::unexpected(ResolveError::protocol);
                        if (!address_query) co_return LocalResponseSelection{std::move(*response),upstream,config.use_tcp,candidate};
                        auto answer=parse_addresses(response->wire,id,{candidate,type},subnet_.has_value(),subnet_);if (!answer) co_return std::unexpected(ResolveError::protocol);
                        if (answer->addresses.empty() && negative_ttl(*response,answer->canonical_name)) {
                            for (auto const& record:response->records) {
                                if (record.section!=Section::answer) continue;
                                if (record.klass!=1 || record.type!=5 ||
                                    std::ranges::find(answer->chain,record.name)==answer->chain.end() || record.name==answer->canonical_name)
                                    co_return std::unexpected(ResolveError::protocol);
                            }
                            last_negative=LocalResponseSelection{std::move(*response),upstream,config.use_tcp,candidate};negative=true;break;
                        }
                        if (answer->addresses.empty() && answer->chain.size()==1) {
                            bool referral=false;
                            for (auto const& record:response->records) if (record.section==Section::authority && record.klass==1 && record.type==2 &&
                                (record.name=="." || record.name==answer->canonical_name ||
                                (answer->canonical_name.size()>record.name.size() && answer->canonical_name.ends_with(record.name) &&
                                 answer->canonical_name[answer->canonical_name.size()-record.name.size()-1]=='.'))) referral=true;
                            co_return std::unexpected(referral ? ResolveError::referral : ResolveError::indeterminate);
                        }
                        co_return LocalResponseSelection{std::move(*response),upstream,config.use_tcp,candidate};
                    }
                    if (negative) break;
                }
                if (!negative) co_return std::unexpected(last);
            }
            if (last_negative) co_return std::move(*last_negative);
            co_return std::unexpected(last);
        }
    };
}
