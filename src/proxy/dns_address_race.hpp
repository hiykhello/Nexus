// Private to the proxy DNS implementation.
class AddressRaceOperation {
    Session& session_;
    nex::corosio::io_context& context_;
    dns::ResponseStep step_;
    Clock::time_point deadline_;
    std::string name_;
    std::uint16_t type_,port_;
    std::shared_ptr<dns::LocalSnapshot const> snapshot_;
    bool rewrite_possible_,canceled_=false;
    std::size_t* rotation_;
    std::optional<std::string> candidate_;
    DnsSlot slot_;
public:
    AddressRaceOperation(Session& session,nex::corosio::io_context& context,dns::ResponseStep step,Clock::time_point deadline,
        std::string const& name,std::uint16_t type,std::uint16_t port,std::shared_ptr<dns::LocalSnapshot const> snapshot,
        bool rewrite_possible,std::size_t* rotation,std::optional<std::string_view> candidate)
        :session_(session),context_(context),step_(step),deadline_(deadline),name_(name),type_(type),port_(port),
         snapshot_(std::move(snapshot)),rewrite_possible_(rewrite_possible),rotation_(rotation),
         candidate_(candidate ? std::optional<std::string>(*candidate) : std::nullopt) {}
    auto cancel() noexcept -> void {canceled_=true;slot_.cancel();}
    auto run() -> nex::capy::task<dns::AddressRaceResult> {
        using Error=dns::detail::ResolveError;
        if(canceled_ || session_.closed)co_return std::unexpected(Error::canceled);
        if(step_.action==policy::DnsAction::evaluate) {
            auto result=co_await resolve_response_owned(session_,context_,slot_,step_.server,name_,type_,deadline_,snapshot_,
                step_.disable_cache || rewrite_possible_,rotation_,candidate_,step_.subnet.value_or(std::nullopt));
            if(!result)co_return std::unexpected(result.error());
            co_return dns::AddressRaceValue{std::move(*result)};
        }
        if(step_.action!=policy::DnsAction::route || step_.server>=session_.dns->routing.servers.size())co_return std::unexpected(Error::state);
        auto local=!session_.dns->routing.servers[step_.server].port;
        auto name=local && candidate_ ? *candidate_+"." : name_;
        auto family=type_==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
        dns::detail::FamilyCachePolicy cache{};cache[type_==1 ? 0 : 1]=step_.disable_cache || rewrite_possible_;
        auto result=co_await resolve_dns_value<true>(session_,context_,step_.server,std::move(name),port_,family,deadline_,
            slot_.operation,slot_.cancel_operation,&slot_.canceled,snapshot_ ? &snapshot_ : nullptr,cache,step_.subnet.value_or(std::nullopt));
        if(canceled_ || session_.closed)co_return std::unexpected(Error::canceled);
        if(!result)co_return std::unexpected(result.error());
        co_return dns::AddressRaceValue{std::move(*result)};
    }
};
struct AddressRaceFactory {
    Session& session;
    nex::corosio::io_context& context;
    std::string const& name;
    std::uint16_t type,port;
    std::shared_ptr<dns::LocalSnapshot const> snapshot;
    bool rewrite_possible;
    std::size_t& rotation;
    std::string const& candidate;
    std::optional<std::pair<std::size_t,std::string>>& local_candidate;
    auto operator()(dns::ResponseStep step,Clock::time_point until) -> std::unique_ptr<AddressRaceOperation> {
        auto fixed=!candidate.empty() ? std::optional<std::string_view>{candidate} :
            local_candidate && local_candidate->first==step.server ? std::optional<std::string_view>{local_candidate->second} : std::nullopt;
        return std::make_unique<AddressRaceOperation>(session,context,step,until,name,type,port,snapshot,rewrite_possible,&rotation,fixed);
    }
    auto completed(dns::ResponseStep const& step,dns::detail::EvaluatedResponseMeta const& meta) -> void {
        dns::AddressRaceLocalCandidate{local_candidate}.completed(step,meta);
    }
};
