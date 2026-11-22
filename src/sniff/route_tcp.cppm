export module sniff.route_tcp;
import std;
import rules;
import sniff.tcp;
import sniff.tcp_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace sniff {
    // Own the exact DNS candidate order for the lifetime of rule evaluation.
    // Replacement is transactional; published views stay valid only until the
    // next successful replacement or destruction of this owner.
    class RouteCandidates {
        std::array<rules::ProgramAddress,256> addresses_{};
        std::size_t size_=0;
        bool resolved_=false;
    public:
        RouteCandidates()=default;
        RouteCandidates(RouteCandidates const&)=delete;
        auto operator=(RouteCandidates const&) -> RouteCandidates& = delete;
        [[nodiscard]] auto assign(std::span<nex::corosio::endpoint const> endpoints,rules::ProgramInput& input) noexcept -> bool {
            if(input.ip || endpoints.size()>addresses_.size())return false;
            std::array<rules::ProgramAddress,256> next{};
            for(std::size_t i=0;i<endpoints.size();++i) {
                auto address=endpoints[i].address();
                if(address.is_v4()) {auto bytes=address.to_v4().to_bytes();next[i].size=4;std::ranges::copy(bytes,next[i].bytes.begin());}
                else if(address.is_v6()) {auto bytes=address.to_v6().to_bytes();next[i].size=16;std::ranges::copy(bytes,next[i].bytes.begin());}
                else return false;
            }
            addresses_=next;size_=endpoints.size();resolved_=true;input.candidates=view();return true;
        }
        [[nodiscard]] auto view() const noexcept -> std::optional<std::span<rules::ProgramAddress const>> {
            if(!resolved_)return {};
            return std::span(addresses_).first(size_);
        }
    };
    // The pre-read buffer is borrowed through replay. Feeding occurs once,
    // before the socket reader starts, so a parser that finishes early or
    // fills its budget cannot discard the remaining bytes.
    class TcpPrefetch {
        std::span<std::uint8_t const> tail_;
        bool fed_=false;
    public:
        TcpPrefetch()=default;
        TcpPrefetch(TcpPrefetch const&)=delete;
        auto operator=(TcpPrefetch const&) -> TcpPrefetch& = delete;
        [[nodiscard]] auto feed(TcpSniffer& sniffer,std::span<std::uint8_t const> bytes) noexcept -> bool {
            if(fed_)return false;
            fed_=true;
            auto result=sniffer.feed(bytes);
            tail_=bytes.subspan(result.consumed);
            return true;
        }
        [[nodiscard]] auto tail() const noexcept -> std::span<std::uint8_t const> {return tail_;}
    };
    enum class RouteResolveError { state,deadline,lookup,invalid_candidates };
    // Resolver returns expected<vector<endpoint>, E> and owns cancellation of
    // its in-flight lookup. Its deadline is the request's absolute deadline.
    // The caller retains endpoints for dialing and candidates for matching.
    template<class Resolver>
    auto resolve_tcp_action(rules::ProgramCursor& cursor,rules::ProgramStep step,rules::ProgramInput& input,
        RouteCandidates& candidates,std::vector<nex::corosio::endpoint>& endpoints,Resolver& resolver,
        std::chrono::steady_clock::time_point deadline) -> nex::capy::task<std::expected<void,RouteResolveError>> {
        auto pending=cursor.pending();
        if(!pending || pending->rule_index!=step.rule_index || pending->next_index!=step.next_index ||
            pending->action.kind!=rules::ProgramActionKind::resolve || step.action.kind!=rules::ProgramActionKind::resolve ||
            pending->action!=step.action)co_return std::unexpected(RouteResolveError::state);
        if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(RouteResolveError::deadline);
        auto domain=input.fakeip_domain ? input.fakeip_domain : input.explicit_domain;
        if(!domain) {
            if(!cursor.complete(step))co_return std::unexpected(RouteResolveError::state);
            co_return std::expected<void,RouteResolveError>{};
        }
        if(!input.port || !*input.port || input.ip)co_return std::unexpected(RouteResolveError::state);
        auto result=co_await resolver(*domain,*input.port,deadline);
        if(!result)co_return std::unexpected(RouteResolveError::lookup);
        if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(RouteResolveError::deadline);
        if(!candidates.assign(*result,input))co_return std::unexpected(RouteResolveError::invalid_candidates);
        endpoints=std::move(*result);
        if(!cursor.complete(step))co_return std::unexpected(RouteResolveError::state);
        co_return std::expected<void,RouteResolveError>{};
    }
    enum class RouteTcpStop { terminal,resolve,options,uncertain,exhausted,canceled,io_error,rule_error,state_error };
    enum class UnknownRoutePolicy { pause,skip };
    struct RouteTcpResult {
        RouteTcpStop stop;
        std::optional<rules::ProgramStep> step;
        std::optional<rules::Error> rule_error;
        std::error_code system{};
        std::optional<TcpReadResult> sniff;
    };
    // Program, cursor, socket, sniffer and all input views outlive this task.
    // The owner must replay sniffer.wire() and any unaccepted prefetched tail
    // exactly once after routing. Resolve remains an explicit pending action;
    // the owner supplies the result and acknowledges it before resuming.
    // Repeated sniff actions reuse the first result and deadline.
    template<class Reader>
    auto run_tcp_route_with_reader(rules::RouteProgram const& program,rules::ProgramCursor& cursor,
        rules::ProgramInput& input,TcpSniffer& sniffer,Reader& reader,
        std::chrono::steady_clock::time_point sniff_deadline,bool wait_unknown=true,
        UnknownRoutePolicy unknown_policy=UnknownRoutePolicy::pause)
        -> nex::capy::task<RouteTcpResult> {
        std::optional<TcpReadResult> last_sniff;
        for (;;) {
            auto result=cursor.poll(program,input,wait_unknown);
            if(!result)co_return {RouteTcpStop::rule_error,{},std::move(result.error()),{},last_sniff};
            if(result->kind==rules::ProgramPreflightKind::uncertain) {
                if(unknown_policy==UnknownRoutePolicy::pause)co_return {RouteTcpStop::uncertain,{},{},{},last_sniff};
                if(!cursor.skip_unknown(result->rule_index))co_return {RouteTcpStop::state_error,{},{},{},last_sniff};
                continue;
            }
            if(result->kind==rules::ProgramPreflightKind::exhausted)co_return {RouteTcpStop::exhausted,{},{},{},last_sniff};
            auto step=*result->step;
            if(step.terminal())co_return {RouteTcpStop::terminal,step,{},{},last_sniff};
            if(step.action.kind==rules::ProgramActionKind::resolve)co_return {RouteTcpStop::resolve,step,{},{},last_sniff};
            if(step.action.kind==rules::ProgramActionKind::route_options)co_return {RouteTcpStop::options,step,{},{},last_sniff};
            if(step.action.kind!=rules::ProgramActionKind::sniff)co_return {RouteTcpStop::state_error,step,{},{},last_sniff};
            last_sniff=co_await reader(sniffer,sniff_deadline);
            if(last_sniff->stop==TcpReadStop::canceled)co_return {RouteTcpStop::canceled,step,{},last_sniff->error,last_sniff};
            if(last_sniff->stop==TcpReadStop::io_error)co_return {RouteTcpStop::io_error,step,{},last_sniff->error,last_sniff};
            // An offered ECH extension can be GREASE, but the outer name is
            // not proof of the inner destination. Preserve it in the sniffer
            // for explicit policies without treating it as the target name.
            input.sniffed_domain=last_sniff->sniff.status==TcpStatus::matched &&
                last_sniff->sniff.name_kind!=TcpNameKind::tls_outer_ech ? last_sniff->sniff.domain : std::nullopt;
            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)]=
                last_sniff->sniff.status==TcpStatus::matched && last_sniff->sniff.name_kind==TcpNameKind::numeric;
            input.tls_ech.reset();
            switch(last_sniff->sniff.protocol) {
            case TcpProtocol::http: input.protocol=rules::Protocol::http;break;
            case TcpProtocol::tls:
                input.protocol=rules::Protocol::tls;
                input.tls_ech=last_sniff->sniff.name_kind==TcpNameKind::tls_outer_ech;
                break;
            case TcpProtocol::ssh:
                input.protocol=rules::Protocol::ssh;
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)]=true;
                break;
            case TcpProtocol::unknown: input.protocol.reset();break;
            }
            if(!cursor.complete(step))co_return {RouteTcpStop::state_error,step,{},{},last_sniff};
        }
    }

    template<class Socket>
    auto run_tcp_route(rules::RouteProgram const& program,rules::ProgramCursor& cursor,rules::ProgramInput& input,
        Socket& socket,TcpSniffer& sniffer,std::chrono::steady_clock::time_point deadline,bool wait_unknown=true,
        UnknownRoutePolicy unknown_policy=UnknownRoutePolicy::pause) -> nex::capy::task<RouteTcpResult> {
        auto reader=[&](TcpSniffer& target,auto limit) {return read_tcp_sniff(socket,target,limit);};
        co_return co_await run_tcp_route_with_reader(program,cursor,input,sniffer,reader,deadline,wait_unknown,unknown_policy);
    }

    enum class ReplayStatus { ready,active,complete,failed };
    // Borrowed segments are in receive order: bytes accepted by the sniffer,
    // then any pre-existing suffix that could not enter its bounded buffer.
    // A failed, canceled or abandoned write poisons the cursor so callers
    // cannot accidentally replay a partially transmitted prefix a second time.
    class TcpReplay {
        std::array<std::span<std::uint8_t const>,2> segments_;
        ReplayStatus status_=ReplayStatus::ready;
        std::size_t segment_=0,offset_=0;
    public:
        TcpReplay(std::span<std::uint8_t const> retained,std::span<std::uint8_t const> tail={}) noexcept
            :segments_{retained,tail} {}
        TcpReplay(TcpReplay const&)=delete;
        auto operator=(TcpReplay const&) -> TcpReplay& = delete;
        [[nodiscard]] auto status() const noexcept -> ReplayStatus {return status_;}
        [[nodiscard]] auto committed() const noexcept -> std::size_t {
            return segment_==0 ? offset_ : segment_==1 ? segments_[0].size()+offset_ : segments_[0].size()+segments_[1].size();
        }
        // The writer consumes an entire segment or reports failure. It may
        // have committed a prefix on failure, so failure poisons this replay.
        template<class Writer>
        auto send_all(Writer& writer,std::chrono::steady_clock::time_point deadline) -> nex::capy::task<bool> {
            if(status_!=ReplayStatus::ready)co_return false;
            status_=ReplayStatus::active;
            struct Guard {TcpReplay& replay;~Guard(){if(replay.status_==ReplayStatus::active)replay.status_=ReplayStatus::failed;}} guard{*this};
            while(segment_<segments_.size()) {
                auto pending=segments_[segment_].subspan(offset_);
                if(pending.empty()){++segment_;offset_=0;continue;}
                if(std::chrono::steady_clock::now()>=deadline)co_return false;
                auto [error]=co_await nex::corosio::timeout(writer(pending),deadline);
                if(error)co_return false;
                offset_+=pending.size();
            }
            status_=ReplayStatus::complete;co_return true;
        }
        template<class Socket>
        auto send(Socket& socket,std::chrono::steady_clock::time_point deadline) -> nex::capy::task<bool> {
            if(status_!=ReplayStatus::ready)co_return false;
            status_=ReplayStatus::active;
            struct Guard {TcpReplay& replay;~Guard(){if(replay.status_==ReplayStatus::active)replay.status_=ReplayStatus::failed;}} guard{*this};
            while(segment_<segments_.size()) {
                auto pending=segments_[segment_].subspan(offset_);
                if(pending.empty()){++segment_;offset_=0;continue;}
                if(std::chrono::steady_clock::now()>=deadline)co_return false;
                auto operation=socket.write_some(nex::capy::const_buffer(pending.data(),pending.size()));
                auto [error,size]=co_await nex::corosio::timeout(std::move(operation),deadline);
                if(size>pending.size())co_return false;
                offset_+=size;
                if(error || !size)co_return false;
            }
            status_=ReplayStatus::complete;co_return true;
        }
    };
}
