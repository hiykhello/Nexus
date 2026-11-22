export module dns.message_exchange;
import std;
import dns.message;
import dns.message_fakeip;
import dns.input_budget;
import dns.response_program;
import dns.message_cache;
import dns.response_query;
import dns.local_config;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace dns {
    struct MessageLocalSource {
        LocalSnapshotSource& snapshots;
        std::atomic<std::uint64_t> rotation{0};
    };
    struct MessageUpstream { nex::corosio::endpoint endpoint;bool tcp;MessageLocalSource* local;std::string host;std::uint16_t port=0;std::optional<std::size_t> resolver; std::shared_ptr<detail::ProtectedQuery const> protection{};
#ifdef NEXUS_DNS_FAKEIP
        FakeIpPublisher const* fakeip = nullptr;
#endif
    };
    // One query owns its transport and bootstrap cancellation state. The
    // immutable client query, upstreams and cache outlive it through drain.
    class MessageExchange {
        using Clock=std::chrono::steady_clock;
        nex::corosio::io_context& context_;
        std::span<MessageUpstream const> upstreams_;
        MessageCache* cache_;
        QueryMessage const& query_;
        InputBudget& override_budget_;
        std::optional<InputBudget::Lease> override_lease_;
        std::optional<QueryMessage> upstream_query_;
        ResponseStep step_;
        Clock::time_point until_;
        std::uint64_t policy_view_;
        std::optional<detail::MessageQuery> active_;
        std::optional<detail::AddressResolver> bootstrap_;
        MessageCache::QueryFlight* flight_=nullptr;
        bool started_=false,canceled_=false,local_synthetic_=false;
        // A refresh owns its cache generation and transport. Retiring the
        // listener cancels that generation before the executor is drained.
        static auto refresh(nex::corosio::io_context& context,std::shared_ptr<MessageCache> cache,MessageCache::Ticket ticket,
            nex::corosio::endpoint endpoint,QueryMessage query,Clock::time_point until,bool tcp,
            std::shared_ptr<detail::ProtectedQuery const> protection,InputBudget::Lease reservation)
            -> nex::capy::task<>;

        auto start_refresh(std::shared_ptr<MessageCache> cache,MessageCache::Ticket ticket,nex::corosio::endpoint endpoint,
            QueryMessage const& query,Clock::time_point until,std::size_t server,bool tcp) -> void;

        static auto run_flight(nex::corosio::io_context& context,std::shared_ptr<MessageCache::QueryFlight> flight,
            nex::corosio::endpoint endpoint,QueryMessage query,bool tcp,
            std::shared_ptr<detail::ProtectedQuery const> protection,InputBudget::Lease reservation)
            -> nex::capy::task<MessageCache::QueryFlight::Result>;

        auto coalesced(MessageCache::JoinedQuery joined,nex::corosio::endpoint endpoint,QueryMessage const& query,
            Clock::time_point until,std::size_t server,bool tcp) -> nex::capy::task<MessageCache::QueryFlight::Result>;

        auto exchange(nex::corosio::endpoint endpoint,QueryMessage const& query,Clock::time_point until,
            std::size_t server,bool tcp,bool disabled,std::shared_ptr<LocalSnapshot const> snapshot={})
            -> nex::capy::task<std::expected<Bytes,detail::ResolveError>>;
    public:
        MessageExchange(nex::corosio::io_context& context,std::span<MessageUpstream const> upstreams,
            MessageCache* cache,QueryMessage const& query,ResponseStep step,Clock::time_point until,
            InputBudget* override_budget=nullptr,std::uint64_t policy_view=0)
            :context_(context),upstreams_(upstreams),cache_(cache),query_(query),
             override_budget_(override_budget ? *override_budget : default_message_override_budget()),
             step_(step),until_(until),policy_view_(policy_view) {}
        MessageExchange(nex::corosio::io_context&,std::span<MessageUpstream const>,MessageCache*,QueryMessage&&,
            ResponseStep,Clock::time_point,InputBudget* =nullptr,std::uint64_t=0)=delete;
        MessageExchange(nex::corosio::io_context&,std::span<MessageUpstream const>,MessageCache*,QueryMessage const&&,
            ResponseStep,Clock::time_point,InputBudget* =nullptr,std::uint64_t=0)=delete;
        MessageExchange(MessageExchange const&)=delete;
        auto operator=(MessageExchange const&) -> MessageExchange& = delete;
        auto cancel() noexcept -> void {
            canceled_=true;
            if (active_) active_->cancel();
            if (bootstrap_) bootstrap_->cancel();
            if (flight_) flight_->changed.set();
        }
        [[nodiscard]] auto upstream_query() const noexcept -> QueryMessage const& {return upstream_query_ ? *upstream_query_ : query_;}
        [[nodiscard]] auto local_synthetic() const noexcept -> bool {return local_synthetic_;}
        auto run() -> nex::capy::task<std::expected<Bytes,detail::ResolveError>>;
    };
    struct EvaluatedMessage {
        std::optional<InputBudget::Lease> lease;
        Bytes wire;
        ResponseEcsView upstream_ecs;
        bool local_synthetic;
        EvaluatedMessage(Bytes bytes,ResponseEcsView view,bool synthetic,std::optional<InputBudget::Lease> reservation={}) noexcept
            :lease(std::move(reservation)),wire(std::move(bytes)),upstream_ecs(view),local_synthetic(synthetic) {}
        EvaluatedMessage(EvaluatedMessage const&)=delete;
        auto operator=(EvaluatedMessage const&) -> EvaluatedMessage& = delete;
        EvaluatedMessage(EvaluatedMessage&&) noexcept = default;
        auto operator=(EvaluatedMessage&& other) noexcept -> EvaluatedMessage& {
            if(this!=&other) {
                Bytes{}.swap(wire);
                lease=std::move(other.lease);
                wire=std::move(other.wire);upstream_ecs=other.upstream_ecs;local_synthetic=other.local_synthetic;
            }
            return *this;
        }
    };
    // Each concurrent owner slot keeps the actual query view alongside its
    // wire result. ECS restoration must use the winning slot's view.
    class EvaluatedMessageExchange {
        MessageExchange exchange_;
    public:
        EvaluatedMessageExchange(nex::corosio::io_context& context,std::span<MessageUpstream const> upstreams,
            MessageCache* cache,QueryMessage const& query,ResponseStep step,std::chrono::steady_clock::time_point until,
            InputBudget* override_budget=nullptr,std::uint64_t policy_view=0)
            :exchange_(context,upstreams,cache,query,step,until,override_budget,policy_view) {}
        EvaluatedMessageExchange(nex::corosio::io_context&,std::span<MessageUpstream const>,MessageCache*,QueryMessage&&,
            ResponseStep,std::chrono::steady_clock::time_point,InputBudget* =nullptr,std::uint64_t=0)=delete;
        EvaluatedMessageExchange(nex::corosio::io_context&,std::span<MessageUpstream const>,MessageCache*,QueryMessage const&&,
            ResponseStep,std::chrono::steady_clock::time_point,InputBudget* =nullptr,std::uint64_t=0)=delete;
        EvaluatedMessageExchange(EvaluatedMessageExchange const&)=delete;
        auto operator=(EvaluatedMessageExchange const&) -> EvaluatedMessageExchange& = delete;
        auto cancel() noexcept -> void {exchange_.cancel();}
        auto run() -> nex::capy::task<std::expected<EvaluatedMessage,detail::ResolveError>>;
    };
}
