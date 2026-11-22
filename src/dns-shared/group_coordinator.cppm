module;

// Coordinated DNS boundary. The shared cache,
// coordinator, worker owners, operations, readers and contexts have strict
// nested lifetimes; stop and drain all operations before destroying owners.
export module dns.shared_coordinator;
import std;
import dns.corosio_cached;
import dns.local_config;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.response_query;
import dns.response_cache;
import dns.response_match;
import dns.shared_cache;
import dns.reverse;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "group_coalesced_resolve.hpp"

export {
#include "group_view_registry.hpp"
}

#ifdef NEXUS_DNS_RESPONSE
namespace dns_hp_experiment {
    class ResponseFlightOwner {
        using Clock=std::chrono::steady_clock;
        struct Entry {
            FlightGroup::Flight* flight;
            d::detail::ResponseQuery query;
            bool finished=false;
            Entry(FlightGroup::Flight*,io::io_context&,d::ResponseCache&);
        };
        io::io_context& context_;d::ResponseCache& cache_;FlightGroup& group_;
        std::map<std::uint64_t,std::unique_ptr<Entry>> active_;
        std::uint64_t next_=0;bool stopped_=false;
        std::chrono::milliseconds timeout_;
        static auto ms(Clock::time_point) noexcept -> std::uint64_t;
        auto monitor(Entry&) -> capy::task<capy::results<>>;
        auto work(Entry&) -> capy::task<capy::results<>>;
        auto run(Entry&) -> capy::task<capy::results<>>;
        auto done(std::uint64_t) noexcept -> void;
    public:
        ResponseFlightOwner(io::io_context&,d::ResponseCache&,FlightGroup&,std::chrono::milliseconds);
        ~ResponseFlightOwner();
        ResponseFlightOwner(ResponseFlightOwner const&)=delete;
        auto start(FlightGroup::Flight*) noexcept -> void;
        auto stop() noexcept -> void;
        [[nodiscard]] auto available() const noexcept -> bool;
        [[nodiscard]] auto drained() const noexcept -> bool;
    };
    struct ResponseOperationTraits {
        using Owner=ResponseFlightOwner;
        using Result=FlightGroup::RawResult;
        struct Delivery { Result answer;bool expired=false; };
        struct Rechecked { Result answer;std::optional<FlightGroup::Clock::time_point> expires; };
        using Clock=FlightGroup::Clock;
        static auto delivered(FlightGroup&,FlightGroup::Waiter const&) -> std::optional<Delivery>;
        static auto age_cached(Rechecked&,Clock::time_point) -> void;
        static auto complete_cached(FlightGroup&,FlightGroup::Flight*,Rechecked&) -> void;
    };
}

#endif

export namespace dns_hp_experiment {
    enum class CoordinatedError {
        state,random,transport,timeout,canceled,protocol,alias_loop,limit,
        name_not_found,no_data,referral,indeterminate,server_failure,refused,policy_rejected,budget_exhausted
    };
    enum class CoordinatedStrategy { prefer_ipv4,prefer_ipv6,ipv4_only,ipv6_only };
    using CoordinatedResult=std::expected<std::vector<dns::Address>,CoordinatedError>;

    class Coordinator {
        FlightGroup group_;
        friend class CoordinatorOwner;
        friend class ResponseCoordinatorOwner;
    public:
        Coordinator(std::size_t flights,std::size_t waiters);
        ~Coordinator();
        Coordinator(Coordinator const&)=delete;
        auto operator=(Coordinator const&) -> Coordinator& = delete;
        [[nodiscard]] auto counts() const noexcept -> std::pair<std::size_t,std::size_t>;
        [[nodiscard]] auto direct_active() const noexcept -> std::size_t;
    };
#ifdef NEXUS_DNS_RESPONSE
    class ResponseCoordinatorOwner {
        nex::corosio::io_context& context_;
        dns::ResponseCache& cache_;
        FlightGroup& group_;
        ResponseFlightOwner owner_;
        friend class ResponseCoordinatorQuery;
    public:
        ResponseCoordinatorOwner(nex::corosio::io_context&,dns::ResponseCache&,Coordinator&,
                                 std::chrono::milliseconds timeout=std::chrono::seconds(5));
        ~ResponseCoordinatorOwner();
        ResponseCoordinatorOwner(ResponseCoordinatorOwner const&)=delete;
        auto stop() noexcept -> void;
        [[nodiscard]] auto drained() const noexcept -> bool;
    };
    class ResponseCoordinatorQuery {
        using Clock=std::chrono::steady_clock;
        ResponseCoordinatorOwner& owner_;
        BasicFlightOperation<ResponseOperationTraits> operation_;
        std::optional<dns::detail::ResponseQuery> direct_;
        bool started_=false,canceled_=false;
        static auto millis(Clock::time_point) noexcept -> std::uint64_t;
        static auto from_ms(std::uint64_t) noexcept -> Clock::time_point;
    public:
        explicit ResponseCoordinatorQuery(ResponseCoordinatorOwner&);
        ~ResponseCoordinatorQuery();
        ResponseCoordinatorQuery(ResponseCoordinatorQuery const&)=delete;
        auto cancel() noexcept -> void;
        // A supplied subnet must also be represented by the caller's view.
        auto resolve(nex::corosio::endpoint,std::uint64_t,dns::Question,Clock::time_point,bool tcp=false,bool edns=false,bool disable_cache=false,
                     std::optional<dns::ClientSubnet> subnet={},
                     std::shared_ptr<dns::detail::ProtectedQuery const> protection={})
            -> nex::capy::task<FlightGroup::RawResult>;
    };
#endif
    class CoordinatorOwner {
        nex::corosio::io_context& context_;
        GroupBinding& cache_;
        FlightGroup& group_;
        FlightOwner<GroupBinding> owner_;
        friend class CoordinatorQuery;
    public:
        // All methods, completions and queries on this owner run on the same
        // serialized executor. The coordinator and cache outlive the owner.
        CoordinatorOwner(nex::corosio::io_context&,GroupBinding&,Coordinator&,
                         std::chrono::milliseconds timeout=std::chrono::seconds(5));
        ~CoordinatorOwner();
        CoordinatorOwner(CoordinatorOwner const&)=delete;
        auto operator=(CoordinatorOwner const&) -> CoordinatorOwner& = delete;
        auto stop() noexcept -> void;
        [[nodiscard]] auto drained() const noexcept -> bool;
    };
    class CoordinatorQuery {
        CoalescedDualResolver<GroupBinding> resolver_;
    public:
        // Each query owns its operation until resolve() returns or unwinds;
        // cancel() and resolve() are serialized on the owner's executor. If
        // subnet is set, view must be obtained with the same subnet from the
        // corresponding view registry; it is part of the cache identity.
        CoordinatorQuery(CoordinatorOwner&,GroupBinding::Reader*,CoordinatedStrategy,
                         bool tcp=false,bool disable_cache=false,bool edns=false,bool optimistic=false,
                         std::optional<dns::detail::FamilyCachePolicy> cache_policy={},
                         std::optional<dns::ClientSubnet> subnet={},
                         std::shared_ptr<dns::detail::ProtectedQuery const> protection={});
        ~CoordinatorQuery();
        CoordinatorQuery(CoordinatorQuery const&)=delete;
        auto operator=(CoordinatorQuery const&) -> CoordinatorQuery& = delete;
        auto cancel() noexcept -> void;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        auto observe_reverse_for_test(dns::ReverseCache& cache) noexcept -> void { resolver_.observe_reverse_for_test(cache); }
#endif
        [[nodiscard]] auto resolve(nex::corosio::endpoint,std::uint64_t view,std::string name,
                                   std::chrono::steady_clock::time_point deadline) -> nex::capy::task<CoordinatedResult>;
        [[nodiscard]] auto resolve_native(nex::corosio::endpoint,std::uint64_t view,std::string name,
            std::chrono::steady_clock::time_point deadline)
            -> nex::capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>>;
        [[nodiscard]] auto resolve_answer(nex::corosio::endpoint,std::uint64_t view,std::string name,
            std::chrono::steady_clock::time_point deadline)
            -> nex::capy::task<std::expected<dns::AddressAnswer,dns::detail::ResolveError>>;
    };

    // A local configuration snapshot is part of a view's identity. Weak keys
    // permit old hosts/resolver files to be reclaimed after in-flight queries
    // drain; monotonically assigned IDs are never reused in this generation.
    class LocalViewRegistry {
        using Snapshot=dns::LocalSnapshot;
        using Endpoint=nex::corosio::endpoint;
        struct Entry { std::weak_ptr<Snapshot const> snapshot; Endpoint endpoint; std::optional<dns::ClientSubnet> subnet; std::uint64_t id; };
        std::mutex mutex_;
        std::vector<Entry> entries_;
        std::uint64_t next_=std::uint64_t{1}<<63;
    public:
        [[nodiscard]] auto view(std::shared_ptr<Snapshot const> const& snapshot,Endpoint endpoint,std::optional<dns::ClientSubnet> subnet={})
            -> std::expected<std::uint64_t,dns::detail::ResolveError> {
            using Error=dns::detail::ResolveError;
            if (!snapshot || !endpoint.port() || (subnet && !dns::valid_client_subnet(*subnet))) return std::unexpected(Error::state);
            std::lock_guard lock(mutex_);
            std::erase_if(entries_,[](Entry const& item) { return item.snapshot.expired(); });
            for (auto const& item:entries_) if (item.endpoint==endpoint && item.subnet==subnet && item.snapshot.lock()==snapshot) return item.id;
            if (entries_.size()>=4096 || next_==std::numeric_limits<std::uint64_t>::max())
                return std::unexpected(Error::limit);
            try { auto id=next_; entries_.push_back({snapshot,endpoint,subnet,id}); ++next_; return id; }
            catch (std::bad_alloc const&) { return std::unexpected(Error::limit); }
        }
    };
    class LocalViewBinding {
        LocalViewRegistry& registry_;
        std::weak_ptr<dns::LocalSnapshot const> snapshot_;
        std::optional<nex::corosio::endpoint> endpoint_;
        std::optional<dns::ClientSubnet> subnet_;
        std::uint64_t view_=0;
    public:
        explicit LocalViewBinding(LocalViewRegistry& registry) : registry_(registry) {}
        [[nodiscard]] auto view(std::shared_ptr<dns::LocalSnapshot const> const& snapshot,nex::corosio::endpoint endpoint,std::optional<dns::ClientSubnet> subnet={})
            -> std::expected<std::uint64_t,dns::detail::ResolveError> {
            if (endpoint_ && *endpoint_==endpoint && subnet_==subnet && snapshot_.lock()==snapshot) return view_;
            auto result=registry_.view(snapshot,endpoint,subnet);
            if (result) { snapshot_=snapshot; endpoint_=endpoint; subnet_=subnet; view_=*result; }
            return result;
        }
    };
    class LocalCoordinatedResolver {
        CoordinatorOwner& owner_;
        GroupBinding::Reader& reader_;
        LocalViewBinding& views_;
        std::shared_ptr<dns::LocalSnapshot const> snapshot_;
        dns::detail::AddressStrategy family_;
        std::size_t rotation_;
        bool disable_cache_,canceled_=false;
        std::optional<dns::detail::FamilyCachePolicy> cache_policy_;
        std::optional<dns::ClientSubnet> subnet_;
        std::optional<CoordinatorQuery> active_;
        template<bool Full>
        auto resolve_endpoint(nex::corosio::endpoint,bool,dns::detail::AddressStrategy,std::string const&,
            std::chrono::steady_clock::time_point)
            -> nex::capy::task<std::expected<dns::detail::AddressResult<Full>,dns::detail::ResolveError>>;
        template<bool Full>
        auto resolve_local(std::string,std::chrono::steady_clock::time_point)
            -> nex::capy::task<std::expected<dns::detail::AddressResult<Full>,dns::detail::ResolveError>>;
    public:
        LocalCoordinatedResolver(CoordinatorOwner&,GroupBinding::Reader&,LocalViewBinding&,
            std::shared_ptr<dns::LocalSnapshot const>,dns::detail::AddressStrategy,
            std::size_t rotation,bool disable_cache,std::optional<dns::detail::FamilyCachePolicy> cache_policy={},
            std::optional<dns::ClientSubnet> subnet={});
        LocalCoordinatedResolver(LocalCoordinatedResolver const&)=delete;
        auto operator=(LocalCoordinatedResolver const&) -> LocalCoordinatedResolver& = delete;
        auto cancel() noexcept -> void;
        auto finish() noexcept -> void;
        auto resolve(nex::corosio::endpoint,bool,dns::detail::AddressStrategy,std::string const&,
                     std::chrono::steady_clock::time_point)
            -> nex::capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>>;
        auto resolve(std::string,std::chrono::steady_clock::time_point)
            -> nex::capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>>;
        auto resolve_answer(nex::corosio::endpoint,bool,dns::detail::AddressStrategy,std::string const&,
            std::chrono::steady_clock::time_point)
            -> nex::capy::task<std::expected<dns::AddressAnswer,dns::detail::ResolveError>>;
        auto resolve_answer(std::string,std::chrono::steady_clock::time_point)
            -> nex::capy::task<std::expected<dns::AddressAnswer,dns::detail::ResolveError>>;
    };
}
