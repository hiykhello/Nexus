module;

module dns.shared_coordinator;
import std;
import dns.corosio_cached;
import dns.corosio_local;
import dns.message;
import dns.cache;
import dns.shared_cache;
import dns.reverse;
import capy;
import corosio;
namespace dns_hp_experiment {
    namespace d=dns;
    Coordinator::Coordinator(std::size_t flights,std::size_t waiters) : group_(flights,waiters) {}
    Coordinator::~Coordinator()=default;
    auto Coordinator::counts() const noexcept -> std::pair<std::size_t,std::size_t> { return group_.counts(); }
    auto Coordinator::direct_active() const noexcept -> std::size_t { return group_.direct_active(); }

    CoordinatorOwner::CoordinatorOwner(io::io_context& context,GroupBinding& cache,Coordinator& coordinator,std::chrono::milliseconds timeout)
        : context_(context),cache_(cache),group_(coordinator.group_),owner_(context,cache,group_,timeout) {}
    CoordinatorOwner::~CoordinatorOwner()=default;
    auto CoordinatorOwner::stop() noexcept -> void { owner_.stop(); }
    auto CoordinatorOwner::drained() const noexcept -> bool { return owner_.drained(); }

    namespace {
        auto strategy(CoordinatedStrategy value) -> d::detail::AddressStrategy {
            switch (value) {
            case CoordinatedStrategy::prefer_ipv4: return d::detail::AddressStrategy::prefer_ipv4;
            case CoordinatedStrategy::prefer_ipv6: return d::detail::AddressStrategy::prefer_ipv6;
            case CoordinatedStrategy::ipv4_only: return d::detail::AddressStrategy::ipv4_only;
            case CoordinatedStrategy::ipv6_only: return d::detail::AddressStrategy::ipv6_only;
            }
            throw std::invalid_argument("invalid coordinated DNS strategy");
        }
        auto error(d::detail::ResolveError value) noexcept -> CoordinatedError {
            switch (value) {
            case d::detail::ResolveError::state: return CoordinatedError::state;
            case d::detail::ResolveError::random: return CoordinatedError::random;
            case d::detail::ResolveError::transport: return CoordinatedError::transport;
            case d::detail::ResolveError::timeout: return CoordinatedError::timeout;
            case d::detail::ResolveError::canceled: return CoordinatedError::canceled;
            case d::detail::ResolveError::protocol: return CoordinatedError::protocol;
            case d::detail::ResolveError::alias_loop: return CoordinatedError::alias_loop;
            case d::detail::ResolveError::limit: return CoordinatedError::limit;
            case d::detail::ResolveError::name_not_found: return CoordinatedError::name_not_found;
            case d::detail::ResolveError::no_data: return CoordinatedError::no_data;
            case d::detail::ResolveError::referral: return CoordinatedError::referral;
            case d::detail::ResolveError::indeterminate: return CoordinatedError::indeterminate;
            case d::detail::ResolveError::server_failure: return CoordinatedError::server_failure;
            case d::detail::ResolveError::refused: return CoordinatedError::refused;
            case d::detail::ResolveError::policy_rejected: return CoordinatedError::policy_rejected;
            case d::detail::ResolveError::budget_exhausted: return CoordinatedError::budget_exhausted;
            }
            return CoordinatedError::state;
        }
    }
    CoordinatorQuery::CoordinatorQuery(CoordinatorOwner& owner,GroupBinding::Reader* reader,CoordinatedStrategy family,
                                       bool tcp,bool disable_cache,bool edns,bool optimistic,
                                       std::optional<d::detail::FamilyCachePolicy> cache_policy,std::optional<d::ClientSubnet> subnet,
                                       std::shared_ptr<d::detail::ProtectedQuery const> protection)
        : resolver_(owner.context_,owner.cache_,reader,owner.group_,owner.owner_,strategy(family),tcp,disable_cache,edns,nullptr,optimistic,cache_policy,subnet,std::move(protection)) {}
    CoordinatorQuery::~CoordinatorQuery()=default;
    auto CoordinatorQuery::cancel() noexcept -> void { resolver_.cancel(); }
    auto CoordinatorQuery::resolve_native(io::endpoint upstream,std::uint64_t view,std::string name,
        std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<std::vector<d::Address>,d::detail::ResolveError>> {
        return resolver_.resolve(upstream,view,std::move(name),deadline);
    }
    auto CoordinatorQuery::resolve_answer(io::endpoint upstream,std::uint64_t view,std::string name,
        std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<d::AddressAnswer,d::detail::ResolveError>> {
        return resolver_.resolve_answer(upstream,view,std::move(name),deadline);
    }
    auto CoordinatorQuery::resolve(io::endpoint upstream,std::uint64_t view,std::string name,
                                   std::chrono::steady_clock::time_point deadline) -> capy::task<CoordinatedResult> {
        auto result=co_await resolver_.resolve(upstream,view,std::move(name),deadline);
        if (!result) co_return std::unexpected(error(result.error()));
        co_return std::move(*result);
    }
    LocalCoordinatedResolver::LocalCoordinatedResolver(CoordinatorOwner& owner,GroupBinding::Reader& reader,
        LocalViewBinding& views,std::shared_ptr<d::LocalSnapshot const> snapshot,d::detail::AddressStrategy family,
        std::size_t rotation,bool disable_cache,std::optional<d::detail::FamilyCachePolicy> cache_policy,std::optional<d::ClientSubnet> subnet)
        : owner_(owner),reader_(reader),views_(views),snapshot_(std::move(snapshot)),family_(family),
          rotation_(rotation),disable_cache_(disable_cache),cache_policy_(cache_policy),subnet_(subnet) {}
    auto LocalCoordinatedResolver::cancel() noexcept -> void { canceled_=true; if (active_) active_->cancel(); }
    auto LocalCoordinatedResolver::finish() noexcept -> void { active_.reset(); }
    template<bool Full>
    auto LocalCoordinatedResolver::resolve_endpoint(io::endpoint endpoint,bool tcp,d::detail::AddressStrategy family,
        std::string const& name,std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<d::detail::AddressResult<Full>,d::detail::ResolveError>> {
        if (canceled_) co_return std::unexpected(d::detail::ResolveError::canceled);
        auto view=views_.view(snapshot_,endpoint,subnet_);
        if (!view) co_return std::unexpected(view.error());
        CoordinatedStrategy selected;
        switch (family) {
        case d::detail::AddressStrategy::prefer_ipv4: selected=CoordinatedStrategy::prefer_ipv4; break;
        case d::detail::AddressStrategy::prefer_ipv6: selected=CoordinatedStrategy::prefer_ipv6; break;
        case d::detail::AddressStrategy::ipv4_only: selected=CoordinatedStrategy::ipv4_only; break;
        case d::detail::AddressStrategy::ipv6_only: selected=CoordinatedStrategy::ipv6_only; break;
        default: std::terminate();
        }
        active_.emplace(owner_,&reader_,selected,tcp,disable_cache_,false,false,cache_policy_,subnet_);
        if constexpr (Full) co_return co_await active_->resolve_answer(endpoint,*view,name,deadline);
        else co_return co_await active_->resolve_native(endpoint,*view,name,deadline);
    }
    template<bool Full>
    auto LocalCoordinatedResolver::resolve_local(std::string name,std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<d::detail::AddressResult<Full>,d::detail::ResolveError>> {
        if (canceled_) co_return std::unexpected(d::detail::ResolveError::canceled);
        if (subnet_ && !d::valid_client_subnet(*subnet_)) co_return std::unexpected(d::detail::ResolveError::state);
        d::detail::BasicLocalAddressResolver<LocalCoordinatedResolver> resolver(*this,snapshot_->config,snapshot_->hosts,family_,rotation_);
        auto task=[&] {
            if constexpr (Full) return resolver.resolve_answer(std::move(name),deadline);
            else return resolver.resolve(std::move(name),deadline);
        }();
        auto result=co_await std::move(task);
        if (canceled_) co_return std::unexpected(d::detail::ResolveError::canceled);
        co_return result;
    }
    auto LocalCoordinatedResolver::resolve(io::endpoint endpoint,bool tcp,d::detail::AddressStrategy family,
        std::string const& name,std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<std::vector<d::Address>,d::detail::ResolveError>> {
        return resolve_endpoint<false>(endpoint,tcp,family,name,deadline);
    }
    auto LocalCoordinatedResolver::resolve_answer(io::endpoint endpoint,bool tcp,d::detail::AddressStrategy family,
        std::string const& name,std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<d::AddressAnswer,d::detail::ResolveError>> {
        return resolve_endpoint<true>(endpoint,tcp,family,name,deadline);
    }
    auto LocalCoordinatedResolver::resolve(std::string name,std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<std::vector<d::Address>,d::detail::ResolveError>> {
        return resolve_local<false>(std::move(name),deadline);
    }
    auto LocalCoordinatedResolver::resolve_answer(std::string name,std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::expected<d::AddressAnswer,d::detail::ResolveError>> {
        return resolve_local<true>(std::move(name),deadline);
    }

}
