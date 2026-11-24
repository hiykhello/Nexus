module dns.shared_coordinator;
import std;
import dns.response_query;
import dns.response_cache;
import dns.response_match;
import capy;
import corosio;

namespace dns_hp_experiment {
    ResponseFlightOwner::Entry::Entry(FlightGroup::Flight* value,io::io_context& context,d::ResponseCache& cache)
        : flight(value),query(context,cache) {}
    ResponseFlightOwner::ResponseFlightOwner(io::io_context& context,d::ResponseCache& cache,FlightGroup& group,std::chrono::milliseconds timeout)
        : context_(context),cache_(cache),group_(group),timeout_(std::clamp(timeout,std::chrono::milliseconds(1),std::chrono::milliseconds(30000))) {}
    ResponseFlightOwner::~ResponseFlightOwner() { if (!active_.empty()) std::terminate(); }
    auto ResponseFlightOwner::ms(Clock::time_point t) noexcept -> std::uint64_t {
        auto n=std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();return n<0 ? 0 : static_cast<std::uint64_t>(n);
    }
    auto ResponseFlightOwner::monitor(Entry& entry) -> capy::task<capy::results<>> {
        while (!entry.finished) {
            if (group_.retiring(entry.flight)) entry.query.cancel();
            auto [error]=co_await entry.flight->control.wait();
            if (error) { entry.query.cancel();break; }
        }
        co_return capy::results<>{};
    }
    auto ResponseFlightOwner::work(Entry& entry) -> capy::task<capy::results<>> {
        using Error=d::detail::ResolveError;
        FlightGroup::RawResult answer=std::unexpected(Error::state);
        std::optional<Clock::time_point> expires;
        auto completed=Clock::now();
        try {
            auto const& key=entry.flight->key;
            std::optional<d::CacheToken> token;
            if (key.use_cache) try { auto t=cache_.begin(key.cache,key.edns);if (t) token=*t; } catch (std::bad_alloc const&) {}
            struct Registration { d::ResponseCache& cache;std::optional<d::CacheToken>& token;
                ~Registration() { if (token) (void)cache.cancel(*token); } } registration{cache_,token};
            answer=co_await entry.query.run(key.upstream,key.cache.view,{key.cache.name,key.cache.type},Clock::now()+timeout_,key.tcp,key.edns,true,key.subnet,key.protection.get());
            completed=Clock::now();
            if (answer) {
                auto ttl=d::ResponseCache::lifetime(*answer,{key.cache.name,key.cache.type});
                if (ttl) expires=completed+std::chrono::seconds(*ttl);
                if (token) try { group_.while_live(entry.flight,[&] { (void)cache_.publish_from(key.cache,*answer,ms(completed),ms(Clock::now()),*token); }); }
                    catch (std::bad_alloc const&) {}
            }
        } catch (...) { answer=std::unexpected(Error::state); }
        entry.finished=true;group_.complete_raw(entry.flight,std::move(answer),completed,expires);entry.flight->control.wake();
        co_return capy::results<>{};
    }
    auto ResponseFlightOwner::run(Entry& entry) -> capy::task<capy::results<>> {
        (void)co_await capy::when_all(work(entry),monitor(entry));co_return capy::results<>{};
    }
    auto ResponseFlightOwner::done(std::uint64_t id) noexcept -> void {
        auto it=active_.find(id);if (it==active_.end()) return;
        auto* flight=it->second->flight;group_.complete_raw(flight,std::unexpected(d::detail::ResolveError::state));
        active_.erase(it);group_.finish(flight);
    }
    auto ResponseFlightOwner::start(FlightGroup::Flight* flight) noexcept -> void {
        using Error=d::detail::ResolveError;
        if (stopped_ || next_==std::numeric_limits<std::uint64_t>::max() || group_.retiring(flight)) {
            group_.complete_raw(flight,std::unexpected(stopped_ || group_.retiring(flight) ? Error::canceled : Error::limit));group_.finish(flight);return;
        }
        auto id=++next_;
        try {
            auto entry=std::make_unique<Entry>(flight,context_,cache_);
            auto [it,inserted]=active_.emplace(id,std::move(entry));
            if (!inserted) { group_.complete_raw(flight,std::unexpected(Error::state));group_.finish(flight);return; }
            try { capy::run_async(context_.get_executor(),[this,id](capy::results<>) { done(id); },
                [this,id](std::exception_ptr) noexcept { done(id); })(run(*it->second)); }
            catch (...) { active_.erase(it);throw; }
        } catch (...) { group_.complete_raw(flight,std::unexpected(Error::state));group_.finish(flight); }
    }
    auto ResponseFlightOwner::stop() noexcept -> void { stopped_=true;for (auto& [id,entry]:active_) { group_.retire(entry->flight);entry->query.cancel(); } }
    auto ResponseFlightOwner::available() const noexcept -> bool { return !stopped_; }
    auto ResponseFlightOwner::drained() const noexcept -> bool { return active_.empty(); }
    auto ResponseOperationTraits::delivered(FlightGroup& group,FlightGroup::Waiter const& waiter) -> std::optional<Delivery> {
        auto raw=group.result_raw(waiter);if (!raw) return {};
        auto now=Clock::now();
        if (raw->expires && now>=*raw->expires) return Delivery{std::unexpected(d::detail::ResolveError::state),true};
        if (raw->answer) {
            auto elapsed=now>raw->completed ? std::chrono::ceil<std::chrono::seconds>(now-raw->completed).count() : 0;
            std::optional<std::uint32_t> cap;
            if (raw->expires) cap=static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(*raw->expires-now).count());
            auto const& wire=raw->answer->wire;
            if (wire.size()<2 || !d::age_response(*raw->answer,static_cast<std::uint64_t>(elapsed),static_cast<std::uint16_t>((std::uint16_t(wire[0])<<8)|wire[1]),cap))
                return Delivery{std::unexpected(d::detail::ResolveError::protocol),false};
        }
        return Delivery{std::move(raw->answer),false};
    }
    auto ResponseOperationTraits::age_cached(Rechecked& cached,Clock::time_point now) -> void {
        if (!cached.answer || !cached.expires) return;
        auto remaining=static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(*cached.expires-now).count());
        auto const& wire=cached.answer->wire;
        if (wire.size()<2 || !d::age_response(*cached.answer,0,static_cast<std::uint16_t>((std::uint16_t(wire[0])<<8)|wire[1]),remaining))
            cached.answer=std::unexpected(d::detail::ResolveError::protocol);
    }
    auto ResponseOperationTraits::complete_cached(FlightGroup& group,FlightGroup::Flight* flight,Rechecked& cached) -> void {
        group.complete_raw(flight,std::move(cached.answer),Clock::now(),cached.expires);
    }
    ResponseCoordinatorOwner::ResponseCoordinatorOwner(io::io_context& context,d::ResponseCache& cache,Coordinator& coordinator,std::chrono::milliseconds timeout)
        : context_(context),cache_(cache),group_(coordinator.group_),owner_(context,cache,group_,timeout) {}
    ResponseCoordinatorOwner::~ResponseCoordinatorOwner()=default;
    auto ResponseCoordinatorOwner::stop() noexcept -> void { owner_.stop(); }
    auto ResponseCoordinatorOwner::drained() const noexcept -> bool { return owner_.drained(); }
    ResponseCoordinatorQuery::ResponseCoordinatorQuery(ResponseCoordinatorOwner& owner) : owner_(owner),operation_(owner.group_,owner.owner_) {}
    ResponseCoordinatorQuery::~ResponseCoordinatorQuery()=default;
    auto ResponseCoordinatorQuery::cancel() noexcept -> void { canceled_=true;operation_.cancel();if (direct_) direct_->cancel(); }
    auto ResponseCoordinatorQuery::millis(Clock::time_point value) noexcept -> std::uint64_t {
        auto n=std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();return n<0 ? 0 : static_cast<std::uint64_t>(n);
    }
    auto ResponseCoordinatorQuery::from_ms(std::uint64_t value) noexcept -> Clock::time_point {
        auto max=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration::max()).count();
        return value>static_cast<std::uint64_t>(max) ? Clock::time_point::max() : Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(value)));
    }
    auto ResponseCoordinatorQuery::resolve(io::endpoint upstream,std::uint64_t view,d::Question question,
                     Clock::time_point deadline,bool tcp,bool edns,bool disable_cache,std::optional<d::ClientSubnet> subnet,
                     std::shared_ptr<d::detail::ProtectedQuery const> protection) -> capy::task<FlightGroup::RawResult> {
        using Error=d::detail::ResolveError;
        if (started_) co_return std::unexpected(Error::state);started_=true;
        if (canceled_ || !owner_.owner_.available()) co_return std::unexpected(Error::canceled);
        if (Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
        if (subnet && !d::valid_client_subnet(*subnet)) co_return std::unexpected(Error::state);
        edns |= subnet.has_value();
        FlightGroup::Key key{{view,question.name,question.type},upstream,tcp,edns,!disable_cache,true};
        key.subnet=subnet;
        key.protection=std::move(protection);
        if (disable_cache) {
            auto lease=owner_.group_.try_direct();if (!lease) co_return std::unexpected(Error::limit);
            direct_.emplace(owner_.context_,owner_.cache_);
            auto result=co_await direct_->run(upstream,view,std::move(question),deadline,tcp,edns,true,subnet,key.protection.get());
            if (canceled_) co_return std::unexpected(Error::canceled);
            co_return result;
        }
        auto recheck=[this](FlightGroup::Key const& k) -> std::optional<ResponseOperationTraits::Rechecked> {
            auto result=owner_.cache_.lookup_entry(k.cache,millis(Clock::now()),0,k.edns);
            if (result && *result) { auto& entry=**result;return ResponseOperationTraits::Rechecked{std::move(entry.response),from_ms(entry.expires)}; }
            return {};
        };
        if (!d::canonicalize_name(key.cache.name) || !upstream.port() || (question.type!=1 && question.type!=28))
            co_return std::unexpected(Error::state);
        try { auto cached=recheck(key);if (cached && cached->expires && Clock::now()<*cached->expires) co_return std::move(cached->answer); }
        catch (std::bad_alloc const&) {}
        co_return co_await operation_.resolve(std::move(key),deadline,recheck);
    }
}
