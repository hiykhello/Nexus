export module anytls.client;
import std;
import anytls.connection;
import anytls.pool;
import anytls.padding;
import anytls.settings;
import anytls.writer;
import tls.connector;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace anytls {
    enum class ClientError { closed,timeout,unavailable };
    // One client belongs to one executor, identity and configuration epoch.
    // Factory creates an independent owned connector from the supplied
    // padding state and wake event. The host retains this owner through
    // context shutdown; every lease belongs to a task on that same context.
    template<class Factory>
    class Client {
    public:
        using Connection=typename Factory::Connection;
        using Pool=ClientPool<Connection>;
        using Lease=typename Pool::Lease;
    private:
        nex::corosio::io_context& context_;
        Factory factory_;
        std::span<std::uint8_t const,32> key_;
        std::string metadata_;
        PaddingScheme padding_;
        nex::capy::async_event changed_;
        Pool pool_;
        std::array<Connection*,256> starting_{};
        std::chrono::milliseconds timeout_;
        std::stop_source stop_;
        bool stopped_=false,monitor_running_=false,failed_=false;
        struct Activity { Client& owner; ~Activity() { owner.changed_.set(); } };
        struct Request {
            Client& owner;
            Connection* active=nullptr;
            bool canceled=false;
            auto cancel() noexcept -> void {
                auto* changed=&owner.changed_;
                auto* connection=active;
                canceled=true;
                if (connection) connection->cancel();
                // Cancellation can synchronously destroy this request while
                // posting an event during context teardown. Client outlives it.
                changed->set();
            }
        };
        struct Registration {
            Connection*& slot;
            explicit Registration(Connection*& value,Connection* connection) noexcept : slot(value) { slot=connection; }
            ~Registration() { slot=nullptr; }
        };
        struct Monitor {
            Client* owner;
            explicit Monitor(Client& value) noexcept : owner(&value) {}
            Monitor(Monitor const&)=delete;
            Monitor(Monitor&& other) noexcept : owner(std::exchange(other.owner,nullptr)) {}
            ~Monitor() { if (owner) { owner->stop(); owner->monitor_running_=false; owner->changed_.set(); } }
        };
        struct Warm {
            Client* owner;
            std::optional<typename Pool::Creation> ticket;
            Warm(Client& value,typename Pool::Creation&& creation) : owner(&value),ticket(std::move(creation)) {}
            Warm(Warm const&)=delete;
            Warm(Warm&& other) noexcept : owner(std::exchange(other.owner,nullptr)),ticket(std::move(other.ticket)) {}
            ~Warm() { ticket.reset(); if (owner) owner->changed_.set(); }
        };
        auto vacant() noexcept -> Connection** {
            auto slot=std::ranges::find(starting_,nullptr);
            return slot==starting_.end() ? nullptr : &*slot;
        }
        auto prewarm_allowed() const noexcept -> bool {
            if constexpr (requires { { factory_.prewarm_allowed() } noexcept -> std::same_as<bool>; })
                return factory_.prewarm_allowed();
            return true;
        }
        static auto warm(Warm job) -> nex::capy::task<> {
            auto& owner=*job.owner;
            if (owner.stopped_ || !owner.prewarm_allowed()) co_return;
            auto connection=owner.factory_(owner.padding_,&owner.changed_);
            auto* slot=owner.vacant();
            if (!connection || !slot) co_return;
            Registration registration(*slot,connection.get());
            auto result=co_await connection->start(owner.key_,IoClock::now()+owner.timeout_,owner.metadata_);
            if (result!=tls::detail::ConnectResult::connected || owner.stopped_ || !owner.prewarm_allowed()) co_return;
            auto lease=job.ticket->commit(std::move(connection));
            if (!lease) co_return;
            try { lease->connection().run(owner.context_); }
            catch (...) { lease->connection().cancel(); throw; }
            // The lease returns the authenticated connection to the idle
            // pool. Its reader continues under the pool's explicit owner.
        }
        static auto monitor(Monitor lifetime) -> nex::capy::task<> {
            auto& owner=*lifetime.owner;
            while (!owner.stopped_) {
                auto prewarm=owner.prewarm_allowed();
                owner.pool_.reap(IoClock::now(),prewarm);
                auto needed=prewarm ? owner.pool_.prewarm_needed() : 0;
                for (std::size_t i=0;i<needed && !owner.stopped_;++i) {
                    auto creation=owner.pool_.reserve();
                    if (!creation) break;
                    nex::capy::run_async(owner.context_.get_executor(),owner.stop_.get_token(),[] {},
                        [parent=&owner](std::exception_ptr) noexcept { parent->failed_=true; parent->stop(); })(
                            warm(Warm(owner,std::move(*creation))));
                }
                auto [error]=co_await nex::corosio::delay(owner.pool_.options().check_interval);
                if (error) break;
            }
        }
    public:
        Client(nex::corosio::io_context& context,Factory factory,std::span<std::uint8_t const,32> key,
            PaddingScheme padding,PoolOptions options={},std::chrono::milliseconds timeout=std::chrono::seconds(10),std::string_view metadata={})
            : context_(context),factory_(std::move(factory)),key_(key),metadata_(metadata),padding_(std::move(padding)),pool_(options),timeout_(timeout) {
            if (!valid_client_metadata(metadata) || timeout.count()<1 || timeout>std::chrono::hours(1))
                throw std::invalid_argument("invalid AnyTLS client options");
        }
        ~Client() { stop(); if (!drained()) std::terminate(); }
        Client(Client const&)=delete;
        auto operator=(Client const&) -> Client& = delete;
        auto start() -> void {
            if (stopped_ || monitor_running_) throw std::logic_error("AnyTLS pool cannot start");
            monitor_running_=true;
            try {
                nex::capy::run_async(context_.get_executor(),stop_.get_token(),[] {},
                    [this](std::exception_ptr) noexcept { failed_=true; stop(); })(monitor(Monitor(*this)));
            } catch (...) { monitor_running_=false; stop(); throw; }
        }
        auto stop() noexcept -> void {
            if (!stopped_) {
                stopped_=true; stop_.request_stop(); pool_.stop();
                for (auto* connection:starting_) if (connection) connection->cancel();
            }
            changed_.set();
        }
        auto drained() const noexcept -> bool { return !monitor_running_ && pool_.drained(); }
        auto idle_count() const noexcept -> std::size_t { return pool_.idle_count(); }
        auto size() const noexcept -> std::size_t { return pool_.size(); }
        auto acquire(IoClock::time_point deadline,std::stop_token token={}) -> nex::capy::task<std::expected<Lease,ClientError>> {
            Activity activity{*this};
            Request request{*this};
            // Cancellation belongs to this request, including its unfinished
            // connector. Other leased and idle sessions remain available.
            std::stop_callback callback(token,[&request]() noexcept { request.cancel(); });
            while (!stopped_) {
                if (request.canceled) co_return std::unexpected(ClientError::closed);
                if (IoClock::now()>=deadline) co_return std::unexpected(ClientError::timeout);
                pool_.reap(IoClock::now(),prewarm_allowed());
                if (auto ready=pool_.acquire()) co_return std::move(*ready);
                auto creation=pool_.reserve();
                if (creation) {
                    auto connection=factory_(padding_,&changed_);
                    auto* slot=vacant();
                    if (!connection || !slot) co_return std::unexpected(ClientError::unavailable);
                    Registration registration(*slot,connection.get());
                    Registration active(request.active,connection.get());
                    auto result=co_await connection->start(key_,deadline,metadata_);
                    if (stopped_ || request.canceled) co_return std::unexpected(ClientError::closed);
                    if (result!=tls::detail::ConnectResult::connected)
                        co_return std::unexpected(result==tls::detail::ConnectResult::timeout ? ClientError::timeout : ClientError::unavailable);
                    auto lease=creation->commit(std::move(connection));
                    if (!lease) co_return std::unexpected(ClientError::unavailable);
                    try { lease->connection().run(context_); }
                    catch (...) { lease->connection().cancel(); throw; }
                    co_return std::move(*lease);
                }
                if (creation.error()!=PoolError::full) co_return std::unexpected(ClientError::unavailable);
                changed_.clear();
                auto [error]=co_await nex::corosio::timeout(changed_.wait(),deadline);
                if (error) co_return std::unexpected(IoClock::now()>=deadline ? ClientError::timeout : ClientError::closed);
            }
            co_return std::unexpected(failed_ ? ClientError::unavailable : ClientError::closed);
        }
    };
}
