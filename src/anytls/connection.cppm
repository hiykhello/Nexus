export module anytls.connection;
import std;
import anytls.session;
import anytls.writer;
import anytls.padding;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import tls.connector;
import tls.byte_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace anytls {
    // An idle connection owns its connector/TLS/protocol independently of a
    // business stream. A host pool outlives the context; both reader teardown
    // and lease release participate in clearing I/O before context destruction.
    template<class Connector>
    class PooledConnection {
    public:
        using ByteStream=websocket::VlessByteStream<typename Connector::Socket>;
        using Protocol=Session<ByteStream>;
        using Channel=StreamChannel<ByteStream>;
    private:
        std::optional<Connector> connector_;
        std::optional<ByteStream> stream_;
        std::optional<Protocol> protocol_;
        PaddingScheme& padding_;
        nex::capy::async_event* changed_;
        httpupgrade::Profile const* transport_=nullptr;
        bool starting_=false,running_=false,leased_=false,canceled_=false;
        unsigned active_calls_=0;
        auto notify() noexcept -> void { if (changed_) changed_->set(); }
        auto clear() noexcept -> void {
            if (active_calls_>1 || starting_ || running_ || leased_ || !canceled_) return;
            protocol_.reset(); stream_.reset(); connector_.reset();
        }
        // Posting an event can synchronously destroy another task during
        // context shutdown. Keep this entry ineligible for reap until every
        // reentrant lifecycle call has finished accessing its owned state.
        struct Call {
            PooledConnection& owner;
            explicit Call(PooledConnection& value) noexcept : owner(value) { ++owner.active_calls_; }
            ~Call() { owner.clear(); --owner.active_calls_; owner.notify(); }
        };
        struct StartGuard {
            PooledConnection& owner; bool done=false;
            ~StartGuard() { Call call(owner); owner.starting_=false; if (!done) owner.cancel(); }
        };
        struct ReaderGuard {
            PooledConnection* owner;
            explicit ReaderGuard(PooledConnection& value) noexcept : owner(&value) {}
            ReaderGuard(ReaderGuard const&)=delete;
            ReaderGuard(ReaderGuard&& other) noexcept : owner(std::exchange(other.owner,nullptr)) {}
            ~ReaderGuard() { if (owner) { Call call(*owner); owner->cancel(); owner->running_=false; } }
        };
        // The guard is a coroutine parameter so even a queued root that has
        // never resumed clears its owned I/O during context abandonment.
        static auto reader(ReaderGuard guard) -> nex::capy::task<> {
            (void)co_await guard.owner->protocol_->run();
        }
    public:
        template<class... Args>
        PooledConnection(PaddingScheme& padding,nex::capy::async_event* changed,Args&&... args)
            : connector_(std::in_place,std::forward<Args>(args)...),padding_(padding),changed_(changed) {}
        auto set_transport(httpupgrade::Profile const* transport) noexcept -> void { transport_=transport; }
        ~PooledConnection() {
            // Destruction cannot drain asynchronous work. The host retains
            // this state until roots and the one borrowing lease are gone.
            if (starting_ || running_ || leased_ || active_calls_) std::terminate();
            changed_=nullptr;
            cancel(); clear();
        }
        PooledConnection(PooledConnection const&)=delete;
        auto operator=(PooledConnection const&) -> PooledConnection& = delete;
        auto acquired() noexcept -> void { leased_=true; }
        auto released() noexcept -> void { Call call(*this); leased_=false; }
        auto cancel() noexcept -> void {
            Call call(*this);
            if (!canceled_) {
                canceled_=true;
                if (protocol_) protocol_->cancel();
                if (connector_) connector_->cancel();
            }
        }
        auto usable() const noexcept -> bool { return !canceled_ && protocol_ && protocol_->usable(); }
        auto drained() const noexcept -> bool { return !starting_ && !running_ && !leased_ && !active_calls_; }
        auto protocol() noexcept -> Protocol* { return protocol_ ? &*protocol_ : nullptr; }
        auto start(std::span<std::uint8_t const> key,IoClock::time_point deadline,std::string_view metadata={})
            -> nex::capy::task<tls::detail::ConnectResult> {
            using Result=tls::detail::ConnectResult;
            if (starting_ || running_ || protocol_ || canceled_ || !connector_) co_return Result::failed;
            starting_=true; StartGuard guard{*this};
            auto connected=co_await connector_->start(deadline);
            if (connected!=Result::connected || canceled_) co_return canceled_ ? Result::failed : connected;
            auto* application=connector_->application();
            if (!application) co_return Result::failed;
            stream_.emplace(*application);
            if (transport_) {
                if (transport_->websocket()) {
                    auto ws=co_await stream_->activate_websocket(*transport_,deadline);
                    if (!ws || canceled_) co_return IoClock::now()>=deadline ? Result::timeout : Result::failed;
                } else {
                    auto ready=co_await httpupgrade::connect(*stream_,*transport_,deadline);
                    if (!ready || !stream_->prepend_owned(std::move(ready->unread)) || canceled_)
                        co_return IoClock::now()>=deadline ? Result::timeout : Result::failed;
                }
            }
            protocol_.emplace(*stream_,padding_,true);
            if (!co_await protocol_->start_client(key,deadline,metadata) || canceled_)
                co_return IoClock::now()>=deadline ? Result::timeout : Result::failed;
            guard.done=true; co_return Result::connected;
        }
        auto run(nex::corosio::io_context& context) -> void {
            if (starting_ || running_ || !usable()) throw std::logic_error("AnyTLS reader cannot start");
            running_=true;
            try {
                nex::capy::run_async(context.get_executor(),[] {},[this](std::exception_ptr) noexcept { cancel(); })(reader(ReaderGuard{*this}));
            } catch (...) {
                running_=false; cancel(); throw;
            }
        }
    };
}
