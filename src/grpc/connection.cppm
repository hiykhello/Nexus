export module grpc.connection;
import std;
import grpc.session;
import grpc.headers;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import tls.connector;
import tls.byte_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace grpc {
    namespace detail {
        struct ByteStreamReadPolicy {
            using Error=tls::detail::ByteStreamError;
            static auto close_deadline() noexcept {return Clock::now()+std::chrono::seconds(10);}
            static auto convert(Failure failure) noexcept -> Error {
                if (failure.error==grpc::Error::state) return Error::state;
                return failure.error==grpc::Error::transport || failure.error==grpc::Error::timeout ||
                    failure.error==grpc::Error::canceled ? Error::io : Error::protocol;
            }
        };
    }
    // One connection is retained by a worker pool independently of any
    // business session. A borrowing lease and the queued/running I/O root
    // must both end before its connector or native protocol can be cleared.
    template<class Connector,class ReadPolicy=detail::ReadFailurePolicy,std::size_t Streams=1>
    class OwnedConnection {
    public:
        using Stream=tls::detail::ByteStream<typename Connector::Socket>;
        using Protocol=std::conditional_t<Streams==1,Channel<Stream,ReadPolicy>,MultiplexChannel<Stream,Streams,ReadPolicy>>;
        using Native=std::conditional_t<Streams==1,Session,MultiplexSession<Streams>>;
    private:
        std::optional<Connector> connector_;
        std::optional<Stream> stream_;
        std::optional<Protocol> protocol_;
        bool starting_=false,running_=false;
        std::conditional_t<Streams==1,bool,std::uint16_t> leased_=0;
        bool returned_=false,canceled_=false,stopped_=false;
        unsigned active_calls_=0;
        auto clear() noexcept -> void {
            if (active_calls_>1 || starting_ || running_ || leased_ || !canceled_) return;
            protocol_.reset();stream_.reset();connector_.reset();
        }
        struct Call {
            OwnedConnection& owner;
            explicit Call(OwnedConnection& value) noexcept : owner(value) {++owner.active_calls_;}
            ~Call() {owner.clear();--owner.active_calls_;}
        };
        struct StartGuard {
            OwnedConnection& owner;bool done=false;
            ~StartGuard() {Call call(owner);owner.starting_=false;if (!done) owner.stop();}
        };
        struct RootGuard {
            OwnedConnection* owner;
            explicit RootGuard(OwnedConnection& value) noexcept : owner(&value) {}
            RootGuard(RootGuard const&)=delete;
            RootGuard(RootGuard&& other) noexcept : owner(std::exchange(other.owner,nullptr)) {}
            ~RootGuard() {if (owner) {Call call(*owner);owner->stop();owner->running_=false;}}
        };
        // Parameter lifetime also covers a root queued but never resumed.
        static auto root(RootGuard guard) -> nex::capy::task<> {
            (void)co_await guard.owner->protocol_->run();
        }
    public:
        template<class... Args>
        explicit OwnedConnection(Args&&... args) : connector_(std::in_place,std::forward<Args>(args)...) {}
        ~OwnedConnection() {
            if (starting_ || running_ || leased_ || active_calls_) std::terminate();
            stop();clear();
        }
        OwnedConnection(OwnedConnection const&)=delete;
        auto operator=(OwnedConnection const&) -> OwnedConnection& = delete;
        auto acquired() noexcept -> void {if constexpr(Streams==1)leased_=true;else ++leased_;}
        auto released() noexcept -> void {
            Call call(*this);
            if constexpr(Streams==1){leased_=false;returned_=true;cancel();}else --leased_;
        }
        // Retirement preserves a normal END_STREAM/last-write/TLS/FIN drain.
        // Explicit business failure calls stop before returning its lease.
        // Pool shutdown uses stop(), so a peer withholding FIN cannot prevent
        // worker shutdown even after a normal stream has been returned.
        auto cancel() noexcept -> void {
            Call call(*this);
            if constexpr(Streams!=1)if(!stopped_&&protocol_&&!protocol_->failure()){
                returned_=true;
                if(protocol_->shutdown())return;
            }
            if (!stopped_ && !leased_ && protocol_ && protocol_->transport_ended() && !protocol_->failure()) return;
            stop();
        }
        auto stop() noexcept -> void {
            Call call(*this);stopped_=canceled_=true;
            if (protocol_) protocol_->cancel();
            if (connector_) connector_->cancel();
        }
        auto usable() const noexcept -> bool {
            if(canceled_||returned_||!protocol_)return false;
            if constexpr(Streams==1)return true;else return protocol_->accepting();
        }
        auto available() noexcept -> bool requires(Streams!=1){return usable()&&protocol_->available();}
        auto drained() const noexcept -> bool {return !starting_ && !running_ && !leased_ && !active_calls_;}
        auto protocol() noexcept -> Protocol* {return protocol_ ? &*protocol_ : nullptr;}
        auto start(RequestProfile const& profile,Limits limits,ResponsePolicy policy,Deadline deadline) -> nex::capy::task<tls::detail::ConnectResult> {
            using Result=tls::detail::ConnectResult;
            if (!deadline || Clock::now()>=*deadline) co_return Result::timeout;
            if (starting_ || running_ || protocol_ || canceled_ || !connector_) co_return Result::failed;
            starting_=true;StartGuard guard{*this};
            auto connected=co_await connector_->start(*deadline);
            if (connected!=Result::connected || canceled_) co_return canceled_ ? Result::failed : connected;
            auto* application=connector_->application();if (!application) co_return Result::failed;
            if constexpr (requires {connector_->accepts_alpn();}) if (!connector_->accepts_alpn()) co_return Result::failed;
            auto native=Native::create(Role::client,profile,policy,limits);
            if (!native) co_return Result::failed;
            stream_.emplace(*application);
            // Connect deadlines apply to accept/start operations. They do not
            // impose a fresh transport lifetime on every later business chunk.
            protocol_.emplace(*stream_,std::move(*native));
            if (Clock::now()>=*deadline || canceled_) co_return Result::timeout;
            guard.done=true;co_return Result::connected;
        }
        auto run(nex::corosio::io_context& context) -> void {
            if (starting_ || running_ || !usable()) throw std::logic_error("gRPC root cannot start");
            running_=true;
            try {
                nex::capy::run_async(context.get_executor(),[] {},[this](std::exception_ptr) noexcept {stop();})(root(RootGuard(*this)));
            } catch (...) {running_=false;stop();throw;}
        }
    };
}
