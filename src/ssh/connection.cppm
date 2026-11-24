export module ssh.connection;
import std;
import ssh.session;
import capy;
import corosio;

export namespace ssh {
    template<class Socket>
    class SocketStream {
        Socket& socket_;
    public:
        explicit SocketStream(Socket& s) noexcept : socket_(s) {}
        auto cancel() noexcept -> void { socket_.cancel(); }
        auto read(std::span<std::uint8_t> out, Clock::time_point dl) -> capy::task<std::expected<std::size_t, std::string>> {
            if constexpr (requires { socket_.read(out, dl); }) {
                auto r = co_await socket_.read(out, dl);
                if (!r) co_return std::unexpected("SSH socket read failed");
                co_return *r;
            } else if constexpr (requires { socket_.read(out); }) {
                co_return co_await socket_.read(out);
            } else {
                auto [err, n] = co_await corosio::timeout(
                    socket_.read_some(capy::mutable_buffer(out.data(), out.size())), dl);
                if (err) {
                    if (capy::is_eof(err)) co_return 0;
                    co_return std::unexpected("SSH socket read failed");
                }
                co_return n;
            }
        }
        auto send(std::span<std::uint8_t const> in, Clock::time_point dl) -> capy::task<bool> {
            if constexpr (requires { socket_.send(in, dl); }) {
                co_return co_await socket_.send(in, dl);
            } else if constexpr (requires { socket_.send(in); }) {
                co_return co_await socket_.send(in);
            } else {
                while (!in.empty()) {
                    auto [err, n] = co_await corosio::timeout(
                        socket_.write_some(capy::const_buffer(in.data(), in.size())), dl);
                    if (err || n == 0) co_return false;
                    in = in.subspan(n);
                }
                co_return true;
            }
        }
    };

    // Multiplexed SSHv2 transport owner using structured concurrency (matching grpc::OwnedConnection).
    template<class Connector>
    class OwnedConnection {
    public:
        using Stream = SocketStream<typename Connector::Socket>;
        using Protocol = Session<Stream>;
    private:
        std::optional<Connector> connector_;
        std::optional<Stream> stream_;
        std::optional<Protocol> protocol_;
        bool starting_ = false, running_ = false, stopped_ = false, canceled_ = false;
        std::uint16_t leased_ = 0;
        unsigned active_calls_ = 0;

        auto clear() noexcept -> void {
            if (active_calls_ > 1 || starting_ || running_ || leased_ || !canceled_) return;
            protocol_.reset();
            stream_.reset();
            connector_.reset();
        }
        struct Call {
            OwnedConnection& owner;
            explicit Call(OwnedConnection& v) noexcept : owner(v) { ++owner.active_calls_; }
            ~Call() { owner.clear(); --owner.active_calls_; }
        };
        struct StartGuard {
            OwnedConnection& owner;
            bool done = false;
            ~StartGuard() { Call call(owner); owner.starting_ = false; if (!done) owner.stop(); }
        };
        struct RootGuard {
            OwnedConnection* owner;
            explicit RootGuard(OwnedConnection& v) noexcept : owner(&v) {}
            RootGuard(RootGuard const&) = delete;
            RootGuard(RootGuard&& o) noexcept : owner(std::exchange(o.owner, nullptr)) {}
            ~RootGuard() { if (owner) { Call call(*owner); owner->stop(); owner->running_ = false; } }
        };
        static auto root(RootGuard guard) -> capy::task<> {
            (void)co_await guard.owner->protocol_->run();
        }
    public:
        template<class... Args>
        explicit OwnedConnection(Args&&... args) : connector_(std::in_place, std::forward<Args>(args)...) {}
        ~OwnedConnection() {
            if (starting_ || running_ || leased_ || active_calls_) std::terminate();
            stop();
            clear();
        }
        OwnedConnection(OwnedConnection const&) = delete;
        auto operator=(OwnedConnection const&) -> OwnedConnection& = delete;

        auto acquired() noexcept -> void { ++leased_; }
        auto released() noexcept -> void { Call call(*this); --leased_; }
        auto cancel() noexcept -> void { stop(); }
        auto stop() noexcept -> void {
            Call call(*this);
            stopped_ = canceled_ = true;
            if (protocol_) protocol_->cancel();
            if (connector_) connector_->cancel();
        }
        auto usable() const noexcept -> bool { return !canceled_ && !stopped_ && protocol_ && protocol_->usable(); }
        auto available() const noexcept -> bool { return usable() && leased_ < kMaxChannels && protocol_->available(); }
        auto drained() const noexcept -> bool { return !starting_ && !running_ && !leased_ && !active_calls_; }
        auto protocol() noexcept -> Protocol* { return protocol_ ? &*protocol_ : nullptr; }

        enum class StartResult { connected, failed, timeout };
        auto start(ClientAuth const& auth, Clock::time_point dl) -> capy::task<StartResult> {
            if (Clock::now() >= dl) co_return StartResult::timeout;
            if (starting_ || running_ || protocol_ || canceled_ || !connector_) co_return StartResult::failed;
            starting_ = true;
            StartGuard guard{*this};
            if (!co_await connector_->connect(dl) || canceled_)
                co_return Clock::now() >= dl ? StartResult::timeout : StartResult::failed;
            stream_.emplace(connector_->socket());
            protocol_.emplace(*stream_);
            if (!co_await protocol_->start_client(auth, dl) || canceled_)
                co_return Clock::now() >= dl ? StartResult::timeout : StartResult::failed;
            if (Clock::now() >= dl || canceled_) co_return StartResult::timeout;
            guard.done = true;
            co_return StartResult::connected;
        }
        auto run(corosio::io_context& context) -> void {
            if (starting_ || running_ || !usable()) throw std::logic_error("SSH root cannot start");
            running_ = true;
            try {
                capy::run_async(context.get_executor(), [] {},
                    [this](std::exception_ptr) noexcept { stop(); })(root(RootGuard(*this)));
            } catch (...) { running_ = false; stop(); throw; }
        }
    };
}
