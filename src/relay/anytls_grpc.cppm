// Private AnyTLS-over-gRPC multiplexed pool client.
module relay:anytls_grpc;
import std;
import proxy.v4;
import anytls;
import anytls.auth;
import anytls.client;
import anytls.connection;
import anytls.padding;
import anytls.pool;
import anytls.session;
import anytls.writer;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.connection;
import tls.profiles;
import tls.connector;
import net.connection_pool;
import net.datagram_frame;
import net.stream_relay;
import uot;
import capy;
import corosio;
import :types;
import :tunnel_facade;
import :session_interface;
import :internal_decls;
import :transport_helpers;
import :grpc_pool;
import :quic_ech;

namespace relay::anytls_grpc {
    namespace a = anytls;
    using Mode = grpc_pool::Mode;
    struct Worker;

    struct Profile {
        std::string host;
        std::uint16_t port;
        a::PasswordKey key;
        tls::ShapedClientProfile tls;
        grpc::RequestProfile request;
        grpc::ResponsePolicy response;
        grpc::Limits limits;
        std::size_t max_sessions;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout;
        TcpSocketOptions options;
        a::PoolOptions pool;
        bool fast_open;
        quic_ech::Profile ech;
        std::mutex mutex;
        std::array<std::unique_ptr<Worker>, 17> physical;
        std::array<std::unique_ptr<Worker>, 17> layered;
        std::array<std::unique_ptr<Worker>, 17> fast;
        ~Profile();
    };

    inline auto endpoint_spec(Profile const& p) noexcept -> grpc_pool::EndpointSpec {
        return {p.host, p.port, p.bootstrap, p.tls, p.request, p.response, p.limits, p.max_sessions, &p.ech};
    }

    class GrpcAnyTlsConnection {
    public:
        using GrpcWorker = grpc_pool::PoolWorker;
        using GrpcPool = typename GrpcWorker::Pool;
        using Rpc = typename grpc_pool::Connection::Protocol::Stream;
        using Adapted = transport_detail::GrpcByteStream<Rpc>;
        using Protocol = a::Session<Adapted>;
        using Channel = a::StreamChannel<Adapted>;
    private:
        GrpcWorker& grpc_worker_;
        a::PaddingScheme& padding_;
        capy::async_event* changed_;
        std::stop_source start_stop_;
        std::optional<typename GrpcPool::Lease> grpc_lease_;
        std::optional<Rpc> rpc_;
        std::optional<Adapted> adapted_;
        std::optional<Protocol> protocol_;
        bool starting_ = false, running_ = false, leased_ = false, canceled_ = false;
        unsigned active_calls_ = 0;

        auto notify() noexcept -> void { if (changed_) changed_->set(); }
        auto clear() noexcept -> void {
            if (active_calls_ > 1 || starting_ || running_ || leased_ || !canceled_) return;
            protocol_.reset();
            adapted_.reset();
            rpc_.reset();
            grpc_lease_.reset();
        }
        struct Call {
            GrpcAnyTlsConnection& owner;
            explicit Call(GrpcAnyTlsConnection& value) noexcept : owner(value) { ++owner.active_calls_; }
            ~Call() { owner.clear(); --owner.active_calls_; owner.notify(); }
        };
        struct StartGuard {
            GrpcAnyTlsConnection& owner;
            bool done = false;
            ~StartGuard() { Call call(owner); owner.starting_ = false; if (!done) owner.cancel(); }
        };
        struct ReaderGuard {
            GrpcAnyTlsConnection* owner;
            explicit ReaderGuard(GrpcAnyTlsConnection& value) noexcept : owner(&value) {}
            ReaderGuard(ReaderGuard const&) = delete;
            ReaderGuard(ReaderGuard&& other) noexcept : owner(std::exchange(other.owner, nullptr)) {}
            ~ReaderGuard() { if (owner) { Call call(*owner); owner->cancel(); owner->running_ = false; } }
        };
        static auto reader(ReaderGuard guard) -> capy::task<> {
            (void)co_await guard.owner->protocol_->run();
        }
    public:
        GrpcAnyTlsConnection(GrpcWorker& grpc_worker, a::PaddingScheme& padding, capy::async_event* changed)
            : grpc_worker_(grpc_worker), padding_(padding), changed_(changed) {}
        ~GrpcAnyTlsConnection() {
            if (starting_ || running_ || leased_ || active_calls_) std::terminate();
            changed_ = nullptr;
            cancel();
            clear();
        }
        GrpcAnyTlsConnection(GrpcAnyTlsConnection const&) = delete;
        auto operator=(GrpcAnyTlsConnection const&) -> GrpcAnyTlsConnection& = delete;
        auto acquired() noexcept -> void { leased_ = true; }
        auto released() noexcept -> void { Call call(*this); leased_ = false; }
        auto cancel() noexcept -> void {
            Call call(*this);
            if (!canceled_) {
                canceled_ = true;
                start_stop_.request_stop();
                if (protocol_) protocol_->cancel();
                if (rpc_) rpc_->cancel();
            }
        }
        auto usable() const noexcept -> bool { return !canceled_ && protocol_ && protocol_->usable(); }
        auto drained() const noexcept -> bool { return !starting_ && !running_ && !leased_ && !active_calls_; }
        auto protocol() noexcept -> Protocol* { return protocol_ ? &*protocol_ : nullptr; }
        auto start(std::span<std::uint8_t const> key, Clock::time_point deadline, std::string_view metadata = {})
            -> capy::task<tls::detail::ConnectResult> {
            using Result = tls::detail::ConnectResult;
            if (starting_ || running_ || protocol_ || canceled_) co_return Result::failed;
            starting_ = true;
            StartGuard guard{*this};
            auto lease = co_await grpc_worker_.acquire(start_stop_, deadline);
            if (!lease) co_return lease.error() == TunnelConnectResult::timeout ? Result::timeout : Result::failed;
            if (canceled_) co_return Result::failed;
            grpc_lease_.emplace(std::move(*lease));
            auto& ch = *grpc_lease_->connection().protocol();
            auto opened = ch.open();
            if (!opened || canceled_) co_return Result::failed;
            rpc_.emplace(ch, *opened);
            adapted_.emplace(*rpc_, nullptr);
            protocol_.emplace(*adapted_, padding_, true);
            if (!co_await protocol_->start_client(key, deadline, metadata) || canceled_)
                co_return Clock::now() >= deadline ? Result::timeout : Result::failed;
            guard.done = true;
            co_return Result::connected;
        }
        auto run(corosio::io_context& context) -> void {
            if (starting_ || running_ || !usable()) throw std::logic_error("AnyTLS gRPC reader cannot start");
            running_ = true;
            try {
                capy::run_async(context.get_executor(), [] {},
                    [this](std::exception_ptr) noexcept { cancel(); })(reader(ReaderGuard{*this}));
            } catch (...) { running_ = false; cancel(); throw; }
        }
    };

    struct Factory {
        using Connection = GrpcAnyTlsConnection;
        grpc_pool::PoolWorker& grpc;
        auto prewarm_allowed() const noexcept -> bool { return grpc.environment().prewarm_allowed(); }
        auto operator()(a::PaddingScheme& padding, capy::async_event* changed) -> std::unique_ptr<Connection> {
            return std::make_unique<Connection>(grpc, padding, changed);
        }
    };

    struct Worker {
        grpc_pool::PoolWorker grpc;
        a::Client<Factory> client;
        Worker(OutboundContext const& env, Profile const& p, TunnelFactory const* detour, TcpSocketOptions opts, Mode mode, a::PaddingScheme padding)
            : grpc(env, endpoint_spec(p), detour, opts, mode),
              client(env.context, Factory{grpc}, p.key.view(), std::move(padding), p.pool, std::chrono::milliseconds(p.timeout)) {}
        auto environment() const noexcept -> OutboundContext const& { return grpc.environment(); }
        auto stop() noexcept -> void { client.stop(); grpc.stop(); }
        auto reap() noexcept -> void { client.reap(); grpc.pool.reap(Clock::time_point::max()); }
        auto drained() const noexcept -> bool { return client.drained() && grpc.drained(); }
    };
    inline Profile::~Profile() = default;

    inline auto initialize(Profile& profile, Mode mode, OutboundContext const& environment,
                           TunnelFactory const* detour, bool direct) -> bool {
        std::lock_guard lock(profile.mutex);
        if (grpc_pool::find(profile, mode, environment.context)) return false;
        auto& entries = grpc_pool::slots(profile, mode);
        auto slot = std::ranges::find_if(entries, [](auto const& w) { return !w; });
        auto padding = a::PaddingScheme::parse(a::default_padding_scheme);
        if (slot == entries.end() || !padding || (direct && !environment.direct_options)) return false;
        auto w = std::make_unique<Worker>(environment, profile, detour,
                                          direct ? *environment.direct_options : profile.options, mode, std::move(*padding));
        w->grpc.start_reaper();
        w->client.start();
        *slot = std::move(w);
        return true;
    }

    class Tunnel {
        using Client = a::Client<Factory>;
        using Connection = typename Factory::Connection;
        Session& session_;
        Client& client_;
        std::uint32_t timeout_;
        bool relay_local_, ready_ = false;
        std::stop_source stop_;
        std::optional<typename Client::Lease> lease_;
        std::optional<typename Connection::Channel> channel_;

        auto start(a::Address address, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (ready_ || lease_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
            struct Guard { Tunnel& owner; bool done = false; ~Guard() { if (!done) owner.cancel(); } } guard{*this};
            auto lease = co_await client_.acquire(deadline, stop_.get_token());
            if (!lease) co_return lease.error() == a::ClientError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            lease_.emplace(std::move(*lease));
            auto* protocol = lease_->connection().protocol();
            auto id = co_await protocol->open(address, deadline);
            if (!id || stop_.stop_requested() || session_.closed)
                co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            channel_.emplace(*protocol, *id);
            ready_ = true;
            guard.done = true;
            co_return TunnelConnectResult::connected;
        }
    public:
        Tunnel(Session& s, Client& c, std::uint32_t timeout, bool local)
            : session_(s), client_(c), timeout_(timeout), relay_local_(local) {}
        auto cancel() noexcept -> void {
            stop_.request_stop();
            if (channel_) channel_->cancel();
            else if (lease_) lease_->connection().cancel();
            if (ready_ && relay_local_) session_.client.cancel();
        }
        auto connect(corosio::endpoint ep) -> capy::task<TunnelConnectResult> {
            return connect_until(ep, session_.started + std::chrono::milliseconds(timeout_));
        }
        auto connect_until(corosio::endpoint ep, Clock::time_point dl) -> capy::task<TunnelConnectResult> {
            a::Address addr; addr.port = ep.port();
            if (ep.address().is_v4()) { addr.family = net::ProxyAddressFamily::ipv4; addr.length = 4; std::ranges::copy(ep.address().to_v4().to_bytes(), addr.bytes.begin()); }
            else { addr.family = net::ProxyAddressFamily::ipv6; addr.length = 16; std::ranges::copy(ep.address().to_v6().to_bytes(), addr.bytes.begin()); }
            return start(addr, dl);
        }
        auto connect_domain(std::string_view dom, std::uint16_t port, Clock::time_point dl) {
            a::Address addr{net::ProxyAddressFamily::domain, {}, static_cast<std::uint8_t>(dom.size()), port};
            std::ranges::copy(dom, addr.bytes.begin());
            return start(addr, dl);
        }
        auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::framed, {}, true}; }
        auto has_uot() const noexcept -> bool { return true; }
        auto has_xudp() const noexcept -> bool { return false; }
        auto connect_packets(Clock::time_point dl) -> capy::task<TunnelConnectResult> {
            a::Address addr{net::ProxyAddressFamily::domain, {}, static_cast<std::uint8_t>(uot::v2_destination.size()), 443};
            std::ranges::copy(uot::v2_destination, addr.bytes.begin());
            return start(addr, dl);
        }
        auto connect_uot_until(Clock::time_point dl) { return connect_packets(dl); }
        auto connect_uot() { return connect_packets(Clock::now() + std::chrono::milliseconds(timeout_)); }
        auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto send(std::span<std::uint8_t const> b) -> capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            auto ok = co_await channel_->send(b);
            if (ok) session_.touched = Clock::now(); else cancel();
            co_return ok;
        }
        auto read(std::span<std::uint8_t> b) -> capy::task<std::expected<std::size_t, std::string>> {
            if (!ready_ || stop_.stop_requested()) co_return std::unexpected("AnyTLS gRPC stream closed");
            auto r = co_await channel_->read(b);
            if (!r) { cancel(); co_return std::unexpected("AnyTLS gRPC read failed"); }
            if (*r) session_.touched = Clock::now();
            co_return *r;
        }
        auto close_output() -> capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            co_return co_await channel_->close_output();
        }
        auto upload() -> capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                session_.client, *channel_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
        auto download() -> capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                session_.client, *channel_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
    };

    inline auto make_factory(std::unique_ptr<Profile> profile) -> TunnelFactory {
        auto timeout = profile->timeout;
        auto need_direct = profile->options.configured() || profile->fast_open;
        auto* borrowed = profile.get();
        TunnelFactory factory{[profile = std::move(profile)](Session& session, corosio::io_context& context, bool local, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            Worker* fast = nullptr;
            { std::lock_guard lock(profile->mutex); fast = grpc_pool::find(*profile, Mode::fast_open, context); }
            if (fast) return pro::make_proxy<TunnelFacade, Tunnel>(session, fast->client, profile->timeout, local);
            Worker* worker = nullptr;
            { std::lock_guard lock(profile->mutex); worker = grpc_pool::find(*profile, Mode::physical, context); }
            return worker ? pro::make_proxy<TunnelFacade, Tunnel>(session, worker->client, profile->timeout, local) : pro::proxy<TunnelFacade>{};
        }, timeout, [borrowed](Session& session, corosio::io_context& context, TunnelFactory const&, bool local) -> pro::proxy<TunnelFacade> {
            Worker* worker = nullptr;
            { std::lock_guard lock(borrowed->mutex); worker = grpc_pool::find(*borrowed, Mode::layered, context); }
            return worker ? pro::make_proxy<TunnelFacade, Tunnel>(session, worker->client, borrowed->timeout, local) : pro::proxy<TunnelFacade>{};
        }, std::nullopt, need_direct};
        factory.start_context = [borrowed](OutboundContext const& environment, TunnelFactory const* detour, bool direct) {
            auto fast = direct && environment.direct_options ? environment.direct_options->tcp_fast_open.value_or(false) : borrowed->fast_open;
            return detour ? initialize(*borrowed, Mode::layered, environment, detour, direct)
                : initialize(*borrowed, fast ? Mode::fast_open : Mode::physical, environment, nullptr, direct);
        };
        factory.stop_context = [borrowed](corosio::io_context& context) noexcept { grpc_pool::stop(*borrowed, context); };
        factory.reap_context = [borrowed](corosio::io_context& context) noexcept { grpc_pool::reap(*borrowed, context); };
        factory.quiesced_context = [borrowed](corosio::io_context& context) noexcept { return grpc_pool::drained(*borrowed, context); };
        factory.finish_context = [borrowed](corosio::io_context& context) noexcept { grpc_pool::finish(*borrowed, context); };
        return factory;
    }
}
