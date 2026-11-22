// Private Trojan-over-gRPC multiplexed outbound included in trojan.cpp.
#pragma once

namespace proxy::trojan_grpc {
    template<int Mode> struct Worker;

    struct Profile {
        std::string host;
        std::uint16_t port;
        trojan::PasswordKey password;
        tls::ShapedClientProfile tls;
        grpc::RequestProfile request;
        grpc::ResponsePolicy response;
        grpc::Limits limits;
        std::size_t max_sessions;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout_ms;
        TcpSocketOptions options;
        bool fast_open;
        std::mutex mutex;
        std::array<std::unique_ptr<Worker<0>>, 17> physical;
        std::array<std::unique_ptr<Worker<1>>, 17> layered;
        std::array<std::unique_ptr<Worker<2>>, 17> fast;
        ~Profile();
    };

    template<int Mode>
    struct Worker {
        using Pool = typename grpc_pool::PoolWorker<Profile, Mode>::Pool;
        grpc_pool::PoolWorker<Profile, Mode> grpc;
        Worker(OutboundContext const& env, Profile const& p, TunnelFactory const* detour, TcpSocketOptions opts)
            : grpc(env, p, detour, opts) {}
        auto environment() const noexcept -> OutboundContext const& { return grpc.environment; }
        auto stop() noexcept -> void { grpc.stop(); }
        auto drained() const noexcept -> bool { return grpc.drained(); }
    };
    Profile::~Profile() = default;

    template<int Mode>
    auto initialize(Profile& profile, OutboundContext const& environment, TunnelFactory const* detour, bool direct) -> bool {
        std::lock_guard lock(profile.mutex);
        if (grpc_pool::find<Mode>(profile, environment.context) || (direct && !environment.direct_options)) return false;
        auto& entries = grpc_pool::slots<Mode>(profile);
        auto slot = std::ranges::find_if(entries, [](auto const& w) { return !w; });
        if (slot == entries.end()) return false;
        *slot = std::make_unique<Worker<Mode>>(environment, profile, detour, direct ? *environment.direct_options : profile.options);
        return true;
    }

    template<int Mode>
    class Tunnel {
        using Pool = typename Worker<Mode>::Pool;
        using Rpc = typename grpc_pool::Connection<Profile, Mode>::Protocol::Stream;
        using Adapted = transport_detail::GrpcByteStream<Rpc>;
        using Socket = typename grpc_pool::Node<Profile, Mode>::Socket;
        using Client = trojan::detail::Client<Socket, Adapted&>;
        Session& session_;
        Worker<Mode>& worker_;
        bool relay_local_, ready_ = false;
        std::stop_source stop_;
        std::optional<typename Pool::Lease> lease_;
        std::optional<Rpc> rpc_;
        std::optional<Adapted> adapted_;
        std::optional<Client> client_;

        auto start(nex::corosio::endpoint endpoint, bool packets, Clock::time_point deadline,
                   std::string_view domain = {}) -> nex::capy::task<TunnelConnectResult> {
            if (ready_ || lease_ || stop_.stop_requested() || session_.closed || worker_.grpc.stopped)
                co_return TunnelConnectResult::failed;
            struct Guard { Tunnel& owner; bool done = false; ~Guard() { if (!done) owner.cancel(); } } guard{*this};
            auto acquired = co_await worker_.grpc.acquire(stop_, deadline);
            if (!acquired || session_.closed || stop_.stop_requested())
                co_return !acquired ? acquired.error()
                    : (Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed);
            lease_.emplace(std::move(*acquired));
            auto& channel = *lease_->connection().protocol();
            auto opened = channel.open();
            if (!opened) co_return TunnelConnectResult::failed;
            rpc_.emplace(channel, *opened);
            adapted_.emplace(*rpc_, &session_);
            client_.emplace(*adapted_);
            trojan::Request request;
            request.command = packets ? trojan::Command::udp : trojan::Command::tcp;
            auto& address = request.destination;
            if (packets) {
                address.family = trojan::Family::ipv4;
                address.length = 4;
            } else {
                address.port = endpoint.port();
                if (!domain.empty()) {
                    address.family = trojan::Family::domain;
                    address.length = static_cast<std::uint8_t>(domain.size());
                    std::ranges::copy(domain, address.bytes.begin());
                } else if (endpoint.address().is_v4()) {
                    address.family = trojan::Family::ipv4;
                    address.length = 4;
                    std::ranges::copy(endpoint.address().to_v4().to_bytes(), address.bytes.begin());
                } else {
                    address.family = trojan::Family::ipv6;
                    address.length = 16;
                    std::ranges::copy(endpoint.address().to_v6().to_bytes(), address.bytes.begin());
                }
            }
            auto sent = co_await client_->start(worker_.grpc.profile.password.view(), request, deadline);
            if (!sent || session_.closed || stop_.stop_requested())
                co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            ready_ = true;
            guard.done = true;
            co_return TunnelConnectResult::connected;
        }
        auto normal() const noexcept -> bool { return rpc_ && rpc_->complete() && !rpc_->failure(); }
    public:
        Tunnel(Session& session, Worker<Mode>& worker, bool relay_local)
            : session_(session), worker_(worker), relay_local_(relay_local) {}
        auto cancel() noexcept -> void {
            if (normal()) return;
            stop_.request_stop();
            if (client_) client_->cancel();
            if (rpc_) rpc_->cancel();
            if (ready_ && relay_local_) session_.client.cancel();
        }
        auto connect(nex::corosio::endpoint ep) -> nex::capy::task<TunnelConnectResult> {
            return connect_until(ep, session_.started + std::chrono::milliseconds(worker_.grpc.profile.timeout_ms));
        }
        auto connect_until(nex::corosio::endpoint ep, Clock::time_point dl) -> nex::capy::task<TunnelConnectResult> {
            return start(ep, false, dl);
        }
        auto connect_domain(std::string_view dom, std::uint16_t port, Clock::time_point dl) -> nex::capy::task<TunnelConnectResult> {
            return start(nex::corosio::endpoint(nex::corosio::ipv4_address{}, port), false, dl, dom);
        }
        auto has_uot() const noexcept -> bool { return false; }
        auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::framed, trojan::datagram_framing, false}; }
        auto connect_packets(Clock::time_point dl) -> nex::capy::task<TunnelConnectResult> { return start({}, true, dl); }
        auto has_xudp() const noexcept -> bool { return false; }
        auto connect_uot() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_xudp() -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_uot_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto connect_xudp_until(Clock::time_point) -> nex::capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        auto send(std::span<std::uint8_t const> b) -> nex::capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            auto ok = co_await client_->send(b);
            if (ok) session_.touched = Clock::now(); else cancel();
            co_return ok;
        }
        auto read(std::span<std::uint8_t> b) -> nex::capy::task<std::expected<std::size_t, std::string>> {
            if (!ready_ || stop_.stop_requested()) co_return std::unexpected("tunnel closed");
            auto r = co_await client_->read(b);
            if (!r) { cancel(); co_return std::unexpected("Trojan gRPC stream read failed"); }
            if (*r) session_.touched = Clock::now();
            co_return *r;
        }
        auto close_output() -> nex::capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            co_return co_await client_->close_output();
        }
        auto upload() -> nex::capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                session_.client, *client_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
        auto download() -> nex::capy::task<bool> {
            if (!ready_ || stop_.stop_requested()) co_return false;
            co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                session_.client, *client_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
        }
    };

    inline auto make_factory(std::unique_ptr<Profile> profile) -> TunnelFactory {
        auto timeout = profile->timeout_ms;
        auto need_direct = profile->options.configured() || profile->fast_open;
        auto* borrowed = profile.get();
        TunnelFactory factory{[profile = std::move(profile)](Session& session, nex::corosio::io_context& context, bool local, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            Worker<2>* fast = nullptr;
            { std::lock_guard lock(profile->mutex); fast = grpc_pool::find<2>(*profile, context); }
            if (fast) return pro::make_proxy<TunnelFacade, Tunnel<2>>(session, *fast, local);
            Worker<0>* worker = nullptr;
            { std::lock_guard lock(profile->mutex); worker = grpc_pool::find<0>(*profile, context); }
            return worker ? pro::make_proxy<TunnelFacade, Tunnel<0>>(session, *worker, local) : pro::proxy<TunnelFacade>{};
        }, timeout, [borrowed](Session& session, nex::corosio::io_context& context, TunnelFactory const&, bool local) -> pro::proxy<TunnelFacade> {
            Worker<1>* worker = nullptr;
            { std::lock_guard lock(borrowed->mutex); worker = grpc_pool::find<1>(*borrowed, context); }
            return worker ? pro::make_proxy<TunnelFacade, Tunnel<1>>(session, *worker, local) : pro::proxy<TunnelFacade>{};
        }, std::nullopt, need_direct};
        factory.start_context = [borrowed](OutboundContext const& environment, TunnelFactory const* detour, bool direct) {
            auto fast = direct && environment.direct_options ? environment.direct_options->tcp_fast_open.value_or(false) : borrowed->fast_open;
            return detour ? initialize<1>(*borrowed, environment, detour, direct)
                : fast ? initialize<2>(*borrowed, environment, nullptr, direct)
                : initialize<0>(*borrowed, environment, nullptr, direct);
        };
        factory.stop_context = [borrowed](nex::corosio::io_context& context) noexcept {
            grpc_pool::stop<0>(*borrowed, context);
            grpc_pool::stop<1>(*borrowed, context);
            grpc_pool::stop<2>(*borrowed, context);
        };
        factory.finish_context = [borrowed](nex::corosio::io_context& context) noexcept {
            grpc_pool::finish<0>(*borrowed, context);
            grpc_pool::finish<1>(*borrowed, context);
            grpc_pool::finish<2>(*borrowed, context);
        };
        return factory;
    }
}
