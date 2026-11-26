module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
module relay;
import std;
import proxy.v4;
import config;
import platform.ip_address;
import tuic.wire;
import tuic.application;
import tuic.client;
import quic.ech_config;
import tls.fingerprint;
import net.datagram_frame;
import net.packet_stream_socket;
import net.unified_datagram;
import net.stream_relay;
import platform.socket_options;
import capy;
import corosio;
import :quic_ech;

namespace relay {
    namespace {
        struct LowerPacketStream {
            Session session;
            pro::proxy<TunnelFacade> tunnel;
            explicit LowerPacketStream(Session const& parent, io::io_context& ctx) : session(ctx) {
                session.dns = parent.dns; session.local_dns = parent.local_dns;
                session.tunnel_factories = parent.tunnel_factories; session.direct_tcp_options = parent.direct_tcp_options;
                session.started = parent.started; session.handshake_deadline = parent.handshake_deadline;
            }
            ~LowerPacketStream() { cancel(); }
            auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
            auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
            auto cancel() noexcept -> void { if (tunnel) tunnel->cancel(); session.close(); }
            auto connect(TunnelFactory const& factory, io::io_context& ctx, net::UnifiedDatagramSocket& socket,
                         io::endpoint peer, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (session.closed || tunnel) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                auto stop = co_await capy::this_coro::stop_token;
                std::stop_callback canceled(stop, [this]() noexcept { cancel(); });
                if (session.closed) co_return TunnelConnectResult::failed;
                tunnel = factory(session, ctx, false);
                if (!tunnel) co_return TunnelConnectResult::failed;
                auto transport = tunnel->packet_transport();
                if (transport.kind == net::PacketTransportKind::none) co_return TunnelConnectResult::failed;
                auto connected = co_await tunnel->connect_packets(net::packet_peer_address(peer), deadline);
                if (connected != TunnelConnectResult::connected) co_return connected;
                if (session.closed || !socket.attach_detour(*this, transport, peer)) co_return TunnelConnectResult::failed;
                if (co_await socket.prepare_detour(deadline) && !session.closed) co_return TunnelConnectResult::connected;
                co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            }
        };

        struct TuicWorker {
            using Client=tuic::Client<net::UnifiedDatagramSocket>;
            struct Attempt {
                // The driver retains the transport until its tasks have joined.
                std::optional<LowerPacketStream> lower;
                Client client;
                Attempt(Session& session,io::io_context& context,tuic::ClientProfile const& profile,bool layered)
                    :client(context,profile) {
                    if (layered) lower.emplace(session,context);
                }
                ~Attempt() {client.finish();}
                auto stop() noexcept -> void {client.begin_shutdown();if (lower) lower->cancel();}
            };

            io::io_context& context;
            tuic::ClientProfile const& profile;
            platform::SocketBinding binding;
            TunnelFactory const* lower;
            std::shared_ptr<Attempt> current;
            capy::async_event changed;
            bool starting=false,started=false,stopping=false;

            TuicWorker(io::io_context& ctx,tuic::ClientProfile const& config,platform::SocketBinding selected,
                TunnelFactory const* via=nullptr)
                :context(ctx),profile(config),binding(std::move(selected)),lower(via) {}

            auto client() noexcept -> Client& {return current->client;}
            auto retired() const noexcept -> bool {
                return stopping || (!starting && current && current->client.retired());
            }

            auto authenticate(Session& session,io::endpoint peer,Clock::time_point deadline,quic::EchConfig const* ech,
                bool const& canceled) -> capy::task<TunnelConnectResult> {
                if (!valid_destination(peer)) co_return TunnelConnectResult::failed;
                auto physical=binding;
                platform::network::InterfaceCandidates paths;
                if (!lower && physical.network) paths=(*physical.network)(peer.is_v6());
                else paths.indices.push_back(physical.interface_index);
                physical.network.reset();
                for (std::size_t index=0;index<paths.indices.size();++index) {
                    auto now=Clock::now();
                    if (stopping || canceled || session.closed) co_return TunnelConnectResult::failed;
                    if (now>=deadline) co_return TunnelConnectResult::timeout;
                    auto until=index+1<paths.indices.size() ? std::min(deadline,now+paths.fallback_delay) : deadline;
                    physical.interface_index=paths.indices[index];
                    auto candidate=std::make_shared<Attempt>(session,context,profile,lower!=nullptr);
                    current=candidate;
                    std::stop_callback cancel(session.stop.get_token(),[candidate]() noexcept {candidate->stop();});
                    auto discard=[&] {
                        candidate->stop();
                        if (current==candidate) current.reset();
                    };
                    auto& client=candidate->client;
                    if (lower) {
                        auto prepared=co_await candidate->lower->connect(*lower,context,client.socket(),peer,until);
                        if (prepared!=TunnelConnectResult::connected) {discard();co_return prepared;}
                    }
                    if (stopping || canceled || session.closed) {discard();co_return TunnelConnectResult::failed;}
                    std::error_code socket_error;
                    if (!client.start(peer,lower ? nullptr : &physical,ech,until,&socket_error)) {
                        discard();
                        if (platform::network::retry_interface_error(socket_error)) continue;
                        co_return Clock::now()>=until ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    }
                    try {
                        capy::run_async(context.get_executor(),[candidate](auto) noexcept {},
                            [candidate](std::exception_ptr) noexcept {candidate->stop();})(client.run());
                    } catch (...) {discard();co_return TunnelConnectResult::failed;}
                    auto accepted=co_await client.ready(until);
                    if (accepted && !stopping && !canceled && !session.closed && Clock::now()<until) {
                        started=true;
                        co_return TunnelConnectResult::connected;
                    }
                    auto retry=client.retryable_handshake(until);
                    discard();
                    if (!retry || stopping || canceled || session.closed) co_return TunnelConnectResult::failed;
                }
                co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
            }

            auto stop() noexcept -> void {
                if (std::exchange(stopping,true)) return;
                if (current) current->stop();
                changed.set();
            }
            auto drained() const noexcept -> bool {
                return !starting && (!current || current->client.retired());
            }
        };

        struct TuicProfile {
            std::string host;
            std::uint16_t port = 0;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout = 10000;
            std::unique_ptr<tuic::ClientProfile> client;
            TcpSocketOptions options;
            quic_ech::Profile ech;
            std::mutex mutex;
            std::vector<std::shared_ptr<TuicWorker>> workers;
            ~TuicProfile() { for (auto& w : workers) w.reset(); }
        };

        auto worker_slot(TuicProfile& profile, io::io_context& ctx) noexcept -> std::shared_ptr<TuicWorker> {
            for (auto const& w : profile.workers) if (w && &w->context == &ctx) return w;
            return {};
        }

        auto acquire_worker(TuicProfile& profile,io::io_context& context) -> std::shared_ptr<TuicWorker> {
            std::shared_ptr<TuicWorker> retired;
            std::shared_ptr<TuicWorker> current;
            {
                std::lock_guard lock(profile.mutex);
                auto slot=std::ranges::find_if(profile.workers,[&](auto const& worker) {
                    return worker && &worker->context==&context;
                });
                if (slot==profile.workers.end()) return {};
                auto& worker=**slot;
                if (worker.retired()) {
                    auto next=std::make_shared<TuicWorker>(context,*profile.client,worker.binding);
                    retired=std::exchange(*slot,std::move(next));
                }
                current=*slot;
            }
            // Existing relays retain their old worker while draining. Close
            // its UDP socket before the replacement tries the same source port.
            if (retired) retired->stop();
            return current;
        }

        auto target_from_endpoint(io::endpoint ep) noexcept -> tuic::TargetAddress {
            tuic::TargetAddress t;
            t.port = ep.port();
            if (ep.is_v4()) {
                t.type = tuic::AddressType::ipv4;
                auto b = ep.address().to_v4().to_bytes();
                std::ranges::copy(b, t.address.begin());
            } else {
                t.type = tuic::AddressType::ipv6;
                auto b = ep.address().to_v6().to_bytes();
                std::ranges::copy(b, t.address.begin());
            }
            return t;
        }

        class TuicTunnel {
            using Worker = TuicWorker;
            Session& session_;
            std::shared_ptr<Worker> worker_;
            TuicProfile& profile_;
            bool relay_local_;
            DnsSlot dns_;
            std::unique_ptr<Worker::Client::Channel> channel_;
            std::optional<std::uint16_t> assoc_;
            std::vector<std::uint8_t> udp_reply_;
            std::size_t udp_reply_off_ = 0;
            bool ready_ = false;
            bool canceled_ = false;

            auto ensure_connected(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                while (worker_->starting && !canceled_ && !session_.closed && !worker_->stopping) {
                    worker_->changed.clear();
                    auto [error]=co_await io::timeout(worker_->changed.wait(),deadline);
                    if (error) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                if (canceled_ || session_.closed || worker_->stopping) co_return TunnelConnectResult::failed;
                if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                if (worker_->started)
                    co_return worker_->client().active() ? TunnelConnectResult::connected : TunnelConnectResult::retryable;
                worker_->starting=true;
                struct Gate {
                    Worker& worker;
                    ~Gate() {worker.starting=false;worker.changed.set();}
                } gate{*worker_};
                auto endpoints=profile_.bootstrap ?
                    co_await resolve_bootstrap_owned(session_,worker_->context,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline) :
                    co_await resolve_local_owned(session_,worker_->context,dns_,profile_.host,profile_.port,deadline);
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                if (!endpoints || endpoints->empty())
                    co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
                auto ech=co_await profile_.ech.resolve(session_,worker_->context,dns_,profile_.bootstrap,profile_.port,deadline);
                if (canceled_ || session_.closed || !ech) co_return TunnelConnectResult::failed;
                co_return co_await worker_->authenticate(session_,endpoints->front(),deadline,*ech ? &**ech : nullptr,canceled_);
            }

        public:
            TuicTunnel(Session& s, std::shared_ptr<Worker> worker, TuicProfile& p, bool local) noexcept
                : session_(s), worker_(std::move(worker)), profile_(p), relay_local_(local) {}
            ~TuicTunnel() {
                if (worker_->lower) cancel();
                else if (assoc_) (void)worker_->client().dissociate(*assoc_);
                channel_.reset();
            }

            auto cancel() noexcept -> void {
                if (std::exchange(canceled_, true)) return;
                dns_.cancel();
                if (channel_) channel_->cancel();
                if (assoc_) { (void)worker_->client().dissociate(*assoc_); assoc_.reset(); }
                if (worker_->lower) worker_->stop();
            }

            auto connect_until(io::endpoint ep, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!valid_destination(ep)) co_return TunnelConnectResult::failed;
                co_return co_await connect_tcp(target_from_endpoint(ep),deadline);
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return connect_tcp({.type=tuic::AddressType::domain,.domain=std::string(domain),.port=port},deadline);
            }
            auto connect_tcp(tuic::TargetAddress target,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (canceled_ || session_.closed || Clock::now() >= deadline)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                if (auto st = co_await ensure_connected(deadline); st != TunnelConnectResult::connected)
                    co_return st;
                auto ch = worker_->client().open_channel(target);
                if (!ch) co_return TunnelConnectResult::failed;
                channel_ = std::move(*ch);
                ready_ = true;
                co_return TunnelConnectResult::connected;
            }
            auto connect(io::endpoint ep) -> capy::task<TunnelConnectResult> {
                return connect_until(ep, session_.started + std::chrono::milliseconds(profile_.timeout));
            }
            auto packet_transport() const noexcept -> net::PacketTransport {
                return {net::PacketTransportKind::framed, {}, false};
            }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (canceled_ || session_.closed || Clock::now() >= deadline)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                if (auto st = co_await ensure_connected(deadline); st != TunnelConnectResult::connected)
                    co_return st;
                assoc_=worker_->client().open_udp();
                if (!assoc_) co_return TunnelConnectResult::failed;
                ready_ = true;
                co_return TunnelConnectResult::connected;
            }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }

            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!ready_ || canceled_) co_return false;
                if (assoc_) {
                    auto frame = net::parse_datagram({}, {}, bytes);
                    if (frame.status != net::DatagramStatus::accepted || frame.consumed != bytes.size()) co_return false;
                    tuic::TargetAddress target;
                    target.port = frame.destination.port;
                    if (frame.destination.family == net::ProxyAddressFamily::ipv4) {
                        target.type = tuic::AddressType::ipv4;
                        std::copy_n(frame.destination.bytes.begin(), 4, target.address.begin());
                    } else if (frame.destination.family == net::ProxyAddressFamily::ipv6) {
                        target.type = tuic::AddressType::ipv6;
                        std::copy_n(frame.destination.bytes.begin(), 16, target.address.begin());
                    } else {
                        target.type = tuic::AddressType::domain;
                        target.domain.assign(reinterpret_cast<char const*>(frame.destination.bytes.data()), frame.destination.length);
                    }
                    bool ok = worker_->client().send_udp(*assoc_, target, frame.payload);
                    if (ok) session_.touched = Clock::now();
                    co_return ok;
                }
                auto ok = co_await channel_->send(bytes);
                if (ok) session_.touched = Clock::now();
                co_return ok;
            }

            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (!ready_ || canceled_) co_return std::unexpected("TUIC tunnel closed");
                if (assoc_) {
                    for (;;) {
                        if (udp_reply_off_ < udp_reply_.size()) {
                            auto n = std::min(bytes.size(), udp_reply_.size() - udp_reply_off_);
                            std::copy_n(udp_reply_.begin() + static_cast<std::ptrdiff_t>(udp_reply_off_), n, bytes.begin());
                            udp_reply_off_ += n;
                            if (udp_reply_off_ == udp_reply_.size()) { udp_reply_.clear(); udp_reply_off_ = 0; }
                            session_.touched = Clock::now();
                            co_return n;
                        }
                        auto pkt=co_await worker_->client().wait_udp(Clock::now()+std::chrono::seconds(300),assoc_);
                        if (!pkt || canceled_ || !assoc_) co_return std::unexpected("TUIC UDP session closed");
                        net::ProxyAddress addr{};
                        addr.port = pkt->destination.port;
                        if (pkt->destination.type == tuic::AddressType::ipv4) {
                            addr.family = net::ProxyAddressFamily::ipv4; addr.length = 4;
                            std::copy_n(pkt->destination.address.begin(), 4, addr.bytes.begin());
                        } else if (pkt->destination.type == tuic::AddressType::ipv6) {
                            addr.family = net::ProxyAddressFamily::ipv6; addr.length = 16;
                            std::copy_n(pkt->destination.address.begin(), 16, addr.bytes.begin());
                        } else if (pkt->destination.type == tuic::AddressType::domain && pkt->destination.domain.size() <= addr.bytes.size()) {
                            addr.family = net::ProxyAddressFamily::domain; addr.length = static_cast<std::uint8_t>(pkt->destination.domain.size());
                            std::ranges::copy(pkt->destination.domain, addr.bytes.begin());
                        } else continue;
                        auto framed = net::encode_datagram({}, addr, pkt->payload);
                        if (framed) { udp_reply_ = std::move(*framed); udp_reply_off_ = 0; }
                    }
                }
                auto n = co_await channel_->read(bytes);
                if (n && *n) session_.touched = Clock::now();
                co_return n;
            }
            auto close_output() -> capy::task<bool> { co_return ready_ && channel_ && co_await channel_->close_output(); }
            auto upload() -> capy::task<bool> {
                if (!ready_ || canceled_ || !channel_) co_return false;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                    session_.client, *channel_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
            auto download() -> capy::task<bool> {
                if (!ready_ || canceled_ || !channel_) co_return false;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                    session_.client, *channel_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
        };
    }

    auto make_tuic_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
        std::string_view password_file, std::string_view server_name, std::string_view ca_file,
        TlsKeyExchange exchange, TlsFingerprint fingerprint, std::string_view cc, bool udp_over_stream,
        std::uint32_t heartbeat_ms, std::uint32_t handshake_ms, std::uint32_t idle_ms, std::size_t native_bytes,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, TcpSocketOptions options,
        QuicEchOptions const& ech, bool dns_available, std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<TunnelFactory, std::string> {
        if (host.empty() || !port || !timeout_ms || timeout_ms > 3600000 || !options.valid())
            return std::unexpected("invalid TUIC dial options");
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!fp) return std::unexpected("invalid TUIC TLS fingerprint");
        tuic::ClientTransportOptions topts{
            std::chrono::milliseconds(handshake_ms), std::chrono::milliseconds(idle_ms),
            std::chrono::milliseconds(heartbeat_ms), native_bytes,
            cc == "bbr" ? tuic::CongestionControl::bbr : cc == "reno" ? tuic::CongestionControl::reno : tuic::CongestionControl::cubic,
            udp_over_stream};
        auto ech_profile = quic_ech::Profile::load(ech, server_name, dns_available);
        if (!ech_profile) return std::unexpected(ech_profile.error());
        auto client = tuic::ClientProfile::load(
            server_name, ca_file, uuid_file, password_file,
            exchange == TlsKeyExchange::x25519 ? 0x001d : 0x11ec,
            exchange == TlsKeyExchange::x25519_mlkem768_only, topts, *fp, pins);
        if (!client) return std::unexpected(client.error());
        auto profile = std::make_unique<TuicProfile>();
        profile->host = std::string(host);
        profile->port = port;
        profile->bootstrap = bootstrap;
        profile->timeout = timeout_ms;
        profile->client = std::move(*client);
        profile->options = options;
        profile->ech = std::move(*ech_profile);
        auto* borrowed = profile.get();

        TunnelFactory factory{
            [profile = std::move(profile)](Session& s, io::io_context& ctx, bool local, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
                auto worker=acquire_worker(*profile,ctx);
                if (!worker) return {};
                return pro::make_proxy<TunnelFacade, TuicTunnel>(s, std::move(worker), *profile, local);
            },
            timeout_ms, {}, std::nullopt, options.configured()};
        // A TUIC peer can choose its UDP socket family from the first target.
        factory.through = [borrowed](Session& session, io::io_context& context, TunnelFactory const& lower,
                                     bool relay_local) -> pro::proxy<TunnelFacade> {
            auto worker = std::make_shared<TuicWorker>(context, *borrowed->client, platform::SocketBinding{}, &lower);
            return pro::make_proxy<TunnelFacade, TuicTunnel>(session, std::move(worker), *borrowed, relay_local);
        };
        factory.start_context = [borrowed](OutboundContext const& env, TunnelFactory const* lower, bool direct) -> bool {
            if (lower) return true;
            auto binding = direct ? env.direct_options->binding : borrowed->options.binding;
            std::lock_guard lock(borrowed->mutex);
            for (auto const& slot : borrowed->workers) if (slot && &slot->context == &env.context) return false;
            auto slot = std::ranges::find_if(borrowed->workers, [](auto const& w) { return !w; });
            auto w = std::make_shared<TuicWorker>(env.context, *borrowed->client, binding);
            if (slot != borrowed->workers.end()) *slot = std::move(w);
            else borrowed->workers.push_back(std::move(w));
            return true;
        };
        factory.stop_context = [borrowed](io::io_context& ctx) noexcept {
            std::shared_ptr<TuicWorker> w;
            { std::lock_guard lock(borrowed->mutex); w = worker_slot(*borrowed, ctx); }
            if (w) w->stop();
        };
        factory.quiesced_context = [borrowed](io::io_context& ctx) noexcept {
            std::lock_guard lock(borrowed->mutex);
            for (auto const& slot : borrowed->workers)
                if (slot && &slot->context == &ctx && !slot->drained()) return false;
            return true;
        };
        factory.finish_context = [borrowed](io::io_context& ctx) noexcept {
            std::shared_ptr<TuicWorker> removed;
            {
                std::lock_guard lock(borrowed->mutex);
                for (auto& slot : borrowed->workers) {
                    if (slot && &slot->context == &ctx) { removed = std::move(slot); break; }
                }
            }
        };
        return factory;
    }
}
