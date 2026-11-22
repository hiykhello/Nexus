module cli.masque_tun;
import std;
import config;
import cli.masque_tun_policy;
import hysteria2.transport_options;
import masque.client_session;
import masque.connect_ip;
import masque.ip_packet;
import net.packet_stream_socket;
import net.udp_socket;
import proxy;
import quic.ech_config;
import packet.fd;
import packet.tun_linux;
import packet.tun_network;
import packet.tun_network_types;
import platform.ip_address;
import platform.socket_options;
import tls.fingerprint;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace cli::tun_enabled {
    namespace {
        namespace io = nex::corosio;
        namespace capy = nex::capy;
        using Clock = std::chrono::steady_clock;
        using Lease = packet::TunNetworkLease<>;

        template<class Client>
        struct Link {
            using Packet = packet::Bytes;
            using Failure = packet::DeviceError;
            Client& client;
            masque::ConnectIpScope const& scope;
            proxy::TrafficRegistration& traffic;
            packet::TunNetworkOptions const* network = nullptr;
            Clock::time_point next_mtu_report{};
            std::array<std::uint8_t,1280> mtu_report;
            std::size_t mtu_report_size = 0;

            auto permits(std::span<std::uint8_t const> bytes, bool inbound) const noexcept -> bool {
                if (!network || bytes.size() > network->mtu) return false;
                auto packet = masque::inspect_ip_packet(bytes);
                return packet && masque_tun::permitted(*packet, *network, client.advertised_routes(), scope, inbound);
            }
            auto send(std::span<std::uint8_t const> bytes) -> std::expected<void, Failure> {
                if (!permits(bytes,false)) return {};
                if (!client.send(bytes)) return std::unexpected(Failure::queue_full);
                traffic.count(true,bytes.size());
                return {};
            }
            auto receive_packet() -> std::expected<std::optional<Packet>, Failure> {
                if (mtu_report_size && client.send(std::span(mtu_report).first(mtu_report_size)))
                    mtu_report_size = 0;
                for (unsigned i = 0; i < 16; ++i) {
                    auto packet = client.try_receive();
                    if (!packet || permits(*packet, true)) return packet;
                    if (network && packet->size() > network->mtu && !mtu_report_size && Clock::now() >= next_mtu_report) {
                        auto view = masque::inspect_ip_packet(*packet);
                        if (!view || !masque_tun::permitted(*view, *network, client.advertised_routes(), scope, true)) continue;
                        auto error = masque_tun::packet_too_big(*view, network->mtu, mtu_report);
                        if (!error.empty()) {
                            if (!client.send(error)) mtu_report_size = error.size();
                            next_mtu_report = Clock::now() + std::chrono::milliseconds(100);
                        }
                    }
                }
                return std::nullopt;
            }
            auto packet_bytes(Packet const& bytes) const noexcept -> std::span<std::uint8_t const> { return bytes; }
            auto output_delivered(std::span<std::uint8_t const> bytes) noexcept -> void {
                traffic.count(false,bytes.size());
            }
            auto retryable(Failure failure) const noexcept -> bool { return failure == Failure::queue_full; }
            auto valid_output(Packet const& bytes) const noexcept -> bool { return permits(bytes, true); }
        };

        auto describe(packet::TunNetworkFailure const& error) -> std::string {
            return std::format("CONNECT-IP TUN network update failed (stage {}, code {}, {})",
                static_cast<int>(error.stage), static_cast<int>(error.code), error.system.message());
        }
    }

    struct MasqueTunHost::Impl {
        config::TunInbound options;
        config::MasqueOutbound outbound;
        std::optional<std::string> lower_host;
        std::unique_ptr<masque::ClientProfile> profile;
        std::optional<quic::EchConfig> ech;
        masque::ConnectIpScope scope;
        std::vector<packet::TunAddress> routes;
        std::array<packet::TunAddress,2> outer_hosts;
        std::size_t outer_count=0;
        io::endpoint peer;
        std::jthread worker;
        mutable std::mutex mutex;
        std::optional<std::string> error;
        std::atomic_bool stopped{false}, failed{false};

        auto fail(std::string reason) -> void {
            std::lock_guard lock(mutex);
            if (!error) error = std::move(reason);
            failed.store(true, std::memory_order_release);
        }

        auto prepare() -> std::expected<void, std::string> {
            auto numeric_host = [](std::string_view text) -> std::optional<platform::IpAddress> {
                auto ip = platform::parse_ip_address(text);
                if (!ip || std::ranges::all_of(ip->view(), [](auto byte) {return byte == 0;})) return {};
                if (ip->size == 16 && ip->bytes[10] == 255 && ip->bytes[11] == 255 &&
                    std::ranges::all_of(ip->view().first(10), [](auto byte) {return byte == 0;})) return {};
                return ip;
            };
            auto outer = numeric_host(outbound.host);
            if (!outer || outbound.bootstrap_resolver)
                return std::unexpected("CONNECT-IP TUN requires a numeric server");
            auto add_outer = [&](platform::IpAddress const& ip) {
                outer_hosts[outer_count++] = {static_cast<std::uint8_t>(ip.size == 4 ? 4 : 6), ip.bytes,
                                             static_cast<std::uint8_t>(ip.size * 8)};
            };
            add_outer(*outer);
            if (lower_host) {
                if (auto lower=numeric_host(*lower_host)) add_outer(*lower);
            }
            if (outbound.local_v4 || outbound.local_v6)
                return std::unexpected("CONNECT-IP TUN takes its local addresses from the peer");
            if (outbound.ech.dns) return std::unexpected("CONNECT-IP TUN uses ech-config-file for ECH");
            if (!outbound.ech.config_file.empty()) {
                auto config = quic::read_ech_config(outbound.ech.config_file);
                if (!config) return std::unexpected(config.error());
                ech.emplace(std::move(*config));
            }
            if (outbound.protocol!="connect-ip")
                return std::unexpected("alternate CONNECT-IP protocols require the proxy outbound");
            if (options.mtu < 1280 || options.mtu > 1500)
                return std::unexpected("CONNECT-IP TUN MTU must be 1280..1500");
            if (outbound.path.starts_with("/.well-known/masque/ip/")) {
                auto parsed = masque::parse_default_ip_path(outbound.path);
                if (!parsed || parsed->kind == masque::IpTargetKind::hostname)
                    return std::unexpected("CONNECT-IP TUN default path requires a wildcard or numeric target");
                scope = std::move(*parsed);
            }
            for (auto const& text : options.connect_ip_routes) {
                auto route = masque_tun::parse_route(text);
                if (!route || std::ranges::any_of(std::span(outer_hosts).first(outer_count), [&](auto const& host) {
                        return masque_tun::route_contains(*route, host);
                    })) return std::unexpected("CONNECT-IP TUN route is invalid or includes an outer server");
                routes.push_back(*route);
            }
            if (outer->size == 4) {
                io::ipv4_address::bytes_type bytes{};
                std::ranges::copy(outer->view(), bytes.begin());
                peer = {io::ipv4_address(bytes), outbound.port};
            } else peer = {io::ipv6_address(outer->bytes), outbound.port};
            if (options.socket_mark) outbound.tcp_options.binding.routing_mark = options.socket_mark;
            auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(outbound.fingerprint));
            if (!fp) return std::unexpected("CONNECT-IP TUN TLS fingerprint is invalid");
            hysteria2::TransportOptions transport{
                std::chrono::milliseconds(outbound.handshake_timeout_ms),
                std::chrono::milliseconds(outbound.idle_timeout_ms), outbound.native_bytes};
            transport.max_udp_payload_size = std::min<std::size_t>(1452, options.mtu + 64);
            auto group = outbound.key_exchange == config::TlsKeyExchange::x25519 ? 0x001d : 0x11ec;
            auto loaded = masque::ClientProfile::load(outbound.server_name, outbound.ca_file, outbound.authority,
                outbound.bearer_file, group, outbound.key_exchange == config::TlsKeyExchange::x25519_mlkem768_only, transport, *fp);
            if (!loaded) return std::unexpected(loaded.error());
            profile = std::move(*loaded);
            return {};
        }

        template<class Client>
        auto bridge(Client& client,proxy::Server& server,Clock::time_point deadline) -> capy::task<capy::results<>> {
            using Pump = packet::StaticFdPump<Link<Client>, 1500>;
            std::optional<packet::LinuxTun> device;
            std::optional<Lease> lease;
            proxy::TrafficRegistration traffic;
            Link link{client,scope,traffic};
            std::optional<Pump> pump;
            struct Cleanup {
                Impl& owner;
                Client& client;
                std::optional<Lease>& lease;
                std::optional<Pump>& pump;
                ~Cleanup() {
                    pump.reset();
                    if (lease) {
                        auto report = lease->stop(Clock::now() + std::chrono::seconds(2));
                        if (report.total || !lease->drained()) owner.fail("CONNECT-IP TUN removal could not be verified");
                    }
                    client.request_stop();
                }
            } cleanup{*this, client, lease, pump};
            if (!co_await client.connect_ip(outbound.path,deadline,options.mtu+16,outbound.protocol,outbound.connect_headers))
                co_return capy::results<>{};
            traffic=server.track_traffic(proxy::TrafficProtocol::masque_ip,proxy::ConnectPath::tunnel,{},outbound.port,true);
            if (!client.address_epoch()) {
                auto family = [&](unsigned version) {
                    return std::ranges::any_of(routes, [&](auto const& route) { return route.family == version; });
                };
                if (!client.request_addresses(family(4), family(6))) co_return capy::results<>{};
            }
            std::pair<std::uint64_t, std::uint64_t> epoch{};
            while (!stopped.load(std::memory_order_acquire) && client.ready() && !traffic.close_requested()) {
                auto control = std::pair{client.address_epoch(), client.route_epoch()};
                if (control != epoch) {
                    epoch = control;
                    if (pump) pump->clear();
                    link.mtu_report_size = 0;
                    client.discard_ip_datagrams(true);
                    auto next = masque_tun::snapshot(options.mtu, client.assigned_addresses(), client.advertised_routes(), routes, scope);
                    if (!next || std::ranges::any_of(std::span(next->addresses).first(next->address_count), [&](auto const& address) {
                            return std::ranges::any_of(std::span(outer_hosts).first(outer_count), [&](auto const& host) {
                                return address.family == host.family && address.bytes == host.bytes;
                            });
                        })) {
                        fail("CONNECT-IP TUN control snapshot is invalid or exceeds capacity");
                        break;
                    }
                    auto apply_by = Clock::now() + std::chrono::milliseconds(750);
                    auto rollback_by = apply_by + std::chrono::seconds(1);
                    if (!lease && next->address_count) {
                        auto created = packet::LinuxTun::create(options.interface_name);
                        if (!created) { fail("cannot create CONNECT-IP TUN device"); break; }
                        device.emplace(std::move(*created));
                        auto token = device->claim_network();
                        if (!token) { fail("cannot claim CONNECT-IP TUN device"); break; }
                        auto placed = Lease::emplace_into(lease, std::move(*token), *next);
                        if (!placed) { fail(describe(placed.error())); break; }
                        auto active = lease->start(apply_by, rollback_by);
                        if (!active) { fail(describe(active.error())); break; }
                        auto prepared = Pump::prepare(lease->native_handle(), options.mtu);
                        if (!prepared) { fail("cannot attach CONNECT-IP TUN packet pump"); break; }
                        pump.emplace(std::move(*prepared), link);
                        link.network = &lease->network_options();
                    } else if (lease && *next != lease->network_options()) {
                        auto updated = lease->replace(*next, apply_by, rollback_by);
                        if (!updated) { fail(describe(updated.error())); break; }
                    }
                }
                if (!pump && Clock::now() >= deadline) break;
                bool moved = false;
                if (pump) for (unsigned i = 0; i < 16; ++i) {
                    auto step = pump->step();
                    if (step.input_error || step.output_error) {
                        fail("CONNECT-IP TUN packet I/O failed");
                        co_return capy::results<>{};
                    }
                    if (!step.input_delivered && !step.output_delivered) break;
                    moved = true;
                }
                auto [ec] = co_await io::delay(moved ? std::chrono::milliseconds(1) : std::chrono::milliseconds(5));
                if (ec) break;
            }
            co_return capy::results<>{};
        }

        template<class Client>
        auto drive(Client& client,proxy::Server& server,Clock::time_point deadline) -> capy::task<> {
            struct Finish {Client& client; ~Finish(){client.finish();}} finish{client};
            (void)co_await capy::when_all(client.run(), bridge(client,server,deadline));
        }

        auto drive_direct(io::io_context& context,proxy::Server& server,Clock::time_point deadline) -> capy::task<> {
            auto binding=outbound.tcp_options.binding;
            if (!binding.network) {
                masque::Client<> client(context,*profile);
                if (client.start(peer,&binding,ech ? &*ech : nullptr,std::chrono::seconds(10),deadline))
                    co_await drive(client,server,deadline);
                co_return;
            }
            auto paths=(*binding.network)(peer.is_v6());
            binding.network.reset();
            auto stop=co_await capy::this_coro::stop_token;
            for (std::size_t index=0;index<paths.indices.size();++index) {
                auto now=Clock::now();
                if (stop.stop_requested() || now>=deadline) co_return;
                auto attempt=index+1<paths.indices.size() ? std::min(deadline,now+paths.fallback_delay) : deadline;
                binding.interface_index=paths.indices[index];
                masque::Client<> client(context,*profile);
                std::error_code error;
                if (!client.start(peer,&binding,ech ? &*ech : nullptr,std::chrono::seconds(10),attempt,&error)) {
                    if (platform::network::retry_interface_error(error)) continue;
                    co_return;
                }
                struct Finish {masque::Client<>& client;~Finish(){client.finish();}} finish{client};
                bool retry=false;
                auto authorize=[&]() -> capy::task<capy::results<>> {
                    auto ready=co_await client.wait_http_ready(attempt,stop);
                    if (ready) co_return co_await bridge(client,server,deadline);
                    retry=!stop.stop_requested() && client.retryable_http_handshake(attempt);
                    client.request_stop();
                    co_return capy::results<>{};
                };
                (void)co_await capy::when_all(client.run(),authorize());
                // Once an authenticated H3 session exists, CONNECT-IP keeps its
                // original deadline and routed lease on the selected socket.
                if (!retry) co_return;
            }
        }

        auto drive_detour(proxy::Server& server, Clock::time_point deadline) -> capy::task<> {
            auto quota = server.acquire_session();
            if (!quota) co_return;
            auto& context = server.executor_context();
            net::UdpEndpoint transport_peer;
            proxy::Session session(context);
            session.physical_peer=&transport_peer;
            server.attach_session(session, std::move(*quota));
            auto tunnel = server.open_packet_tunnel(session, *outbound.detour_index);
            if (!tunnel) co_return;
            struct Cancel {proxy::PacketTunnel& tunnel; ~Cancel(){tunnel.cancel();}} cancel{*tunnel};
            auto stop = co_await capy::this_coro::stop_token;
            std::stop_callback canceled(stop, [&]() noexcept {tunnel->cancel();});
            if (stop.stop_requested()) co_return;
            auto connected = co_await tunnel->connect_until(net::packet_peer_address(peer),deadline);
            if (connected != proxy::PacketConnectResult::connected || stop.stop_requested()) co_return;
            if (!transport_peer.port) {
                fail("CONNECT-IP TUN could not identify the physical detour peer");
                co_return;
            }
            auto address=transport_peer.address;
            auto family=transport_peer.family;
            if (family==6 && address[10]==255 && address[11]==255 &&
                std::ranges::all_of(std::span(address).first<10>(),[](auto byte) {return byte==0;})) {
                address={address[12],address[13],address[14],address[15]};
                family=4;
            }
            packet::TunAddress outer{family,address,static_cast<std::uint8_t>(family==4 ? 32 : 128)};
            if (std::ranges::any_of(routes,[&](auto const& route) {return masque_tun::route_contains(route,outer);})) {
                fail("CONNECT-IP TUN route includes the connected physical detour peer");
                co_return;
            }
            outer_hosts[1]=outer;
            outer_count=2;
            masque::Client<net::PacketStreamSocket<proxy::PacketTunnel>> client(context, *profile);
            if (!client.socket().attach(*tunnel, tunnel->transport(), peer)) co_return;
            auto prepared = co_await client.socket().prepare(deadline);
            if (!prepared || stop.stop_requested()) co_return;
            if (client.start(peer, nullptr, ech ? &*ech : nullptr, std::chrono::seconds(10)))
                co_await drive(client,server,deadline);
        }

        auto run(proxy::Server& server) -> void {
            std::optional<io::io_context> direct;
            if (!lower_host) direct.emplace();
            auto& context = direct ? *direct : server.executor_context();
            auto backoff = std::chrono::milliseconds(100);
            while (!stopped.load(std::memory_order_acquire) && !failed.load(std::memory_order_acquire)) {
                bool done = false;
                std::stop_source cancel;
                auto deadline = Clock::now() + std::chrono::milliseconds(outbound.connect_timeout_ms);
                capy::run_async(context.get_executor(), cancel.get_token(), [&]() noexcept { done = true; },
                    [&](std::exception_ptr) noexcept { done = true; })
                    (direct ? drive_direct(context,server,deadline) : drive_detour(server, deadline));
                while (!done) {
                    if (stopped.load(std::memory_order_acquire)) cancel.request_stop();
                    context.restart();
                    context.run_for(std::chrono::milliseconds(10));
                }
                auto retry_at = Clock::now() + backoff;
                while (!stopped.load(std::memory_order_acquire) && !failed.load(std::memory_order_acquire) && Clock::now() < retry_at)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                backoff = std::min(backoff * 2, std::chrono::milliseconds(2000));
            }
        }
    };

    MasqueTunHost::MasqueTunHost(config::TunInbound options, config::MasqueOutbound outbound, std::optional<std::string> lower_host)
        : impl_(new Impl{std::move(options), std::move(outbound), std::move(lower_host)}) {}
    MasqueTunHost::~MasqueTunHost() { stop(); }
    auto MasqueTunHost::start(proxy::Server& server) -> std::expected<std::string, std::string> {
        auto ready = impl_->prepare();
        if (!ready) return std::unexpected(ready.error());
        if (impl_->lower_host) {
            auto prepared = server.prepare_routing(1);
            if (!prepared) return std::unexpected("cannot prepare CONNECT-IP TUN outbound: " + prepared.error().message());
            auto active = server.activate_context();
            if (!active) return std::unexpected("cannot activate CONNECT-IP TUN outbound: " + active.error().message());
        }
        impl_->worker = std::jthread([owner = impl_.get(), &server] {
            try { owner->run(server); }
            catch (...) { owner->fail("CONNECT-IP TUN worker failed"); }
        });
        return impl_->options.interface_name;
    }
    auto MasqueTunHost::healthy() const noexcept -> bool { return !impl_->failed.load(std::memory_order_acquire); }
    auto MasqueTunHost::failure() const -> std::optional<std::string> {
        std::lock_guard lock(impl_->mutex);
        return impl_->error;
    }
    auto MasqueTunHost::stop() noexcept -> void {
        impl_->stopped.store(true, std::memory_order_release);
        if (impl_->worker.joinable()) impl_->worker.join();
    }
}
