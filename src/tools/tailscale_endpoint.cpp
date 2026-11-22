module cli.tailscale_endpoint;
import std;
import nexus.compat;
import cli.tailscale_identity;
import crypto;
import endpoint.process_signals;
import http2.client_channel;
import memory.budget;
import tailscale.control;
import tailscale.control_application;
import tailscale.control_connection;
import tailscale.control_messages;
import tailscale.derp_connection;
import tailscale.map_session;
import tailscale.wireguard_tun;
import tls.connector;
import tls.profiles;
import platform.ip_address;
import platform.socket_options;
import platform.netlink_abi;
import rulefile;
import proxy;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace cli::tailscale_endpoint {
    namespace {
        namespace io = nex::corosio;
        namespace capy = nex::capy;
        namespace app = tailscale::control_application;
        namespace cm = tailscale::control_messages;
        namespace noise = tailscale::control;
        using Clock = app::Clock;

        auto endpoint(net::UdpEndpoint const& value) -> io::endpoint {
            if (value.family == 6) return {io::ipv6_address(value.address),value.port};
            io::ipv4_address::bytes_type bytes{};
            std::copy_n(value.address.begin(),bytes.size(),bytes.begin());
            return {io::ipv4_address(bytes),value.port};
        }

        struct Resolver {
            io::endpoint remote;
            bool stopped = false;
            auto cancel() noexcept -> void { stopped = true; }
            auto operator()(Clock::time_point deadline) -> capy::task<std::expected<std::array<io::endpoint,1>,int>> {
                if (stopped || Clock::now() >= deadline) co_return std::unexpected(1);
                co_return std::array{remote};
            }
        };
        using Connector = tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
        using Connection = tailscale::control_connection::Connection<Connector,4>;
        using Relay = tailscale::derp::Connection<Connector>;
        using Device = tailscale::wireguard_tun::Device;
#include "tailscale_mesh_link.hpp"

        struct PreparedRelay {
            RelayConfig const* config;
            tls::ClientProfile tls;
        };

        struct Sink {
            Device& device;
            Config const& config;
            std::uint16_t port;
            std::span<PreparedRelay const> relays;
            PreparedRelay const*& selected;
            Relay*& active_relay;
            UserspaceLink* userspace;
            bool ready = false;

            auto select(tailscale::map_session::State const& state) const -> PreparedRelay const* {
                if (config.relay) return &relays.front();
                auto preferred = state.self()->home_derp;
                auto authorized = [&](PreparedRelay const& relay) {
                    auto const& policy = *relay.config;
                    return std::ranges::any_of(state.derp_nodes(), [&](auto const& node) {
                        if (node.region != policy.region || node.port != policy.server.port || node.host != policy.server_name)
                            return false;
                        auto const& text = policy.server.family == 4 ? node.ipv4 : node.ipv6;
                        if (text.empty()) return true;
                        auto address = platform::parse_ip_address(text);
                        return address && address->size == (policy.server.family == 4 ? 4 : 16) &&
                            address->bytes == policy.server.address;
                    });
                };
                auto relay = std::ranges::find_if(relays, [&](auto const& entry) {
                    return entry.config->region == preferred && authorized(entry);
                });
                if (relay == relays.end()) relay = std::ranges::find_if(relays, [&](auto const& entry) {
                    return std::ranges::any_of(state.peers(), [&](auto const& peer) {
                        return peer.machine_authorized && !peer.expired && peer.home_derp == entry.config->region;
                    }) && authorized(entry);
                });
                return relay == relays.end() ? nullptr : &*relay;
            }
            auto set_relay(PreparedRelay const* relay) noexcept -> void {
                if (selected == relay) return;
                selected = relay;
                if (active_relay) active_relay->cancel();
                device.relay_ready(false);
                device.select_relay(selected ? selected->config->region : 0);
            }
            auto install(tailscale::map_session::State const& state) -> bool {
                if (!state.self()) return false;
                set_relay(select(state));
                if (!device.install(state)) {
                    std::cerr << "Tailscale endpoint: could not install authorized WireGuard routes\n";
                    return false;
                }
                if (userspace) userspace->synchronize(device);
                if (!ready) {
                    std::cout << "Tailscale endpoint \"" << config.name << "\" ready: device=" << config.interface
                              << " port=" << port << '\n' << std::flush;
                    ready = true;
                }
                return true;
            }
            auto revoke() noexcept -> void {
                set_relay(nullptr);
                device.revoke();
                if (userspace) userspace->withdraw();
                ready = false;
            }
        };

        struct Runtime {
            Config const& config;
            tls::ClientProfile const& tls_profile;
            noise::MachinePrivate const& machine;
            noise::NodePublic node;
            noise::ControlPublic pin;
            Device& device;
            std::string_view auth_key;
            net::UdpEndpoint bound;
            std::span<PreparedRelay const> relays;
            crypto::X25519Private const* node_identity;
            std::stop_token shutdown;
            UserspaceLink* userspace;
            io::io_context context;
            Connection* active = nullptr;
            Relay* active_relay = nullptr;
            PreparedRelay const* selected_relay = nullptr;
            bool registered = false, done = false, fatal = false;
            auto stopping() const noexcept -> bool {
                return shutdown.stop_requested() || (!userspace && ::endpoint::process::StopRequested{}());
            }

            auto advertised(std::optional<net::UdpEndpoint> mapping) const -> nexus::inplace_vector<cm::Endpoint,2> {
                nexus::inplace_vector<cm::Endpoint,2> endpoints;
                endpoints.push_back({bound.address,bound.family,bound.port});
                if (mapping && *mapping != bound) endpoints.push_back({mapping->address,mapping->family,mapping->port});
                return endpoints;
            }

            auto consume(Connection& connection, std::shared_ptr<memory::Budget> const& budget,
                         Clock::time_point deadline, std::uint64_t generation, bool& finished) -> capy::task<capy::results<>> {
                struct Done {
                    Runtime& runtime;
                    bool& flag;
                    ~Done() { flag = true; if (runtime.active_relay) runtime.active_relay->cancel(); }
                } completion{*this, finished};
                Sink sink{device, config, bound.port, relays, selected_relay, active_relay, userspace};
                auto endpoints=advertised(device.mapping());
                app::Options options{config.authority, {node,auth_key,config.name,"linux","Nexus",config.ephemeral},
                                     endpoints,generation};
                options.registered = &registered;
                options.disco=device.discovery_key();
                auto result = co_await app::run(*connection.channel(), options, sink, budget, deadline);
                if (!result) {
                    switch (result.error()) {
                    case app::Error::register_denied:
                        std::cerr << "Tailscale endpoint: Control registration failed or was denied\n";
                        fatal = true;
                        break;
                    case app::Error::map_policy:
                        std::cerr << "Tailscale endpoint: Control Map update could not be authorized\n";
                        fatal = true;
                        break;
                    default: break;
                    }
                }
                co_return capy::results<>{};
            }

            auto packets(Connection& connection, bool& finished) -> capy::task<capy::results<>> {
                auto published=device.mapping();
                if (userspace) userspace->synchronize(device);
                while (!finished && !stopping()) {
                    if (!device.poll()) { fatal = true; connection.cancel(); break; }
                    if (userspace) userspace->synchronize(device);
                    if (auto mapping=device.mapping(); mapping!=published) {
                        auto endpoints=advertised(mapping);
                        if (!co_await app::update_endpoints(*connection.channel(),config.authority,node,endpoints,
                                device.discovery_key(),Clock::now()+std::chrono::seconds(5))) {
                            connection.cancel();
                            break;
                        }
                        published=mapping;
                    }
                    auto [error] = co_await io::delay(std::chrono::milliseconds(5));
                    if (error) break;
                }
                co_return capy::results<>{};
            }

            auto relay_read(Relay& relay) -> capy::task<capy::results<>> {
                while (auto packet = co_await relay.receive(Clock::now() + std::chrono::seconds(110))) {
                    if (!device.deliver_relay(packet->peer,packet->bytes)) { fatal = true; break; }
                }
                relay.cancel();
                co_return capy::results<>{};
            }

            auto relay_write(Relay& relay) -> capy::task<capy::results<>> {
                auto limits = relay.settings();
                if (!limits) co_return capy::results<>{};
                auto burst = static_cast<double>(limits->burst ? limits->burst : limits->bytes_per_second);
                double tokens = burst;
                auto last = Clock::now();
                std::optional<Device::RelayPacket> pending;
                while (relay.settings()) {
                    if (pending && !device.valid_relay_packet(*pending)) pending.reset();
                    if (!pending) pending = device.next_relay_packet();
                    auto now = Clock::now();
                    if (limits->bytes_per_second) {
                        tokens = std::min(burst, tokens + std::chrono::duration<double>(now-last).count() * limits->bytes_per_second);
                        last = now;
                    }
                    if (pending) {
                        auto size = pending->bytes.size() + 37;
                        if (!limits->bytes_per_second || size <= tokens) {
                            if (!co_await relay.send(pending->peer,pending->bytes,now + std::chrono::seconds(5))) break;
                            if (limits->bytes_per_second) tokens -= size;
                            pending.reset();
                            continue;
                        }
                        if (size > burst) pending.reset();
                    }
                    auto [error] = co_await io::delay(std::chrono::milliseconds(5));
                    if (error) break;
                }
                relay.cancel();
                co_return capy::results<>{};
            }

            auto relay_task(bool& finished) -> capy::task<capy::results<>> {
                if (relays.empty() || !node_identity) co_return capy::results<>{};
                while (!finished && !fatal && !stopping()) {
                    auto selected = selected_relay;
                    if (!selected) {
                        auto [error] = co_await io::delay(std::chrono::milliseconds(30));
                        if (error) break;
                        continue;
                    }
                    auto const& options = *selected->config;
                    platform::TcpSocketOptions binding;
                    Relay relay(options.authority,*node_identity,options.pin,context,Resolver{endpoint(options.server)},selected->tls,binding);
                    struct ClearRelay {
                        Runtime& runtime;
                        ~ClearRelay() { runtime.active_relay = nullptr; runtime.device.relay_ready(false); }
                    } clear{*this};
                    active_relay = &relay;
                    auto ready = co_await relay.start(Clock::now() + std::chrono::seconds(10));
                    if (ready && !finished && selected_relay == selected) {
                        device.relay_ready(true);
                        (void)co_await capy::when_all(relay_read(relay),relay_write(relay));
                    }
                    device.relay_ready(false);
                    auto retry = Clock::now() + std::chrono::seconds(1);
                    while (!finished && !fatal && selected == selected_relay &&
                           !stopping() && Clock::now() < retry) {
                        auto [error] = co_await io::delay(std::chrono::milliseconds(50));
                        if (error) break;
                    }
                }
                co_return capy::results<>{};
            }

            auto attempt(std::uint64_t generation) -> capy::task<> {
                struct Complete {
                    Runtime& runtime;
                    ~Complete() { runtime.active = nullptr; runtime.done = true; }
                } complete{*this};
                auto budget = std::make_shared<memory::Budget>(16u << 20);
                http2::ClientLimits limits;
                limits.shared_bytes = budget->limit();
                platform::TcpSocketOptions binding;
                auto connection = std::make_unique<Connection>(machine,pin,budget,131072,context,
                    Resolver{endpoint(config.control)},tls_profile,binding);
                struct ClearActive {
                    Runtime& runtime;
                    ~ClearActive() { runtime.active = nullptr; }
                } clear{*this};
                active = connection.get();
                std::vector<std::uint8_t> early(65536);
                auto deadline = Clock::now() + std::chrono::seconds(10);
                if (!co_await connection->start(config.authority,early,deadline,limits,true)) co_return;
                bool finished = false;
                (void)co_await capy::when_all(connection->run(), consume(*connection,budget,deadline,generation,finished),
                                              packets(*connection,finished), relay_task(finished));
                connection->cancel();
                if (!connection->drained()) fatal = true;
            }

            auto run() -> bool {
                auto retry = std::chrono::milliseconds(250);
                for (std::uint64_t generation = 1; !fatal && generation && !stopping(); ++generation) {
                    done = false;
                    capy::run_async(context.get_executor(), []() noexcept {},
                        [this](std::exception_ptr) noexcept { fatal = true; done = true; })(attempt(generation));
                    while (!done) {
                        if (stopping()) {
                            if (active) active->cancel();
                            if (active_relay) active_relay->cancel();
                        }
                        context.restart();
                        context.run_for(std::chrono::milliseconds(10));
                    }
                    device.revoke();
                    if (userspace) userspace->synchronize(device);
                    auto next = Clock::now() + retry;
                    while (Clock::now() < next && !fatal && !stopping())
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    retry = std::min(retry * 2,std::chrono::milliseconds(3000));
                }
                return !fatal && device.healthy();
            }
        };
    }

    static auto run_impl(Config const& config, bool check, std::stop_token stop, UserspaceLink* userspace) -> int {
        auto reject = [](std::string_view reason) { std::cerr << "Tailscale endpoint: " << reason << '\n'; return 1; };
        auto auth = rulefile::read_password_file(config.auth_key_file);
        if (!auth) return reject(auth.error());
        struct Wipe {
            std::string& value;
            ~Wipe() { crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(value.data()),value.size())); }
        } wipe{*auth};
        if (auth->empty() || auth->size() > 4096) return reject("invalid auth-key length");
        constexpr std::array<std::string_view,1> alpn{"http/1.1"};
        auto tls_profile = tls::ClientProfile::load(config.server_name,config.ca_file,0x001d,false,alpn);
        if (!tls_profile) return reject(tls_profile.error());
        std::vector<PreparedRelay> relays;
        auto relay_options = config.relay ? std::span(&*config.relay, 1) : std::span<RelayConfig const>(config.relay_candidates);
        for (auto const& relay : relay_options) {
            auto profile = tls::ClientProfile::load(relay.server_name,relay.ca_file,0x001d,false,alpn);
            if (!profile) return reject(profile.error());
            relays.push_back({&relay, std::move(*profile)});
        }
        auto keys = tailscale_identity::load(config.state_dir,config.ephemeral,check);
        if (!keys) return reject(keys.error());
        auto pin = noise::ControlPublic::from_bytes(config.pin);
        if (!pin) return reject("invalid control pin");
        if (check) {
            std::cout << "Tailscale endpoint configuration valid\n";
            return 0;
        }
        auto machine = noise::MachinePrivate::from_bytes(keys->machine.view());
        keys->machine.clear();
        auto node = noise::NodePrivate::from_bytes(keys->node.view());
        if (!machine || !node || !machine->agree(*pin)) return reject("invalid identity or control pin");
        auto public_node = node->public_key();
        if (!public_node) return reject("cannot derive node identity");
        std::optional<crypto::X25519Private> node_identity;
        std::vector<net::UdpEndpoint> protected_endpoints{config.control,config.listen};
        if(config.stun_server)protected_endpoints.push_back(*config.stun_server);
        if (!relays.empty()) {
            auto identity = crypto::X25519Private::from_bytes(keys->node.view());
            if (!identity) return reject("invalid DERP node key");
            for (auto const& relay : relay_options) {
                if (!identity->agree(relay.pin)) return reject("invalid DERP server pin");
                protected_endpoints.push_back(relay.server);
            }
            node_identity.emplace(std::move(*identity));
        }
        auto device = std::make_unique<Device>(keys->node.view(), tailscale::wireguard_tun::Options{
            userspace ? std::string_view{} : config.interface,config.listen,protected_endpoints,config.mtu,
            config.accept_routes,0,config.discover_paths,config.stun_server});
        keys->node.clear();
        if (!device->open()) return reject(std::format("cannot bind Tailscale UDP listener on port {}",config.listen.port));
        auto bound = device->local_endpoint();
        if (!bound) return reject("cannot inspect UDP listener");
        Runtime runtime{config,*tls_profile,*machine,*public_node,*pin,*device,*auth,*bound,
                        relays,node_identity ? &*node_identity : nullptr,stop,userspace};
        if (!runtime.run()) return reject("control or data plane failed");
        return !userspace && ::endpoint::process::requested_signal == platform::netlink_abi::SIGHUP ? reject("SIGHUP reload is unsupported") : 0;
    }

    auto run(Config const& config, bool check, bool) -> int {
        return run_impl(config,check,{},nullptr);
    }

    auto make_userspace(Config config) -> std::shared_ptr<proxy::MeshLink> {
        return std::make_shared<OutboundLink>([config=std::move(config)](std::stop_token stop, UserspaceLink& link) {
            return run_impl(config,false,stop,&link);
        });
    }
}
