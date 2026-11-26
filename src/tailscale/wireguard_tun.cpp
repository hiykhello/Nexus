module tailscale.wireguard_tun;
import std;
import containers.inplace_vector;
import crypto;
import net.udp_socket;
import packet.fd;
import packet.tun_network_types;
import tailscale.map_session;
import tailscale.control_messages;
import tailscale.control;
import tailscale.box;
import tailscale.magic_dns;
import tailscale.netlink_worker;
import tailscale.snapshot;
import tailscale.stun_queries;
import tailscale.packet_filter;
import tailscale.wireguard_routes;
import tailscale.discovery;
import wireguard;
import wireguard.endpoint;
import wireguard.port;
import wireguard.port_types;
import wireguard.routing;

namespace tailscale::wireguard_tun {
    using Clock = std::chrono::steady_clock;
    using Wall = std::chrono::system_clock;
    namespace discovery = tailscale::discovery;
    using wireguard_tun_detail::NetlinkWorker;

    struct Device::Impl {
        using RelayPacket = Device::RelayPacket;
    private:
        struct Outer {
            Impl* owner;
            auto allows(net::UdpEndpoint const& endpoint) const noexcept -> bool { return owner->outer_allowed(endpoint); }
            auto allows_peer(wireguard::routing::PeerHandle peer, net::UdpEndpoint const& endpoint) const noexcept -> bool {
                return owner->outer_peer_allowed(peer, endpoint);
            }
            auto receive_auxiliary(net::UdpEndpoint const& source, std::span<const std::uint8_t> bytes, Clock::time_point now) const -> bool {
                return owner->receive_auxiliary(source, bytes, now);
            }
            auto send_relay(wireguard::routing::PeerHandle peer, std::span<const std::uint8_t> bytes) const
                -> std::expected<void, std::error_code> {
                return owner->send_relay(peer, bytes);
            }
        };
        using Port = wireguard::UdpPort<64, 32, 2048, 64, wireguard::PortNoHooks, Outer>;
        using Bytes = std::span<const std::uint8_t>;
        struct ActivePeer { wireguard::routing::PeerHandle handle; wireguard_routes::Peer config; };
        struct Flow {
            packet_filter::Address source, destination;
            std::uint8_t protocol = 0;
            std::uint16_t source_port = 0, destination_port = 0;
            auto operator==(Flow const&) const -> bool = default;
            auto reverse() const noexcept -> Flow { return {destination, source, protocol, destination_port, source_port}; }
        };
        struct Reply { Flow flow; Clock::time_point expires; };

        static auto tuple(Bytes wire) noexcept -> std::optional<Flow> {
            auto ip = wireguard::parse_inner_packet(wire);
            if (!ip || ip->packet.size() != wire.size()) return {};
            auto ipv4 = ip->family == 4;
            if (ipv4 && ((wire[0] & 15) != 5 || (wire[6] & 0xbf) || wire[7] || !wire[8])) return {};
            if (!ipv4 && !wire[7]) return {};
            auto protocol = ipv4 ? wire[9] : wire[6];
            auto data = wire.subspan(ipv4 ? 20 : 40);
            if (protocol == 6) {
                if (data.size() < 20 || (data[12] >> 4) < 5 || (data[12] >> 4) * 4u > data.size()) return {};
            } else if (protocol == 17) {
                if (data.size() < 8 || ((std::size_t(data[4]) << 8) | data[5]) != data.size()) return {};
            } else return {};
            auto port = [&](std::size_t o) { return static_cast<std::uint16_t>((std::uint16_t(data[o]) << 8) | data[o + 1]); };
            if (!port(0) || !port(2)) return {};
            return Flow{{ip->source, ip->family}, {ip->destination, ip->family}, protocol, port(0), port(2)};
        }

        mutable std::mutex mutex_;
        Options options_;
        std::string exit_node_name_owned_;
        std::vector<control_messages::Prefix> advertise_routes_owned_;
        std::vector<control_messages::Prefix> lan_bypass_routes_;
        std::shared_ptr<magic_dns::Resolver> magic_dns_;
        discovery::Paths paths_;
        std::expected<Port, wireguard::PortFailure> port_;
        NetlinkWorker netlink_;
        int active_tun_fd_ = -1;
        std::optional<packet::TunNetworkOptions> desired_network_, applied_network_, userspace_network_;
        std::uint64_t userspace_revision_ = 0, relay_revision_ = 0;
        containers::inplace_vector<ActivePeer, 64> peers_;
        map_session::State const* state_ = nullptr;
        std::optional<std::chrono::sys_seconds> expires_;
        std::array<Reply, 512> replies_{};
        std::size_t reply_cursor_ = 0;
        bool failed_ = false, relay_ready_ = false, relay_dirty_ = false, uses_exit_node_ = false, applied_uses_exit_node_ = false;
        std::deque<RelayPacket> relay_packets_;
        void (*relay_wake_fn_)(void*) noexcept = nullptr;
        void* relay_wake_ctx_ = nullptr;

        auto receive_auxiliary(net::UdpEndpoint source, Bytes bytes, Clock::time_point now) -> bool {
            return paths_.receive(source, bytes, now, [this](auto target, auto wire) { return port_->send_auxiliary(target, wire); });
        }
        auto outer_peer_allowed(wireguard::routing::PeerHandle peer, net::UdpEndpoint const& source) const noexcept -> bool {
            auto found = std::ranges::find(peers_, peer, &ActivePeer::handle);
            return found != peers_.end() && (!found->config.managed_path || paths_.verified(found->config.settings.peer_public) == source);
        }
        auto outer_allowed(net::UdpEndpoint const& endpoint) const noexcept -> bool {
            namespace p = packet::tun_network_detail;
            packet::TunAddress address{endpoint.family, endpoint.address, static_cast<std::uint8_t>(p::ip_bytes(endpoint.family) * 8)};
            auto contains_addr = [&](packet::TunAddress const& entry) { return p::contains(entry, address); };
            auto allowed_for = [&](packet::TunNetworkOptions const& network, bool allow_def1) {
                auto contains_route = [&](packet::TunAddress const& entry) {
                    if (allow_def1 && entry.prefix == 1) return false;
                    return p::contains(entry, address);
                };
                return std::ranges::none_of(std::span(network.routes).first(network.route_count), contains_route) &&
                    std::ranges::none_of(std::span(network.addresses).first(network.address_count), contains_addr);
            };
            return (!userspace_network_ || allowed_for(*userspace_network_, uses_exit_node_)) &&
                (!applied_network_ || allowed_for(*applied_network_, applied_uses_exit_node_)) &&
                (!desired_network_ || allowed_for(*desired_network_, uses_exit_node_));
        }
        auto send_relay(wireguard::routing::PeerHandle peer, Bytes bytes) -> std::expected<void, std::error_code> {
            if (!relay_ready_) return std::unexpected(std::make_error_code(std::errc::host_unreachable));
            if (relay_packets_.size() >= 64) return std::unexpected(std::make_error_code(std::errc::no_buffer_space));
            auto found = std::ranges::find(peers_, peer, &ActivePeer::handle);
            if (!state_ || found == peers_.end()) return std::unexpected(std::make_error_code(std::errc::permission_denied));
            relay_packets_.push_back({found->config.settings.peer_public, {bytes.begin(), bytes.end()}, relay_revision_});
            if (relay_wake_fn_) relay_wake_fn_(relay_wake_ctx_);
            return {};
        }
        static auto same(wireguard_routes::Peer const& a, wireguard_routes::Peer const& b) noexcept -> bool {
            return a.id == b.id && a.settings.peer_public == b.settings.peer_public &&
                a.managed_path == b.managed_path && a.settings.allowed_ips == b.settings.allowed_ips &&
                a.is_exit_node == b.is_exit_node &&
                (a.managed_path || (a.settings.peer == b.settings.peer && a.settings.relay_only == b.settings.relay_only));
        }
        auto local(packet_filter::Address const& address) const noexcept -> bool {
            auto const* network = applied_network_ ? &*applied_network_ : userspace_network_ ? &*userspace_network_ : nullptr;
            if (!network) return false;
            return std::ranges::any_of(std::span(network->addresses).first(network->address_count), [&](auto const& entry) {
                return entry.family == address.family && entry.bytes == address.bytes;
            });
        }
        auto in_advertised_route(packet_filter::Address const& address) const noexcept -> bool {
            namespace p = packet::tun_network_detail;
            auto width = static_cast<std::uint8_t>(p::ip_bytes(address.family) * 8);
            packet::TunAddress host{address.family, address.bytes, width};
            for (auto const& adv : advertise_routes_owned_) {
                if (adv.family != address.family) continue;
                if (adv.bits == 0) return true;
                packet::TunAddress net{adv.family, adv.address, adv.bits};
                if (p::contains(net, host)) return true;
            }
            return false;
        }
        auto in_lan_bypass(packet_filter::Address const& address) const noexcept -> bool {
            namespace p = packet::tun_network_detail;
            auto width = static_cast<std::uint8_t>(p::ip_bytes(address.family) * 8);
            packet::TunAddress host{address.family, address.bytes, width};
            for (auto const& bypass : lan_bypass_routes_) {
                if (bypass.family != address.family) continue;
                if (bypass.bits == 0) return true;
                packet::TunAddress net{bypass.family, bypass.address, bypass.bits};
                if (p::contains(net, host)) return true;
            }
            return false;
        }
        auto permits(Flow const& flow, bool inbound, Clock::time_point now) const noexcept -> bool {
            if (!state_ || (!applied_network_ && !userspace_network_) || (expires_ && Wall::now() >= *expires_)) return false;
            if (!inbound) {
                if (!local(flow.source) && !in_advertised_route(flow.source)) return false;
                if (uses_exit_node_ && !lan_bypass_routes_.empty() && in_lan_bypass(flow.destination) &&
                    !in_advertised_route(flow.destination)) return false;
                return true;
            }
            if (!local(flow.destination) && !in_advertised_route(flow.destination)) return false;
            auto reply = std::ranges::any_of(replies_, [&](auto const& entry) { return entry.expires > now && entry.flow == flow; });
            return reply || state_->matches(flow.source, flow.destination, flow.protocol, flow.destination_port);
        }
        auto remember(Flow const& flow, Clock::time_point now) noexcept -> void {
            auto reply = flow.reverse();
            auto existing = std::ranges::find(replies_, reply, &Reply::flow);
            if (existing == replies_.end()) { existing = replies_.begin() + reply_cursor_; reply_cursor_ = (reply_cursor_ + 1) % replies_.size(); }
            *existing = {reply, now + std::chrono::seconds(flow.protocol == 6 ? 300 : 30)};
        }

        struct Link {
            using Packet = Port::Packet;
            using Failure = wireguard::PortFailure;
            Impl& owner;
            auto send(Bytes wire) -> std::expected<void, Failure> {
                auto flow = tuple(wire);
                auto now = Clock::now();
                if (!flow || !owner.permits(*flow, false, now)) return {};
                auto result = owner.port_->enqueue_ip(wire, now);
                if (!result && result.error().code == wireguard::PortError::queue_full) return std::unexpected(result.error());
                if (result) owner.remember(*flow, now);
                return {};
            }
            auto receive_packet() noexcept -> std::expected<std::optional<Packet>, Failure> {
                for (unsigned attempt = 0; attempt < 16; ++attempt) {
                    auto packet = owner.port_->take_packet();
                    if (!packet || valid_output(*packet)) return packet;
                }
                return std::nullopt;
            }
            auto packet_bytes(Packet const& packet) const noexcept -> Bytes { return Bytes(packet.bytes).first(packet.size); }
            auto retryable(Failure const& failure) const noexcept -> bool { return failure.code == wireguard::PortError::queue_full; }
            auto valid_output(Packet const& packet) const noexcept -> bool {
                if (!owner.port_->valid_output(packet)) return false;
                auto flow = tuple(packet_bytes(packet));
                return flow && owner.permits(*flow, true, Clock::now());
            }
        } link_{*this};
        using Pump = packet::StaticFdPump<Link, 1500>;
        std::optional<Pump> pump_;

        auto fail_locked() noexcept -> bool { revoke_locked(); failed_ = true; return false; }

        auto attach_locked(packet::TunNetworkOptions const& network) -> bool {
            if (options_.interface.empty()) {
                std::array<unsigned, 2> counts{};
                for (auto const& item : std::span(network.addresses).first(network.address_count))
                    if (++counts[item.family == 6] > 1) return false;
                if (userspace_network_ != network) ++userspace_revision_;
                userspace_network_ = network;
                return true;
            }
            if (netlink_.failed()) return false;
            if (!netlink_.pending() && applied_network_ && *applied_network_ == network && pump_) {
                desired_network_ = network;
                return true;
            }
            pump_.reset(); active_tun_fd_ = -1; desired_network_ = network;
            return netlink_.request_apply(network);
        }

        auto sync_netlink_locked() -> bool {
            if (options_.interface.empty()) return true;
            auto status = netlink_.sync();
            if (status.failed) return fail_locked();
            if (!state_ || !status.ready) return true;
            if (active_tun_fd_ == status.tun_fd && applied_network_ == status.network && pump_) return true;
            pump_.reset(); active_tun_fd_ = -1;
            auto setup = Pump::prepare(status.tun_fd, options_.mtu);
            if (!setup) return fail_locked();
            pump_.emplace(std::move(*setup), link_);
            active_tun_fd_ = status.tun_fd;
            applied_network_ = status.network;
            applied_uses_exit_node_ = uses_exit_node_;
            return true;
        }

        auto install_locked(map_session::State const& state, bool paths_only = false) -> bool {
            if (!port_ || failed_) return false;
            if (netlink_.failed()) return fail_locked();
            relay_dirty_ = false;
            if (!paths_only) paths_.install(state);
            std::function<std::optional<net::UdpEndpoint>(control::NodePublic const&)> verified;
            if (options_.discover_paths) verified = [this](auto const& node) {
                discovery::Key key; std::ranges::copy(node.view(), key.begin()); return paths_.verified(key);
            };
            wireguard_routes::Policy policy{
                .accept_routes = options_.accept_routes,
                .exit_node = options_.exit_node,
                .exit_node_name = exit_node_name_owned_,
                .exit_node_allow_lan_access = options_.exit_node_allow_lan_access,
                .advertise_routes = advertise_routes_owned_,
            };
            auto next = wireguard_routes::plan(state, policy, options_.mtu, options_.protected_endpoints,
                                               Wall::now(), options_.relay_region, std::move(verified));
            if (!next) return fail_locked();
            state_ = nullptr;
            ++relay_revision_;
            if (pump_) pump_->clear();
            if (!paths_only) { replies_ = {}; reply_cursor_ = 0; }
            if (!paths_only && userspace_network_) ++userspace_revision_;
            relay_packets_.clear();
            for (auto current = peers_.begin(); current != peers_.end();) {
                auto updated = std::ranges::find_if(next->peers, [&](auto const& peer) { return same(current->config, peer); });
                if (updated != next->peers.end()) {
                    auto& settings = current->config.settings; auto const& next_settings = updated->settings;
                    if (settings.peer != next_settings.peer || settings.relay_only != next_settings.relay_only) {
                        if (!port_->change_peer_path(current->handle, next_settings.peer, next_settings.relay_only)) return fail_locked();
                        settings.peer = next_settings.peer; settings.relay_only = next_settings.relay_only;
                    }
                    ++current; continue;
                }
                if (!port_->erase_peer(current->handle)) return fail_locked();
                current = peers_.erase(current);
            }
            for (auto& peer : next->peers) {
                if (std::ranges::any_of(peers_, [&](auto const& current) { return same(current.config, peer); })) continue;
                auto added = port_->add_peer(peer.settings);
                if (!added) return fail_locked();
                peers_.push_back({*added, std::move(peer)});
                for (auto const& route : peers_.back().config.settings.allowed_ips)
                    if (!port_->assign_route(*added, route)) return fail_locked();
            }
            uses_exit_node_ = next->exit_node_peer_id.has_value();
            lan_bypass_routes_ = next->lan_bypass_routes;
            if (!attach_locked(next->network)) return fail_locked();
            expires_ = next->expires;
            state_ = &state;
            if (magic_dns_) state.sync_magic_dns(*magic_dns_);
            return true;
        }

        auto revoke_locked() noexcept -> void {
            state_ = nullptr; paths_.clear(); ++relay_revision_; relay_dirty_ = false;
            uses_exit_node_ = false; applied_uses_exit_node_ = false; lan_bypass_routes_.clear(); expires_.reset();
            pump_.reset(); active_tun_fd_ = -1; desired_network_.reset(); applied_network_.reset();
            if (port_) for (auto const& peer : peers_) if (!port_->erase_peer(peer.handle)) failed_ = true;
            peers_.clear(); relay_packets_.clear(); userspace_network_.reset();
            if (magic_dns_) magic_dns_->clear();
            netlink_.request_revoke();
        }

    public:
        Impl(std::span<const std::uint8_t> node_private, Options options)
            : options_(options),
              exit_node_name_owned_(options.exit_node_name),
              advertise_routes_owned_(options.advertise_routes.begin(), options.advertise_routes.end()),
              magic_dns_(options.magic_dns ? options.magic_dns : std::make_shared<magic_dns::Resolver>()),
              paths_(node_private, options.discover_paths, options.stun_server),
              port_(Port::create(node_private, wireguard::PortOptions{.auto_cookie = true}, Outer{this})),
              netlink_(options.interface) {}
        Impl(Impl const&) = delete;
        auto operator=(Impl const&) -> Impl& = delete;
        ~Impl() { { std::lock_guard lock(mutex_); revoke_locked(); } netlink_.shutdown_and_join(); }

        auto open() -> bool {
            std::lock_guard lock(mutex_);
            return port_ && (!options_.discover_paths || paths_.public_key()) &&
                port_->open(options_.local_endpoint, Clock::now()).has_value();
        }
        auto local_endpoint() const -> std::optional<net::UdpEndpoint> {
            std::lock_guard lock(mutex_);
            if (!port_) return {};
            auto endpoint = port_->local_endpoint();
            return endpoint ? std::optional(*endpoint) : std::nullopt;
        }
        auto healthy() const noexcept -> bool { std::lock_guard lock(mutex_); return !failed_ && !netlink_.failed(); }
        auto mapping() const noexcept -> std::optional<net::UdpEndpoint> { std::lock_guard lock(mutex_); return paths_.mapped_endpoint(); }
        auto discovery_key() const noexcept -> std::optional<control_messages::DiscoKey> { std::lock_guard lock(mutex_); return paths_.public_key(); }
        auto using_exit_node() const noexcept -> bool { std::lock_guard lock(mutex_); return uses_exit_node_; }
        auto lan_bypass_routes() const -> std::vector<control_messages::Prefix> { std::lock_guard lock(mutex_); return lan_bypass_routes_; }
        auto magic_dns() const noexcept -> std::shared_ptr<magic_dns::Resolver> { return magic_dns_; }
        auto install(map_session::State const& state) -> bool { std::lock_guard lock(mutex_); return install_locked(state, false); }
        auto revoke() noexcept -> void { std::lock_guard lock(mutex_); revoke_locked(); }
        auto relay_ready(bool ready) noexcept -> void {
            std::lock_guard lock(mutex_);
            if (!ready) { ++relay_revision_; relay_packets_.clear(); }
            relay_ready_ = ready;
        }
        auto select_relay(std::uint16_t region) noexcept -> void {
            std::lock_guard lock(mutex_);
            if (std::exchange(options_.relay_region, region) != region) {
                ++relay_revision_; relay_packets_.clear(); relay_ready_ = false; relay_dirty_ = true;
            }
        }
        auto set_relay_wake(void (*fn)(void*) noexcept, void* ctx) noexcept -> void {
            std::lock_guard lock(mutex_);
            relay_wake_fn_ = fn; relay_wake_ctx_ = ctx;
        }
        auto watch_fds() const noexcept -> std::array<int, 2> {
            std::lock_guard lock(mutex_);
            return {port_ ? port_->native_handle() : -1, active_tun_fd_ >= 0 ? active_tun_fd_ : netlink_.notify_fd()};
        }
        auto has_active_peers() const noexcept -> bool { std::lock_guard lock(mutex_); return !peers_.empty(); }
        auto next_relay_packet() -> std::optional<RelayPacket> {
            std::lock_guard lock(mutex_);
            if (!state_ || !relay_ready_ || relay_packets_.empty()) return {};
            auto packet = std::move(relay_packets_.front()); relay_packets_.pop_front(); return packet;
        }
        auto valid_relay_packet(RelayPacket const& packet) const noexcept -> bool {
            std::lock_guard lock(mutex_);
            return state_ && relay_ready_ && packet.revision == relay_revision_;
        }
        auto userspace_network() const noexcept -> std::optional<Device::UserspaceNetwork> {
            std::lock_guard lock(mutex_);
            if (!state_ || !userspace_network_ || (expires_ && Wall::now() >= *expires_)) return {};
            Device::UserspaceNetwork result{.revision = userspace_revision_};
            for (auto const& item : std::span(userspace_network_->addresses).first(userspace_network_->address_count)) {
                if (item.family == 4) { result.ipv4.emplace(); std::copy_n(item.bytes.begin(), 4, result.ipv4->begin()); }
                else result.ipv6 = item.bytes;
            }
            return result;
        }
        auto send_ip(Bytes bytes) -> bool {
            std::lock_guard lock(mutex_);
            if (!userspace_network_) return false;
            auto flow = tuple(bytes); auto now = Clock::now();
            if (!flow || !permits(*flow, false, now) || !port_->enqueue_ip(bytes, now)) return false;
            remember(*flow, now); return true;
        }
        auto receive_ip() -> std::optional<std::vector<std::uint8_t>> {
            std::lock_guard lock(mutex_);
            if (!userspace_network_) return {};
            auto packet = link_.receive_packet();
            if (!packet || !*packet) return {};
            auto view = link_.packet_bytes(**packet);
            return std::vector<std::uint8_t>(view.begin(), view.end());
        }
        auto deliver_relay(wireguard::Key const& peer, Bytes bytes) -> bool {
            std::lock_guard lock(mutex_);
            if (!state_ || !relay_ready_ || (expires_ && Wall::now() >= *expires_)) return true;
            if (!port_->receive_relay(peer, bytes, Clock::now())) return fail_locked();
            return true;
        }
        auto poll() -> bool {
            std::lock_guard lock(mutex_);
            if (failed_ || !port_) return false;
            if (!sync_netlink_locked()) return false;
            if (!state_) return true;
            if (expires_ && Wall::now() >= *expires_) { auto state = state_; if (!install_locked(*state)) return false; }
            if (relay_dirty_) { auto state = state_; if (!install_locked(*state, true)) return false; }
            if (!port_->poll(Clock::now(), Wall::now())) return fail_locked();
            paths_.poll(Clock::now(), [this](auto target, auto wire) { return port_->send_auxiliary(target, wire); });
            if (paths_.changed()) { auto state = state_; if (!install_locked(*state, true)) return false; }
            for (unsigned attempt = 0; pump_ && attempt < 256; ++attempt) {
                auto progress = pump_->step();
                if (progress.input_error || progress.output_error) return fail_locked();
                if (!progress.input_delivered && !progress.output_delivered) break;
            }
            return true;
        }
    };

    Device::Device(std::span<const std::uint8_t> key, Options options) : impl_(std::make_unique<Impl>(key, options)) {}
    Device::~Device() = default;
    auto Device::select_relay(std::uint16_t region) noexcept -> void { impl_->select_relay(region); }
    auto Device::mapping() const noexcept -> std::optional<net::UdpEndpoint> { return impl_->mapping(); }
    auto Device::discovery_key() const noexcept -> std::optional<control_messages::DiscoKey> { return impl_->discovery_key(); }
    auto Device::userspace_network() const noexcept -> std::optional<UserspaceNetwork> { return impl_->userspace_network(); }
    auto Device::send_ip(std::span<const std::uint8_t> bytes) -> bool { return impl_->send_ip(bytes); }
    auto Device::receive_ip() -> std::optional<std::vector<std::uint8_t>> { return impl_->receive_ip(); }
    auto Device::open() -> bool { return impl_->open(); }
    auto Device::local_endpoint() const -> std::optional<net::UdpEndpoint> { return impl_->local_endpoint(); }
    auto Device::healthy() const noexcept -> bool { return impl_->healthy(); }
    auto Device::install(map_session::State const& state) -> bool { return impl_->install(state); }
    auto Device::revoke() noexcept -> void { impl_->revoke(); }
    auto Device::poll() -> bool { return impl_->poll(); }
    auto Device::relay_ready(bool ready) noexcept -> void { impl_->relay_ready(ready); }
    auto Device::set_relay_wake(void(*fn)(void*) noexcept, void* ctx) noexcept -> void { impl_->set_relay_wake(fn, ctx); }
    auto Device::watch_fds() const noexcept -> std::array<int, 2> { return impl_->watch_fds(); }
    auto Device::has_active_peers() const noexcept -> bool { return impl_->has_active_peers(); }
    auto Device::using_exit_node() const noexcept -> bool { return impl_->using_exit_node(); }
    auto Device::lan_bypass_routes() const -> std::vector<control_messages::Prefix> { return impl_->lan_bypass_routes(); }
    auto Device::magic_dns() const noexcept -> std::shared_ptr<magic_dns::Resolver> { return impl_->magic_dns(); }
    auto Device::next_relay_packet() -> std::optional<RelayPacket> { return impl_->next_relay_packet(); }
    auto Device::valid_relay_packet(RelayPacket const& packet) const noexcept -> bool { return impl_->valid_relay_packet(packet); }
    auto Device::deliver_relay(wireguard::Key const& peer, std::span<const std::uint8_t> bytes) -> bool {
        return impl_->deliver_relay(peer, bytes);
    }
}
