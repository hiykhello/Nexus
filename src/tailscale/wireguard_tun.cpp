module tailscale.wireguard_tun;
import std;
import crypto;
import net.udp_socket;
import packet.fd;
import packet.tun_linux;
import packet.tun_network;
import packet.tun_network_types;
import tailscale.map_session;
import tailscale.control_messages;
import tailscale.control;
import tailscale.box;
import tailscale.snapshot;
import tailscale.stun_queries;
import tailscale.packet_filter;
import tailscale.wireguard_routes;
import wireguard;
import wireguard.endpoint;
import wireguard.port;
import wireguard.port_types;
import wireguard.routing;

namespace tailscale::wireguard_tun {
    using Clock = std::chrono::steady_clock;
    using Wall = std::chrono::system_clock;
#include "discovery.hpp"
    struct Device::Impl {
        using RelayPacket = Device::RelayPacket;
    private:
        struct Outer {
            Impl* owner;
            auto allows(net::UdpEndpoint const& endpoint) const noexcept -> bool { return owner->outer_allowed(endpoint); }
            auto allows_peer(wireguard::routing::PeerHandle peer,net::UdpEndpoint const& endpoint) const noexcept -> bool {
                return owner->outer_peer_allowed(peer,endpoint);
            }
            auto receive_auxiliary(net::UdpEndpoint const& source,std::span<const std::uint8_t> bytes,Clock::time_point now) const -> bool {
                return owner->receive_auxiliary(source,bytes,now);
            }
            auto send_relay(wireguard::routing::PeerHandle peer, std::span<const std::uint8_t> bytes) const
                -> std::expected<void,std::error_code> {
                return owner->send_relay(peer,bytes);
            }
        };
        using Port = wireguard::UdpPort<64,32,2048,64,wireguard::PortNoHooks,Outer>;
        using Lease = packet::TunNetworkLease<>;
        using Bytes = std::span<const std::uint8_t>;
        struct ActivePeer {
            wireguard::routing::PeerHandle handle;
            wireguard_routes::Peer config;
        };
        struct Flow {
            packet_filter::Address source, destination;
            std::uint8_t protocol = 0;
            std::uint16_t source_port = 0, destination_port = 0;
            auto operator==(Flow const&) const -> bool = default;
            auto reverse() const noexcept -> Flow { return {destination, source, protocol, destination_port, source_port}; }
        };
        struct Reply {
            Flow flow;
            Clock::time_point expires;
        };

        static auto tuple(Bytes wire) noexcept -> std::optional<Flow> {
            auto ip = wireguard::parse_inner_packet(wire);
            if (!ip || ip->packet.size() != wire.size()) return {};
            // Limit authorization to plain IP headers and TCP/UDP. Options,
            // extension headers and fragments lack a supported tuple here.
            auto ipv4 = ip->family == 4;
            if (ipv4 && ((wire[0]&15) != 5 || (wire[6]&0xbf) || wire[7] || !wire[8])) return {};
            if (!ipv4 && !wire[7]) return {};
            auto protocol = ipv4 ? wire[9] : wire[6];
            auto data = wire.subspan(ipv4 ? 20 : 40);
            if (protocol == 6) {
                if (data.size() < 20 || (data[12] >> 4) < 5 || (data[12] >> 4) * 4u > data.size()) return {};
            } else if (protocol == 17) {
                if (data.size() < 8 || ((std::size_t(data[4]) << 8) | data[5]) != data.size()) return {};
            } else return {};
            auto port = [&](std::size_t offset) {
                return static_cast<std::uint16_t>((std::uint16_t(data[offset]) << 8) | data[offset+1]);
            };
            if (!port(0) || !port(2)) return {};
            return Flow{{ip->source, ip->family}, {ip->destination, ip->family}, protocol, port(0), port(2)};
        }

        Options options_;
        discovery::Paths paths_;
        std::expected<Port,wireguard::PortFailure> port_;
        std::optional<packet::LinuxTun> device_;
        std::optional<Lease> lease_;
        std::optional<packet::TunNetworkOptions> userspace_network_;
        std::uint64_t userspace_revision_ = 0;
        std::inplace_vector<ActivePeer,64> peers_;
        map_session::State const* state_ = nullptr;
        std::optional<std::chrono::sys_seconds> expires_;
        std::array<Reply,512> replies_{};
        std::size_t reply_cursor_ = 0;
        bool failed_ = false;
        bool relay_ready_ = false;
        std::uint64_t relay_revision_ = 0;
        std::deque<RelayPacket> relay_packets_;

        auto receive_auxiliary(net::UdpEndpoint source,Bytes bytes,Clock::time_point now) -> bool {
            return paths_.receive(source,bytes,now,[this](auto target,auto wire) {return port_->send_auxiliary(target,wire);});
        }
        auto outer_peer_allowed(wireguard::routing::PeerHandle peer, net::UdpEndpoint const& source) const noexcept -> bool {
            auto found=std::ranges::find(peers_,peer,&ActivePeer::handle);
            return found!=peers_.end() && (!found->config.managed_path || paths_.verified(found->config.settings.peer_public)==source);
        }

        auto outer_allowed(net::UdpEndpoint const& endpoint) const noexcept -> bool {
            if (!lease_ && !userspace_network_) return true;
            auto const& network=lease_ ? lease_->network_options() : *userspace_network_;
            namespace p=packet::tun_network_detail;
            packet::TunAddress address{endpoint.family,endpoint.address,
                                       static_cast<std::uint8_t>(p::ip_bytes(endpoint.family)*8)};
            auto contains=[&](auto const& entry) { return p::contains(entry,address); };
            return std::ranges::none_of(std::span(network.routes).first(network.route_count),contains) &&
                std::ranges::none_of(std::span(network.addresses).first(network.address_count),contains);
        }

        auto send_relay(wireguard::routing::PeerHandle peer, Bytes bytes) -> std::expected<void,std::error_code> {
            if (!relay_ready_) return std::unexpected(std::make_error_code(std::errc::host_unreachable));
            if (relay_packets_.size() >= 64) return std::unexpected(std::make_error_code(std::errc::no_buffer_space));
            auto found = std::ranges::find(peers_,peer,&ActivePeer::handle);
            if (!state_ || found == peers_.end())
                return std::unexpected(std::make_error_code(std::errc::permission_denied));
            relay_packets_.push_back({found->config.settings.peer_public,{bytes.begin(),bytes.end()},relay_revision_});
            return {};
        }

        static auto same(wireguard_routes::Peer const& a, wireguard_routes::Peer const& b) noexcept -> bool {
            return a.id == b.id && a.settings.peer_public == b.settings.peer_public &&
                a.managed_path == b.managed_path && a.settings.allowed_ips == b.settings.allowed_ips &&
                (a.managed_path || (a.settings.peer == b.settings.peer && a.settings.relay_only == b.settings.relay_only));
        }

        auto local(packet_filter::Address const& address) const noexcept -> bool {
            auto const& network = lease_ ? lease_->network_options() : *userspace_network_;
            return std::ranges::any_of(std::span(network.addresses).first(network.address_count), [&](auto const& entry) {
                return entry.family == address.family && entry.bytes == address.bytes;
            });
        }

        auto permits(Flow const& flow, bool inbound, Clock::time_point now) const noexcept -> bool {
            if (!state_ || (!lease_ && !userspace_network_) || (expires_ && Wall::now() >= *expires_)) return false;
            if (!inbound) return local(flow.source);
            if (!local(flow.destination)) return false;
            auto reply = std::ranges::any_of(replies_, [&](auto const& entry) { return entry.expires > now && entry.flow == flow; });
            return reply || state_->matches(flow.source, flow.destination, flow.protocol, flow.destination_port);
        }

        auto remember(Flow const& flow, Clock::time_point now) noexcept -> void {
            auto reply = flow.reverse();
            auto existing = std::ranges::find(replies_, reply, &Reply::flow);
            if (existing == replies_.end()) {
                existing = replies_.begin() + reply_cursor_;
                reply_cursor_ = (reply_cursor_ + 1) % replies_.size();
            }
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
        using Pump = packet::StaticFdPump<Link,1500>;
        std::optional<Pump> pump_;

        auto fail() noexcept -> bool { revoke(); failed_ = true; return false; }

        auto attach(packet::TunNetworkOptions const& network) -> bool {
            if (options_.interface.empty()) {
                std::array<unsigned,2> counts{};
                for(auto const& item:std::span(network.addresses).first(network.address_count))
                    if(++counts[item.family==6]>1)return false;
                if(userspace_network_!=network)++userspace_revision_;
                userspace_network_=network;
                return true;
            }
            auto apply = Clock::now() + std::chrono::milliseconds(750);
            auto rollback = apply + std::chrono::seconds(1);
            if (lease_) return network == lease_->network_options() || lease_->replace(network, apply, rollback).has_value();
            auto tun = packet::LinuxTun::create(options_.interface);
            if (!tun) return false;
            device_.emplace(std::move(*tun));
            auto token = device_->claim_network();
            if (!token || !Lease::emplace_into(lease_, std::move(*token), network) || !lease_->start(apply, rollback)) return false;
            auto setup = Pump::prepare(lease_->native_handle(), options_.mtu);
            if (!setup) return false;
            pump_.emplace(std::move(*setup), link_);
            return true;
        }

    public:
        Impl(std::span<const std::uint8_t> node_private, Options options)
            : options_(options), paths_(node_private,options.discover_paths,options.stun_server),
              port_(Port::create(node_private, wireguard::PortOptions{.auto_cookie=true},Outer{this})) {}
        Impl(Impl const&) = delete;
        auto operator=(Impl const&) -> Impl& = delete;
        ~Impl() { revoke(); }

        auto open() -> bool {
            return port_ && (!options_.discover_paths || paths_.public_key()) &&
                port_->open(options_.local_endpoint, Clock::now()).has_value();
        }

        auto local_endpoint() const -> std::optional<net::UdpEndpoint> {
            if (!port_) return {};
            auto endpoint = port_->local_endpoint();
            return endpoint ? std::optional(*endpoint) : std::nullopt;
        }

        auto healthy() const noexcept -> bool { return !failed_; }
        auto mapping() const noexcept -> std::optional<net::UdpEndpoint> { return paths_.mapped_endpoint(); }
        auto discovery_key() const noexcept -> std::optional<control_messages::DiscoKey> { return paths_.public_key(); }

        auto install(map_session::State const& state, bool paths_only = false) -> bool {
            if (!port_ || failed_) return false;
            if (!paths_only) paths_.install(state);
            std::function<std::optional<net::UdpEndpoint>(control::NodePublic const&)> verified;
            if (options_.discover_paths) verified = [this](auto const& node) {
                discovery::Key key;
                std::ranges::copy(node.view(),key.begin());
                return paths_.verified(key);
            };
            auto next = wireguard_routes::plan(state, options_.accept_routes, options_.mtu, options_.protected_endpoints,
                                               Wall::now(), options_.relay_region, std::move(verified));
            if (!next) return fail();
            state_ = nullptr;
            ++relay_revision_;
            if (pump_) pump_->clear();
            if (!paths_only) { replies_ = {}; reply_cursor_ = 0; }
            if (!paths_only && userspace_network_) ++userspace_revision_;
            relay_packets_.clear();
            for (auto current = peers_.begin(); current != peers_.end();) {
                auto updated = std::ranges::find_if(next->peers, [&](auto const& peer) { return same(current->config, peer); });
                if (updated != next->peers.end()) {
                    auto& settings = current->config.settings;
                    auto const& next_settings = updated->settings;
                    if (settings.peer != next_settings.peer || settings.relay_only != next_settings.relay_only) {
                        if (!port_->change_peer_path(current->handle,next_settings.peer,next_settings.relay_only)) return fail();
                        settings.peer = next_settings.peer;
                        settings.relay_only = next_settings.relay_only;
                    }
                    ++current;
                    continue;
                }
                if (!port_->erase_peer(current->handle)) return fail();
                current = peers_.erase(current);
            }
            for (auto& peer : next->peers) {
                if (std::ranges::any_of(peers_, [&](auto const& current) { return same(current.config, peer); })) continue;
                auto added = port_->add_peer(peer.settings);
                if (!added) return fail();
                peers_.push_back({*added, std::move(peer)});
                for (auto const& route : peers_.back().config.settings.allowed_ips)
                    if (!port_->assign_route(*added, route)) return fail();
            }
            if (!attach(next->network)) return fail();
            expires_ = next->expires;
            state_ = &state;
            return true;
        }

        auto revoke() noexcept -> void {
            state_ = nullptr;
            paths_.clear();
            ++relay_revision_;
            expires_.reset();
            pump_.reset();
            if (port_) for (auto const& peer : peers_) if (!port_->erase_peer(peer.handle)) failed_ = true;
            peers_.clear();
            relay_packets_.clear();
            if (lease_) {
                auto report = lease_->stop(Clock::now() + std::chrono::seconds(2));
                if (report.total || !lease_->drained()) failed_ = true;
                lease_.reset();
            }
            device_.reset();
            userspace_network_.reset();
        }

        auto relay_ready(bool ready) noexcept -> void {
            relay_ready_ = ready;
            if (!ready) relay_packets_.clear();
        }
        auto select_relay(std::uint16_t region) noexcept -> void {
            if (std::exchange(options_.relay_region, region) != region) relay_ready(false);
        }

        auto next_relay_packet() -> std::optional<RelayPacket> {
            if (!state_ || !relay_ready_ || relay_packets_.empty()) return {};
            auto packet = std::move(relay_packets_.front());
            relay_packets_.pop_front();
            return packet;
        }

        auto valid_relay_packet(RelayPacket const& packet) const noexcept -> bool {
            return state_ && relay_ready_ && packet.revision == relay_revision_;
        }

        auto userspace_network() const noexcept -> std::optional<Device::UserspaceNetwork> {
            if(!state_ || !userspace_network_ || (expires_ && Wall::now()>=*expires_))return {};
            Device::UserspaceNetwork result{.revision=userspace_revision_};
            for(auto const& item:std::span(userspace_network_->addresses).first(userspace_network_->address_count)) {
                if(item.family==4) {
                    result.ipv4.emplace();
                    std::copy_n(item.bytes.begin(),4,result.ipv4->begin());
                } else result.ipv6=item.bytes;
            }
            return result;
        }
        auto send_ip(Bytes bytes) -> bool {
            if(!userspace_network_)return false;
            auto flow=tuple(bytes);
            auto now=Clock::now();
            if(!flow || !permits(*flow,false,now) || !port_->enqueue_ip(bytes,now))return false;
            remember(*flow,now);
            return true;
        }
        auto receive_ip() -> std::optional<std::vector<std::uint8_t>> {
            if(!userspace_network_)return {};
            auto packet=link_.receive_packet();
            if(!packet || !*packet)return {};
            auto view=link_.packet_bytes(**packet);
            return std::vector<std::uint8_t>(view.begin(),view.end());
        }

        auto deliver_relay(wireguard::Key const& peer, Bytes bytes) -> bool {
            if (!state_ || !relay_ready_ || (expires_ && Wall::now() >= *expires_)) return true;
            if (!port_->receive_relay(peer,bytes,Clock::now())) return fail();
            return true;
        }

        auto poll() -> bool {
            if (failed_ || !port_) return false;
            if (!state_) return true;
            if (expires_ && Wall::now() >= *expires_) {
                auto state = state_;
                if (!install(*state)) return false;
            }
            if (!port_->poll(Clock::now(), Wall::now())) return fail();
            paths_.poll(Clock::now(),[this](auto target,auto wire) {return port_->send_auxiliary(target,wire);});
            if (paths_.changed() && !install(*state_, true)) return false;
            for (unsigned attempt = 0; pump_ && attempt < 16; ++attempt) {
                auto progress = pump_->step();
                if (progress.input_error || progress.output_error) return fail();
                if (!progress.input_delivered && !progress.output_delivered) break;
            }
            return true;
        }
    };

    Device::Device(std::span<const std::uint8_t> key, Options options) : impl_(std::make_unique<Impl>(key,options)) {}
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
    auto Device::next_relay_packet() -> std::optional<RelayPacket> { return impl_->next_relay_packet(); }
    auto Device::valid_relay_packet(RelayPacket const& packet) const noexcept -> bool { return impl_->valid_relay_packet(packet); }
    auto Device::deliver_relay(wireguard::Key const& peer, std::span<const std::uint8_t> bytes) -> bool {
        return impl_->deliver_relay(peer,bytes);
    }
}
