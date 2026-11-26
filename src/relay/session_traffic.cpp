// Connection endpoint inspection, protocol naming, and TrafficRegistry implementation.
module;
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

module relay;
import std;
import corosio;
import net.datagram_frame;
import net.udp_route;
import platform.network_state;
import rules;

namespace relay {
    namespace {
        auto cached_network_metadata(std::shared_ptr<platform::network::Snapshot const> const& snap) noexcept
            -> std::shared_ptr<NetworkMetadataSnapshot const> {
            if (!snap) return {};
            struct CacheEntry {
                std::weak_ptr<platform::network::Snapshot const> source;
                std::shared_ptr<NetworkMetadataSnapshot const> metadata;
            };
            thread_local CacheEntry cache{};
            if (!cache.source.owner_before(snap) && !snap.owner_before(cache.source))
                return cache.metadata;
            try {
                auto built = std::make_shared<NetworkMetadataSnapshot>();
                if (snap->default_network_type) {
                    using P = platform::network::NetworkType;
                    using R = rules::NetworkType;
                    switch (*snap->default_network_type) {
                    case P::wifi: built->network_type = R::wifi; break;
                    case P::cellular: built->network_type = R::cellular; break;
                    case P::ethernet: built->network_type = R::ethernet; break;
                    case P::other: built->network_type = R::other; break;
                    }
                }
                built->network_is_expensive = snap->network_is_expensive;
                built->network_is_constrained = snap->network_is_constrained;
                if (snap->wifi_ssid && !snap->wifi_ssid->empty()) built->wifi_ssid = *snap->wifi_ssid;
                built->wifi_bssid = snap->wifi_bssid;
                auto addrs = snap->default_interface_addresses();
                built->default_interface_addresses.reserve(addrs.size());
                for (auto const& [bytes, size] : addrs)
                    built->default_interface_addresses.push_back({bytes, size});
                bool const has_any = built->network_type.has_value() ||
                    built->network_is_expensive.has_value() ||
                    built->network_is_constrained.has_value() ||
                    !built->wifi_ssid.empty() ||
                    built->wifi_bssid.has_value() ||
                    !built->default_interface_addresses.empty();
                cache.source = snap;
                cache.metadata = has_any ? std::move(built) : std::shared_ptr<NetworkMetadataSnapshot const>{};
                return cache.metadata;
            } catch (...) {
                return {};
            }
        }

        auto accepted_endpoint(io::tcp_socket const& socket,
            int (*lookup)(int, sockaddr*, socklen_t*)) noexcept -> io::endpoint {
            sockaddr_storage storage{};
            socklen_t size = sizeof(storage);
            if (lookup(socket.native_handle(), reinterpret_cast<sockaddr*>(&storage), &size) < 0) return {};
            if (storage.ss_family == AF_INET) {
                auto const& peer = *reinterpret_cast<sockaddr_in const*>(&storage);
                io::ipv4_address::bytes_type bytes;
                std::memcpy(bytes.data(), &peer.sin_addr, bytes.size());
                return {io::ipv4_address(bytes), ntohs(peer.sin_port)};
            }
            if (storage.ss_family == AF_INET6) {
                auto const& peer = *reinterpret_cast<sockaddr_in6 const*>(&storage);
                io::ipv6_address::bytes_type bytes;
                std::memcpy(bytes.data(), &peer.sin6_addr, bytes.size());
                if (std::ranges::all_of(std::span(bytes).first<10>(), [](auto byte) { return byte == 0; }) &&
                    bytes[10] == 255 && bytes[11] == 255) {
                    io::ipv4_address::bytes_type ipv4;
                    std::ranges::copy(std::span(bytes).last<4>(), ipv4.begin());
                    return {io::ipv4_address(ipv4), ntohs(peer.sin6_port)};
                }
                return {io::ipv6_address(bytes, peer.sin6_scope_id), ntohs(peer.sin6_port)};
            }
            return {};
        }
    }

    auto accepted_local(io::tcp_socket const& socket) noexcept -> io::endpoint {
        return accepted_endpoint(socket, ::getsockname);
    }

    auto accepted_peer(io::tcp_socket const& socket) noexcept -> io::endpoint {
        // Linux multishot accept can overwrite its shared sockaddr before
        // the corresponding CQE is dispatched. Read the accepted fd instead.
        return accepted_endpoint(socket, ::getpeername);
    }

    auto traffic_protocol_name(TrafficProtocol protocol) noexcept -> std::string_view {
        switch (protocol) {
        case TrafficProtocol::socks5: return "socks5";
        case TrafficProtocol::http_connect: return "http-connect";
        case TrafficProtocol::http_forward: return "http-forward";
        case TrafficProtocol::socks_udp: return "socks5-udp";
        case TrafficProtocol::trojan: return "trojan";
        case TrafficProtocol::shadowsocks: return "ss2022";
        case TrafficProtocol::vless: return "vless";
        case TrafficProtocol::grpc_vless: return "grpc-vless";
        case TrafficProtocol::anytls: return "anytls";
        case TrafficProtocol::snell: return "snell";
        case TrafficProtocol::shadowtls: return "shadowtls";
        case TrafficProtocol::hysteria2: return "hysteria2";
        case TrafficProtocol::tuic: return "tuic";
        case TrafficProtocol::trojan_udp: return "trojan-udp";
        case TrafficProtocol::shadowsocks_uot: return "ss2022-uot";
        case TrafficProtocol::anytls_uot: return "anytls-uot";
        case TrafficProtocol::snell_udp: return "snell-udp";
        case TrafficProtocol::hysteria2_udp: return "hysteria2-udp";
        case TrafficProtocol::tun_tcp: return "tun-tcp";
        case TrafficProtocol::tun_udp: return "tun-udp";
        case TrafficProtocol::tuic_udp: return "tuic-udp";
        case TrafficProtocol::shadowsocks_udp: return "ss2022-udp";
        case TrafficProtocol::xudp: return "xudp";
        case TrafficProtocol::masque_udp: return "masque-udp";
        case TrafficProtocol::masque_ip: return "masque-ip";
        case TrafficProtocol::redirect: return "redirect";
        case TrafficProtocol::tproxy: return "tproxy";
        case TrafficProtocol::tproxy_udp: return "tproxy-udp";
        case TrafficProtocol::fixed_tcp: return "fixed-tcp";
        case TrafficProtocol::naive: return "naive";
        case TrafficProtocol::http3_connect: return "http3-connect";
        case TrafficProtocol::http3_udp: return "http3-udp";
        }
        return {};
    }

    auto TrafficRegistry::Slot::bytes() const noexcept -> TrafficBytes {
        return {upload.load(std::memory_order_relaxed), download.load(std::memory_order_relaxed)};
    }

    TrafficRegistry::TrafficRegistry(std::size_t limit) : slots_(limit) {
        free_.reserve(limit);
        active_.reserve(limit);
        for (auto& slot : slots_) free_.push_back(&slot);
    }

    auto TrafficRegistry::add(ActiveConnection connection) -> Slot* {
        std::lock_guard lock(mutex_);
        if (free_.empty()) return nullptr;
        auto* slot = free_.back();
        free_.pop_back();
        slot->active_index = active_.size();
        active_.push_back(slot);
        static std::atomic<std::uint64_t> global_traffic_id{1};
        connection.id = global_traffic_id.fetch_add(1, std::memory_order_relaxed);
        next_id_ = connection.id + 1;
        slot->connection = std::move(connection);
        slot->path.store(ConnectPath::dialing, std::memory_order_relaxed);
        slot->close_requested.store(false, std::memory_order_relaxed);
        slot->upload.store(0, std::memory_order_relaxed);
        slot->download.store(0, std::memory_order_relaxed);
        return slot;
    }

    auto GroupRuntimeHooks::mark_active(std::size_t group_index) noexcept -> void {
        if (group_index >= kMaxGroups) return;
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        last_active_ms_[group_index].store(now, std::memory_order_relaxed);
    }

    auto GroupRuntimeHooks::last_active_ms(std::size_t group_index) const noexcept -> std::int64_t {
        return group_index < kMaxGroups ? last_active_ms_[group_index].load(std::memory_order_relaxed) : 0;
    }

    auto GroupRuntimeHooks::record_dial_failure(std::string_view group_tag, std::size_t outbound) noexcept -> void {
        try {
            {
                std::lock_guard lock(mutex_);
                if (failures_.size() >= kMaxFailures) failures_.pop_front();
                failures_.push_back({std::string(group_tag), outbound});
            }
            if (wake_) wake_();
        } catch (...) {}
    }

    auto GroupRuntimeHooks::drain_dial_failures(std::vector<GroupDialFailure>& out) -> void {
        std::lock_guard lock(mutex_);
        while (!failures_.empty()) {
            out.push_back(std::move(failures_.front()));
            failures_.pop_front();
        }
    }

    auto TrafficRegistry::remove(Slot& slot) noexcept -> void {
        std::lock_guard lock(mutex_);
        auto bytes = slot.bytes();
        finished_.upload += bytes.upload;
        finished_.download += bytes.download;
        slot.connection.process_path = std::string{};
        slot.connection.group_tag = std::string{};
        auto* last = active_.back();
        active_[slot.active_index] = last;
        last->active_index = slot.active_index;
        active_.pop_back();
        free_.push_back(&slot);
    }

    auto TrafficRegistry::record_route(Slot& slot, TrafficRoute route, ConnectPath path,
        std::string_view group_tag) noexcept -> void {
        // The slot's executor is the sole writer and snapshots read under the lock.
        if (slot.connection.route == route && slot.path.load(std::memory_order_relaxed) == path &&
            (group_tag.empty() || slot.connection.group_tag == group_tag)) return;
        std::lock_guard lock(mutex_);
        slot.connection.route = route;
        if (!group_tag.empty()) {
            try { slot.connection.group_tag.assign(group_tag); } catch (...) {}
        }
        slot.path.store(path, std::memory_order_relaxed);
    }

    auto TrafficRegistry::record_group(Slot& slot, std::string_view group_tag) noexcept -> void {
        if (group_tag.empty()) return;
        std::lock_guard lock(mutex_);
        try { slot.connection.group_tag.assign(group_tag); } catch (...) {}
    }

    auto TrafficRegistry::snapshot() const -> TrafficSnapshot {
        TrafficSnapshot result;
        std::lock_guard lock(mutex_);
        result.active.reserve(active_.size());
        result.bytes = finished_;
        for (auto const* slot : active_) {
            auto row = slot->connection;
            row.path = slot->path.load(std::memory_order_relaxed);
            row.bytes = slot->bytes();
            result.bytes.upload += row.bytes.upload;
            result.bytes.download += row.bytes.download;
            result.active.push_back(row);
        }
        return result;
    }

    auto TrafficRegistry::request_close(std::uint64_t id) -> TrafficCloseRequest {
        std::lock_guard lock(mutex_);
        auto slot = std::ranges::find(active_, id, [](auto const* row) { return row->connection.id; });
        if (slot == active_.end()) return TrafficCloseRequest::missing;
        if (!(*slot)->connection.can_close) return TrafficCloseRequest::unavailable;
        (*slot)->close_requested.store(true, std::memory_order_relaxed);
        return TrafficCloseRequest::queued;
    }

    auto TrafficRegistry::close_group_sessions(std::string_view group_tag, std::optional<std::size_t> outbound)
        -> std::size_t {
        std::lock_guard lock(mutex_);
        std::size_t closed = 0;
        for (auto* slot : active_) {
            if (!slot->connection.can_close) continue;
            bool match = false;
            if (!group_tag.empty()) {
                match = slot->connection.group_tag == group_tag &&
                    (!outbound || (slot->connection.route && slot->connection.route->outbound == *outbound));
            } else if (outbound && slot->connection.route && slot->connection.route->outbound == *outbound) {
                match = true;
            }
            if (match) {
                slot->close_requested.store(true, std::memory_order_relaxed);
                ++closed;
            }
        }
        return closed;
    }

    TrafficRegistration::TrafficRegistration(TrafficRegistration&& other) noexcept
        : registry_(std::exchange(other.registry_, nullptr)), slot_(std::exchange(other.slot_, nullptr)) {}

    auto TrafficRegistration::operator=(TrafficRegistration&& other) noexcept -> TrafficRegistration& {
        if (this != &other) {
            reset();
            registry_ = std::exchange(other.registry_, nullptr);
            slot_ = std::exchange(other.slot_, nullptr);
        }
        return *this;
    }

    TrafficRegistration::~TrafficRegistration() {
        reset();
    }

    auto TrafficRegistration::begin(std::optional<net::UdpEndpoint> source, std::uint16_t port,
        TrafficProtocol protocol, Clock::time_point started, bool can_close, std::optional<std::uint32_t> source_uid,
        std::string_view process_path, std::optional<TransparentDatagram> transparent_datagram, std::uint64_t route_generation,
        std::string_view inbound_name) -> void {
        if (registry_ && !slot_)
            slot_ = registry_->add({.source = source, .destination_port = port, .started = started, .protocol = protocol,
                .can_close = can_close, .source_uid = source_uid, .process_path = std::string(process_path),
                .inbound_name = std::string(inbound_name), .transparent_datagram = transparent_datagram,
                .route_generation = route_generation});
    }

    auto TrafficRegistration::reset() noexcept -> void {
        if (slot_) registry_->remove(*std::exchange(slot_, nullptr));
    }

    auto Session::populate_network_metadata() noexcept -> void {
        auto snap = network_monitor ? network_monitor->get() : nullptr;
        if (!snap) return;
        network_metadata = cached_network_metadata(snap);
    }

    auto Session::begin_traffic(TrafficProtocol protocol, std::uint16_t port,
        std::optional<TransparentDatagram> transparent_datagram) -> void {
        if (!traffic.registry_ && transport_owner) traffic.registry_ = transport_owner->traffic.registry_;
        if (traffic.registry_)
            traffic.begin(source_endpoint(*this, true), port, protocol, started, registry != nullptr, source_uid, process_path_view(),
                transparent_datagram, route_snapshot ? route_snapshot->generation : 1, inbound.value_or(std::string_view{}));
    }

    auto Session::set_traffic_group(std::string_view tag) noexcept -> void {
        group_tag = tag;
        if (traffic.slot_) traffic.registry_->record_group(*traffic.slot_, tag);
    }

    auto Session::record_traffic_route(TrafficRoute route, ConnectPath path) noexcept -> void {
        std::string_view resolved_group = group_tag;
        if (route_snapshot && route_snapshot->group_tags) {
            if (auto gidx = route_snapshot->group_tags->resolve(
                    route.mode == TrafficRouteMode::ordered, route.rule, route.outbound)) {
                resolved_group = route_snapshot->group_tags->name(*gidx);
                group_tag = resolved_group;
                if (group_hooks) group_hooks->mark_active(*gidx);
            }
        }
        if (traffic.slot_) traffic.registry_->record_route(*traffic.slot_, route, path, resolved_group);
    }

    auto Session::record_dial_failure(TrafficRoute const& route) noexcept -> void {
        if (!group_hooks || route.outbound < 2) return;
        std::string_view tag = group_tag;
        if (route_snapshot && route_snapshot->group_tags) {
            if (auto gidx = route_snapshot->group_tags->resolve(
                    route.mode == TrafficRouteMode::ordered, route.rule, route.outbound)) {
                tag = route_snapshot->group_tags->name(*gidx);
            }
        }
        group_hooks->record_dial_failure(tag, route.outbound);
    }

    auto Session::record_dial_failure(std::size_t outbound) noexcept -> void {
        if (!group_hooks || outbound < 2) return;
        std::string_view tag = group_tag;
        if (tag.empty() && route_snapshot && route_snapshot->group_tags) {
            if (auto gidx = route_snapshot->group_tags->resolve(false, {}, outbound))
                tag = route_snapshot->group_tags->name(*gidx);
        }
        group_hooks->record_dial_failure(tag, outbound);
    }

    auto Session::record_datagram_route(bool ordered, net::UdpSelection const& selection) noexcept -> void {
        record_traffic_route({ordered ? TrafficRouteMode::ordered : TrafficRouteMode::indexed,
            selection.outbound, selection.rule, selection.predicate, selection.target}, ConnectPath::datagrams);
    }

    auto Session::register_child_traffic() -> void {
        if (!transport_owner || !transport_owner->traffic.registry_ || !transport_owner->registry) return;
        auto& sessions = *transport_owner->registry;
        sessions.push_back(this);
        registry_index = sessions.size() - 1;
        registry = &sessions;
    }

    auto Session::end_traffic() noexcept -> void {
        traffic.reset();
    }

    auto Session::track_child_traffic(TrafficProtocol protocol, ConnectPath path, std::uint16_t port, bool can_close) -> TrafficRegistration {
        auto* registry = traffic.registry_;
        if (!registry && transport_owner) registry = transport_owner->traffic.registry_;
        TrafficRegistration child(registry);
        if (registry) child.begin(source_endpoint(*this, true), port, protocol, Clock::now(), can_close);
        child.select_path(path);
        return child;
    }

    auto Server::enable_traffic_stats(std::size_t packet_slots) -> bool {
        if (running || !workers.empty() || !sessions.empty() ||
            packet_slots > std::numeric_limits<std::size_t>::max() - quota.limit()) return false;
        traffic_slot_limit = quota.limit() + packet_slots;
        if (!traffic) traffic = std::make_shared<TrafficRegistry>(traffic_slot_limit);
        return true;
    }

    auto Server::track_traffic(TrafficProtocol protocol, ConnectPath path, std::optional<net::UdpEndpoint> source,
        std::uint16_t port, bool can_close) const -> TrafficRegistration {
        TrafficRegistration registration(traffic.get());
        registration.begin(source, port, protocol, Clock::now(), can_close);
        registration.select_path(path);
        return registration;
    }

    auto Server::set_find_process(bool enabled) noexcept -> void {
        find_process_enabled = enabled;
        for (auto& w : workers) w->set_find_process(enabled);
    }

    auto Server::set_group_hooks(std::shared_ptr<GroupRuntimeHooks> hooks) noexcept -> void {
        group_hooks = std::move(hooks);
        for (auto& w : workers) w->set_group_hooks(group_hooks);
    }

    auto Server::close_group_sessions(std::string_view group_tag, std::optional<std::size_t> outbound) -> std::size_t {
        std::size_t closed = 0;
        if (traffic) closed += traffic->close_group_sessions(group_tag, outbound);
        if (workers.empty()) {
            if (closed > 0) process_traffic_closes();
            return closed;
        }
        for (auto const& worker : workers) {
            if (worker->traffic && worker->traffic != traffic)
                closed += worker->traffic->close_group_sessions(group_tag, outbound);
            worker->context.stop();
        }
        return closed;
    }

    auto Server::request_traffic_close(std::uint64_t id) -> TrafficCloseRequest {
        if (!traffic) return TrafficCloseRequest::missing;
        auto status = traffic->request_close(id);
        if (status != TrafficCloseRequest::missing || workers.empty()) return status;
        for (auto const& worker : workers) {
            if (!worker->traffic || worker->traffic == traffic) continue;
            status = worker->traffic->request_close(id);
            if (status != TrafficCloseRequest::missing) return status;
        }
        return TrafficCloseRequest::missing;
    }

    auto Server::traffic_snapshot() const -> TrafficSnapshot {
        if (!traffic) return {};
        auto result = traffic->snapshot();
        for (auto const& worker : workers) {
            if (!worker->traffic || worker->traffic == traffic) continue;
            auto part = worker->traffic->snapshot();
            result.bytes.upload += part.bytes.upload;
            result.bytes.download += part.bytes.download;
            result.active.insert(result.active.end(),
                std::make_move_iterator(part.active.begin()), std::make_move_iterator(part.active.end()));
        }
        return result;
    }
}
