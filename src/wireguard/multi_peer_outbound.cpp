module wireguard.multi_peer_outbound;
import std;
import crypto;
import net.udp_socket;
import platform.linux_random;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.identity;
import wireguard.port_types;
import wireguard.registry;
import wireguard.routing;

namespace wireguard {
    namespace {
        auto fill_random(std::span<std::uint8_t> out) noexcept -> bool {
            return platform::secure_random(std::as_writable_bytes(out)).has_value();
        }
    }

    MultiPeerOutbound::MultiPeerOutbound(SecretKey private_bytes, crypto::X25519Private identity) noexcept
        : private_bytes_(std::move(private_bytes)),
          identity_(std::move(identity)),
          ingress_(IdentityIngress::create(*identity_)) {}

    MultiPeerOutbound::~MultiPeerOutbound() {
        close();
        private_bytes_.clear();
    }

    auto MultiPeerOutbound::create(std::span<std::uint8_t const> local_private_key)
        -> std::expected<std::unique_ptr<MultiPeerOutbound>, MultiPeerError> {
        if (local_private_key.size() != 32) return std::unexpected(MultiPeerError::configuration);
        auto id = crypto::X25519Private::from_bytes(local_private_key);
        if (!id) return std::unexpected(MultiPeerError::configuration);
        SecretKey secret;
        std::ranges::copy(local_private_key, secret.writable().begin());
        auto out = std::unique_ptr<MultiPeerOutbound>(new MultiPeerOutbound(std::move(secret), std::move(*id)));
        if (!out->ingress_) return std::unexpected(MultiPeerError::configuration);
        return out;
    }

    auto MultiPeerOutbound::observe(Clock::time_point now) noexcept -> std::expected<void, MultiPeerError> {
        if (closed_) return std::unexpected(MultiPeerError::closed);
        if (now < Clock::time_point{} || (observed_ && now < *observed_))
            return std::unexpected(MultiPeerError::clock);
        observed_ = now;
        return {};
    }

    auto MultiPeerOutbound::find_by_public(PeerHandle handle) noexcept -> Slot* {
        if (handle.slot >= peer_capacity || !handle.generation) return nullptr;
        auto& s = slots_[handle.slot];
        return (s.occupied && s.handle == handle) ? &s : nullptr;
    }

    auto MultiPeerOutbound::find_by_public(PeerHandle handle) const noexcept -> Slot const* {
        if (handle.slot >= peer_capacity || !handle.generation) return nullptr;
        auto const& s = slots_[handle.slot];
        return (s.occupied && s.handle == handle) ? &s : nullptr;
    }

    auto MultiPeerOutbound::find_by_internal(PeerHandle internal) noexcept -> Slot* {
        if (internal.slot >= peer_capacity || !internal.generation) return nullptr;
        auto idx = internal_to_slot_[internal.slot];
        if (!idx) return nullptr;
        auto& s = slots_[*idx];
        return (s.occupied && s.internal_handle == internal) ? &s : nullptr;
    }

    auto MultiPeerOutbound::find_by_internal(PeerHandle internal) const noexcept -> Slot const* {
        if (internal.slot >= peer_capacity || !internal.generation) return nullptr;
        auto idx = internal_to_slot_[internal.slot];
        if (!idx) return nullptr;
        auto const& s = slots_[*idx];
        return (s.occupied && s.internal_handle == internal) ? &s : nullptr;
    }

    auto MultiPeerOutbound::unbind_internal_handle(Slot& slot) noexcept -> void {
        if (!slot.internal_handle.generation) return;
        internal_to_slot_[slot.internal_handle.slot].reset();
        (void)routes_.erase(slot.internal_handle);
        (void)keys_.erase(slot.internal_handle);
        (void)registry_.erase(slot.internal_handle);
        slot.internal_handle = {};
    }

    auto MultiPeerOutbound::bind_internal_handle(Slot& slot) -> std::expected<void, MultiPeerError> {
        auto ih = registry_.add();
        if (!ih) return std::unexpected(MultiPeerError::full);
        if (!routes_.activate(*ih) || !keys_.activate(*ih, slot.spec.peer_public)) {
            (void)routes_.erase(*ih);
            (void)keys_.erase(*ih);
            (void)registry_.erase(*ih);
            return std::unexpected(MultiPeerError::full);
        }
        for (auto const& prefix : slot.spec.allowed_ips) {
            if (!routes_.assign(*ih, prefix)) {
                (void)routes_.erase(*ih);
                (void)keys_.erase(*ih);
                (void)registry_.erase(*ih);
                return std::unexpected(MultiPeerError::full);
            }
        }
        slot.internal_handle = *ih;
        internal_to_slot_[ih->slot] = slot.handle.slot;
        return {};
    }

    auto MultiPeerOutbound::sync_registry(Slot& slot) noexcept -> void {
        if (slot.occupied && slot.endpoint && slot.internal_handle.generation) {
            (void)registry_.sync(slot.internal_handle, *slot.endpoint);
        }
    }

    auto MultiPeerOutbound::create_endpoint_for(Slot& slot) -> std::expected<void, MultiPeerError> {
        auto id = crypto::X25519Private::from_bytes(private_bytes_.view());
        if (!id) return std::unexpected(MultiPeerError::protocol);
        EndpointConfig cfg{};
        cfg.peer_public = slot.spec.peer_public;
        cfg.allowed_ips = slot.spec.allowed_ips;
        cfg.peer = slot.spec.endpoint;
        cfg.mtu = slot.spec.mtu;
        cfg.persistent_keepalive = slot.spec.persistent_keepalive;
        auto psk = slot.spec.psk ? std::span<std::uint8_t const>(slot.spec.psk->view()) : std::span<std::uint8_t const>{};
        auto created = Endpoint::emplace_into(slot.endpoint, std::move(*id), std::move(cfg), psk);
        if (!created) return std::unexpected(MultiPeerError::configuration);
        slot.endpoint->seed_initiation_timestamp(slot.saved_timestamp);
        return {};
    }

    auto MultiPeerOutbound::sleep_slot(Slot& slot) noexcept -> void {
        if (!slot.occupied || slot.state == PeerActivationState::asleep) return;
        slot.pending_tx.reset();
        if (slot.endpoint) {
            auto ts = slot.endpoint->last_initiation_timestamp();
            if (ts > slot.saved_timestamp) slot.saved_timestamp = ts;
            slot.endpoint->close();
            slot.endpoint.reset();
        }
        // Release all active receiver indexes while keeping routes & public key active
        // so outbound packets still match this peer and wake it transparently.
        if (auto lat = registry_.latest(slot.internal_handle)) {
            (void)registry_.sync(slot.internal_handle, ReceiverIndexes{}, *lat);
        }
        slot.state = PeerActivationState::asleep;
        ++stats_.sleeps;
    }

    auto MultiPeerOutbound::wake_slot(Slot& slot, Clock::time_point now) -> std::expected<void, MultiPeerError> {
        // Rotate internal registry handle so a freshly created Endpoint starts cleanly at attempt 0.
        if (auto lat = registry_.latest(slot.internal_handle); lat && *lat > 0) {
            unbind_internal_handle(slot);
            if (auto bound = bind_internal_handle(slot); !bound) return bound;
        }
        if (!slot.endpoint) {
            if (auto created = create_endpoint_for(slot); !created) return created;
        }
        slot.state = PeerActivationState::waking;
        slot.last_activity = now;
        ++stats_.wakes;
        auto req = slot.endpoint->request_handshake(now);
        if (!req) return std::unexpected(MultiPeerError::protocol);
        return {};
    }

    auto MultiPeerOutbound::add_peer(OutboundPeerSpec spec, Clock::time_point now)
        -> std::expected<PeerHandle, MultiPeerError> {
        if (auto ok = observe(now); !ok) return std::unexpected(ok.error());
        if (spec.allowed_ips.empty() || !spec.endpoint.port ||
            (spec.endpoint.family != 4 && spec.endpoint.family != 6))
            return std::unexpected(MultiPeerError::configuration);
        if (spec.on_demand && spec.idle_timeout.count() <= 0)
            return std::unexpected(MultiPeerError::configuration);
        for (auto const& prefix : spec.allowed_ips) {
            if (!valid_prefix(prefix)) return std::unexpected(MultiPeerError::invalid_prefix);
        }
        std::optional<std::uint16_t> free_idx;
        for (std::uint16_t i = 0; i < peer_capacity; ++i) {
            if (slots_[i].occupied) {
                if (slots_[i].spec.peer_public == spec.peer_public)
                    return std::unexpected(MultiPeerError::duplicate_peer);
            } else if (!free_idx) {
                free_idx = i;
            }
        }
        if (!free_idx) return std::unexpected(MultiPeerError::full);
        auto& slot = slots_[*free_idx];
        slot.occupied = true;
        slot.handle = PeerHandle{*free_idx, next_public_gen_++};
        slot.internal_handle = {};
        slot.saved_timestamp = {};
        slot.spec = std::move(spec);
        slot.last_activity = now;
        slot.pending_tx.reset();
        if (auto bound = bind_internal_handle(slot); !bound) {
            slot.occupied = false;
            return std::unexpected(bound.error());
        }
        if (slot.spec.on_demand) {
            slot.endpoint.reset();
            slot.state = PeerActivationState::asleep;
        } else {
            if (auto created = create_endpoint_for(slot); !created) {
                unbind_internal_handle(slot);
                slot.occupied = false;
                return std::unexpected(created.error());
            }
            slot.state = PeerActivationState::waking;
            (void)slot.endpoint->request_handshake(now);
            sync_registry(slot);
        }
        return slot.handle;
    }

    auto MultiPeerOutbound::remove_peer(PeerHandle handle) noexcept -> std::expected<void, MultiPeerError> {
        auto* slot = find_by_public(handle);
        if (!slot) return std::unexpected(MultiPeerError::peer_not_found);
        slot->pending_tx.reset();
        if (slot->endpoint) { slot->endpoint->close(); slot->endpoint.reset(); }
        if (slot->spec.psk) slot->spec.psk->clear();
        unbind_internal_handle(*slot);
        slot->occupied = false;
        return {};
    }

    auto MultiPeerOutbound::update_peer_endpoint(PeerHandle handle, EndpointAddress endpoint) noexcept
        -> std::expected<void, MultiPeerError> {
        if (!endpoint.port || (endpoint.family != 4 && endpoint.family != 6))
            return std::unexpected(MultiPeerError::configuration);
        auto* slot = find_by_public(handle);
        if (!slot) return std::unexpected(MultiPeerError::peer_not_found);
        if (slot->endpoint) {
            if (!slot->endpoint->change_path(endpoint, false))
                return std::unexpected(MultiPeerError::configuration);
        }
        slot->spec.endpoint = endpoint;
        return {};
    }

    auto MultiPeerOutbound::lookup_destination(std::span<std::uint8_t const> ip_packet) const noexcept
        -> std::optional<PeerHandle> {
        auto parsed = parse_inner_packet(ip_packet);
        if (!parsed) return std::nullopt;
        auto dst = std::span<std::uint8_t const>(parsed->destination).first(parsed->family == 4 ? 4u : 16u);
        auto ih = routes_.lookup(parsed->family, dst);
        if (!ih) return std::nullopt;
        auto const* slot = find_by_internal(*ih);
        return slot ? std::optional(slot->handle) : std::nullopt;
    }

    auto MultiPeerOutbound::enqueue_ip(std::span<std::uint8_t const> ip_packet, Clock::time_point now)
        -> std::expected<PeerHandle, MultiPeerError> {
        if (auto ok = observe(now); !ok) return std::unexpected(ok.error());
        auto peer = lookup_destination(ip_packet);
        if (!peer) {
            ++stats_.route_misses;
            return std::unexpected(MultiPeerError::no_route);
        }
        auto* slot = find_by_public(*peer);
        if (!slot) return std::unexpected(MultiPeerError::no_route);
        if (slot->state == PeerActivationState::asleep) {
            if (auto woke = wake_slot(*slot, now); !woke) return std::unexpected(woke.error());
        } else {
            slot->last_activity = now;
        }
        auto enq = slot->endpoint->enqueue(ip_packet, now);
        if (!enq) {
            if (enq.error().code == EndpointError::queue_full)
                return std::unexpected(MultiPeerError::queue_full);
            return std::unexpected(MultiPeerError::protocol);
        }
        return slot->handle;
    }

    auto MultiPeerOutbound::prepare_handshake(Slot& slot, HandshakeRequest req, Clock::time_point now,
                                              std::chrono::system_clock::time_point wall)
        -> std::expected<void, MultiPeerError> {
        sync_registry(slot);
        SecretKey eph_bytes;
        if (!fill_random(eph_bytes.writable())) return std::unexpected(MultiPeerError::entropy);
        auto ephemeral = crypto::X25519Private::from_bytes(eph_bytes.view());
        if (!ephemeral) return std::unexpected(MultiPeerError::protocol);
        std::array<std::uint8_t, 4> seed{};
        if (!fill_random(seed)) return std::unexpected(MultiPeerError::entropy);
        auto index = registry_.reserve(slot.internal_handle, req.ticket, load_le32(seed));
        if (!index) return std::unexpected(MultiPeerError::full);

        std::expected<EndpointDatagram, EndpointFailure> out =
            std::unexpected(EndpointFailure{EndpointError::protocol, {}});
        if (req.reason == HandshakeReason::response) {
            out = slot.endpoint->respond(req, index->index, std::move(*ephemeral), now, IndexMode::exact);
        } else {
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(wall.time_since_epoch());
            auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(wall.time_since_epoch() - secs);
            auto ts = secs.count() < 0
                ? std::expected<Timestamp, Error>(std::unexpected(Error::invalid_timestamp))
                : make_timestamp(secs.count(), nanos.count());
            if (!ts) {
                (void)registry_.release(*index);
                return std::unexpected(MultiPeerError::clock);
            }
            out = slot.endpoint->initiate(req, index->index, std::move(*ephemeral), *ts,
                                          std::chrono::milliseconds(0), now, IndexMode::exact);
        }
        if (!out) {
            (void)registry_.release(*index);
            sync_registry(slot);
            if (out.error().code == EndpointError::not_due || out.error().code == EndpointError::stale_attempt)
                return {};
            return std::unexpected(MultiPeerError::protocol);
        }
        sync_registry(slot);
        slot.pending_tx = std::move(*out);
        return {};
    }

    auto MultiPeerOutbound::receive_udp(std::span<std::uint8_t const> wire, EndpointAddress source,
                                        Clock::time_point now)
        -> std::expected<bool, MultiPeerError> {
        if (auto ok = observe(now); !ok) return std::unexpected(ok.error());
        std::vector<std::uint8_t> normalized;
        std::span<std::uint8_t const> canonical = wire;
        if (wire.size() >= 4 && (wire[1] != 0 || wire[2] != 0 || wire[3] != 0)) {
            normalized.assign(wire.begin(), wire.end());
            normalized[1] = normalized[2] = normalized[3] = 0;
            canonical = normalized;
        }
        auto mtype = message_type(canonical);
        if (!mtype) return false;

        if (*mtype == MessageType::initiation) {
            if (!ingress_) return false;
            auto rec = ingress_->receive(canonical, source, true, now, keys_.view(), false, false);
            if (!rec || !rec->selected) return false;
            auto ih = rec->selected->peer();
            auto* slot = find_by_internal(ih);
            if (!slot) return false;
            if (slot->state == PeerActivationState::asleep) {
                if (auto lat = registry_.latest(slot->internal_handle); lat && *lat > 0) {
                    unbind_internal_handle(*slot);
                    if (auto bound = bind_internal_handle(*slot); !bound) return std::unexpected(bound.error());
                    // Re-select against rotated generation for strict PeerKeyView match.
                    rec = ingress_->receive(canonical, source, true, now, keys_.view(), false, false);
                    if (!rec || !rec->selected) return false;
                    ih = rec->selected->peer();
                }
                if (auto created = create_endpoint_for(*slot); !created) return std::unexpected(created.error());
                slot->state = PeerActivationState::waking;
                ++stats_.wakes;
            }
            slot->last_activity = now;
            auto res = slot->endpoint->receive_selected(std::move(*rec->selected), keys_.view(), now, routes_.view(ih));
            sync_registry(*slot);
            if (!res) return false;
            if (res->key_confirmed) slot->state = PeerActivationState::active;
            return true;
        }

        auto binding = registry_.classify(canonical);
        if (!binding) return false;
        auto* slot = find_by_internal(binding->peer);
        if (!slot || !slot->endpoint) return false;
        auto res = slot->endpoint->receive(canonical, source, true, now, false, routes_.view(slot->internal_handle));
        sync_registry(*slot);
        if (!res) {
            if (res.error().code == EndpointError::disallowed_source) ++stats_.rpf_drops;
            return false;
        }
        if (res->key_confirmed || !res->packet.empty() || res->keepalive ||
            slot->endpoint->status().current.has_value()) {
            slot->state = PeerActivationState::active;
            slot->last_activity = now;
        }
        if (!res->packet.empty()) {
            if (rx_queue_.size() < max_rx_queue) {
                rx_queue_.push_back({slot->handle, std::move(res->packet)});
                ++stats_.rx_packets;
            }
        }
        return true;
    }

    auto MultiPeerOutbound::poll_tx(Clock::time_point now, std::chrono::system_clock::time_point wall,
                                    std::size_t max_datagrams)
        -> std::expected<std::vector<OutboundDatagram>, MultiPeerError> {
        if (auto ok = observe(now); !ok) return std::unexpected(ok.error());
        std::vector<OutboundDatagram> out;
        for (std::size_t step = 0; step < peer_capacity && out.size() < max_datagrams; ++step) {
            std::size_t idx = (next_poll_slot_ + step) % peer_capacity;
            auto& slot = slots_[idx];
            if (!slot.occupied) continue;
            if (slot.spec.on_demand && slot.state != PeerActivationState::asleep) {
                bool idle_expired = now >= slot.last_activity &&
                    std::chrono::duration_cast<std::chrono::seconds>(now - slot.last_activity) >= slot.spec.idle_timeout;
                if (idle_expired && (!slot.endpoint || slot.endpoint->queued_packets() == 0)) {
                    sleep_slot(slot);
                    continue;
                }
            }
            if (slot.state == PeerActivationState::asleep || !slot.endpoint) continue;

            for (unsigned burst = 0; burst < 8 && out.size() < max_datagrams; ++burst) {
                if (!slot.pending_tx) {
                    auto polled = slot.endpoint->poll(now);
                    if (!polled) return std::unexpected(MultiPeerError::protocol);
                    if (polled->handshake) {
                        if (auto prep = prepare_handshake(slot, *polled->handshake, now, wall); !prep)
                            return std::unexpected(prep.error());
                    } else if (polled->datagram) {
                        slot.pending_tx = std::move(*polled->datagram);
                    } else {
                        break;
                    }
                }
                if (!slot.pending_tx) break;
                if (!slot.endpoint->output_valid(slot.pending_tx->serial)) {
                    slot.pending_tx.reset();
                    continue;
                }
                auto dgram = std::move(*slot.pending_tx);
                slot.pending_tx.reset();
                auto complete = slot.endpoint->complete_send(dgram.serial, true, now);
                if (!complete) return std::unexpected(MultiPeerError::protocol);
                if (dgram.kind == OutboundKind::data) {
                    slot.state = PeerActivationState::active;
                    slot.last_activity = now;
                }
                if (!slot.spec.reserved.apply(dgram.bytes))
                    return std::unexpected(MultiPeerError::protocol);
                out.push_back({slot.handle, dgram.destination, std::move(dgram.bytes), dgram.kind});
                ++stats_.tx_datagrams;
            }
        }
        next_poll_slot_ = (next_poll_slot_ + 1) % peer_capacity;
        return out;
    }

    auto MultiPeerOutbound::take_rx() noexcept -> std::optional<InboundPacket> {
        if (rx_queue_.empty()) return std::nullopt;
        auto pkt = std::move(rx_queue_.front());
        rx_queue_.pop_front();
        return pkt;
    }

    auto MultiPeerOutbound::peer_state(PeerHandle handle) const noexcept
        -> std::optional<PeerActivationState> {
        auto const* slot = find_by_public(handle);
        return slot ? std::optional(slot->state) : std::nullopt;
    }

    auto MultiPeerOutbound::stats() const noexcept -> MultiPeerStats {
        MultiPeerStats s = stats_;
        s.peer_count = s.active_peers = s.waking_peers = s.asleep_peers = 0;
        for (auto const& slot : slots_) {
            if (!slot.occupied) continue;
            ++s.peer_count;
            if (slot.state == PeerActivationState::active) ++s.active_peers;
            else if (slot.state == PeerActivationState::waking) ++s.waking_peers;
            else ++s.asleep_peers;
        }
        return s;
    }

    auto MultiPeerOutbound::close() noexcept -> void {
        if (closed_) return;
        closed_ = true;
        for (auto& slot : slots_) {
            if (!slot.occupied) continue;
            slot.pending_tx.reset();
            if (slot.endpoint) { slot.endpoint->close(); slot.endpoint.reset(); }
            if (slot.spec.psk) slot.spec.psk->clear();
            unbind_internal_handle(slot);
            slot.occupied = false;
        }
        rx_queue_.clear();
        identity_.reset();
        private_bytes_.clear();
    }
}
