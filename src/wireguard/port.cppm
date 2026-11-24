export module wireguard.port;
import std;
import crypto;
import net.udp_socket;
import platform.linux_random;
import wireguard;
import wireguard.admission;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.host;
import wireguard.identity;
import wireguard.port_types;
import wireguard.registry;
import wireguard.routing;

export namespace wireguard {
    // One stable owner/executor and one real UDP socket for all peers. poll
    // performs a bounded nonblocking step; its caller drives readiness and
    // next_poll on the existing executor. No task or forwarding loop is hidden.
    template<std::size_t PeerCapacity=32,std::size_t PacketCapacity=32,std::size_t PacketBytes=2048,
             std::size_t PrefixCapacity=1024,class Hooks=PortNoHooks,class OuterPolicy=PortOuterAllowAll,
             class WireProfile=PortStandardWire,class Socket=net::UdpSocket>
    class UdpPort {
    public:
        using Packet=PortPacket<PacketBytes>;
        static constexpr std::size_t packet_bytes=PacketBytes;
        class ConstructionKey { friend class UdpPort; ConstructionKey()=default; public: ConstructionKey(ConstructionKey&&)=default; };
    private:
        struct PeerSlot { std::optional<PeerHandle> handle; std::optional<Endpoint> endpoint; std::optional<EndpointDatagram> sending; std::size_t pending_business_bytes=0; };
        struct Delivery { bool used=false; PortPacket<PacketBytes> packet; };
        PortOptions options_;
        [[no_unique_address]] OuterPolicy outer_;
        [[no_unique_address]] WireProfile wire_profile_;
        // Existing Endpoint identities are initialized from this secret once
        // per configured peer. It is not an additional per-packet allocation.
        SecretKey private_bytes_;
        std::optional<crypto::X25519Private> identity_;
        std::expected<IdentityIngress,identity::Failure> ingress_;
        Socket socket_;
        PeerHost<PeerCapacity,PacketCapacity,PacketBytes,std::min<std::size_t>(4,PacketCapacity)> host_;
        routing::RouteTable<PeerCapacity,PrefixCapacity> routes_;
        PeerKeys<PeerCapacity> keys_;
        std::array<PeerSlot,PeerCapacity> peers_{};
        std::array<Delivery,PacketCapacity> deliveries_{};
        std::array<std::uint8_t,PacketBytes> input_{};
        std::optional<admission::Reply> cookie_;
        std::size_t delivery_count_=0,delivery_bytes_=0,next_peer_=0;
        std::uint64_t delivery_serial_=0,policy_epoch_=1;
        std::optional<Clock::time_point> observed_;
        Clock::time_point deadline_=Clock::time_point::max(),cookie_rotated_{};
        port_detail::HandshakePressure handshake_pressure_;
        PortMetrics metrics_;
        bool opened_=false,stopped_=false;
        std::uint16_t business_packets_=0;
        std::uint32_t business_bytes_=0;
        auto slot_handle(std::size_t position) const noexcept -> std::optional<PeerHandle> {
            auto const& handle=peers_[position].handle; return handle && host_.registry().valid(*handle) ? handle : std::nullopt;
        }
        auto observe(Clock::time_point now) noexcept -> std::expected<void,PortFailure> {
            if (stopped_) return port_detail::failure(PortError::closed);
            if (now<Clock::time_point{} || (observed_ && now<*observed_)) return port_detail::failure(PortError::clock);
            observed_=now; return {};
        }
        static auto entropy(std::span<std::uint8_t> output) noexcept -> std::expected<void,PortFailure> {
            auto filled=platform::secure_random(std::as_writable_bytes(output));
            if (!filled) return port_detail::failure(PortError::entropy,filled.error()); return {};
        }
        auto rotate_cookie(Clock::time_point now) -> std::expected<void,PortFailure> {
            SecretKey secret; auto filled=entropy(secret.writable()); if (!filled) return filled;
            auto rotated=ingress_->rotate_cookie_secret(std::move(secret),now);
            if (!rotated) return port_detail::identity_failure(identity::Failure{identity::ErrorCode::admission,{},rotated.error()});
            cookie_.reset(); cookie_rotated_=now; return {};
        }
        auto sync(PeerHandle peer) noexcept -> std::expected<void,PortFailure> {
            auto synced=host_.registry().sync(peer,*peers_[peer.slot].endpoint);
            if (!synced) return port_detail::host_failure(synced.error()); return {};
        }
        auto clear_sending(PeerSlot& slot) noexcept -> void {
            if (slot.pending_business_bytes) {
                --business_packets_;
                business_bytes_-=static_cast<std::uint32_t>(slot.pending_business_bytes);
                slot.pending_business_bytes=0;
            }
            slot.sending.reset();
        }
        auto discard(Delivery& slot) noexcept -> void {
            crypto::cleanse(std::span(slot.packet.bytes).first(slot.packet.size)); --delivery_count_; delivery_bytes_-=slot.packet.size; slot={};
        }
        auto prune_deliveries() noexcept -> void {
            if (!delivery_count_) return;
            for (auto& slot:deliveries_) if (slot.used && !valid_output(slot.packet)) discard(slot);
        }
        auto discard_business() noexcept -> void {
            for (auto& slot:peers_) if (slot.endpoint) {
                slot.endpoint->discard_business();
                if (slot.sending && slot.sending->kind==OutboundKind::data) slot.sending.reset();
                slot.pending_business_bytes=0;
            }
            business_packets_=0; business_bytes_=0;
            prune_deliveries();
        }
        auto erase_peer_unchecked(PeerHandle peer) noexcept -> void {
            (void)routes_.erase(peer); (void)keys_.erase(peer); (void)host_.registry().erase(peer);
            auto& slot=peers_[peer.slot]; clear_sending(slot);
            if (slot.endpoint) {
                business_packets_-=static_cast<std::uint16_t>(slot.endpoint->queued_packets());
                business_bytes_-=static_cast<std::uint32_t>(slot.endpoint->queued_bytes());
            }
            slot.endpoint.reset(); slot.handle.reset();
        }
        static auto initial_policy_epoch() noexcept -> std::uint64_t {
            if constexpr (requires { Hooks::initial_policy_epoch(); }) {
                static_assert(noexcept(Hooks::initial_policy_epoch())); return Hooks::initial_policy_epoch();
            } else return 1;
        }
        auto received(PeerHandle peer,std::expected<EndpointReceived,EndpointFailure> result) -> std::expected<void,PortFailure> {
            auto synced=sync(peer); if (!synced) return synced;
            auto& peer_slot=peers_[peer.slot];
            if (peer_slot.sending && !peer_slot.endpoint->output_valid(peer_slot.sending->serial)) clear_sending(peer_slot);
            if (!result) {
                ++metrics_.dropped;
                if (result.error().code==EndpointError::disallowed_source) ++metrics_.source_rejects;
                if (result.error().protocol==Error::authentication) ++metrics_.authentication_rejects;
                if (result.error().protocol==Error::replay) ++metrics_.replay_rejects;
                if (result.error().protocol==Error::backend) return port_detail::endpoint_failure(result.error());
                return {};
            }
            if (result->packet.empty()) return {};
            detail::Erase erase{result->packet};
            auto slot=std::ranges::find(deliveries_,false,&Delivery::used);
            if (slot==deliveries_.end() || result->packet.size()>PacketBytes) return port_detail::failure(PortError::queue_full);
            if (delivery_serial_==std::numeric_limits<std::uint64_t>::max()) return port_detail::failure(PortError::configuration);
            slot->used=true; slot->packet.peer=peer; slot->packet.size=result->packet.size(); slot->packet.serial=++delivery_serial_;
            slot->packet.policy_epoch=policy_epoch_;
            std::ranges::copy(result->packet,slot->packet.bytes.begin()); ++delivery_count_; delivery_bytes_+=result->packet.size(); ++metrics_.delivered; return {};
        }
        auto challenge(admission::CookieRequest request,Clock::time_point now) -> std::expected<void,PortFailure> {
            std::array<std::uint8_t,24> nonce{}; auto filled=entropy(nonce); if (!filled) return filled;
            auto reply=ingress_->respond_cookie(request,nonce,now);
            if (!reply) return port_detail::identity_failure(identity::Failure{identity::ErrorCode::admission,{},reply.error()});
            cookie_=*reply; return {};
        }
        auto prepare(PeerHandle peer,HandshakeRequest request,Clock::time_point now,std::chrono::system_clock::time_point wall) -> std::expected<void,PortFailure> {
            auto synced=sync(peer); if (!synced) return synced;
            SecretKey bytes; auto filled=entropy(bytes.writable()); if (!filled) return filled;
            auto ephemeral=crypto::X25519Private::from_bytes(bytes.view()); if (!ephemeral) return port_detail::failure(PortError::identity);
            std::array<std::uint8_t,4> seed{}; filled=entropy(seed); if (!filled) return filled;
            auto index=host_.registry().reserve(peer,request.ticket,load_le32(seed)); if (!index) return port_detail::host_failure(index.error());
            std::expected<EndpointDatagram,EndpointFailure> output=std::unexpected(EndpointFailure{EndpointError::protocol,{}});
            auto& endpoint=*peers_[peer.slot].endpoint;
            if (request.reason==HandshakeReason::response) output=endpoint.respond(request,index->index,std::move(*ephemeral),now,IndexMode::exact);
            else {
                auto seconds=std::chrono::duration_cast<std::chrono::seconds>(wall.time_since_epoch());
                auto nanoseconds=std::chrono::duration_cast<std::chrono::nanoseconds>(wall.time_since_epoch()-seconds);
                auto timestamp=seconds.count()<0 ? std::expected<Timestamp,Error>(std::unexpected(Error::invalid_timestamp)) : make_timestamp(seconds.count(),nanoseconds.count());
                std::uint32_t sample=0,threshold=(std::uint32_t{0}-334)%334; unsigned attempts=0;
                do {
                    if (++attempts>16) { (void)host_.registry().release(*index); return port_detail::failure(PortError::entropy,std::make_error_code(std::errc::io_error)); }
                    filled=entropy(seed); if (!filled) { (void)host_.registry().release(*index); return filled; } sample=load_le32(seed);
                } while (sample<threshold);
                if (!timestamp) { (void)host_.registry().release(*index); return port_detail::failure(PortError::clock); }
                output=endpoint.initiate(request,index->index,std::move(*ephemeral),*timestamp,std::chrono::milliseconds(sample%334),now,IndexMode::exact);
            }
            if (!output) {
                (void)host_.registry().release(*index); auto updated=sync(peer); if (!updated) return updated;
                if (output.error().code==EndpointError::not_due || output.error().code==EndpointError::stale_attempt) return {};
                return port_detail::endpoint_failure(output.error());
            }
            synced=sync(peer); if (!synced) return synced;
            clear_sending(peers_[peer.slot]);
            peers_[peer.slot].sending=std::move(*output); return {};
        }
        using SendByte=std::conditional_t<std::same_as<WireProfile,PortStandardWire>,std::uint8_t const,std::uint8_t>;
        auto send(std::optional<PeerHandle> peer,OutboundKind kind,EndpointAddress destination,std::span<SendByte> bytes)
            -> std::expected<void,std::error_code> {
            static_assert(noexcept(outer_.allows(destination)));
            if (!outer_.allows(destination)) return std::unexpected(std::make_error_code(std::errc::permission_denied));
            // The standard specialization has a trivial empty guard: no
            // constructor, destructor, runtime profile branch or wrapper call.
            [[maybe_unused]] std::conditional_t<std::same_as<WireProfile,PortStandardWire>,port_detail::StandardWireRestore,port_detail::ProviderWireRestore> restore;
            if constexpr(!std::same_as<WireProfile,PortStandardWire>) {
                static_assert(noexcept(wire_profile_.apply(bytes)));
                auto applied=wire_profile_.apply(bytes);
                if(!applied)return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                // Pending output stays canonical across EAGAIN and retries.
                // The complete authenticated datagram is never copied.
                restore.bytes=bytes.subspan(1,3);
            }
            static_assert(noexcept(Hooks::before_send(peer,kind,bytes)));
            if (auto failure=Hooks::before_send(peer,kind,bytes)) return std::unexpected(*failure);
            return socket_.send(destination,bytes);
        }
        // A blocked cookie reply is held separately until its original
        // deadline; other queued peer outputs still get a send attempt.
        auto flush_cookie(PortProgress& progress) -> void {
            if (cookie_ && !ingress_->cookie_output_valid(cookie_->request.ticket)) cookie_.reset();
            if (!cookie_) return;
            auto sent=send({},OutboundKind::cookie,cookie_->destination,cookie_->bytes);
            if (!sent && (sent.error()==std::errc::resource_unavailable_try_again || sent.error()==std::errc::operation_would_block || sent.error()==std::errc::interrupted)) {
                progress.write_blocked=true;return;
            }
            if (sent) {++progress.sent;++metrics_.sent;}
            else {++metrics_.send_errors;progress.send_error=sent.error();}
            cookie_.reset();
        }
        auto flush(Clock::time_point now,PortProgress& progress) -> std::expected<void,PortFailure> {
            auto handled=[&](std::expected<void,std::error_code> const& result) {
                if (result) { ++progress.sent; ++metrics_.sent; return true; }
                if (result.error()==std::errc::resource_unavailable_try_again || result.error()==std::errc::operation_would_block || result.error()==std::errc::interrupted) {
                    progress.write_blocked=true; return false;
                }
                ++metrics_.send_errors; progress.send_error=result.error(); return true;
            };
            if (!progress.write_blocked) flush_cookie(progress);
            for (std::size_t offset=0;offset<PeerCapacity;++offset) {
                auto position=(next_peer_+offset)%PeerCapacity; auto& slot=peers_[position];
                if (!slot.endpoint || !slot.sending) continue;
                if (!slot.endpoint->output_valid(slot.sending->serial)) { clear_sending(slot); continue; }
                auto handle=slot_handle(position); if (!handle) return port_detail::failure(PortError::stale_peer);
                auto sent=[&] -> std::expected<void,std::error_code> {
                    if (!slot.sending->relay) return send(*handle,slot.sending->kind,slot.sending->destination,slot.sending->bytes);
                    if constexpr (requires { outer_.send_relay(*handle,slot.sending->bytes); })
                        return outer_.send_relay(*handle,slot.sending->bytes);
                    else return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
                }();
                if (!handled(sent)) return {};
                auto complete=slot.endpoint->complete_send(slot.sending->serial,sent.has_value(),now);
                if (!complete) return port_detail::endpoint_failure(complete.error());
                clear_sending(slot);
            }
            return {};
        }
    public:
        UdpPort(ConstructionKey,SecretKey private_bytes,crypto::X25519Private identity,PortOptions options,OuterPolicy policy={},WireProfile profile={})
            : options_(options),outer_(std::move(policy)),wire_profile_(std::move(profile)),private_bytes_(std::move(private_bytes)),identity_(std::move(identity)),ingress_(IdentityIngress::create(*identity_)),policy_epoch_(initial_policy_epoch()) {
            static_assert(std::is_nothrow_move_constructible_v<OuterPolicy> && std::is_nothrow_move_constructible_v<WireProfile>);
        }
        ~UdpPort() { stop(); }
        UdpPort(UdpPort const&)=delete;
        auto operator=(UdpPort const&) -> UdpPort& = delete;
        UdpPort(UdpPort&&)=delete;
        auto operator=(UdpPort&&) -> UdpPort& = delete;
        [[nodiscard]] static auto create(std::span<std::uint8_t const> private_bytes,PortOptions options={},OuterPolicy policy={},WireProfile profile={}) -> std::expected<UdpPort,PortFailure> {
            if (private_bytes.size()!=32 || !options.business_packets || options.business_packets>1024 || options.business_bytes<68 || options.business_bytes>16*1024*1024 || options.tick.count()<1 || options.tick.count()>1000)
                return port_detail::failure(PortError::configuration);
            auto identity=crypto::X25519Private::from_bytes(private_bytes); if (!identity) return port_detail::failure(PortError::identity);
            SecretKey secret; std::ranges::copy(private_bytes,secret.writable().begin());
            return std::expected<UdpPort,PortFailure>(std::in_place,ConstructionKey{},std::move(secret),std::move(*identity),options,std::move(policy),std::move(profile));
        }
        template<class Prepare=PortNoSocketPreparation>
        [[nodiscard]] auto open(EndpointAddress local,Clock::time_point now,Clock::time_point deadline=Clock::time_point::max(),Prepare prepare={}) -> std::expected<void,PortFailure> {
            auto checked=observe(now); if (!checked) return checked;
            if (opened_) return port_detail::failure(PortError::already_open);
            if (!ingress_) return port_detail::identity_failure(ingress_.error());
            if (deadline<=now) return port_detail::failure(PortError::configuration);
            auto rotated=rotate_cookie(now); if (!rotated) return rotated;
            struct SocketGuard {
                Socket& socket;
                bool active=false;
                ~SocketGuard() {
                    if (!active) return;
                    if constexpr (requires { socket.discard(); }) socket.discard();
                    else socket.close();
                }
            } guard{socket_};
            if constexpr (!std::is_same_v<Prepare,PortNoSocketPreparation>) {
                auto opened=socket_.open(); if (!opened) return port_detail::failure(PortError::io,opened.error());
                guard.active=true;
                static_assert(noexcept(prepare(socket_.native_handle())));
                if (auto error=prepare(socket_.native_handle())) return port_detail::failure(PortError::io,error);
            }
            auto bound=socket_.bind(local); if (!bound) return port_detail::failure(PortError::io,bound.error());
            guard.active=false;
            opened_=true; deadline_=deadline; return {};
        }
        [[nodiscard]] auto local_endpoint() const -> std::expected<EndpointAddress,std::error_code> { return socket_.local_endpoint(); }
        [[nodiscard]] auto native_handle() const noexcept -> int { return socket_.native_handle(); }
        [[nodiscard]] auto transport_socket() noexcept -> Socket& requires (!std::same_as<Socket,net::UdpSocket>) { return socket_; }
        auto send_auxiliary(net::UdpEndpoint target,std::span<const std::uint8_t> packet) -> bool
            requires requires { outer_.receive_auxiliary(target,packet,Clock::time_point{}); } {
            return opened_ && !stopped_ && outer_.allows(target) && socket_.send(target,packet).has_value();
        }
        [[nodiscard]] auto add_peer(EndpointConfig config,std::span<std::uint8_t const> psk={}) -> std::expected<PeerHandle,PortFailure> {
            if (stopped_) return port_detail::failure(PortError::closed);
            if (!opened_) return port_detail::failure(PortError::not_open);
            if constexpr (!requires(PeerHandle handle,std::span<const std::uint8_t> data) { outer_.send_relay(handle,data); })
                if (config.relay_only) return port_detail::failure(PortError::configuration);
            if (config.mtu>PacketBytes-transport_overhead) return port_detail::failure(PortError::configuration);
            config.queue_packets=std::min(config.queue_packets,options_.business_packets); config.queue_bytes=std::min(config.queue_bytes,options_.business_bytes);
            auto identity=crypto::X25519Private::from_bytes(private_bytes_.view()); if (!identity) return port_detail::failure(PortError::identity);
            auto handle=host_.registry().add(); if (!handle) return port_detail::host_failure(handle.error());
            auto key=keys_.activate(*handle,config.peer_public);
            if (!key) { (void)host_.registry().erase(*handle); return port_detail::identity_failure(key.error()); }
            std::expected<void,EndpointFailure> endpoint;
            try { endpoint=Endpoint::emplace_into(peers_[handle->slot].endpoint,std::move(*identity),std::move(config),psk); }
            catch (std::bad_alloc const&) { (void)keys_.erase(*handle); (void)host_.registry().erase(*handle); return port_detail::failure(PortError::allocation); }
            if (!endpoint) { (void)keys_.erase(*handle); (void)host_.registry().erase(*handle); return port_detail::endpoint_failure(endpoint.error()); }
            auto routed=routes_.activate(*handle);
            if (!routed) { peers_[handle->slot].endpoint.reset(); (void)keys_.erase(*handle); (void)host_.registry().erase(*handle); return port_detail::route_failure(routed.error()); }
            peers_[handle->slot].handle=*handle; return *handle;
        }
        [[nodiscard]] auto assign_route(PeerHandle peer,AllowedPrefix const& prefix) noexcept -> std::expected<void,PortFailure> {
            if (!host_.registry().valid(peer)) return port_detail::failure(PortError::stale_peer);
            if (policy_epoch_==std::numeric_limits<std::uint64_t>::max()) return port_detail::failure(PortError::policy_exhausted);
            auto assigned=routes_.assign(peer,prefix); if (!assigned) return port_detail::route_failure(assigned.error());
            ++policy_epoch_; discard_business(); return {};
        }
        [[nodiscard]] auto erase_peer(PeerHandle peer) noexcept -> std::expected<void,PortFailure> {
            if (!host_.registry().valid(peer)) return port_detail::failure(PortError::stale_peer);
            if (policy_epoch_==std::numeric_limits<std::uint64_t>::max()) return port_detail::failure(PortError::policy_exhausted);
            ++policy_epoch_; erase_peer_unchecked(peer); discard_business(); return {};
        }
        [[nodiscard]] auto change_peer_path(PeerHandle peer,std::optional<EndpointAddress> address,bool relay) noexcept
            -> std::expected<void,PortFailure> requires requires(std::span<const std::uint8_t> bytes) { outer_.send_relay(peer,bytes); } {
            if (!host_.registry().valid(peer)) return port_detail::failure(PortError::stale_peer);
            auto& slot=peers_[peer.slot];
            auto changed=slot.endpoint->change_path(address,relay);
            if (!changed) return port_detail::endpoint_failure(changed.error());
            if (slot.sending && !slot.endpoint->output_valid(slot.sending->serial)) clear_sending(slot);
            return sync(peer);
        }
        [[nodiscard]] auto peer_status(PeerHandle peer) const noexcept -> std::expected<EndpointStatus,PortFailure> {
            if (!host_.registry().valid(peer)) return port_detail::failure(PortError::stale_peer); return peers_[peer.slot].endpoint->status();
        }
        [[nodiscard]] auto request_handshake(PeerHandle peer,Clock::time_point now) -> std::expected<void,PortFailure> {
            auto checked=observe(now); if (!checked) return checked;
            if (!host_.registry().valid(peer)) return port_detail::failure(PortError::stale_peer);
            auto requested=peers_[peer.slot].endpoint->request_handshake(now); if (!requested) return port_detail::endpoint_failure(requested.error()); return {};
        }
        [[nodiscard]] auto enqueue_ip(std::span<std::uint8_t const> packet,Clock::time_point now) -> std::expected<PeerHandle,PortFailure> {
            auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
            auto parsed=parse_inner_packet(packet); if (!parsed || parsed->packet.size()!=packet.size()) return port_detail::failure(PortError::configuration);
            auto peer=routes_.lookup(parsed->family,std::span(parsed->destination).first(parsed->family==4 ? 4 : 16));
            if (!peer || !host_.registry().valid(*peer)) return port_detail::failure(PortError::no_route);
            if (business_packets_>=options_.business_packets || packet.size()>options_.business_bytes-business_bytes_) return port_detail::failure(PortError::queue_full);
            try {
                auto queued=peers_[peer->slot].endpoint->enqueue(packet,now); if (!queued) return port_detail::endpoint_failure(queued.error());
                ++business_packets_; business_bytes_+=static_cast<std::uint32_t>(packet.size()); return *peer;
            } catch (std::bad_alloc const&) { return port_detail::failure(PortError::allocation); }
        }
        [[nodiscard]] auto take_packet() noexcept -> std::optional<PortPacket<PacketBytes>> {
            prune_deliveries(); if (!delivery_count_) return {}; Delivery* oldest=nullptr;
            for (auto& slot:deliveries_) if (slot.used && (!oldest || slot.packet.serial<oldest->packet.serial)) oldest=&slot;
            if (!oldest) return {}; auto packet=oldest->packet; discard(*oldest); return packet;
        }
        // The relay transport supplies an authenticated outer connection and
        // the sender's node key. WireGuard still verifies the inner message
        // and global source route, with no synthetic UDP roaming endpoint.
        [[nodiscard]] auto receive_relay(Key const& sender,std::span<const std::uint8_t> wire,Clock::time_point now)
            -> std::expected<void,PortFailure> requires requires(PeerHandle handle) { outer_.send_relay(handle,wire); } {
            auto checked=observe(now); if (!checked) return checked;
            if (!opened_) return port_detail::failure(PortError::not_open);
            if (wire.size()>PacketBytes || delivery_count_==PacketCapacity) return {};
            auto peer=keys_.view().find(sender);
            if (!peer || !host_.registry().valid(*peer)) return {};
            try {
                auto accepted=peers_[peer->slot].endpoint->receive_relay(wire,now,routes_.view(*peer));
                return received(*peer,std::move(accepted));
            } catch (std::bad_alloc const&) { return port_detail::failure(PortError::allocation); }
        }
        [[nodiscard]] auto valid(PeerHandle peer) const noexcept -> bool { return host_.registry().valid(peer); }
        [[nodiscard]] auto valid_output(PortPacket<PacketBytes> const& packet) const noexcept -> bool {
            return !stopped_ && packet.policy_epoch==policy_epoch_ && host_.registry().valid(packet.peer);
        }
        [[nodiscard]] auto poll(Clock::time_point now,std::chrono::system_clock::time_point wall) -> std::expected<PortProgress,PortFailure> {
            auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
            if (!opened_) return port_detail::failure(PortError::not_open);
            if (now>=deadline_) { stop(); return port_detail::failure(PortError::timeout); }
            try { return poll_step(now,wall); }
            catch (std::bad_alloc const&) { stop(); return port_detail::failure(PortError::allocation); }
        }
    private:
        auto poll_step(Clock::time_point now,std::chrono::system_clock::time_point wall) -> std::expected<PortProgress,PortFailure> {
            if (now-cookie_rotated_>=cookie_refresh_time) { auto rotated=rotate_cookie(now); if (!rotated) return std::unexpected(rotated.error()); }
            PortProgress progress{.next_poll=std::min(deadline_,port_detail::after(now,options_.tick))}; prune_deliveries();
            if (cookie_ && now>=cookie_->request.expires) {cookie_.reset();ingress_->cancel_cookie();}
            if (cookie_) flush_cookie(progress);
            for (std::size_t count=0;count<PacketCapacity;++count) {
                if (delivery_count_==PacketCapacity || (host_.queued_packets()==PacketCapacity && host_.status().packets==PacketCapacity)) { progress.read_paused=true; break; }
                auto datagram=socket_.receive(input_); if (!datagram) return port_detail::failure(PortError::io,datagram.error());
                if (!*datagram) break; ++progress.received; ++metrics_.received;
                auto const& packet=**datagram;
                if (!packet.valid) { ++metrics_.dropped; continue; }
                static_assert(noexcept(outer_.allows(packet.source)));
                if (!outer_.allows(packet.source)) { ++metrics_.dropped; ++metrics_.source_rejects; continue; }
                auto wire=std::span(input_).first(packet.size);
                if constexpr (requires { outer_.receive_auxiliary(packet.source,wire,now); })
                    if (outer_.receive_auxiliary(packet.source,wire,now)) continue;
                auto type=[&]() __attribute__((always_inline)) -> std::expected<MessageType,Error> {
                    if constexpr(std::same_as<WireProfile,PortStandardWire>)return message_type(wire);
                    else {
                        static_assert(noexcept(wire_profile_.restore(wire,true)));
                        return wire_profile_.restore(wire,true);
                    }
                }();
                if (!type) { ++metrics_.dropped; continue; }
                auto cookie_required=options_.require_cookie;
                if(options_.auto_cookie && (*type==MessageType::initiation || *type==MessageType::response))
                    cookie_required|=handshake_pressure_.observe(now);
                if (*type==MessageType::initiation) {
                    auto selected=ingress_->receive(wire,packet.source,true,now,keys_.view(),cookie_required,!cookie_);
                    if (!selected) { ++metrics_.dropped; if (selected.error().code==identity::ErrorCode::rate_limited) ++metrics_.rate_limit_rejects; if (selected.error().protocol==Error::backend) return port_detail::identity_failure(selected.error()); continue; }
                    if (selected->cookie) { auto replied=challenge(*selected->cookie,now); if (!replied) return std::unexpected(replied.error()); if (!progress.write_blocked) flush_cookie(progress); continue; }
                    auto peer=selected->selected->peer(); if (!host_.registry().valid(peer)) { ++metrics_.dropped; continue; }
                    if constexpr (requires { outer_.allows_peer(peer,packet.source); })
                        if (!outer_.allows_peer(peer,packet.source)) { ++metrics_.source_rejects; continue; }
                    auto accepted=peers_[peer.slot].endpoint->receive_selected(std::move(*selected->selected),keys_.view(),now,routes_.view(peer));
                    if (accepted && !cookie_) ingress_->cancel_cookie(); auto handled=received(peer,std::move(accepted)); if (!handled) return std::unexpected(handled.error());
                } else {
                    if (*type==MessageType::response && cookie_required) {
                        auto admitted=ingress_->admit_response(wire,packet.source,true,now,true,!cookie_);
                        if (!admitted) { ++metrics_.dropped; if (admitted.error().code==identity::ErrorCode::rate_limited) ++metrics_.rate_limit_rejects; continue; }
                        if (admitted->cookie) { auto replied=challenge(*admitted->cookie,now); if (!replied) return std::unexpected(replied.error()); if (!progress.write_blocked) flush_cookie(progress); continue; }
                    }
                    auto queued=host_.enqueue_indexed(wire,packet.source,true); if (!queued) ++metrics_.dropped;
                }
            }
            for (std::size_t count=0;count<PacketCapacity && delivery_count_<PacketCapacity;++count) {
                auto candidate=host_.take(); if (!candidate) break; ++progress.processed;
                if (!host_.valid(*candidate)) { ++metrics_.dropped; continue; }
                auto peer=candidate->peer;
                if constexpr (requires { outer_.allows_peer(peer,candidate->source); })
                    if (!outer_.allows_peer(peer,candidate->source)) { ++metrics_.source_rejects; continue; }
                auto accepted=peers_[peer.slot].endpoint->receive(candidate->wire(),candidate->source,true,now,false,routes_.view(peer));
                if (accepted && candidate->wire()[0]==2 && !cookie_) ingress_->cancel_cookie();
                auto handled=received(peer,std::move(accepted)); if (!handled) return std::unexpected(handled.error());
            }
            for (std::size_t offset=0;offset<PeerCapacity;++offset) {
                auto position=(next_peer_+offset)%PeerCapacity; auto& slot=peers_[position]; if (!slot.endpoint) continue;
                auto handle=slot_handle(position); if (!handle) return port_detail::failure(PortError::stale_peer);
                auto packets_before=slot.endpoint->queued_packets(),bytes_before=slot.endpoint->queued_bytes();
                auto output=slot.endpoint->poll(now);
                auto packets_after=slot.endpoint->queued_packets(),bytes_after=slot.endpoint->queued_bytes();
                business_packets_-=static_cast<std::uint16_t>(packets_before-packets_after);
                business_bytes_-=static_cast<std::uint32_t>(bytes_before-bytes_after);
                if (!output) {
                    if (slot.sending && !slot.endpoint->output_valid(slot.sending->serial)) clear_sending(slot);
                    if (output.error().code==EndpointError::source) continue;
                    return port_detail::endpoint_failure(output.error());
                }
                auto synced=sync(*handle); if (!synced) return std::unexpected(synced.error());
                if (slot.sending && !slot.endpoint->output_valid(slot.sending->serial)) clear_sending(slot);
                if (output->handshake) { auto prepared=prepare(*handle,*output->handshake,now,wall); if (!prepared) return std::unexpected(prepared.error()); }
                else if (output->datagram) {
                    clear_sending(slot);
                    if (output->datagram->kind==OutboundKind::data) {
                        auto popped=bytes_before-bytes_after;
                        slot.pending_business_bytes=popped;
                        if (popped) { ++business_packets_; business_bytes_+=static_cast<std::uint32_t>(popped); }
                    }
                    slot.sending=std::move(*output->datagram);
                }
            }
            auto flushed=flush(now,progress); if (!flushed) return std::unexpected(flushed.error());
            next_peer_=(next_peer_+1)%PeerCapacity;
            if (host_.queued_packets() && delivery_count_<PacketCapacity && host_.status().packets) progress.next_poll=now;
            if (cookie_) progress.next_poll=std::min(progress.next_poll,cookie_->request.expires);
            progress.read_paused|=delivery_count_==PacketCapacity; return progress;
        }
    public:
        [[nodiscard]] auto opened() const noexcept -> bool { return opened_; }
        [[nodiscard]] auto stopped() const noexcept -> bool { return stopped_; }
        [[nodiscard]] auto delivery_packets() const noexcept -> std::size_t { return delivery_count_; }
        [[nodiscard]] auto delivery_bytes() const noexcept -> std::size_t { return delivery_bytes_; }
        [[nodiscard]] auto business_packets() const noexcept -> std::size_t { return business_packets_; }
        [[nodiscard]] auto business_bytes() const noexcept -> std::size_t { return business_bytes_; }
        [[nodiscard]] auto status() noexcept -> PortStatus {
            prune_deliveries(); PortStatus result{.registry=host_.registry().status(),.ingress=host_.status(),.routes=routes_.status().prefixes,.keys=keys_.size(),
                .delivery_packets=delivery_count_,.delivery_bytes=delivery_bytes_,.pending_sends=std::size_t(cookie_.has_value()),
                .business_packets=business_packets_,.business_bytes=business_bytes_,.metrics=metrics_,.opened=opened_,.stopped=stopped_,
                .automatic_cookie_active=!stopped_ && options_.auto_cookie && observed_ && handshake_pressure_.active(*observed_)};
            for (auto const& slot:peers_) if (slot.endpoint) result.pending_sends+=slot.sending.has_value();
            return result;
        }
        auto stop() noexcept -> void {
            if (stopped_) return;
            stopped_=true;
            for (std::size_t position=0;position<PeerCapacity;++position) if (auto handle=slot_handle(position)) erase_peer_unchecked(*handle);
            host_.clear(); for (auto& delivery:deliveries_) if (delivery.used) discard(delivery);
            cookie_.reset(); if (ingress_) ingress_->close(); socket_.close(); private_bytes_.clear(); identity_.reset();
            business_packets_=0; business_bytes_=0; opened_=false; stopped_=true;
        }
        [[nodiscard]] auto drained() noexcept -> bool { auto current=status(); return stopped_ && !current.registry.peers && !current.registry.indexes && !current.ingress.packets && !current.delivery_packets && !current.pending_sends && !current.routes && !current.keys && !current.business_packets; }
    };
}
