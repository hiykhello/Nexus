module wireguard.endpoint;
import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.admission;
import wireguard.crypto;
import wireguard.noise;
import wireguard.routing;
import wireguard.session;

namespace wireguard {
    namespace {
        auto failure(EndpointError code,std::optional<Error> protocol={}) -> std::unexpected<EndpointFailure> { return std::unexpected(EndpointFailure{code,protocol}); }
    }
    auto Endpoint::valid_address(EndpointAddress const& peer) noexcept -> bool {
        return admission::valid_source(peer);
    }
    auto parse_inner_packet(std::span<std::uint8_t const> input) noexcept -> std::expected<InnerPacket,EndpointFailure> {
        if (input.empty()) return failure(EndpointError::invalid_packet);
        auto family=input[0]>>4;
        auto u16=[&](std::size_t offset) { return (std::size_t(input[offset])<<8)|input[offset+1]; };
        InnerPacket result{static_cast<std::uint8_t>(family)};
        std::size_t length=0;
        if (family==4) {
            if (input.size()<20) return failure(EndpointError::invalid_packet);
            auto header=std::size_t(input[0]&15)*4; length=u16(2);
            if (header<20 || header>60 || length<header || length>input.size()) return failure(EndpointError::invalid_packet);
            std::copy_n(input.begin()+12,4,result.source.begin()); std::copy_n(input.begin()+16,4,result.destination.begin());
        } else if (family==6) {
            if (input.size()<40) return failure(EndpointError::invalid_packet);
            length=40+u16(4);
            if (length>input.size()) return failure(EndpointError::invalid_packet);
            std::copy_n(input.begin()+8,16,result.source.begin()); std::copy_n(input.begin()+24,16,result.destination.begin());
        } else return failure(EndpointError::invalid_packet);
        result.packet=input.first(length); return result;
    }
    Endpoint::Endpoint(ConstructionKey,crypto::X25519Private identity,Key local_public,SecretKey psk,EndpointConfig config)
        : identity_(std::move(identity)),admission_(local_public),psk_(std::move(psk)),config_(std::move(config)) {}
    Endpoint::~Endpoint() { close(); }
    auto Endpoint::validate(crypto::X25519Private const& identity,EndpointConfig& config,std::span<std::uint8_t const> psk)
        -> std::expected<Key,EndpointFailure> {
        if ((!psk.empty() && psk.size()!=32) || config.mtu<68 || config.mtu>endpoint_max_inner_mtu ||
            !config.queue_packets || config.queue_packets>1024 || config.queue_bytes<config.mtu || config.queue_bytes>16*1024*1024 ||
            config.persistent_keepalive.count()<0 || config.persistent_keepalive.count()>65535 || config.allowed_ips.size()>1024 ||
            (config.peer && (config.relay_only || !valid_address(*config.peer)))) return failure(EndpointError::configuration);
        for (auto const& prefix:config.allowed_ips) if (!valid_prefix(prefix)) return failure(EndpointError::configuration);
        std::ranges::sort(config.allowed_ips);
        if (std::ranges::adjacent_find(config.allowed_ips)!=config.allowed_ips.end()) return failure(EndpointError::configuration);
        auto public_key=identity.public_key();
        auto shared=identity.agree(config.peer_public);
        if (!public_key || !shared) return failure(EndpointError::configuration,Error::invalid_key);
        return *public_key;
    }
    auto Endpoint::create(crypto::X25519Private identity,EndpointConfig config,std::span<std::uint8_t const> psk)
        -> std::expected<Endpoint,EndpointFailure> {
        auto public_key=validate(identity,config,psk); if (!public_key) return std::unexpected(public_key.error());
        SecretKey secret; std::ranges::copy(psk,secret.writable().begin());
        return std::expected<Endpoint,EndpointFailure>(std::in_place,ConstructionKey{},std::move(identity),*public_key,std::move(secret),std::move(config));
    }
    auto Endpoint::emplace_into(std::optional<Endpoint>& target,crypto::X25519Private identity,EndpointConfig config,std::span<std::uint8_t const> psk)
        -> std::expected<void,EndpointFailure> {
        if (target) return failure(EndpointError::configuration);
        auto public_key=validate(identity,config,psk); if (!public_key) return std::unexpected(public_key.error());
        SecretKey secret; std::ranges::copy(psk,secret.writable().begin());
        target.emplace(ConstructionKey{},std::move(identity),*public_key,std::move(secret),std::move(config)); return {};
    }
    auto Endpoint::close() noexcept -> void {
        if (closed_) return;
        clear_attempt(); drop(pending_); drop(previous_); drop(current_); sending_.reset(); queue_.clear(); queued_bytes_=0;
        clear_cookie_challenge(); cookie_binding_.reset(); cookie_generator_.reset(); admission_.close();
        psk_.clear(); identity_.reset(); closed_=true;
    }
    auto Endpoint::discard_business() noexcept -> void {
        queue_.clear(); queued_bytes_=0;
        if (sending_ && sending_->kind==OutboundKind::data) sending_.reset();
    }
    auto Endpoint::change_path(std::optional<EndpointAddress> peer,bool relay) noexcept -> std::expected<void,EndpointFailure> {
        if (closed_) return failure(EndpointError::closed);
        if (relay==peer.has_value() || (peer && !valid_address(*peer))) return failure(EndpointError::configuration);
        if (config_.peer==peer && config_.relay_only==relay) return {};
        if (sending_ && sending_->kind==OutboundKind::response) drop(pending_);
        clear_attempt();
        clear_cookie_challenge();
        cookie_binding_.reset();
        cookie_generator_.reset();
        sending_.reset();
        window_.reset();
        next_send_={};
        config_.peer=peer;
        config_.relay_only=relay;
        return {};
    }
    auto Endpoint::observe(Clock::time_point now) noexcept -> std::expected<void,EndpointFailure> {
        if (closed_) return failure(EndpointError::closed);
        if (now<Clock::time_point{} || (observed_ && now<*observed_)) return failure(EndpointError::clock);
        if (!observed_ && config_.persistent_keepalive.count()) {
            auto delay=std::chrono::duration_cast<Clock::duration>(config_.persistent_keepalive);
            next_persistent_=now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        }
        observed_=now; return {};
    }
    auto Endpoint::reserve_index(std::uint32_t seed,std::uint64_t ticket,IndexMode mode) noexcept -> std::expected<std::uint32_t,EndpointFailure> {
        auto slot=std::ranges::find(indexes_,false,&Index::used);
        if (slot==indexes_.end()) return failure(EndpointError::index_exhausted);
        auto probes=mode==IndexMode::exact ? 1u : indexes_.size()+1;
        for (std::size_t probe=0;probe<probes;++probe) {
            auto value=seed+static_cast<std::uint32_t>(probe);
            if (std::ranges::any_of(indexes_,[&](auto const& index) { return index.used && index.value==value; })) continue;
            *slot=Index{true,value,ticket}; return value;
        }
        return failure(mode==IndexMode::exact ? EndpointError::index_conflict : EndpointError::index_exhausted);
    }
    auto Endpoint::release_index(std::uint32_t value,std::uint64_t ticket) noexcept -> void {
        for (auto& index:indexes_) if (index.used && index.value==value && index.ticket==ticket) { index={}; break; }
    }
    Endpoint::IndexLease::~IndexLease() { if (!committed) owner.release_index(index,ticket); }
    auto Endpoint::clear_attempt(bool release) noexcept -> void {
        if (!attempt_) return;
        if (release && attempt_->index) release_index(*attempt_->index,attempt_->request.ticket);
        if (sending_ && sending_->ticket==attempt_->request.ticket &&
            (sending_->kind==OutboundKind::initiation || sending_->kind==OutboundKind::response)) sending_.reset();
        attempt_.reset();
    }
    auto Endpoint::drop(std::optional<Generation>& generation) noexcept -> void {
        if (!generation) return;
        release_index(generation->index,generation->ticket);
        if (sending_ && sending_->kind!=OutboundKind::cookie && sending_->ticket==generation->ticket) sending_.reset();
        generation.reset();
        if (&generation==&current_) { confirmation_=false; send_rekey_=false; receive_rekey_=false; }
    }
    auto Endpoint::prune(Clock::time_point now) noexcept -> void {
        for (auto* generation:{&current_,&previous_,&pending_})
            if (*generation && now>=(*generation)->born && now-(*generation)->born>=reject_after_time) drop(*generation);
    }
    auto Endpoint::note_received(bool data,bool rekey,Clock::time_point now) noexcept -> void {
        last_received_=now; receipt_owed_=false;
        if (data && !keepalive_owed_) { last_data_received_=now; keepalive_owed_=true; }
        receive_rekey_|=rekey;
        if (config_.persistent_keepalive.count()) {
            auto delay=std::chrono::duration_cast<Clock::duration>(config_.persistent_keepalive);
            next_persistent_=now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        }
    }
    auto Endpoint::allowed(InnerPacket const& packet,bool source) const noexcept -> bool {
        auto const& address=source ? packet.source : packet.destination;
        auto bytes=std::span(address).first(packet.family==4 ? 4 : 16);
        return std::ranges::any_of(config_.allowed_ips,[&](auto const& prefix) { return prefix_contains(prefix,packet.family,bytes); });
    }
    auto Endpoint::issue(HandshakeReason reason,AttemptPhase phase,Clock::time_point now) -> std::expected<HandshakeRequest,EndpointFailure> {
        if (latest_==std::numeric_limits<std::uint64_t>::max()) return failure(EndpointError::protocol,Error::counter_exhausted);
        clear_attempt(); drop(pending_);
        auto delay=std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(5));
        auto expires=now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        HandshakeRequest request{++latest_,reason,expires}; attempt_.emplace(request,phase); return request;
    }
    auto Endpoint::promote_pending() noexcept -> void {
        if (!pending_ || pending_->ticket!=latest_) return;
        drop(previous_);
        if (current_) { previous_.emplace(std::move(*current_)); current_.reset(); }
        current_.emplace(std::move(*pending_)); pending_.reset();
        confirmation_=false; window_.reset(); manual_=false; send_rekey_=false; receive_rekey_=false;
    }
    auto Endpoint::install_current(Session session,std::uint32_t index,std::uint64_t ticket,Clock::time_point now) noexcept -> void {
        drop(previous_); drop(pending_);
        if (current_) { previous_.emplace(std::move(*current_)); current_.reset(); }
        current_.emplace(std::move(session),index,ticket,now,true); confirmation_=true;
        window_.reset(); manual_=false; send_rekey_=false; receive_rekey_=false;
    }
    auto Endpoint::output(std::vector<std::uint8_t> bytes,OutboundKind kind,std::uint64_t ticket,EndpointAddress target)
        -> std::expected<EndpointDatagram,EndpointFailure> {
        if (sending_) return failure(EndpointError::not_due);
        if (serial_==std::numeric_limits<std::uint64_t>::max()) return failure(EndpointError::protocol,Error::counter_exhausted);
        auto serial=++serial_; sending_=Sending{serial,ticket,kind};
        return EndpointDatagram{serial,target,std::move(bytes),kind,config_.relay_only};
    }
    auto Endpoint::emit_transport(std::span<std::uint8_t const> plaintext,OutboundKind kind,Clock::time_point now)
        -> std::expected<EndpointDatagram,EndpointFailure> {
        if (!current_ || (!config_.relay_only && !config_.peer)) return failure(EndpointError::no_key);
        auto bytes=current_->session.seal(plaintext,now,config_.mtu);
        if (!bytes) return failure(EndpointError::protocol,bytes.error());
        return output(std::move(*bytes),kind,current_->ticket,config_.peer.value_or(EndpointAddress{}));
    }
    auto Endpoint::enqueue(std::span<std::uint8_t const> input,Clock::time_point now) -> std::expected<void,EndpointFailure> {
        auto checked=observe(now); if (!checked) return checked;
        auto packet=parse_inner_packet(input); if (!packet || packet->packet.size()!=input.size() || input.size()>config_.mtu) return failure(EndpointError::invalid_packet);
        if (!allowed(*packet,false)) return failure(EndpointError::disallowed_destination);
        if (queue_.size()>=config_.queue_packets || input.size()>config_.queue_bytes-queued_bytes_) return failure(EndpointError::queue_full);
        queue_.emplace_back(input); queued_bytes_+=input.size();
        if ((!current_ || attempt_) && !window_) window_=now;
        return {};
    }
    auto Endpoint::request_handshake(Clock::time_point now) -> std::expected<void,EndpointFailure> {
        auto checked=observe(now); if (!checked) return checked;
        manual_=true; window_=now; return {};
    }
    auto Endpoint::output_valid(std::uint64_t serial) const noexcept -> bool { return !closed_ && sending_ && sending_->serial==serial; }
    auto Endpoint::complete_send(std::uint64_t serial,bool success,Clock::time_point now) -> std::expected<void,EndpointFailure> {
        auto checked=observe(now); if (!checked) return checked;
        if (!sending_ || sending_->serial!=serial) return failure(EndpointError::stale_attempt);
        auto sent=*sending_; sending_.reset();
        if (success) {
            next_send_=now;
            if (sent.kind==OutboundKind::cookie) return {};
            last_sent_=now; keepalive_owed_=false;
            if (sent.kind==OutboundKind::data) {
                if (!receipt_owed_) last_data_sent_=now;
                receipt_owed_=true;
                if (current_ && current_->ticket==sent.ticket) current_->sent_data=true;
            }
            if (current_ && current_->ticket==sent.ticket && (sent.kind==OutboundKind::data || sent.kind==OutboundKind::keepalive)) {
                confirmation_=false; send_rekey_|=current_->session.rekey_due(now);
            }
            if (config_.persistent_keepalive.count()) {
                auto delay=std::chrono::duration_cast<Clock::duration>(config_.persistent_keepalive);
                next_persistent_=now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
            }
        } else {
            auto delay=std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1));
            next_send_=now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        }
        return {};
    }
    auto Endpoint::status() const noexcept -> EndpointStatus {
        EndpointStatus result; result.peer=config_.peer; result.latest_attempt=latest_; result.queued_packets=queue_.size(); result.queued_bytes=queued_bytes_;
        if (current_) result.current=current_->index;
        if (previous_) result.previous=previous_->index;
        if (pending_) result.pending=pending_->index;
        if (attempt_) result.handshake=attempt_->index;
        result.indexes=std::ranges::count(indexes_,true,&Index::used); return result;
    }
    auto Endpoint::receiver_indexes() const noexcept -> ReceiverIndexes { return indexes_; }
}
