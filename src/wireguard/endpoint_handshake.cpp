module wireguard.endpoint;
import std;
import crypto;
import wireguard;
import wireguard.admission;
import wireguard.crypto;
import wireguard.identity;
import wireguard.initiation;
import wireguard.noise;
import wireguard.routing;
import wireguard.session;

namespace wireguard {
    namespace {
        auto failure(EndpointError code,std::optional<Error> protocol={}) -> std::unexpected<EndpointFailure> { return std::unexpected(EndpointFailure{code,protocol}); }
        auto after(Clock::time_point now,Clock::duration delay) noexcept -> Clock::time_point {
            return now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        }
    }
    auto Endpoint::initiate(HandshakeRequest request,std::uint32_t seed,crypto::X25519Private ephemeral,Timestamp const& timestamp,
        std::chrono::milliseconds jitter,Clock::time_point now,IndexMode mode) -> std::expected<EndpointDatagram,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        if (!attempt_ || request.ticket!=latest_ || attempt_->request.ticket!=request.ticket ||
            attempt_->phase!=AttemptPhase::initiation_requested || now>=attempt_->request.expires) return failure(EndpointError::stale_attempt);
        if (window_ && now-*window_>=std::chrono::seconds(90)) return failure(EndpointError::stale_attempt);
        if (!config_.peer && !config_.relay_only) return failure(EndpointError::source);
        if (sending_ || jitter.count()<0 || jitter.count()>333 || (last_handshake_ && now-*last_handshake_<std::chrono::seconds(5))) return failure(EndpointError::not_due);
        auto handshake=Handshake::create(*identity_,config_.peer_public,psk_.view());
        if (!handshake) return failure(EndpointError::protocol,handshake.error());
        auto index=reserve_index(seed,request.ticket,mode); if (!index) return std::unexpected(index.error());
        IndexLease lease{*this,*index,request.ticket};
        auto wire=handshake->initiate(*index,timestamp,std::move(ephemeral)); if (!wire) return failure(EndpointError::protocol,wire.error());
        std::vector<std::uint8_t> bytes(wire->begin(),wire->end());
        auto destination=config_.peer.value_or(EndpointAddress{});
        if (config_.peer) {
            auto macs=apply_cookie(bytes,request.ticket,destination,now); if (!macs) return std::unexpected(macs.error());
        }
        attempt_->handshake.emplace(std::move(*handshake)); attempt_->index=*index; attempt_->phase=AttemptPhase::initiation_sent;
        attempt_->retry=after(now,std::chrono::seconds(5)+jitter); last_handshake_=now;
        if (!window_) window_=now;
        lease.committed=true; return output(std::move(bytes),OutboundKind::initiation,request.ticket,destination);
    }
    auto Endpoint::respond(HandshakeRequest request,std::uint32_t seed,crypto::X25519Private ephemeral,Clock::time_point now,IndexMode mode)
        -> std::expected<EndpointDatagram,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        if (!attempt_ || request.ticket!=latest_ || attempt_->request.ticket!=request.ticket ||
            attempt_->phase!=AttemptPhase::response_requested || !attempt_->handshake ||
            (!config_.relay_only && !attempt_->source) || now>=attempt_->request.expires)
            return failure(EndpointError::stale_attempt);
        if (sending_) return failure(EndpointError::not_due);
        auto index=reserve_index(seed,request.ticket,mode); if (!index) return std::unexpected(index.error());
        IndexLease lease{*this,*index,request.ticket};
        auto wire=attempt_->handshake->respond(*index,std::move(ephemeral)); if (!wire) return failure(EndpointError::protocol,wire.error());
        std::vector<std::uint8_t> bytes(wire->begin(),wire->end());
        auto destination=attempt_->source.value_or(EndpointAddress{});
        if (attempt_->source) {
            auto macs=apply_cookie(bytes,request.ticket,destination,now); if (!macs) { clear_attempt(); return std::unexpected(macs.error()); }
        }
        auto session=attempt_->handshake->finish(now); if (!session) return failure(EndpointError::protocol,session.error());
        drop(pending_); pending_.emplace(std::move(*session),*index,request.ticket,now,false);
        clear_attempt(false); lease.committed=true;
        return output(std::move(bytes),OutboundKind::response,request.ticket,destination);
    }
    auto Endpoint::receive(std::span<std::uint8_t const> wire,EndpointAddress source,bool source_allowed,Clock::time_point now,bool require_cookie,SourcePolicyView source_policy)
        -> std::expected<EndpointReceived,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        if (config_.relay_only || !source_allowed || !valid_address(source)) return failure(EndpointError::source);
        if (!source_policy.current()) return failure(EndpointError::disallowed_source);
        prune(now);
        auto type=message_type(wire); if (!type) return failure(EndpointError::protocol,type.error());
        if (*type==MessageType::initiation || (require_cookie && *type==MessageType::response)) {
            auto admitted=admit_handshake(wire,source,now,require_cookie); if (!admitted) return std::unexpected(admitted.error());
            if (admitted->cookie) { EndpointReceived result; if (!sending_) result.cookie=*admitted->cookie; return result; }
            if (*type==MessageType::initiation) return receive_initiation(std::move(*admitted->admitted),source,now);
        }
        switch (*type) {
        case MessageType::initiation: return failure(EndpointError::protocol,Error::invalid_state);
        case MessageType::response: return receive_response(wire,source,now);
        case MessageType::transport: return receive_transport(wire,source,now,source_policy);
        case MessageType::cookie: return receive_cookie(wire,source,now);
        }
        return failure(EndpointError::protocol,Error::invalid_type);
    }
    auto Endpoint::receive_relay(std::span<const std::uint8_t> wire,Clock::time_point now,SourcePolicyView source_policy)
        -> std::expected<EndpointReceived,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        if (!config_.relay_only || !source_policy.enabled() || !source_policy.current()) return failure(EndpointError::source);
        prune(now);
        auto type=message_type(wire); if (!type) return failure(EndpointError::protocol,type.error());
        switch (*type) {
        case MessageType::initiation: {
            auto admitted=AdmittedHandshake::authenticate(admission_.local_public(),wire);
            if (!admitted) return failure(EndpointError::protocol,admitted.error());
            return receive_initiation(std::move(*admitted),std::nullopt,now);
        }
        case MessageType::response: return receive_response(wire,std::nullopt,now);
        case MessageType::transport: return receive_transport(wire,std::nullopt,now,source_policy);
        case MessageType::cookie: break;
        }
        return failure(EndpointError::protocol,Error::invalid_type);
    }
    auto Endpoint::receive_initiation(AdmittedHandshake admitted,std::optional<EndpointAddress> source,Clock::time_point now)
        -> std::expected<EndpointReceived,EndpointFailure> {
        auto opened=OpenedInitiation::open(*identity_,admission_.local_public(),std::move(admitted)); if (!opened) return failure(EndpointError::protocol,opened.error());
        return receive_opened(std::move(*opened),source,now);
    }
    auto Endpoint::receive_selected(SelectedInitiation selected,PeerKeyView peers,Clock::time_point now,SourcePolicyView source_policy)
        -> std::expected<EndpointReceived,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        if (!source_policy.matches_peer(selected.peer())) return failure(EndpointError::disallowed_source);
        auto state=selected.take(peers); if (!state) return failure(EndpointError::stale_attempt);
        if (config_.relay_only || !valid_address(state->source)) return failure(EndpointError::source);
        prune(now); return receive_opened(std::move(state->opened),state->source,now);
    }
    auto Endpoint::receive_opened(OpenedInitiation opened,std::optional<EndpointAddress> source,Clock::time_point now)
        -> std::expected<EndpointReceived,EndpointFailure> {
        if (!opened.valid()) return failure(EndpointError::protocol,Error::invalid_state);
        if (!crypto::constant_time_equal(opened.local_public(),admission_.local_public()) || !crypto::constant_time_equal(opened.remote_public(),config_.peer_public))
            return failure(EndpointError::protocol,Error::authentication);
        auto handshake=Handshake::create(*identity_,config_.peer_public,psk_.view());
        if (!handshake) return failure(EndpointError::protocol,handshake.error());
        auto accepted=handshake->consume_opened(std::move(opened),timestamps_,now); if (!accepted) return failure(EndpointError::protocol,accepted.error());
        auto request=issue(HandshakeReason::response,AttemptPhase::response_requested,now); if (!request) return std::unexpected(request.error());
        attempt_->handshake.emplace(std::move(*handshake)); attempt_->source=source;
        clear_cookie_challenge();
        auto changed=config_.peer!=source;
        config_.peer=source; note_received(false,false,now); window_.reset(); manual_=false;
        EndpointReceived result; if (!sending_) result.handshake=*request; result.peer_changed=changed; return result;
    }
    auto Endpoint::receive_response(std::span<std::uint8_t const> wire,std::optional<EndpointAddress> source,Clock::time_point now)
        -> std::expected<EndpointReceived,EndpointFailure> {
        if (!attempt_ || attempt_->phase!=AttemptPhase::initiation_sent || !attempt_->handshake || !attempt_->index || attempt_->request.ticket!=latest_)
            return failure(EndpointError::stale_attempt);
        if (window_ && now-*window_>=std::chrono::seconds(90)) return failure(EndpointError::stale_attempt);
        auto response=parse_response(wire); if (!response) return failure(EndpointError::protocol,response.error());
        auto index=std::ranges::find_if(indexes_,[&](auto const& value) { return value.used && value.value==response->receiver && value.ticket==latest_; });
        if (index==indexes_.end() || response->receiver!=*attempt_->index) return failure(EndpointError::stale_attempt);
        auto accepted=attempt_->handshake->consume_response(wire); if (!accepted) return failure(EndpointError::protocol,accepted.error());
        auto session=attempt_->handshake->finish(now); if (!session) return failure(EndpointError::protocol,session.error());
        auto local=*attempt_->index;
        auto ticket=attempt_->request.ticket;
        install_current(std::move(*session),local,ticket,now); clear_attempt(false);
        clear_cookie_challenge();
        auto changed=config_.peer!=source;
        config_.peer=source; note_received(false,false,now);
        EndpointReceived result; result.peer_changed=changed; return result;
    }
    auto Endpoint::receive_transport(std::span<std::uint8_t const> wire,std::optional<EndpointAddress> source,Clock::time_point now,SourcePolicyView const& source_policy)
        -> std::expected<EndpointReceived,EndpointFailure> {
        auto transport=parse_transport(wire); if (!transport) return failure(EndpointError::protocol,transport.error());
        Generation* generation=nullptr;
        bool is_pending=false;
        for (auto* item:{&current_,&previous_,&pending_}) if (*item && (*item)->index==transport->receiver) {
            generation=&**item; is_pending=item==&pending_; break;
        }
        if (!generation || (is_pending && generation->ticket!=latest_)) return failure(EndpointError::no_key);
        auto owned=std::ranges::any_of(indexes_,[&](auto const& index) { return index.used && index.value==generation->index && index.ticket==generation->ticket; });
        if (!owned) return failure(EndpointError::no_key);
        auto plaintext=generation->session.open(wire,now); if (!plaintext) return failure(EndpointError::protocol,plaintext.error());
        detail::Erase erase{*plaintext};
        bool keepalive=plaintext->empty();
        if (!keepalive) {
            auto packet=parse_inner_packet(*plaintext); if (!packet) return std::unexpected(packet.error());
            if (!allowed(*packet,true)) return failure(EndpointError::disallowed_source);
            if (!source_policy.permits(packet->family,std::span(packet->source).first(packet->family==4 ? 4 : 16))) return failure(EndpointError::disallowed_source);
            crypto::cleanse(std::span(*plaintext).subspan(packet->packet.size())); plaintext->resize(packet->packet.size());
        }
        auto rekey=current_ && generation==&*current_ && generation->session.receive_rekey_due(now);
        if (is_pending) promote_pending();
        auto changed=config_.peer!=source;
        config_.peer=source; note_received(!keepalive,rekey,now);
        EndpointReceived result; result.packet=std::move(*plaintext); result.keepalive=keepalive;
        result.peer_changed=changed; result.key_confirmed=is_pending; return result;
    }
}
