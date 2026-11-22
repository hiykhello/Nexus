module wireguard.endpoint;
import std;
import wireguard;
import wireguard.admission;
import wireguard.crypto;
import wireguard.session;

namespace wireguard {
    namespace {
        auto failure(EndpointError code,std::optional<Error> protocol={}) -> std::unexpected<EndpointFailure> { return std::unexpected(EndpointFailure{code,protocol}); }
        auto after(Clock::time_point now,Clock::duration delay) noexcept -> Clock::time_point {
            return now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        }
    }
    auto Endpoint::poll(Clock::time_point now) -> std::expected<EndpointPoll,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        prune(now);
        EndpointPoll result;
        auto cookie=admission_.poll(now); if (!cookie) return std::unexpected(admission_failure(cookie.error()));
        if (window_ && now-*window_>=std::chrono::seconds(90)) {
            clear_attempt(); sending_.reset(); queue_.clear(); queued_bytes_=0; window_.reset(); manual_=false;
            receipt_owed_=false; send_rekey_=false; receive_rekey_=false; result.gave_up=true;
            if (config_.persistent_keepalive.count()) next_persistent_=after(now,config_.persistent_keepalive);
        }
        if (*cookie && !sending_) { result.cookie=**cookie; return result; }
        auto rate_ready=!last_handshake_ || now-*last_handshake_>=std::chrono::seconds(5);
        if (attempt_) {
            if (attempt_->phase==AttemptPhase::initiation_sent) {
                if (now>=attempt_->retry) {
                    auto request=issue(HandshakeReason::retry,AttemptPhase::initiation_requested,now);
                    if (!request) return std::unexpected(request.error());
                }
            } else if (now>=attempt_->request.expires) {
                auto response=attempt_->phase==AttemptPhase::response_requested;
                clear_attempt();
                if (!response && window_ && rate_ready) {
                    auto request=issue(HandshakeReason::retry,AttemptPhase::initiation_requested,now);
                    if (!request) return std::unexpected(request.error());
                }
            }
            if (attempt_ && attempt_->phase!=AttemptPhase::initiation_sent) {
                if (!sending_) result.handshake=attempt_->request;
                return result;
            }
        }
        auto persistent=config_.persistent_keepalive.count() && now>=next_persistent_;
        auto awaiting=pending_ && now-pending_->born<std::chrono::seconds(15);
        auto no_reply=receipt_owed_ && last_data_sent_ && now-*last_data_sent_>=std::chrono::seconds(15);
        auto time_to_rekey=send_rekey_ || receive_rekey_ || (current_ && !queue_.empty() && current_->session.rekey_due(now));
        auto reason=HandshakeReason::data;
        bool has_path=config_.relay_only || config_.peer.has_value();
        bool needs=manual_;
        if (needs) reason=HandshakeReason::manual;
        else if (!awaiting && (no_reply || time_to_rekey)) { needs=true; reason=HandshakeReason::rekey; }
        else if (!current_ && !awaiting && !queue_.empty()) needs=true;
        else if (!current_ && !awaiting && persistent && has_path) { needs=true; reason=HandshakeReason::persistent_keepalive; }
        if (needs && !attempt_ && rate_ready && !sending_) {
            if (!has_path) return failure(EndpointError::source);
            if (!window_) window_=now;
            auto request=issue(reason,AttemptPhase::initiation_requested,now); if (!request) return std::unexpected(request.error());
            result.handshake=*request; return result;
        }
        if (sending_ || !current_ || !has_path || now<next_send_) return result;
        if (!queue_.empty()) {
            auto datagram=emit_transport(queue_.front().bytes,OutboundKind::data,now);
            if (!datagram) {
                if (datagram.error().protocol==Error::counter_exhausted || datagram.error().protocol==Error::expired) {
                    manual_=true; if (!window_) window_=now;
                    return result;
                }
                return std::unexpected(datagram.error());
            }
            queued_bytes_-=queue_.front().bytes.size(); queue_.pop_front(); result.datagram=std::move(*datagram); return result;
        }
        auto keepalive=keepalive_owed_ && last_data_received_ && now-*last_data_received_>=std::chrono::seconds(10);
        if (confirmation_ || keepalive || persistent) {
            auto datagram=emit_transport({},OutboundKind::keepalive,now); if (!datagram) return std::unexpected(datagram.error());
            result.datagram=std::move(*datagram);
        }
        return result;
    }
}
