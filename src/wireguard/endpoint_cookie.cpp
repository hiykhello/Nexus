module wireguard.endpoint;
import std;
import crypto;
import wireguard;
import wireguard.admission;
import wireguard.cookie;
import wireguard.crypto;

namespace wireguard {
    namespace {
        auto failure(EndpointError code,std::optional<Error> protocol={}) -> std::unexpected<EndpointFailure> { return std::unexpected(EndpointFailure{code,protocol}); }
    }
    auto Endpoint::clear_cookie_challenge() noexcept -> void {
        if (sending_ && sending_->kind==OutboundKind::cookie) sending_.reset();
        admission_.cancel();
    }
    auto Endpoint::admission_failure(admission::Failure error) noexcept -> EndpointFailure {
        using Code=admission::ErrorCode;
        auto code=error.code==Code::closed ? EndpointError::closed : error.code==Code::clock ? EndpointError::clock : error.code==Code::source ? EndpointError::source :
            error.code==Code::cookie_secret ? EndpointError::cookie_secret : error.code==Code::stale_request ? EndpointError::stale_attempt : EndpointError::protocol;
        return {code,error.protocol};
    }
    auto Endpoint::rotate_cookie_secret(SecretKey secret,Clock::time_point now) -> std::expected<void,EndpointFailure> {
        auto checked=observe(now); if (!checked) return checked;
        auto rotated=admission_.rotate_secret(std::move(secret),now); if (!rotated) return std::unexpected(admission_failure(rotated.error()));
        clear_cookie_challenge();
        return {};
    }
    auto Endpoint::apply_cookie(std::span<std::uint8_t> wire,std::uint64_t ticket,EndpointAddress destination,Clock::time_point now)
        -> std::expected<void,EndpointFailure> {
        if (!cookie_generator_) {
            auto generator=CookieGenerator::create(config_.peer_public); if (!generator) return failure(EndpointError::protocol,generator.error());
            cookie_generator_.emplace(std::move(*generator));
        }
        auto applied=cookie_generator_->apply(wire,now); if (!applied) return failure(EndpointError::protocol,applied.error());
        cookie_binding_=CookieBinding{ticket,load_le32(std::span<std::uint8_t const>(wire).subspan<4,4>()),destination};
        return {};
    }
    auto Endpoint::admit_handshake(std::span<std::uint8_t const> wire,EndpointAddress source,Clock::time_point now,bool require_cookie)
        -> std::expected<admission::Decision,EndpointFailure> {
        auto admitted=admission_.admit(wire,source,true,now,require_cookie); if (!admitted) return std::unexpected(admission_failure(admitted.error()));
        if (admitted->cookie && sending_ && sending_->kind==OutboundKind::cookie) sending_.reset();
        return std::move(*admitted);
    }
    auto Endpoint::respond_cookie(CookieRequest request,std::span<std::uint8_t const,24> nonce,Clock::time_point now)
        -> std::expected<EndpointDatagram,EndpointFailure> {
        auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
        if (sending_) return failure(EndpointError::not_due);
        std::vector<std::uint8_t> bytes(cookie_size);
        auto reply=admission_.respond(request,nonce,now); if (!reply) return std::unexpected(admission_failure(reply.error()));
        std::ranges::copy(reply->bytes,bytes.begin());
        return output(std::move(bytes),OutboundKind::cookie,request.ticket,reply->destination);
    }
    auto Endpoint::receive_cookie(std::span<std::uint8_t const> wire,EndpointAddress source,Clock::time_point now)
        -> std::expected<EndpointReceived,EndpointFailure> {
        if (!cookie_generator_ || !cookie_binding_ || cookie_binding_->destination!=source) return failure(EndpointError::stale_attempt);
        auto message=parse_cookie(wire); if (!message) return failure(EndpointError::protocol,message.error());
        auto const binding=*cookie_binding_;
        if (binding.ticket!=latest_ || message->receiver!=binding.sender) return failure(EndpointError::stale_attempt);
        auto initiating=attempt_ && attempt_->phase==AttemptPhase::initiation_sent && attempt_->request.ticket==binding.ticket && attempt_->index==binding.sender;
        auto responding=pending_ && pending_->ticket==binding.ticket && pending_->index==binding.sender;
        auto owned=std::ranges::any_of(indexes_,[&](auto const& index) { return index.used && index.ticket==binding.ticket && index.value==binding.sender; });
        if ((!initiating && !responding) || !owned) return failure(EndpointError::stale_attempt);
        auto consumed=cookie_generator_->consume(wire,now); if (!consumed) return failure(EndpointError::protocol,consumed.error());
        cookie_binding_.reset();
        EndpointReceived result; result.cookie_consumed=true; return result;
    }
}
