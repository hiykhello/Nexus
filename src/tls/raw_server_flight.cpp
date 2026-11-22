module tls.raw_server_flight;
import tls.server_hello;
import tls.handshake;
import std;

namespace tls {
    RawServerFlight::RawServerFlight(HandshakeSecrets&& keys) noexcept
        : keys_(FinishedSecrets{keys.hash,std::move(keys.transcript),std::move(keys.client_traffic)}) {}
    RawServerFlight::RawServerFlight(RawServerFlight&& other) noexcept
        : state_(other.state_),keys_(std::move(other.keys_)) { other.state_=State::failed; }
    auto RawServerFlight::operator=(RawServerFlight&& other) noexcept -> RawServerFlight& {
        if (this!=&other) { state_=other.state_; keys_=std::move(other.keys_); other.state_=State::failed; } return *this;
    }
    auto RawServerFlight::cancel() noexcept -> void { state_=State::failed; keys_.reset(); }
    auto RawServerFlight::fail(RawServerError error) noexcept -> std::unexpected<RawServerError> { cancel(); return std::unexpected(error); }
    auto RawServerFlight::complete() const noexcept -> bool { return state_==State::complete; }
    auto RawServerFlight::awaiting_finished() const noexcept -> bool { return state_==State::awaiting_finished; }



}
