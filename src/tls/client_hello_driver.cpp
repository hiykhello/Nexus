module tls.client_hello_driver;
import std;
namespace tls {

    ClientHelloDriver::ClientHelloDriver(ClientHelloExchange&& exchange,ServerHelloStream&& stream) noexcept
        : exchange_(std::move(exchange)),stream_(std::move(stream)) {}
    ClientHelloDriver::ClientHelloDriver(ClientHelloDriver&& other) noexcept
        : exchange_(std::move(other.exchange_)),verifier_(std::move(other.verifier_)),authenticated_(other.authenticated_),stream_(std::move(other.stream_)) { other.authenticated_=false; }
    auto ClientHelloDriver::operator=(ClientHelloDriver&& other) noexcept -> ClientHelloDriver& {
        if (this!=&other) { exchange_=std::move(other.exchange_); verifier_=std::move(other.verifier_); authenticated_=other.authenticated_; stream_=std::move(other.stream_); other.authenticated_=false; } return *this;
    }
    auto ClientHelloDriver::create(ClientHello hello,std::uint16_t group) -> std::expected<ClientHelloDriver,ClientHelloDriverError> {
        return create(std::move(hello),group ? std::span<std::uint16_t const>(&group,1) : std::span<std::uint16_t const>{});
    }

    auto ClientHelloDriver::initial_record() const -> std::expected<crypto::Bytes,ClientHelloDriverError> {
        if (!exchange_.can_start()) return std::unexpected(ClientHelloDriverError::invalid_state);
        return record(exchange_.initial(),1);
    }
    auto ClientHelloDriver::initial_sent() -> std::expected<void,ClientHelloDriverError> { return exchange_.initial_sent(); }

    auto ClientHelloDriver::retry_sent() -> std::expected<void,ClientHelloDriverError> {
        if (!exchange_.awaiting_retry_output()) return std::unexpected(ClientHelloDriverError::invalid_state);
        if (!stream_.resume_retry()) { exchange_.cancel(); return std::unexpected(ClientHelloDriverError::invalid_state); }
        return exchange_.retry_sent();
    }

    auto ClientHelloDriver::take_authenticated_handshake() -> std::expected<ClientHandshake,ClientHelloDriverError> {
        if (!exchange_.ready() || !authenticated_ || !verifier_) return std::unexpected(ClientHelloDriverError::invalid_state);
        auto pending=std::move(verifier_);
        auto raw=exchange_.take_flight(); if (!raw) return std::unexpected(raw.error());
        auto flight=ClientFlight::from_raw(std::move(*raw)); if (!flight) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto handshake=ClientHandshake::create_from_flight_with_verifier(std::move(*flight),pending.release());
        if (!handshake) return std::unexpected(ClientHelloDriverError::invalid_hello);
        return std::move(*handshake);
    }
}
