module tls.client_hello_driver;
import std;
namespace tls {

    ClientHelloDriver::ClientHelloDriver(ClientHelloExchange&& exchange,ServerHelloStream&& stream,
        std::unique_ptr<quic::EchClient> ech,std::optional<crypto::Bytes> initial_outer) noexcept
        : exchange_(std::move(exchange)),stream_(std::move(stream)),ech_(std::move(ech)),initial_outer_(std::move(initial_outer)) {}
    ClientHelloDriver::ClientHelloDriver(ClientHelloDriver&& other) noexcept
        : exchange_(std::move(other.exchange_)),verifier_(std::move(other.verifier_)),authenticated_(other.authenticated_),stream_(std::move(other.stream_)),ech_(std::move(other.ech_)),initial_outer_(std::move(other.initial_outer_)) { other.authenticated_=false; }
    auto ClientHelloDriver::operator=(ClientHelloDriver&& other) noexcept -> ClientHelloDriver& {
        if (this!=&other) { exchange_=std::move(other.exchange_); verifier_=std::move(other.verifier_); authenticated_=other.authenticated_; stream_=std::move(other.stream_); ech_=std::move(other.ech_); initial_outer_=std::move(other.initial_outer_); other.authenticated_=false; } return *this;
    }
    auto ClientHelloDriver::create(ClientHello hello,std::uint16_t group) -> std::expected<ClientHelloDriver,ClientHelloDriverError> {
        return create(std::move(hello),group ? std::span<std::uint16_t const>(&group,1) : std::span<std::uint16_t const>{});
    }
    auto ClientHelloDriver::create_ech(ClientHello hello,std::span<std::uint16_t const> groups,quic::EchConfig const& ech) -> std::expected<ClientHelloDriver,ClientHelloDriverError> {
        if (hello.extension(quic::ech_extension)) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto client=quic::EchClient::create(ech);
        if (!client) return std::unexpected(ClientHelloDriverError::crypto_error);
        hello.extensions.push_back({quic::ech_extension,{1}});
        auto exchange=ClientHelloExchange::create(std::move(hello),groups,HandshakeTransport::tcp);
        if (!exchange) return std::unexpected(exchange.error());
        auto outer=client->seal(exchange->first_hello(),false);
        if (!outer) return std::unexpected(outer.error()==quic::EchHandshakeError::crypto ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_hello);
        if (outer->size()>16384) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto stream=ServerHelloStream::create();
        if (!stream) return std::unexpected(ClientHelloDriverError::crypto_error);
        return ClientHelloDriver(std::move(*exchange),std::move(*stream),std::make_unique<quic::EchClient>(std::move(*client)),std::move(*outer));
    }

    auto ClientHelloDriver::initial_record() const -> std::expected<crypto::Bytes,ClientHelloDriverError> {
        if (!exchange_.can_start()) return std::unexpected(ClientHelloDriverError::invalid_state);
        return record(initial_outer_ ? std::span<std::uint8_t const>(*initial_outer_) : exchange_.initial(),1);
    }
    auto ClientHelloDriver::initial_sent() -> std::expected<void,ClientHelloDriverError> {
        auto result=exchange_.initial_sent();
        if (result) initial_outer_.reset();
        return result;
    }

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
