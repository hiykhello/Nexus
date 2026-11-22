module tls.client_session_handshake;
import std;
namespace tls {
    ClientSessionHandshake::ClientSessionHandshake(ClientHelloDriver&& hello, std::vector<crypto::Bytes>&& anchors, crypto::Bytes&& name, PeerNameKind kind, std::int64_t time) noexcept
        : hello_(std::move(hello)), anchors_(std::move(anchors)), name_(std::move(name)), kind_(kind), time_(time) {}
    ClientSessionHandshake::ClientSessionHandshake(ClientSessionHandshake&& o) noexcept : state_(o.state_), hello_(std::move(o.hello_)), handshake_(std::move(o.handshake_)), anchors_(std::move(o.anchors_)), name_(std::move(o.name_)), kind_(o.kind_), time_(o.time_), pins_(std::move(o.pins_)) { o.state_=State::failed; }
    auto ClientSessionHandshake::operator=(ClientSessionHandshake&& o) noexcept -> ClientSessionHandshake& {
        if (this!=&o) { state_=o.state_; hello_=std::move(o.hello_); handshake_=std::move(o.handshake_); anchors_=std::move(o.anchors_); name_=std::move(o.name_); kind_=o.kind_; time_=o.time_;pins_=std::move(o.pins_); o.state_=State::failed; } return *this;
    }
    auto ClientSessionHandshake::create(ClientTlsConfig config) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError> {
        if (config.trust_anchors.empty()) return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        std::vector<std::span<std::uint8_t const>> views; for (auto const& anchor:config.trust_anchors) views.emplace_back(anchor);
        return create(std::move(config.hello),config.initial_group,views,config.peer_name_kind,config.peer_name,config.verification_time);
    }
    auto ClientSessionHandshake::create_authenticated(ClientHelloDriver&& driver)
        -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError> {
        if (!driver.can_start_authenticated()) return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        return ClientSessionHandshake(std::move(driver),{}, {},PeerNameKind::dns,0);
    }
    auto ClientSessionHandshake::create(ClientHello hello, std::uint16_t group, std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError> {
        return create(std::move(hello),group ? std::span<std::uint16_t const>(&group,1) : std::span<std::uint16_t const>{},anchors,kind,name,time);
    }

    auto ClientSessionHandshake::initial_record() const -> std::expected<crypto::Bytes,ClientSessionHandshakeError> {
        if (state_!=State::initial) return std::unexpected(ClientSessionHandshakeError::invalid_state);
        auto out=hello_.initial_record(); if (!out) return std::unexpected(ClientSessionHandshakeError::protocol_error); return std::move(*out);
    }


    auto ClientSessionHandshake::finish_input() -> std::expected<void,ClientSessionHandshakeError> {
        if (state_==State::complete || state_==State::failed) return std::unexpected(ClientSessionHandshakeError::invalid_state);
        state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error);
    }
    auto ClientSessionHandshake::negotiated() const noexcept -> EncryptedExtensions const* { return state_==State::complete && handshake_ ? handshake_->negotiated() : nullptr; }
    auto ClientSessionHandshake::take_application_records() -> std::expected<ApplicationRecords,ClientSessionHandshakeError> {
        if (state_!=State::complete || !handshake_) return std::unexpected(ClientSessionHandshakeError::invalid_state);
        auto records=handshake_->take_application_records(); if (!records) return std::unexpected(ClientSessionHandshakeError::invalid_state); return std::move(*records);
    }
}
