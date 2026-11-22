module tls.client_hello_exchange;
import tls.handshake;
import tls.hello_config;
import std;

namespace tls {

    ClientHelloExchange::ClientHelloExchange(ClientHello&& hello,crypto::Bytes&& wire,HandshakeTransport transport)
        : transport_(transport),first_(std::move(hello)),current_(first_),first_wire_(std::move(wire)),current_wire_(first_wire_) {}
    ClientHelloExchange::ClientHelloExchange(ClientHelloExchange&& other) noexcept
        : state_(other.state_),transport_(other.transport_),first_(std::move(other.first_)),current_(std::move(other.current_)),first_wire_(std::move(other.first_wire_)),current_wire_(std::move(other.current_wire_)),retry_wire_(std::move(other.retry_wire_)),server_wire_(std::move(other.server_wire_)),x_(std::move(other.x_)),hybrid_(std::move(other.hybrid_)),ec_(std::move(other.ec_)) { other.state_=State::failed; }
    auto ClientHelloExchange::operator=(ClientHelloExchange&& other) noexcept -> ClientHelloExchange& {
        if (this!=&other) { state_=other.state_; transport_=other.transport_; first_=std::move(other.first_); current_=std::move(other.current_); first_wire_=std::move(other.first_wire_); current_wire_=std::move(other.current_wire_); retry_wire_=std::move(other.retry_wire_); server_wire_=std::move(other.server_wire_); x_=std::move(other.x_); hybrid_=std::move(other.hybrid_); ec_=std::move(other.ec_); other.state_=State::failed; } return *this;
    }
    auto ClientHelloExchange::can_start() const noexcept -> bool { return state_==State::initial; }
    auto ClientHelloExchange::can_receive() const noexcept -> bool { return state_==State::first || state_==State::final; }
    auto ClientHelloExchange::awaiting_retry_output() const noexcept -> bool { return state_==State::sending_retry; }
    auto ClientHelloExchange::ready() const noexcept -> bool { return state_==State::ready; }
    auto ClientHelloExchange::first_hello() const noexcept -> ClientHello const& { return first_; }
    auto ClientHelloExchange::current_hello() const noexcept -> ClientHello const& { return current_; }
    auto ClientHelloExchange::initial() const noexcept -> std::span<std::uint8_t const> { return can_start() ? std::span(first_wire_) : std::span<std::uint8_t const>{}; }
    auto ClientHelloExchange::hello_transcript() const noexcept -> HelloTranscript {
        return {first_wire_, retry_wire_, retry_wire_.empty() ? std::span<const std::uint8_t>{} : std::span(current_wire_)};
    }
    auto ClientHelloExchange::initial_key() const noexcept -> crypto::X25519Private const* { return can_start() ? (x_ ? &*x_ : hybrid_ ? hybrid_->x25519_key() : nullptr) : nullptr; }
    auto ClientHelloExchange::cancel() noexcept -> void { state_=State::failed; x_.reset(); hybrid_.reset(); ec_.clear(); }
    auto ClientHelloExchange::make_share(std::uint16_t group) -> std::expected<KeyShareEntry,ClientHelloDriverError> {
        if (group==0x001d) {
            auto key=crypto::X25519Private::generate(); if (!key) return std::unexpected(ClientHelloDriverError::crypto_error);
            auto share=key->public_key(); if (!share) return std::unexpected(ClientHelloDriverError::crypto_error);
            x_.emplace(std::move(*key)); return KeyShareEntry{group,{share->begin(),share->end()}};
        }
        if (group==x25519_mlkem768_group) {
            auto key=HybridClient::generate(); if (!key) return std::unexpected(ClientHelloDriverError::crypto_error);
            auto share=key->share(); if (!share) return std::unexpected(ClientHelloDriverError::crypto_error);
            hybrid_.emplace(std::move(*key)); return KeyShareEntry{group,{share->begin(),share->end()}};
        }
        if (crypto::nist_curve(group) && ec_.size()<ec_.capacity()) {
            auto key=crypto::EcPrivate::generate(group); if (!key) return std::unexpected(ClientHelloDriverError::crypto_error);
            auto share=key->public_key(); if (!share) return std::unexpected(ClientHelloDriverError::crypto_error);
            ec_.push_back(std::move(*key)); auto bytes=share->view(); return KeyShareEntry{group,{bytes.begin(),bytes.end()}};
        }
        return std::unexpected(ClientHelloDriverError::invalid_hello);
    }
    auto ClientHelloExchange::create(ClientHello hello,std::uint16_t group,HandshakeTransport transport) -> std::expected<ClientHelloExchange,ClientHelloDriverError> {
        return create(std::move(hello),group ? std::span<std::uint16_t const>(&group,1) : std::span<std::uint16_t const>{},transport);
    }

    auto ClientHelloExchange::replace_session_id(std::span<std::uint8_t const> id) -> std::expected<void,ClientHelloDriverError> {
        if (!can_start()) return std::unexpected(ClientHelloDriverError::invalid_state);
        if (first_.session_id.size()>32 || id.size()!=first_.session_id.size() || first_wire_.size()<39+id.size() ||
            current_wire_.size()!=first_wire_.size() || first_wire_[38]!=id.size()) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
        std::ranges::copy(id,first_.session_id.begin()); std::ranges::copy(id,current_.session_id.begin());
        std::ranges::copy(id,first_wire_.begin()+39); std::ranges::copy(id,current_wire_.begin()+39); return {};
    }
    auto ClientHelloExchange::initial_sent() -> std::expected<void,ClientHelloDriverError> {
        if (!can_start()) return std::unexpected(ClientHelloDriverError::invalid_state);
        state_=State::first; return {};
    }

    auto ClientHelloExchange::retry_sent() -> std::expected<void,ClientHelloDriverError> {
        if (!awaiting_retry_output()) return std::unexpected(ClientHelloDriverError::invalid_state);
        state_=State::final; return {};
    }

}
