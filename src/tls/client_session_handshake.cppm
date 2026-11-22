export module tls.client_session_handshake;
export import tls.client_hello_driver;
export import tls.hello_config;
import std;
export namespace tls {
    enum class ClientSessionHandshakeError { invalid_state, invalid_configuration, protocol_error, authentication_failed, crypto_error, record_overflow, illegal_parameter, bad_certificate };
    struct ClientTlsConfig {
        ClientHello hello;
        std::vector<crypto::Bytes> trust_anchors;
        crypto::Bytes peer_name;
        PeerNameKind peer_name_kind=PeerNameKind::dns;
        std::int64_t verification_time=0;
        std::uint16_t initial_group=0;
    };
    struct ClientSessionHandshakeFeed { std::size_t consumed=0; std::optional<crypto::Bytes> outbound; };
    // Socket-free handshake. The caller writes each outbound record in full and acknowledges it.
    class ClientSessionHandshake {
        enum class State { initial, hello, retry_write, encrypted, finished_write, complete, failed } state_=State::initial;
        ClientHelloDriver hello_;
        std::optional<ClientHandshake> handshake_;
        std::vector<crypto::Bytes> anchors_;
        crypto::Bytes name_;
        PeerNameKind kind_;
        std::int64_t time_;
        std::vector<std::array<std::uint8_t,32>> pins_;
        ClientSessionHandshake(ClientHelloDriver&& hello, std::vector<crypto::Bytes>&& anchors, crypto::Bytes&& name, PeerNameKind kind, std::int64_t time) noexcept;
    public:
        auto set_certificate_pins(std::span<std::array<std::uint8_t,32> const> pins) -> void { pins_.assign(pins.begin(),pins.end()); }
        ClientSessionHandshake(ClientSessionHandshake const&)=delete;
        auto operator=(ClientSessionHandshake const&) -> ClientSessionHandshake& = delete;
        ClientSessionHandshake(ClientSessionHandshake&&) noexcept;
        auto operator=(ClientSessionHandshake&&) noexcept -> ClientSessionHandshake&;
        [[nodiscard]] static auto create(ClientHello hello, std::uint16_t initial_group,
            std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError>;
        [[nodiscard]] static auto create(ClientTlsConfig config) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError>;
        // The driver must have completed first-Hello authentication and own a
        // verifier. This entry point never falls back to the PKI configuration.
        [[nodiscard]] static auto create_authenticated(ClientHelloDriver&& driver)
            -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError>;
        [[nodiscard]] auto initial_record() const -> std::expected<crypto::Bytes,ClientSessionHandshakeError>;
        [[nodiscard]] auto replace_session_id(std::span<std::uint8_t const> id) -> std::expected<void,ClientSessionHandshakeError> {
            if (state_!=State::initial) return std::unexpected(ClientSessionHandshakeError::invalid_state);
            if (!hello_.replace_session_id(id)) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); }
            return {};
        }
        // Returns at one record boundary or epoch transition. Resubmit the unconsumed suffix.
        // An exception while processing input invalidates the handshake.
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientSessionHandshakeError>;
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const*;
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientSessionHandshakeError>;
        template<class... Recovery>
        static inline auto create(ClientHello hello, std::span<std::uint16_t const> groups, std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time,Recovery&... recovery) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (anchors.empty() || anchors.size()>1024 || name.empty() || name.size()>253 || (kind!=PeerNameKind::dns && kind!=PeerNameKind::ip) || (kind==PeerNameKind::ip && name.size()!=4 && name.size()!=16)) return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        if (kind==PeerNameKind::dns && std::ranges::any_of(name,[](auto c) { return c<=0x20 || c>=0x7f; }))
            return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        std::size_t total=0; std::vector<crypto::Bytes> copies;
        for (auto cert:anchors) { if (cert.empty() || cert.size()>1048576 || cert.size()>4194304-total) return std::unexpected(ClientSessionHandshakeError::invalid_configuration); total+=cert.size(); copies.emplace_back(cert.begin(),cert.end()); }
        auto driver=ClientHelloDriver::create(std::move(hello),groups,recovery...); if (!driver) return std::unexpected(driver.error()==ClientHelloDriverError::crypto_error ? ClientSessionHandshakeError::crypto_error : ClientSessionHandshakeError::invalid_configuration);
        return ClientSessionHandshake(std::move(*driver),std::move(copies),crypto::Bytes(name.begin(),name.end()),kind,time);
        }
        template<class... Recovery>
        inline auto sent(Recovery&... recovery) -> std::expected<void,ClientSessionHandshakeError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_==State::initial) { if (!hello_.initial_sent()) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); } state_=State::hello; return {}; }
        if (state_==State::retry_write) { if (!hello_.retry_sent()) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); } state_=State::hello; return {}; }
        if (state_==State::finished_write) { if constexpr(Policy::enabled) {auto done=recovery_policy(recovery...).finished_sent();if (!done) {state_=State::failed;return std::unexpected(ClientSessionHandshakeError::crypto_error);}}
            state_=State::complete; return {}; }
        return std::unexpected(ClientSessionHandshakeError::invalid_state);
        }
        template<class... Recovery>
        inline auto feed(std::span<std::uint8_t const> input,Recovery&... recovery) -> std::expected<ClientSessionHandshakeFeed,ClientSessionHandshakeError>{
        using Policy=RecoveryPolicy<Recovery...>;
        try {
        if (state_==State::hello) {
            auto result=hello_.feed(input,recovery...); if (!result) { state_=State::failed; return std::unexpected(result.error()==ClientHelloDriverError::crypto_error ? ClientSessionHandshakeError::crypto_error : ClientSessionHandshakeError::protocol_error); }
            ClientSessionHandshakeFeed out{result->consumed,std::move(result->outbound)};
            if (out.outbound) state_=State::retry_write;
            if (result->server_hello) {
                std::vector<std::span<std::uint8_t const>> anchors; for (auto const& a:anchors_) anchors.emplace_back(a);
                auto handshake=hello_.uses_authentication() ? hello_.take_authenticated_handshake() : hello_.take_handshake(anchors,kind_,name_,time_,recovery...); if (!handshake) { state_=State::failed; return std::unexpected(handshake.error()==ClientHelloDriverError::crypto_error ? ClientSessionHandshakeError::crypto_error : ClientSessionHandshakeError::protocol_error); }
                handshake->set_certificate_pins(pins_);
                handshake_=std::move(*handshake); state_=State::encrypted;
            }
            return out;
        }
        if (state_==State::encrypted) {
            auto result=handshake_->feed(input,recovery...); if (!result) { state_=State::failed; return std::unexpected(result.error()==ClientHandshakeError::record_overflow ? ClientSessionHandshakeError::record_overflow : result.error()==ClientHandshakeError::illegal_parameter ? ClientSessionHandshakeError::illegal_parameter : result.error()==ClientHandshakeError::bad_certificate ? ClientSessionHandshakeError::bad_certificate : result.error()==ClientHandshakeError::crypto_error ? ClientSessionHandshakeError::crypto_error : result.error()==ClientHandshakeError::authentication_failed ? ClientSessionHandshakeError::authentication_failed : ClientSessionHandshakeError::protocol_error); }
            ClientSessionHandshakeFeed out{result->consumed,std::move(result->client_finished_record)}; if (out.outbound) state_=State::finished_write; return out;
        }
        return std::unexpected(ClientSessionHandshakeError::invalid_state);
        } catch (...) { state_=State::failed; handshake_.reset(); throw; }
        }
        [[nodiscard]] auto take_overflow_alert() -> std::expected<crypto::Bytes,ClientSessionHandshakeError> {
            if (state_!=State::failed || !handshake_) return std::unexpected(ClientSessionHandshakeError::invalid_state);
            auto record=handshake_->take_overflow_alert();
            if (!record) return std::unexpected(ClientSessionHandshakeError::crypto_error);
            return std::move(*record);
        }
        auto abort() noexcept -> void {state_=State::failed;hello_.cancel();handshake_.reset();}
    };
}
