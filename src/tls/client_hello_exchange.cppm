export module tls.client_hello_exchange;
export import tls.raw_client_flight;
export import tls.server_hello;
import tls.handshake;
import tls.hello_config;
import std;
import containers.inplace_vector;

export namespace tls {
    enum class ClientHelloDriverError { invalid_state, invalid_hello, invalid_record, invalid_retry, crypto_error };
    struct HelloExchangeFeed { std::span<std::uint8_t const> outbound; bool server_hello=false; };
    // Owns the exact Hello/HRR transcript and ephemeral keys. This core sees
    // complete raw Handshake messages; transports own reassembly and records.
    class ClientHelloExchange {
        enum class State { initial,first,sending_retry,final,ready,complete,failed } state_=State::initial;
        HandshakeTransport transport_=HandshakeTransport::tcp;
        ClientHello first_,current_;
        crypto::Bytes first_wire_,current_wire_,retry_wire_,server_wire_;
        std::optional<crypto::X25519Private> x_;
        std::optional<HybridClient> hybrid_;
        containers::inplace_vector<crypto::EcPrivate,2> ec_;
        ClientHelloExchange(ClientHello&& hello,crypto::Bytes&& wire,HandshakeTransport transport);
        static auto frame(ClientHello const& hello) -> std::expected<crypto::Bytes,ClientHelloDriverError> {
            auto body=hello.encode();if (!body)return std::unexpected(ClientHelloDriverError::invalid_hello);
            auto wire=HandshakeDecoder::encode(1,*body,65531);if (!wire)return std::unexpected(ClientHelloDriverError::invalid_hello);return std::move(*wire);
        }
        auto make_share(std::uint16_t group) -> std::expected<KeyShareEntry,ClientHelloDriverError>;
    public:
        ClientHelloExchange(ClientHelloExchange const&)=delete;
        auto operator=(ClientHelloExchange const&) -> ClientHelloExchange& = delete;
        ClientHelloExchange(ClientHelloExchange&&) noexcept;
        auto operator=(ClientHelloExchange&&) noexcept -> ClientHelloExchange&;
        [[nodiscard]] static auto create(ClientHello hello,std::uint16_t initial_group,HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<ClientHelloExchange,ClientHelloDriverError>;
        [[nodiscard]] auto initial() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto initial_key() const noexcept -> crypto::X25519Private const*;
        [[nodiscard]] auto first_hello() const noexcept -> ClientHello const&;
        [[nodiscard]] auto current_hello() const noexcept -> ClientHello const&;
        struct HelloTranscript {
            std::span<const std::uint8_t> first, retry, second;
        };
        [[nodiscard]] auto hello_transcript() const noexcept -> HelloTranscript;
        [[nodiscard]] auto can_start() const noexcept -> bool;
        [[nodiscard]] auto can_receive() const noexcept -> bool;
        [[nodiscard]] auto awaiting_retry_output() const noexcept -> bool;
        [[nodiscard]] auto ready() const noexcept -> bool;
        [[nodiscard]] auto replace_session_id(std::span<std::uint8_t const> id) -> std::expected<void,ClientHelloDriverError>;
        [[nodiscard]] auto initial_sent() -> std::expected<void,ClientHelloDriverError>;
        [[nodiscard]] auto retry_sent() -> std::expected<void,ClientHelloDriverError>;
        auto cancel() noexcept -> void;
        template<class... Recovery>
        static inline auto create(ClientHello hello,std::span<std::uint16_t const> initial_groups,HandshakeTransport transport=HandshakeTransport::tcp,Recovery&... recovery) -> std::expected<ClientHelloExchange,ClientHelloDriverError>{
        using Policy=RecoveryPolicy<Recovery...>;
        std::conditional_t<Policy::enabled,std::optional<std::size_t>,NoPsk> padding_target;
        if constexpr(Policy::enabled) {
            if (hello.extension(21)) {auto size=hello.encoding_size();if (!size)return std::unexpected(ClientHelloDriverError::invalid_hello);padding_target=*size;}
            auto prepared=recovery_policy(recovery...).prepare(hello);if (!prepared)return std::unexpected(Policy::local_error(prepared.error()) ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_hello);
        }
        if (!hello.validate_tls13() || (!Policy::enabled && hello.extension(41)) ||
            (hello.extension(42) && (!EarlyDataPolicy<Policy> || transport!=HandshakeTransport::quic)) ||
            hello.extension(44) || !hello.extension(51)) return std::unexpected(ClientHelloDriverError::invalid_hello);
        if (!validate_handshake_transport(hello,transport) || initial_groups.size()>2) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto* groups=hello.extension(10);
        if (!groups || groups->data.size()<4 || ((std::size_t{groups->data[0]}<<8)|groups->data[1])!=groups->data.size()-2 || (groups->data.size()-2)%2) return std::unexpected(ClientHelloDriverError::invalid_hello);
        std::bitset<65536> seen;
        for (std::size_t i=2;i<groups->data.size();i+=2) {
            auto value=static_cast<std::uint16_t>((std::uint16_t{groups->data[i]}<<8)|groups->data[i+1]);
            if ((value!=0x001d && value!=x25519_mlkem768_group && !crypto::nist_curve(value) && !is_grease(value)) || seen.test(value)) return std::unexpected(ClientHelloDriverError::invalid_hello);
            seen.set(value);
        }
        for (std::size_t i=0;i<initial_groups.size();++i) {
            auto value=initial_groups[i];
            if ((value!=0x001d && value!=x25519_mlkem768_group && !crypto::nist_curve(value)) || !seen.test(value) || (i && initial_groups[0]==value)) return std::unexpected(ClientHelloDriverError::invalid_hello);
        }
        auto template_shares=KeyShare::parse_client(hello.extension(51)->data);
        if (!template_shares) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto wire=frame(hello); if (!wire) return std::unexpected(wire.error());
        ClientHelloExchange result(std::move(hello),std::move(*wire),transport);
        std::vector<KeyShareEntry> entries;
        for (auto const& entry:*template_shares) if (is_grease(entry.group)) {
            if (!seen.test(entry.group) || entry.key_exchange.size()!=1) return std::unexpected(ClientHelloDriverError::invalid_hello);
            entries.push_back(entry);
        }
        for (auto group:initial_groups) {
            auto share=result.make_share(group); if (!share) return std::unexpected(share.error()); entries.push_back(std::move(*share));
        }
        // RFC 8446: key_share is an ordered subset of supported_groups.
        auto const& offered=result.first_.extension(10)->data;
        std::size_t position=2;
        for (auto const& entry:entries) {
            while (position<offered.size() && ((std::uint16_t{offered[position]}<<8)|offered[position+1])!=entry.group) position+=2;
            if (position==offered.size()) return std::unexpected(ClientHelloDriverError::invalid_hello);
            position+=2;
        }
        auto encoded=KeyShare::encode_client(entries); if (!encoded) return std::unexpected(ClientHelloDriverError::invalid_hello);
        for (auto& extension:result.first_.extensions) if (extension.type==51) extension.data=std::move(*encoded);
        if constexpr(Policy::enabled) if (padding_target && !repad_client_hello(result.first_,*padding_target)) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto actual=frame(result.first_); if (!actual) return std::unexpected(actual.error());
        if constexpr(Policy::enabled) {auto bound=recovery_policy(recovery...).seal(result.first_,*actual);if (!bound)return std::unexpected(Policy::local_error(bound.error()) ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_hello);}
        result.current_=result.first_; result.first_wire_=std::move(*actual); result.current_wire_=result.first_wire_;
        return result;
        }
        template<class... Recovery>
        inline auto receive(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<HelloExchangeFeed,ClientHelloDriverError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (!can_receive()) return std::unexpected(ClientHelloDriverError::invalid_state);
        try {
            if (message.size()<4 || message[0]!=2 || ((std::size_t{message[1]}<<16)|(std::size_t{message[2]}<<8)|message[3])!=message.size()-4) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
            auto hello=ServerHello::parse(message.subspan(4)); if (!hello) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
            if (!hello->is_retry()) { server_wire_.assign(message.begin(),message.end()); state_=State::ready; return HelloExchangeFeed{{},true}; }
            if (state_==State::final) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_retry); }
            auto selected=hello->template validate_retry_request<Policy::enabled,EarlyDataPolicy<Policy>>(first_); if (!selected) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_retry); }
            std::optional<KeyShareEntry> share;
            if (*selected) { x_.reset(); hybrid_.reset(); ec_.clear(); auto fresh=make_share(**selected); if (!fresh) { cancel(); return std::unexpected(fresh.error()); } share=std::move(*fresh); }
            auto second=hello->template retry_client_hello<Policy::enabled,EarlyDataPolicy<Policy>>(first_,std::move(share)); if (!second) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_retry); }
            if constexpr(Policy::enabled) {auto prepared=recovery_policy(recovery...).retry(*second,hello->cipher_suite);if (!prepared) {cancel();recovery_policy(recovery...).cancel();return std::unexpected(Policy::local_error(prepared.error()) ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_retry);}}
            if (first_.extension(21) && !repad_client_hello(*second,first_wire_.size()-4)) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_retry); }
            auto wire=frame(*second); if (!wire) { cancel(); return std::unexpected(wire.error()); }
            if constexpr(Policy::enabled) {auto bound=recovery_policy(recovery...).seal(*second,*wire,first_wire_,message);if (!bound) {cancel();recovery_policy(recovery...).cancel();return std::unexpected(Policy::local_error(bound.error()) ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_retry);}}
            retry_wire_.assign(message.begin(),message.end()); current_=std::move(*second); current_wire_=std::move(*wire); state_=State::sending_retry;
            return HelloExchangeFeed{current_wire_,false};
        } catch (...) { cancel(); throw; }
        }
        template<class... Recovery>
        inline auto take_flight(Recovery&... recovery) -> std::expected<RawClientFlight,ClientHelloDriverError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (!ready()) return std::unexpected(ClientHelloDriverError::invalid_state);
        state_=State::failed;
        try {
            auto server=ServerHello::parse(std::span(server_wire_).subspan(4)); if (!server) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
            auto share=std::ranges::find(server->extensions,std::uint16_t{51},&Extension::type);
            if (share==server->extensions.end()) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
            auto peer=KeyShare::parse_server(share->data); if (!peer) { cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
            std::optional<RawClientFlight> result;
            auto failure=ClientHelloDriverError::invalid_hello;
            auto retain=[&](auto&& raw) {
                if (raw) result.emplace(std::move(*raw));
                else if (raw.error().kind==ClientFlightError::crypto_error) failure=ClientHelloDriverError::crypto_error;
            };
            if (peer->group==0x001d && x_) {
                auto raw=[&]() {
                    if constexpr(Policy::enabled) return RawClientFlight::create_psk<Policy>(current_wire_,server_wire_,std::move(*x_),retry_wire_.empty() ? std::span<std::uint8_t const>{} : std::span<std::uint8_t const>(first_wire_),retry_wire_,transport_,recovery...);
                    else return retry_wire_.empty() ? RawClientFlight::create_x25519(first_wire_,server_wire_,std::move(*x_),transport_) : RawClientFlight::create_x25519_retry(first_wire_,retry_wire_,current_wire_,server_wire_,std::move(*x_),transport_);
                }();
                retain(std::move(raw));
            } else if (peer->group==x25519_mlkem768_group && hybrid_) {
                auto raw=[&]() {
                    if constexpr(Policy::enabled) return RawClientFlight::create_psk<Policy>(current_wire_,server_wire_,std::move(*hybrid_),retry_wire_.empty() ? std::span<std::uint8_t const>{} : std::span<std::uint8_t const>(first_wire_),retry_wire_,transport_,recovery...);
                    else return retry_wire_.empty() ? RawClientFlight::create_hybrid(first_wire_,server_wire_,std::move(*hybrid_),transport_) : RawClientFlight::create_hybrid_retry(first_wire_,retry_wire_,current_wire_,server_wire_,std::move(*hybrid_),transport_);
                }();
                retain(std::move(raw));
            } else if (crypto::nist_curve(peer->group)) {
                auto key=std::ranges::find(ec_,peer->group,&crypto::EcPrivate::group);
                if (key!=ec_.end()) {
                    auto raw=[&]() {
                    if constexpr(Policy::enabled) return RawClientFlight::create_psk<Policy>(current_wire_,server_wire_,std::move(*key),retry_wire_.empty() ? std::span<std::uint8_t const>{} : std::span<std::uint8_t const>(first_wire_),retry_wire_,transport_,recovery...);
                    else return retry_wire_.empty() ? RawClientFlight::create_ecdh(first_wire_,server_wire_,std::move(*key),transport_) : RawClientFlight::create_ecdh_retry(first_wire_,retry_wire_,current_wire_,server_wire_,std::move(*key),transport_);
                }();
                    retain(std::move(raw));
                }
            }
            x_.reset(); hybrid_.reset(); ec_.clear(); if (!result) return std::unexpected(failure);
            state_=State::complete; return std::move(*result);
        } catch (...) { cancel(); throw; }
        }
    };
}
