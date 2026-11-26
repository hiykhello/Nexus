export module tls.client_hello_driver;
export import tls.client_handshake;
export import tls.server_hello_stream;
export import tls.client_hello_exchange;
export import quic.ech_config;
import quic.ech_client;
import functional;
import std;
export namespace tls {
    struct ClientHelloDriverFeed { std::size_t consumed=0; std::optional<crypto::Bytes> outbound; bool server_hello=false; };
    namespace detail {
        template<class> inline constexpr bool nullable_callable=false;
        template<class Signature> inline constexpr bool nullable_callable<functional::move_only_function<Signature>> = true;
        template<class Signature> inline constexpr bool nullable_callable<functional::copyable_function<Signature>> = true;
    }
    // Holds a small, nothrow movable policy until ServerHello. Releasing it
    // creates the usual CertificateVerifier at the original handshake stage;
    // large or over-aligned policies use that verifier as their early storage.
    class PendingCertificateVerifier {
    public:
        static constexpr std::size_t inline_capacity=64;
        template<class T> static constexpr bool stores_inline =
            sizeof(T)<=inline_capacity && alignof(T)<=alignof(std::max_align_t) &&
            std::is_nothrow_move_constructible_v<T>;
    private:
        struct Operations {
            CertificateVerifier (*release)(void*);
            void (*destroy)(void*) noexcept;
            void (*move)(void*,void*) noexcept;
        };
        alignas(std::max_align_t) std::byte storage_[inline_capacity];
        Operations const* operations_=nullptr;
        template<class T> using Holder=std::conditional_t<stores_inline<T>,T,CertificateVerifier>;
        template<class T> static auto object(void* p) noexcept -> T* {
            return std::launder(reinterpret_cast<T*>(p));
        }
        template<class T> static auto release(void* p) -> CertificateVerifier {
            return CertificateVerifier(std::move(*object<Holder<T>>(p)));
        }
        template<class T> static void destroy(void* p) noexcept { std::destroy_at(object<Holder<T>>(p)); }
        template<class T> static void move(void* to,void* from) noexcept {
            std::construct_at(reinterpret_cast<Holder<T>*>(to),std::move(*object<Holder<T>>(from)));
            std::destroy_at(object<Holder<T>>(from));
        }
        template<class T> inline static constexpr Operations operations{release<T>,destroy<T>,move<T>};
        void reset() noexcept {
            if (operations_) { operations_->destroy(storage_); operations_=nullptr; }
        }
    public:
        PendingCertificateVerifier() noexcept = default;
        PendingCertificateVerifier(std::nullptr_t) noexcept {}
        PendingCertificateVerifier(PendingCertificateVerifier const&)=delete;
        auto operator=(PendingCertificateVerifier const&) -> PendingCertificateVerifier& = delete;
        PendingCertificateVerifier(PendingCertificateVerifier&& other) noexcept : operations_(std::exchange(other.operations_,nullptr)) {
            if (operations_) operations_->move(storage_,other.storage_);
        }
        auto operator=(PendingCertificateVerifier&& other) noexcept -> PendingCertificateVerifier& {
            if (this!=&other) {
                reset(); operations_=std::exchange(other.operations_,nullptr);
                if (operations_) operations_->move(storage_,other.storage_);
            }
            return *this;
        }
        template<class F,class T=std::decay_t<F>>
            requires (!std::same_as<T,PendingCertificateVerifier> && std::is_constructible_v<CertificateVerifier,F>)
        PendingCertificateVerifier(F&& f) {
            if constexpr (std::is_pointer_v<T> || std::is_member_pointer_v<T> || detail::nullable_callable<T>)
                if (f==nullptr) return;
            std::construct_at(reinterpret_cast<Holder<T>*>(storage_),std::forward<F>(f));
            operations_=&operations<T>;
        }
        template<class F> requires std::is_constructible_v<PendingCertificateVerifier,F>
        auto operator=(F&& f) -> PendingCertificateVerifier& {
            *this=PendingCertificateVerifier(std::forward<F>(f)); return *this;
        }
        auto operator=(std::nullptr_t) noexcept -> PendingCertificateVerifier& { reset(); return *this; }
        ~PendingCertificateVerifier() { reset(); }
        explicit operator bool() const noexcept { return operations_!=nullptr; }
        [[nodiscard]] auto release() -> CertificateVerifier {
            if (!operations_) return {};
            auto result=operations_->release(storage_); reset(); return result;
        }
    };
    struct ClientHelloAuthentication {
        std::array<std::uint8_t,32> session_id{};
        std::size_t session_id_size=0;
        PendingCertificateVerifier verifier;
    };
    // Owns ephemeral keys and exact Hello bytes. The template must have a key_share extension.
    class ClientHelloDriver {
        ClientHelloExchange exchange_;
        PendingCertificateVerifier verifier_;
        bool authenticated_=false;
        ServerHelloStream stream_;
        std::unique_ptr<quic::EchClient> ech_;
        std::optional<crypto::Bytes> initial_outer_;
        static auto record(std::span<std::uint8_t const> wire,std::uint8_t version) -> std::expected<crypto::Bytes,ClientHelloDriverError> {
            if (wire.size()>16384)return std::unexpected(ClientHelloDriverError::invalid_hello);
            crypto::Bytes result{22,3,version,static_cast<std::uint8_t>(wire.size()>>8),static_cast<std::uint8_t>(wire.size())};
            result.insert(result.end(),wire.begin(),wire.end());return result;
        }
        ClientHelloDriver(ClientHelloExchange&& exchange,ServerHelloStream&& stream,
            std::unique_ptr<quic::EchClient> ech={},std::optional<crypto::Bytes> initial_outer={}) noexcept;
    public:
        ClientHelloDriver(ClientHelloDriver const&)=delete;
        auto operator=(ClientHelloDriver const&) -> ClientHelloDriver& = delete;
        ClientHelloDriver(ClientHelloDriver&&) noexcept;
        auto operator=(ClientHelloDriver&&) noexcept -> ClientHelloDriver&;
        // initial_group is 0 for an empty key_share; otherwise an implemented X25519, ML-KEM or NIST group.
        [[nodiscard]] static auto create(ClientHello hello, std::uint16_t initial_group) -> std::expected<ClientHelloDriver,ClientHelloDriverError>;
        [[nodiscard]] static auto create_ech(ClientHello hello, std::span<std::uint16_t const> groups,
            quic::EchConfig const& ech) -> std::expected<ClientHelloDriver,ClientHelloDriverError>;
        // Called once before sending, with the exact first Hello and the private
        // X25519 key matching its standalone share if offered, otherwise the
        // X25519 component of the hybrid share. Only the session ID can be replaced. The
        // verifier is mandatory and retries retain that ID and verifier.
        template<class Authenticator>
        [[nodiscard]] auto authenticate_first(Authenticator&& authenticator) -> std::expected<void,ClientHelloDriverError> {
            if (!exchange_.can_start() || authenticated_ || ech_) return std::unexpected(ClientHelloDriverError::invalid_state);
            auto* key=exchange_.initial_key();
            if (!key) { exchange_.cancel(); return std::unexpected(ClientHelloDriverError::invalid_hello); }
            try {
                auto result=std::forward<Authenticator>(authenticator)(exchange_.initial(),*key);
                if (!result || !result->verifier || result->session_id_size!=exchange_.first_hello().session_id.size()) {
                    exchange_.cancel(); return std::unexpected(result ? ClientHelloDriverError::invalid_hello : result.error());
                }
                auto changed=exchange_.replace_session_id(std::span(result->session_id).first(result->session_id_size));
                if (!changed) return std::unexpected(changed.error());
                verifier_=std::move(result->verifier); authenticated_=true; return {};
            } catch (...) { exchange_.cancel(); throw; }
        }
        [[nodiscard]] auto uses_authentication() const noexcept -> bool { return authenticated_; }
        [[nodiscard]] auto can_start_authenticated() const noexcept -> bool { return exchange_.can_start() && authenticated_; }
        [[nodiscard]] auto take_authenticated_handshake() -> std::expected<ClientHandshake,ClientHelloDriverError>;
        [[nodiscard]] auto replace_session_id(std::span<std::uint8_t const> id) -> std::expected<void,ClientHelloDriverError> {
            if (ech_) return std::unexpected(ClientHelloDriverError::invalid_state);
            return exchange_.replace_session_id(id);
        }
        [[nodiscard]] auto initial_record() const -> std::expected<crypto::Bytes,ClientHelloDriverError>;
        [[nodiscard]] auto initial_sent() -> std::expected<void,ClientHelloDriverError>;
        // Send outbound fully before calling retry_sent; input after consumed remains with caller.
        [[nodiscard]] auto retry_sent() -> std::expected<void,ClientHelloDriverError>;
        template<class... Recovery>
        static inline auto create(ClientHello hello,std::span<std::uint16_t const> groups,Recovery&... recovery) -> std::expected<ClientHelloDriver,ClientHelloDriverError>{
        using Policy=RecoveryPolicy<Recovery...>;
        auto exchange=ClientHelloExchange::create(std::move(hello),groups,HandshakeTransport::tcp,recovery...);
        if (!exchange) return std::unexpected(exchange.error());
        if (exchange->initial().size()>16384) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto stream=ServerHelloStream::create(); if (!stream) return std::unexpected(ClientHelloDriverError::crypto_error);
        return ClientHelloDriver(std::move(*exchange),std::move(*stream));
        }
        template<class... Recovery>
        inline auto feed(std::span<std::uint8_t const> input,Recovery&... recovery) -> std::expected<ClientHelloDriverFeed,ClientHelloDriverError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (!exchange_.can_receive()) return std::unexpected(ClientHelloDriverError::invalid_state);
        try {
            auto parsed=stream_.feed(input); if (!parsed) { exchange_.cancel(); ech_.reset(); return std::unexpected(ClientHelloDriverError::invalid_record); }
            ClientHelloDriverFeed result{parsed->consumed,{},false}; if (!parsed->message) return result;
            if (ech_) {
                auto transcript=exchange_.hello_transcript();
                auto accepted=quic::verify_ech_acceptance(transcript.first,*parsed->message,transcript.retry,transcript.second);
                if (!accepted) {
                    exchange_.cancel(); ech_.reset();
                    return std::unexpected(accepted.error()==quic::EchHandshakeError::crypto
                        ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_hello);
                }
            }
            auto received=exchange_.receive(*parsed->message,recovery...); if (!received) { ech_.reset(); return std::unexpected(received.error()); }
            if (received->server_hello) { ech_.reset(); result.server_hello=true; return result; }
            if (ech_) {
                auto sealed=ech_->seal(exchange_.current_hello(),true);
                if (!sealed) {
                    exchange_.cancel(); ech_.reset();
                    return std::unexpected(sealed.error()==quic::EchHandshakeError::crypto
                        ? ClientHelloDriverError::crypto_error : ClientHelloDriverError::invalid_hello);
                }
                auto outbound=record(*sealed,3);
                if (!outbound) { exchange_.cancel(); ech_.reset(); return std::unexpected(outbound.error()); }
                result.outbound=std::move(*outbound); return result;
            }
            auto outbound=record(received->outbound,3); if (!outbound) { exchange_.cancel(); return std::unexpected(outbound.error()); }
            result.outbound=std::move(*outbound); return result;
        } catch (...) { exchange_.cancel(); ech_.reset(); throw; }
        }
        template<class... Recovery>
        inline auto take_handshake(std::span<std::span<std::uint8_t const> const> anchors,PeerNameKind kind,std::span<std::uint8_t const> name,std::int64_t time,Recovery&... recovery) -> std::expected<ClientHandshake,ClientHelloDriverError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (!exchange_.ready()) return std::unexpected(ClientHelloDriverError::invalid_state);
        if (authenticated_) { exchange_.cancel(); verifier_=nullptr; return std::unexpected(ClientHelloDriverError::invalid_state); }
        auto raw=exchange_.take_flight(recovery...); if (!raw) return std::unexpected(raw.error());
        auto flight=ClientFlight::from_raw(std::move(*raw)); if (!flight) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto handshake=ClientHandshake::create_from_flight(std::move(*flight),anchors,kind,name,time);
        if (!handshake) return std::unexpected(ClientHelloDriverError::invalid_hello);
        return std::move(*handshake);
        }
        auto cancel() noexcept -> void {exchange_.cancel();verifier_=nullptr;authenticated_=false;ech_.reset();initial_outer_.reset();}
    };
}
