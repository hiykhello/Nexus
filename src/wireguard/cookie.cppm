export module wireguard.cookie;
import std;
import crypto;
import wireguard;
import wireguard.crypto;

export namespace wireguard {
    struct CookieSource {
        std::span<std::uint8_t const> address;
        std::uint16_t port;
    };
    namespace detail {
        struct SourceBytes { std::array<std::uint8_t,18> bytes{}; std::size_t size=0; };
        inline auto source_bytes(CookieSource source) noexcept -> std::expected<SourceBytes,Error> {
            if ((source.address.size()!=4 && source.address.size()!=16) || !source.port) return std::unexpected(Error::source);
            SourceBytes result; std::ranges::copy(source.address,result.bytes.begin()); result.size=source.address.size()+2;
            result.bytes[result.size-2]=static_cast<std::uint8_t>(source.port>>8); result.bytes[result.size-1]=static_cast<std::uint8_t>(source.port);
            return result;
        }
    }
    // One checker per local identity/executor. The owner supplies an independent
    // 32-byte cryptographic secret and rotates it every 120s; no clock/RNG/I/O
    // is hidden in this core. MAC1 always precedes cookie work and allocation.
    class CookieChecker {
        SecretKey mac1_,encryption_,secret_;
        Clock::time_point rotated_;
        bool closed_=false;
        CookieChecker(SecretKey mac1,SecretKey encryption,SecretKey secret,Clock::time_point now) noexcept
            : mac1_(std::move(mac1)),encryption_(std::move(encryption)),secret_(std::move(secret)),rotated_(now) {}
        auto active(Clock::time_point now) const noexcept -> bool { return !closed_ && now>=rotated_ && now-rotated_<cookie_refresh_time; }
        auto authenticate(std::span<std::uint8_t const> wire) const noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::invalid_state);
            auto valid=detail::valid_handshake(wire); if (!valid) return valid;
            auto expected=detail::mac(mac1_.view(),wire.first(wire.size()-32)); if (!expected) return std::unexpected(expected.error());
            if (!crypto::constant_time_equal(*expected,wire.subspan(wire.size()-32,16))) return std::unexpected(Error::authentication);
            return {};
        }
    public:
        ~CookieChecker() { close(); }
        CookieChecker(CookieChecker const&)=delete;
        auto operator=(CookieChecker const&) -> CookieChecker& = delete;
        CookieChecker(CookieChecker&& other) noexcept : mac1_(std::move(other.mac1_)),encryption_(std::move(other.encryption_)),
            secret_(std::move(other.secret_)),rotated_(other.rotated_),closed_(other.closed_) { other.close(); }
        auto operator=(CookieChecker&&) -> CookieChecker& = delete;
        static auto create(Key const& local,SecretKey secret,Clock::time_point now) noexcept -> std::expected<CookieChecker,Error> {
            auto mac1=detail::label_key("mac1----",local); if (!mac1) return std::unexpected(mac1.error());
            auto encryption=detail::label_key("cookie--",local); if (!encryption) return std::unexpected(encryption.error());
            return CookieChecker(std::move(*mac1),std::move(*encryption),std::move(secret),now);
        }
        auto close(this CookieChecker& self) noexcept -> void { self.mac1_.clear(); self.encryption_.clear(); self.secret_.clear(); self.closed_=true; }
        auto rotate(SecretKey secret,Clock::time_point now) noexcept -> std::expected<void,Error> {
            if (closed_ || now<rotated_) return std::unexpected(Error::invalid_state);
            secret_=std::move(secret); rotated_=now; return {};
        }
        auto check(std::span<std::uint8_t const> wire,CookieSource source,Clock::time_point now,bool require_cookie) const noexcept
            -> std::expected<void,Error> {
            auto authenticated=authenticate(wire); if (!authenticated) return authenticated;
            if (!require_cookie) return {};
            if (!active(now)) return std::unexpected(Error::expired);
            auto encoded=detail::source_bytes(source); if (!encoded) return std::unexpected(encoded.error());
            Secret<16> cookie;
            auto derived=detail::mac_to(cookie.writable(),secret_.view(),std::span(encoded->bytes).first(encoded->size)); if (!derived) return derived;
            auto expected=detail::mac(cookie.view(),wire.first(wire.size()-16)); if (!expected) return std::unexpected(expected.error());
            if (!crypto::constant_time_equal(*expected,wire.last(16))) return std::unexpected(Error::authentication);
            return {};
        }
        auto reply(std::span<std::uint8_t const> wire,CookieSource source,std::span<std::uint8_t const,24> nonce,Clock::time_point now) const
            -> std::expected<std::array<std::uint8_t,cookie_size>,Error> {
            auto authenticated=authenticate(wire); if (!authenticated) return std::unexpected(authenticated.error());
            if (!active(now)) return std::unexpected(Error::expired);
            auto encoded=detail::source_bytes(source); if (!encoded) return std::unexpected(encoded.error());
            Secret<16> cookie;
            auto derived=detail::mac_to(cookie.writable(),secret_.view(),std::span(encoded->bytes).first(encoded->size)); if (!derived) return std::unexpected(derived.error());
            auto encrypted=crypto::seal(crypto::Aead::xchacha20_poly1305,encryption_.view(),nonce,cookie.view(),wire.subspan(wire.size()-32,16));
            if (!encrypted || encrypted->size()!=32) return std::unexpected(Error::backend);
            CookieReply result; result.receiver=load_le32(wire.subspan<4,4>());
            std::ranges::copy(nonce,result.nonce.begin()); std::ranges::copy(*encrypted,result.encrypted_cookie.begin()); return encode(result);
        }
    };
    // One generator per remote identity. Cookie replies bind one outstanding
    // MAC1/sender index, so forged, unrelated or already consumed replies fail.
    class CookieGenerator {
        SecretKey mac1_,encryption_;
        Secret<16> cookie_;
        std::optional<Clock::time_point> received_;
        std::optional<Clock::time_point> pending_;
        Mac last_mac1_{};
        std::optional<std::uint32_t> sender_;
        bool closed_=false;
        CookieGenerator(SecretKey mac1,SecretKey encryption) noexcept : mac1_(std::move(mac1)),encryption_(std::move(encryption)) {}
    public:
        ~CookieGenerator() { close(); }
        CookieGenerator(CookieGenerator const&)=delete;
        auto operator=(CookieGenerator const&) -> CookieGenerator& = delete;
        CookieGenerator(CookieGenerator&& other) noexcept : mac1_(std::move(other.mac1_)),encryption_(std::move(other.encryption_)),
            cookie_(std::move(other.cookie_)),received_(other.received_),pending_(other.pending_),last_mac1_(other.last_mac1_),sender_(other.sender_),closed_(other.closed_) { other.close(); }
        auto operator=(CookieGenerator&&) -> CookieGenerator& = delete;
        static auto create(Key const& remote) noexcept -> std::expected<CookieGenerator,Error> {
            auto mac1=detail::label_key("mac1----",remote); if (!mac1) return std::unexpected(mac1.error());
            auto encryption=detail::label_key("cookie--",remote); if (!encryption) return std::unexpected(encryption.error());
            return CookieGenerator(std::move(*mac1),std::move(*encryption));
        }
        auto close(this CookieGenerator& self) noexcept -> void {
            self.mac1_.clear(); self.encryption_.clear(); self.cookie_.clear(); crypto::cleanse(self.last_mac1_);
            self.received_.reset(); self.pending_.reset(); self.sender_.reset(); self.closed_=true;
        }
        auto apply(std::span<std::uint8_t> wire,Clock::time_point now) noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::invalid_state);
            auto valid=detail::valid_handshake(wire); if (!valid) return valid;
            auto mac1=detail::mac(mac1_.view(),wire.first(wire.size()-32)); if (!mac1) return std::unexpected(mac1.error());
            std::ranges::copy(*mac1,wire.end()-32); std::fill_n(wire.end()-16,16,0);
            if (received_) {
                if (now<*received_ || now-*received_>=cookie_refresh_time) { received_.reset(); cookie_.clear(); }
                else {
                    auto mac2=detail::mac(cookie_.view(),wire.first(wire.size()-16)); if (!mac2) return std::unexpected(mac2.error());
                    std::ranges::copy(*mac2,wire.end()-16);
                }
            }
            last_mac1_=*mac1; sender_=load_le32(std::span<std::uint8_t const>(wire).subspan<4,4>()); pending_=now; return {};
        }
        auto consume(std::span<std::uint8_t const> wire,Clock::time_point now) -> std::expected<void,Error> {
            if (closed_ || !sender_ || !pending_) return std::unexpected(Error::invalid_state);
            if (now<*pending_ || now-*pending_>=cookie_refresh_time || (received_ && now<*received_)) return std::unexpected(Error::expired);
            auto message=parse_cookie(wire); if (!message) return std::unexpected(message.error());
            if (message->receiver!=*sender_) return std::unexpected(Error::invalid_state);
            auto plaintext=crypto::open(crypto::Aead::xchacha20_poly1305,encryption_.view(),message->nonce,message->encrypted_cookie,last_mac1_);
            if (!plaintext) return std::unexpected(detail::open_error(plaintext.error()));
            if (plaintext->size()!=16) { crypto::cleanse(*plaintext); return std::unexpected(Error::authentication); }
            detail::Erase erase{*plaintext}; std::ranges::copy(*plaintext,cookie_.writable().begin()); received_=now; pending_.reset(); sender_.reset(); return {};
        }
    };
}
