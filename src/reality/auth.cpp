module reality.auth;
import tls.hello;
import tls.certificate_verify;
import std;
namespace reality {
    namespace {
        auto valid(std::span<std::uint8_t const> h) -> bool {
            return h.size()>=71 && h[0]==1 && h[4]==3 && h[5]==3 && h[38]==32 &&
                   ((std::size_t{h[1]}<<16)|(std::size_t{h[2]}<<8)|h[3])==h.size()-4 &&
                   tls::ClientHello::parse(h.subspan(4)).has_value();
        }
        struct Clean { crypto::Bytes& value; ~Clean() { crypto::cleanse(value); } };
    }
    AuthKey::AuthKey(std::span<std::uint8_t const,32> bytes) noexcept : valid_(true) { std::ranges::copy(bytes,bytes_.begin()); }
    AuthKey::~AuthKey() { crypto::cleanse(bytes_); }
    AuthKey::AuthKey(AuthKey&& other) noexcept : bytes_(other.bytes_), valid_(std::exchange(other.valid_,false)) { crypto::cleanse(other.bytes_); }
    auto AuthKey::operator=(AuthKey&& other) noexcept -> AuthKey& {
        if (this!=&other) { crypto::cleanse(bytes_); bytes_=other.bytes_; valid_=std::exchange(other.valid_,false); crypto::cleanse(other.bytes_); }
        return *this;
    }
    auto AuthKey::view() const noexcept -> std::span<std::uint8_t const> { return valid_ ? std::span<std::uint8_t const>{bytes_} : std::span<std::uint8_t const>{}; }
    auto AuthKey::derive(crypto::X25519Private const& own,std::span<std::uint8_t const> peer,std::span<std::uint8_t const> random)
            -> std::expected<AuthKey,AuthError> {
            if (random.size()!=32) return std::unexpected(AuthError::invalid_hello);
            auto shared=own.agree(peer); if (!shared) return std::unexpected(AuthError::cryptographic_failure);
            auto prk=crypto::hkdf_extract(crypto::Hash::sha256,random.first(20),shared->view());
            if (!prk) return std::unexpected(AuthError::cryptographic_failure);
            Clean cleanup{*prk}; constexpr std::array<std::uint8_t,7> info{'R','E','A','L','I','T','Y'};
            auto result=crypto::hkdf_expand(crypto::Hash::sha256,*prk,info,32);
            if (!result) return std::unexpected(AuthError::cryptographic_failure);
            Clean clean_result{*result};
            return AuthKey(std::span<std::uint8_t const,32>{result->data(),32});
    }
    auto AuthKey::verify_certificate(std::span<std::uint8_t const> der) const -> std::expected<void,AuthError> {
        if (!valid_) return std::unexpected(AuthError::invalid_state);
        auto fields=tls::ed25519_certificate_fields(der);
        if (!fields) return std::unexpected(AuthError::invalid_certificate);
        auto mac=crypto::hmac(crypto::Hash::sha512,bytes_,fields->public_key);
        if (!mac) return std::unexpected(AuthError::cryptographic_failure);
        Clean clean_mac{*mac};
        auto matches=crypto::constant_time_equal(*mac,fields->signature);
        if (!matches) return std::unexpected(AuthError::authentication_failed);
        return {};
    }
    auto seal_client_hello(std::span<std::uint8_t const> hello,crypto::X25519Private const& ephemeral,
                           std::span<std::uint8_t const> server_public,Identity identity) -> std::expected<SealedHello,AuthError> {
        if (!valid(hello)) return std::unexpected(AuthError::invalid_hello);
        crypto::Bytes wire(hello.begin(),hello.end()); std::fill_n(wire.begin()+39,32,0);
        auto random=std::span(wire).subspan(6,32); auto secret=AuthKey::derive(ephemeral,server_public,random);
        if (!secret) return std::unexpected(secret.error());
        std::array<std::uint8_t,16> plain{}; std::copy(identity.version.begin(),identity.version.end(),plain.begin());
        for (unsigned i=0;i<4;++i) plain[4+i]=static_cast<std::uint8_t>(identity.timestamp>>(24-8*i));
        std::copy(identity.short_id.begin(),identity.short_id.end(),plain.begin()+8);
        auto sealed=crypto::seal(crypto::Aead::aes_256_gcm,secret->view(),random.subspan(20,12),plain,wire);
        crypto::cleanse(plain);
        if (!sealed || sealed->size()!=32) return std::unexpected(AuthError::cryptographic_failure);
        std::copy(sealed->begin(),sealed->end(),wire.begin()+39); return SealedHello{std::move(wire),std::move(*secret)};
    }
    auto open_client_hello(std::span<std::uint8_t const> hello,crypto::X25519Private const& server_private,
                           std::span<std::uint8_t const> client_public) -> std::expected<OpenedHello,AuthError> {
        if (!valid(hello)) return std::unexpected(AuthError::invalid_hello);
        crypto::Bytes aad(hello.begin(),hello.end()); std::fill_n(aad.begin()+39,32,0);
        auto random=std::span(aad).subspan(6,32); auto secret=AuthKey::derive(server_private,client_public,random);
        if (!secret) return std::unexpected(secret.error());
        auto plain=crypto::open(crypto::Aead::aes_256_gcm,secret->view(),random.subspan(20,12),hello.subspan(39,32),aad);
        if (!plain) return std::unexpected(AuthError::authentication_failed);
        Clean clean_plain{*plain}; if (plain->size()!=16 || (*plain)[3]) return std::unexpected(AuthError::authentication_failed);
        Identity result; std::copy_n(plain->begin(),3,result.version.begin());
        for (unsigned i=0;i<4;++i) result.timestamp=(result.timestamp<<8)|(*plain)[4+i];
        std::copy_n(plain->begin()+8,8,result.short_id.begin()); return OpenedHello{result,std::move(*secret)};
    }
}
