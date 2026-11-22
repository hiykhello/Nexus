export module hysteria2.credential;
import std;
import crypto;
import hysteria2.auth;

export namespace hysteria2 {
    // Obfuscation passwords are not HTTP header values and do not inherit the
    // authentication credential's header-specific validation.
    class SalamanderKey {
        crypto::Bytes bytes_;
        explicit SalamanderKey(crypto::Bytes&& bytes) noexcept:bytes_(std::move(bytes)) {}
    public:
        SalamanderKey(SalamanderKey const&)=delete;
        auto operator=(SalamanderKey const&) -> SalamanderKey& = delete;
        SalamanderKey(SalamanderKey&& other) noexcept:bytes_(std::move(other.bytes_)) {}
        auto operator=(SalamanderKey&& other) noexcept -> SalamanderKey& {
            if(this!=&other){crypto::cleanse(bytes_);bytes_=std::move(other.bytes_);}return *this;
        }
        ~SalamanderKey(){crypto::cleanse(bytes_);}
        auto bytes() const noexcept -> std::span<std::uint8_t const> {return bytes_;}
        static auto create(std::span<std::uint8_t const> bytes) -> std::expected<SalamanderKey,std::string> {
            if(bytes.empty() || bytes.size()>255)return std::unexpected("invalid Salamander password length");
            return SalamanderKey(crypto::Bytes(bytes.begin(),bytes.end()));
        }
    };
    // An immutable startup profile owns wire credentials. ClientAuthHeaders
    // borrows this storage. Moving or destroying a password erases its previous
    // live bytes; file access belongs to the existing rulefile loader.
    class Password {
        crypto::Bytes bytes_;
        explicit Password(crypto::Bytes&& bytes) noexcept:bytes_(std::move(bytes)){}
    public:
        Password(Password const&)=delete;
        auto operator=(Password const&) -> Password& = delete;
        Password(Password&& other) noexcept:bytes_(std::move(other.bytes_)){}
        auto operator=(Password&& other) noexcept -> Password& {
            if(this!=&other){crypto::cleanse(bytes_);bytes_=std::move(other.bytes_);}return *this;
        }
        ~Password(){crypto::cleanse(bytes_);}
        auto bytes() const noexcept -> std::span<std::uint8_t const> {return bytes_;}
        auto view() const noexcept -> std::string_view {return {reinterpret_cast<char const*>(bytes_.data()),bytes_.size()};}
        static auto create(std::span<std::uint8_t const> bytes) -> std::expected<Password,AuthError> {
            auto view=std::string_view(reinterpret_cast<char const*>(bytes.data()),bytes.size());
            auto checked=ClientAuthHeaders::create(view,0);if(!checked)return std::unexpected(checked.error());
            return Password(crypto::Bytes(bytes.begin(),bytes.end()));
        }
    };
    // The immutable profile validates duplicate credentials before startup.
    // Every configured user is compared; the selected index only borrows its
    // profile's name. No allocation or additional credential copy on auth.
    inline auto authenticate(std::span<Password const> users,std::string_view credential) noexcept -> std::optional<std::size_t> {
        auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(credential.data()),credential.size());
        std::optional<std::size_t> selected;
        for(std::size_t i=0;i<users.size();++i)if(crypto::constant_time_equal(users[i].bytes(),bytes))selected=i;
        return selected;
    }
}
