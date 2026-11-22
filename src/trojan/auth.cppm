export module trojan.auth;
import std;
import trojan;
import crypto;
import rulefile;

export namespace trojan {
    // A password hash is a reusable authentication secret. Retain it only in
    // the immutable profile and erase it on moves and destruction.
    class PasswordKey {
        Key bytes_{};
    public:
        PasswordKey()=default;
        ~PasswordKey() { crypto::cleanse(bytes_); }
        PasswordKey(PasswordKey const&)=delete;
        auto operator=(PasswordKey const&) -> PasswordKey& = delete;
        PasswordKey(PasswordKey&& other) noexcept : bytes_(other.bytes_) { crypto::cleanse(other.bytes_); }
        auto operator=(PasswordKey&& other) noexcept -> PasswordKey& {
            if (this!=&other) { crypto::cleanse(bytes_); bytes_=other.bytes_; crypto::cleanse(other.bytes_); } return *this;
        }
        auto view() const noexcept -> std::span<std::uint8_t const,56> { return bytes_; }
        static auto from_password(std::span<std::uint8_t const> password) -> std::expected<PasswordKey,std::string> {
            if (password.empty() || password.size()>4096) return std::unexpected("invalid Trojan password length");
            auto hash=crypto::digest(crypto::Hash::sha224,password);
            if (!hash || hash->size()!=28) return std::unexpected("cannot derive Trojan password key");
            PasswordKey result;
            constexpr std::string_view hex="0123456789abcdef";
            for (std::size_t i=0;i<hash->size();++i) {
                result.bytes_[2*i]=static_cast<std::uint8_t>(hex[(*hash)[i]>>4]);
                result.bytes_[2*i+1]=static_cast<std::uint8_t>(hex[(*hash)[i]&15]);
            }
            crypto::cleanse(*hash); return result;
        }
        static auto load(std::string_view path) -> std::expected<PasswordKey,std::string> {
            auto secret=rulefile::read_private_file(path);
            if (!secret) return std::unexpected("Trojan password file: "+secret.error());
            auto bytes=secret->bytes();
            if (!bytes.empty() && bytes.back()=='\n') bytes=bytes.first(bytes.size()-1);
            return from_password({reinterpret_cast<std::uint8_t const*>(bytes.data()),bytes.size()});
        }
    };
    inline auto authenticate(std::span<PasswordKey const> users,std::span<std::uint8_t const> key) noexcept -> std::optional<std::size_t> {
        if (key.size()!=56) return {};
        std::optional<std::size_t> found;
        for (std::size_t i=0;i<users.size();++i) if (crypto::constant_time_equal(users[i].view(),key)) found=i;
        return found;
    }
}
