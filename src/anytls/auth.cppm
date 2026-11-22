export module anytls.auth;
import std;
import anytls;
import anytls.padding;
import crypto;
import rulefile;
import platform.linux_random;

export namespace anytls {
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
        auto view() const noexcept -> std::span<std::uint8_t const,32> { return bytes_; }
        static auto from_password(std::span<std::uint8_t const> password) -> std::expected<PasswordKey,std::string> {
            if (password.empty() || password.size()>4096) return std::unexpected("invalid AnyTLS password length");
            auto hash=crypto::digest(crypto::Hash::sha256,password);
            if (!hash || hash->size()!=32) return std::unexpected("cannot derive AnyTLS password key");
            PasswordKey result;
            std::ranges::copy(*hash,result.bytes_.begin()); crypto::cleanse(*hash); return result;
        }
        static auto load(std::string_view path) -> std::expected<PasswordKey,std::string> {
            auto secret=rulefile::read_private_file(path);
            if (!secret) return std::unexpected("AnyTLS password file: "+secret.error());
            auto bytes=secret->bytes();
            if (!bytes.empty() && bytes.back()=='\n') bytes=bytes.first(bytes.size()-1);
            return from_password({reinterpret_cast<std::uint8_t const*>(bytes.data()),bytes.size()});
        }
    };
    inline auto authenticate(std::span<PasswordKey const> users,std::span<std::uint8_t const> key) noexcept -> std::optional<std::size_t> {
        if (key.size()!=32) return {};
        std::optional<std::size_t> found;
        for (std::size_t i=0;i<users.size();++i) if (crypto::constant_time_equal(users[i].view(),key)) found=i;
        return found;
    }
    inline auto padding_fingerprint(PaddingScheme const& scheme) -> std::expected<std::string,crypto::Error> {
        auto raw=scheme.raw();
        auto digest=crypto::md5_fingerprint({reinterpret_cast<std::uint8_t const*>(raw.data()),raw.size()});
        if (!digest) return std::unexpected(digest.error());
        constexpr std::string_view hex="0123456789abcdef";
        std::string output(32,'0');
        for (std::size_t i=0;i<digest->size();++i) { output[i*2]=hex[(*digest)[i]>>4]; output[i*2+1]=hex[(*digest)[i]&15]; }
        return output;
    }
    inline auto random_padding(PaddingStep step) -> std::expected<std::uint32_t,std::error_code> {
        if (step.check || !step.min || step.max<step.min || step.max>max_padding_size)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (step.min==step.max) return step.min;
        for (;;) {
            std::uint32_t sample;
            auto random=platform::secure_random(std::as_writable_bytes(std::span(&sample,1)));
            if (!random) return std::unexpected(random.error());
            if (auto length=sample_padding(step,sample)) return *length;
        }
    }
}
