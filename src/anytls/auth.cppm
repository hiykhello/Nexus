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

    // Flat open-addressing hash table for O(1), zero-allocation, constant-time AnyTLS authentication.
    class UserTable {
        static constexpr std::uint32_t kEmpty = 0xffffffffu;
        std::vector<PasswordKey> users_;
        std::vector<std::uint32_t> buckets_;
        std::uint64_t seed_ = 0;

        static auto hash_key(std::span<std::uint8_t const> key, std::uint64_t seed) noexcept -> std::uint64_t {
            std::uint64_t h = seed ^ 0xcbf29ce484222325ULL;
            for (auto b : key) { h ^= b; h *= 0x100000001b3ULL; }
            h ^= h >> 30; h *= 0xbf58476d1ce4e5b9ULL;
            h ^= h >> 27; h *= 0x94d049bb133111ebULL;
            return h ^ (h >> 31);
        }
    public:
        UserTable() = default;
        [[nodiscard]] static auto create(std::vector<PasswordKey> users) -> std::expected<UserTable,std::string> {
            if (users.empty() || users.size() > 65535u) return std::unexpected("invalid AnyTLS users");
            UserTable out;
            std::uint64_t seed = 0x517cc1b727220a95ULL;
            (void)crypto::random_bytes(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&seed), sizeof(seed)));
            std::size_t cap = 4;
            while (cap < users.size() * 2) cap <<= 1;
            out.seed_ = seed;
            out.buckets_.assign(cap, kEmpty);
            std::size_t const mask = cap - 1;
            for (std::size_t i = 0; i < users.size(); ++i) {
                auto slot = static_cast<std::size_t>(hash_key(users[i].view(), seed)) & mask;
                while (out.buckets_[slot] != kEmpty) {
                    if (crypto::constant_time_equal(users[out.buckets_[slot]].view(), users[i].view()))
                        return std::unexpected("duplicate AnyTLS password");
                    slot = (slot + 1) & mask;
                }
                out.buckets_[slot] = static_cast<std::uint32_t>(i);
            }
            out.users_ = std::move(users);
            return out;
        }
        [[nodiscard]] auto authenticate(std::span<std::uint8_t const> key) const noexcept -> std::optional<std::size_t> {
            if (key.size() != 32 || buckets_.empty()) return std::nullopt;
            std::size_t const mask = buckets_.size() - 1;
            auto slot = static_cast<std::size_t>(hash_key(key, seed_)) & mask;
            while (buckets_[slot] != kEmpty) {
                auto const idx = buckets_[slot];
                if (crypto::constant_time_equal(users_[idx].view(), key)) return idx;
                slot = (slot + 1) & mask;
            }
            return std::nullopt;
        }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return users_.size(); }
    };
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
