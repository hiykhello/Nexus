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

    // Flat open-addressing hash table for O(1), zero-allocation, constant-time Trojan authentication.
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
            if (users.empty() || users.size() > 65535u) return std::unexpected("invalid Trojan users");
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
                        return std::unexpected("duplicate Trojan password");
                    slot = (slot + 1) & mask;
                }
                out.buckets_[slot] = static_cast<std::uint32_t>(i);
            }
            out.users_ = std::move(users);
            return out;
        }
        [[nodiscard]] auto authenticate(std::span<std::uint8_t const> key) const noexcept -> std::optional<std::size_t> {
            if (key.size() != 56 || buckets_.empty()) return std::nullopt;
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
        [[nodiscard]] auto users() const noexcept -> std::span<PasswordKey const> { return users_; }
    };
}
