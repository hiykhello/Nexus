export module snell.kdf;
import std;
extern "C" int nexus_snell_argon2id_hash_raw(std::uint32_t,std::uint32_t,std::uint32_t,void const*,std::size_t,void const*,std::size_t,void*,std::size_t);
export namespace snell {
    class Key {
        std::array<std::uint8_t,16> bytes_{};
        auto clear() noexcept -> void { volatile std::uint8_t* p=bytes_.data();for(std::size_t i=0;i<bytes_.size();++i)p[i]=0; }
    public:
        Key()=default;~Key(){clear();}
        Key(Key const&)=delete;auto operator=(Key const&) -> Key& =delete;
        Key(Key&& other) noexcept:bytes_(other.bytes_){other.clear();}
        auto operator=(Key&& other) noexcept -> Key& {if(this!=&other){clear();bytes_=other.bytes_;other.clear();}return *this;}
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const,16>{return bytes_;}
        // Failure is kept distinct from bad credentials; no silent fallback.
        [[nodiscard]] static auto derive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const,16> salt) -> std::expected<Key,int> {
            if(psk.empty())return std::unexpected(-1);
            std::array<std::uint8_t,32> full{};
            int rc=nexus_snell_argon2id_hash_raw(3,8,1,psk.data(),psk.size(),salt.data(),salt.size(),full.data(),full.size());
            Key key;if(!rc)std::copy_n(full.begin(),16,key.bytes_.begin());
            volatile std::uint8_t* p=full.data();for(std::size_t i=0;i<full.size();++i)p[i]=0;
            if(rc)return std::unexpected(rc);return key;
        }
    };
}
