export module wireguard.crypto;
import std;
import crypto;
import wireguard;
import wireguard.blake2s;

export namespace wireguard {
    using Clock=std::chrono::steady_clock;
    template<std::size_t N>
    class Secret {
        std::array<std::uint8_t,N> bytes_{};
    public:
        Secret()=default;
        explicit Secret(std::span<std::uint8_t const,N> bytes) noexcept { std::ranges::copy(bytes,bytes_.begin()); }
        ~Secret() { clear(); }
        Secret(Secret const&)=delete;
        auto operator=(Secret const&) -> Secret& = delete;
        Secret(Secret&& other) noexcept : bytes_(other.bytes_) { other.clear(); }
        auto operator=(Secret&& other) noexcept -> Secret& {
            if (this!=&other) { clear(); bytes_=other.bytes_; other.clear(); } return *this;
        }
        auto view(this Secret const& self) noexcept -> std::span<std::uint8_t const,N> { return self.bytes_; }
        auto writable(this Secret& self) noexcept -> std::span<std::uint8_t,N> { return self.bytes_; }
        auto clear(this Secret& self) noexcept -> void { crypto::cleanse(self.bytes_); }
    };
    using SecretKey=Secret<32>;
    namespace detail {
        inline auto bytes(std::string_view text) noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()};
        }
        template<class Array> struct Erase { Array& data; ~Erase() { crypto::cleanse(data); } };
        inline auto hash(std::initializer_list<std::span<std::uint8_t const>> parts) noexcept -> std::expected<SecretKey,Error> {
            SecretKey result;
            auto hashed=blake2s::digest_parts_to(result.writable(),parts); if (!hashed) return std::unexpected(Error::backend);
            return result;
        }
        inline auto derive(std::span<std::uint8_t const,32> chain,std::span<std::uint8_t const> data,unsigned count) noexcept
            -> std::expected<std::array<SecretKey,3>,Error> {
            if (!count || count>3) return std::unexpected(Error::invalid_state);
            SecretKey extract;
            auto extracted=blake2s::hmac_to(extract.writable(),chain,{data}); if (!extracted) return std::unexpected(Error::backend);
            std::array<SecretKey,3> output;
            for (unsigned i=0;i<count;++i) {
                std::array<std::uint8_t,1> label{static_cast<std::uint8_t>(i+1)};
                auto previous=i ? std::span<std::uint8_t const>(output[i-1].view()) : std::span<std::uint8_t const>{};
                auto value=blake2s::hmac_to(output[i].writable(),extract.view(),{previous,label}); if (!value) return std::unexpected(Error::backend);
            }
            return output;
        }
        inline auto label_key(std::string_view label,Key const& public_key) noexcept -> std::expected<SecretKey,Error> {
            return hash({bytes(label),public_key});
        }
        inline auto mac(std::span<std::uint8_t const> key,std::span<std::uint8_t const> input) noexcept -> std::expected<Mac,Error> {
            auto result=blake2s::digest<16>(input,key); if (!result) return std::unexpected(Error::backend); return *result;
        }
        inline auto mac_to(std::span<std::uint8_t,16> output,std::span<std::uint8_t const> key,std::span<std::uint8_t const> input) noexcept
            -> std::expected<void,Error> {
            auto result=blake2s::digest_to(output,input,key); if (!result) return std::unexpected(Error::backend); return {};
        }
        inline auto open_error(crypto::Error error) noexcept -> Error {
            return error==crypto::Error::authentication_failed ? Error::authentication : Error::backend;
        }
        inline auto valid_handshake(std::span<std::uint8_t const> wire) noexcept -> std::expected<void,Error> {
            auto type=message_type(wire); if (!type) return std::unexpected(type.error());
            if (*type!=MessageType::initiation && *type!=MessageType::response) return std::unexpected(Error::invalid_type);
            return {};
        }
        inline auto add_macs(std::span<std::uint8_t> wire,Key const& remote,std::span<std::uint8_t const> cookie={}) noexcept
            -> std::expected<void,Error> {
            auto valid=valid_handshake(wire); if (!valid) return valid;
            if (!cookie.empty() && cookie.size()!=16) return std::unexpected(Error::invalid_key);
            auto key=label_key("mac1----",remote); if (!key) return std::unexpected(key.error());
            auto mac1=mac(key->view(),wire.first(wire.size()-32)); if (!mac1) return std::unexpected(mac1.error());
            std::ranges::copy(*mac1,wire.begin()+wire.size()-32); std::fill_n(wire.end()-16,16,0);
            if (!cookie.empty()) {
                auto mac2=mac(cookie,wire.first(wire.size()-16)); if (!mac2) return std::unexpected(mac2.error());
                std::ranges::copy(*mac2,wire.end()-16);
            }
            return {};
        }
        inline auto check_mac1(std::span<std::uint8_t const> wire,Key const& local) noexcept -> std::expected<void,Error> {
            auto valid=valid_handshake(wire); if (!valid) return valid;
            auto key=label_key("mac1----",local); if (!key) return std::unexpected(key.error());
            auto expected=mac(key->view(),wire.first(wire.size()-32)); if (!expected) return std::unexpected(expected.error());
            if (!crypto::constant_time_equal(*expected,wire.subspan(wire.size()-32,16))) return std::unexpected(Error::authentication);
            return {};
        }
        struct Transcript {
            SecretKey chain,hash;
            Transcript()=default;
            Transcript(Transcript&&)=default;
            auto operator=(Transcript&&) -> Transcript& = default;
            auto clone() const noexcept -> Transcript {
                Transcript result; result.chain=SecretKey(chain.view()); result.hash=SecretKey(hash.view()); return result;
            }
            static auto initial(Key const& responder) noexcept -> std::expected<Transcript,Error> {
                auto chain=detail::hash({bytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")}); if (!chain) return std::unexpected(chain.error());
                auto hash=detail::hash({chain->view(),bytes("WireGuard v1 zx2c4 Jason@zx2c4.com")}); if (!hash) return std::unexpected(hash.error());
                auto mixed=detail::hash({hash->view(),responder}); if (!mixed) return std::unexpected(mixed.error());
                Transcript result; result.chain=std::move(*chain); result.hash=std::move(*mixed); return result;
            }
            auto mix_hash(std::span<std::uint8_t const> input) noexcept -> std::expected<void,Error> {
                auto next=detail::hash({hash.view(),input}); if (!next) return std::unexpected(next.error());
                hash=std::move(*next); return {};
            }
            auto mix_key(std::span<std::uint8_t const> input) noexcept -> std::expected<void,Error> {
                auto next=derive(chain.view(),input,1); if (!next) return std::unexpected(next.error());
                chain=std::move((*next)[0]); return {};
            }
            auto mix_key2(std::span<std::uint8_t const> input) noexcept -> std::expected<SecretKey,Error> {
                auto next=derive(chain.view(),input,2); if (!next) return std::unexpected(next.error());
                chain=std::move((*next)[0]); return std::move((*next)[1]);
            }
            auto mix_psk(std::span<std::uint8_t const,32> psk) noexcept -> std::expected<SecretKey,Error> {
                auto next=derive(chain.view(),psk,3); if (!next) return std::unexpected(next.error());
                auto mixed=mix_hash((*next)[1].view()); if (!mixed) return std::unexpected(mixed.error());
                chain=std::move((*next)[0]); return std::move((*next)[2]);
            }
        };
    }
}
