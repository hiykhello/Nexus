module quic.packet_keys;
import std;
import crypto;
import crypto.aead_context;
import nexus.thirdparty.boringssl;
import quic.varint;

namespace quic {
    packet_key_detail::EraseBytes::~EraseBytes() { crypto::cleanse(bytes); }
    auto packet_key_detail::expand(crypto::Hash hash,std::span<std::uint8_t const> secret,std::string_view label,std::size_t length)
        -> std::expected<crypto::Bytes,crypto::Error> {
        constexpr std::string_view prefix="tls13 ";
        if (label.size()>249 || length>65535) return std::unexpected(crypto::Error::invalid_length);
        std::array<std::uint8_t,259> info{};
        info[0]=static_cast<std::uint8_t>(length>>8); info[1]=static_cast<std::uint8_t>(length);
        info[2]=static_cast<std::uint8_t>(prefix.size()+label.size());
        std::ranges::copy(prefix,info.begin()+3); std::ranges::copy(label,info.begin()+3+prefix.size());
        auto size=4+prefix.size()+label.size(); // Empty context ends in zero.
        return crypto::hkdf_expand(hash,secret,std::span(info).first(size),length);
    }
    InitialSecrets::InitialSecrets()=default;
    InitialSecrets::~InitialSecrets() { crypto::cleanse(client_); crypto::cleanse(server_); }
    auto InitialSecrets::reset(std::uint32_t version,std::span<std::uint8_t const> destination_id) -> std::expected<void,crypto::Error> {
        if (ready_) return std::unexpected(crypto::Error::invalid_state);
        if (version!=1) return std::unexpected(crypto::Error::unsupported_algorithm);
        constexpr std::array<std::uint8_t,20> salt{0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
        return reset_with_salt(salt,destination_id);
    }
    auto InitialSecrets::reset_v2(std::span<std::uint8_t const> destination_id) -> std::expected<void,crypto::Error> {
        constexpr std::array<std::uint8_t,20> salt{0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
        return reset_with_salt(salt,destination_id);
    }
    auto InitialSecrets::reset_with_salt(std::span<std::uint8_t const> salt,std::span<std::uint8_t const> destination_id) -> std::expected<void,crypto::Error> {
        if (ready_) return std::unexpected(crypto::Error::invalid_state);
        if (destination_id.empty() || destination_id.size()>20) return std::unexpected(crypto::Error::invalid_length);
        auto initial=crypto::hkdf_extract(crypto::Hash::sha256,salt,destination_id);
        if (!initial) return std::unexpected(initial.error());
        packet_key_detail::EraseBytes erase_initial{*initial};
        auto client=packet_key_detail::expand(crypto::Hash::sha256,*initial,"client in",32);
        if (!client) return std::unexpected(client.error());
        packet_key_detail::EraseBytes erase_client{*client};
        auto server=packet_key_detail::expand(crypto::Hash::sha256,*initial,"server in",32);
        if (!server) return std::unexpected(server.error());
        packet_key_detail::EraseBytes erase_server{*server};
        std::ranges::copy(*client,client_.begin()); std::ranges::copy(*server,server_.begin()); ready_=true;
        return {};
    }
    auto InitialSecrets::client() const noexcept -> std::span<std::uint8_t const> { return ready_ ? std::span(client_) : std::span<std::uint8_t const>{}; }
    auto InitialSecrets::server() const noexcept -> std::span<std::uint8_t const> { return ready_ ? std::span(server_) : std::span<std::uint8_t const>{}; }
    auto packet_nonce(std::span<std::uint8_t const,12> iv,std::uint64_t packet) -> std::expected<std::array<std::uint8_t,12>,crypto::Error> {
        if (packet>max_varint) return std::unexpected(crypto::Error::invalid_nonce);
        std::array<std::uint8_t,12> result{};
        std::ranges::copy(iv,result.begin());
        for (unsigned i=0;i<8;++i) result[11-i]^=static_cast<std::uint8_t>(packet>>(8*i));
        return result;
    }
    PacketKeys::PacketKeys()=default;
    PacketKeys::~PacketKeys() { clear(); }
    auto PacketKeys::clear() noexcept -> void {
        aead_.clear();
        crypto::cleanse({reinterpret_cast<std::uint8_t*>(&header_),sizeof(header_)}); crypto::cleanse(iv_); ready_=chacha_=false;
    }
    auto PacketKeys::ready() const noexcept -> bool { return ready_; }
    auto PacketKeys::aead_context() noexcept -> crypto::AeadContext& { return aead_; }
    auto PacketKeys::reset(PacketSuite suite,std::span<std::uint8_t const> secret) -> std::expected<void,crypto::Error> {
        return reset_with_labels(suite,secret,false);
    }
    auto PacketKeys::reset_v2(PacketSuite suite,std::span<std::uint8_t const> secret) -> std::expected<void,crypto::Error> {
        return reset_with_labels(suite,secret,true);
    }
    auto PacketKeys::reset_with_labels(PacketSuite suite,std::span<std::uint8_t const> secret,bool v2) -> std::expected<void,crypto::Error> {
        if (ready_) return std::unexpected(crypto::Error::invalid_state);
        if (suite!=PacketSuite::aes128_gcm_sha256 && suite!=PacketSuite::aes256_gcm_sha384 && suite!=PacketSuite::chacha20_poly1305_sha256)
            return std::unexpected(crypto::Error::unsupported_algorithm);
        bool aes128=suite==PacketSuite::aes128_gcm_sha256;
        auto hash=suite==PacketSuite::aes256_gcm_sha384 ? crypto::Hash::sha384 : crypto::Hash::sha256;
        auto key_bytes=aes128 ? 16u : 32u;
        if (secret.size()!=(suite==PacketSuite::aes256_gcm_sha384 ? 48u : 32u)) return std::unexpected(crypto::Error::invalid_key);
        auto key=packet_key_detail::expand(hash,secret,v2 ? "quicv2 key" : "quic key",key_bytes);
        if (!key) return std::unexpected(key.error());
        packet_key_detail::EraseBytes erase_key{*key};
        auto iv=packet_key_detail::expand(hash,secret,v2 ? "quicv2 iv" : "quic iv",12);
        if (!iv) return std::unexpected(iv.error());
        packet_key_detail::EraseBytes erase_iv{*iv};
        auto hp=packet_key_detail::expand(hash,secret,v2 ? "quicv2 hp" : "quic hp",key_bytes);
        if (!hp) return std::unexpected(hp.error());
        packet_key_detail::EraseBytes erase_hp{*hp};
        auto chacha=suite==PacketSuite::chacha20_poly1305_sha256;
        if (chacha) {
            std::construct_at(&header_.chacha);
            std::ranges::copy(*hp,header_.chacha.begin());
        } else {
            std::construct_at(&header_.aes);
            if (nex::boringssl::AES_set_encrypt_key(hp->data(),static_cast<int>(key_bytes*8),&header_.aes)!=0)
                { clear(); return std::unexpected(crypto::Error::backend_failure); }
        }
        auto algorithm=chacha ? crypto::Aead::chacha20_poly1305 : aes128 ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
        auto installed=aead_.reset(algorithm,*key);
        if (!installed) { clear(); return installed; }
        std::ranges::copy(*iv,iv_.begin()); chacha_=chacha; ready_=true; return {};
    }
    auto PacketKeys::iv() const noexcept -> std::span<std::uint8_t const,12> { return iv_; }
    auto PacketKeys::mask_to(std::span<std::uint8_t,16> output,std::span<std::uint8_t const,16> sample) const noexcept -> std::expected<void,crypto::Error> {
        if (!ready_) return std::unexpected(crypto::Error::invalid_state);
        std::array<std::uint8_t,16> input{}; std::ranges::copy(sample,input.begin());
        if (chacha_) {
            // RFC9001 5.4.4: sample counter is little endian, nonce is the
            // following 12 bytes. Generate the mask from a zero plaintext.
            auto counter=std::uint32_t{input[0]}|(std::uint32_t{input[1]}<<8)|(std::uint32_t{input[2]}<<16)|(std::uint32_t{input[3]}<<24);
            constexpr std::array<std::uint8_t,16> zero{};
            nex::boringssl::CRYPTO_chacha_20(output.data(),zero.data(),output.size(),header_.chacha.data(),input.data()+4,counter);
        } else nex::boringssl::AES_encrypt(input.data(),output.data(),&header_.aes);
        return {};
    }
    auto PacketKeys::seal_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,
        std::span<std::uint8_t const> plaintext,std::span<std::uint8_t const> aad) -> std::expected<std::size_t,crypto::Error> {
        if (!ready_) return std::unexpected(crypto::Error::invalid_state);
        return aead_.seal_to(output,nonce,plaintext,aad);
    }
    auto PacketKeys::open_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,
        std::span<std::uint8_t const> ciphertext,std::span<std::uint8_t const> aad) -> std::expected<std::size_t,crypto::Error> {
        if (!ready_) return std::unexpected(crypto::Error::invalid_state);
        return aead_.open_to(output,nonce,ciphertext,aad);
    }
}
