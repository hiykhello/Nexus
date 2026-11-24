module tls.tls12_client;
import std;
import containers.inplace_vector;
import crypto.ecdh;
import tls.hello_config;
import tls.server_hello;
import tls.tls12_schedule;
import tls.tls12_peer_auth;
import tls.certificate_trust;

namespace tls {
    namespace {
        using Error=Tls12ClientError;
        constexpr std::size_t handshake_limit=4194300;
        constexpr std::array<std::uint16_t,4> groups{29,23,24,25};
        constexpr std::array<std::uint16_t,9> signatures{
            0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0401,0x0501,0x0601
        };
        auto u16(std::span<std::uint8_t const> bytes,std::size_t offset) -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{bytes[offset]}<<8)|bytes[offset+1]);
        }
        auto u24(std::span<std::uint8_t const> bytes,std::size_t offset) -> std::size_t {
            return (std::size_t{bytes[offset]}<<16)|(std::size_t{bytes[offset+1]}<<8)|bytes[offset+2];
        }
        auto check_alpn(std::span<std::uint8_t const> offered,std::span<std::uint8_t const> response)
            -> std::optional<crypto::Bytes> {
            if (response.size()<4 || u16(response,0)!=response.size()-2 || response[2]!=response.size()-3) return {};
            for (std::size_t offset=2;offset<offered.size();) {
                auto size=offered[offset++];
                auto protocol=offered.subspan(offset,size);
                if (std::ranges::equal(protocol,response.subspan(3))) return crypto::Bytes(protocol.begin(),protocol.end());
                offset+=size;
            }
            return {};
        }
    }

    auto Tls12Client::hello(std::span<std::uint8_t const> body) -> std::expected<void,Tls12ClientError> {
        auto hello=ServerHello::parse(body);
        if (!hello || hello->legacy_version!=0x0303 || hello->compression_method || hello->is_retry())
            return std::unexpected(Error::protocol);
        constexpr std::array<std::uint8_t,8> downgrade{'D','O','W','N','G','R','D',1};
        auto sentinel=std::span(hello->random).last<8>();
        if (!std::ranges::contains(offer_.cipher_suites,hello->cipher_suite) ||
            (offer_.extension(43) && std::ranges::equal(sentinel.first<7>(),std::span(downgrade).first<7>()) && sentinel[7]<=1))
            return std::unexpected(Error::protocol);
        switch (hello->cipher_suite) {
        case 0xcca8:
        case 0xcca9:
            cipher_=crypto::Aead::chacha20_poly1305;
            ecdsa_=hello->cipher_suite==0xcca9;
            break;
        case 0xc02b: ecdsa_=true; break;
        case 0xc02f: break;
        case 0xc02c:
        case 0xc030:
            ecdsa_=hello->cipher_suite==0xc02c;
            hash_=crypto::Hash::sha384;
            cipher_=crypto::Aead::aes_256_gcm;
            break;
        default: return std::unexpected(Error::protocol);
        }
        bool extended_master=false,renegotiation_info=false;
        for (auto const& extension:hello->extensions) {
            auto const& data=extension.data;
            switch (extension.type) {
            case 0:
                if (!data.empty() || !offer_.extension(0)) return std::unexpected(Error::protocol);
                negotiated_.server_name_acknowledged=true; break;
            case 11:
                if (data.size()<2 || data[0]!=data.size()-1 || !std::ranges::contains(std::span(data).subspan(1),0))
                    return std::unexpected(Error::protocol);
                break;
            case 16: {
                auto offered=offer_.extension(16);
                if (!offered) return std::unexpected(Error::protocol);
                negotiated_.alpn=check_alpn(offered->data,data);
                if (!negotiated_.alpn) return std::unexpected(Error::protocol);
                break;
            }
            case 5:
                if (!offer_.extension(5) || !data.empty()) return std::unexpected(Error::protocol);
                status_expected_=true;
                break;
            case 18:
                if (!offer_.extension(18) || data.size()<4 || u16(data,0)!=data.size()-2)
                    return std::unexpected(Error::protocol);
                break;
            case 28: {
                auto* offer=offer_.extension(28);
                if (!offer || offer->data.size()!=2 || u16(offer->data,0)<64 ||
                    data.size()!=2 || u16(data,0)<64 || u16(data,0)>16385)
                    return std::unexpected(Error::protocol);
                read_limit_=std::min<std::uint16_t>(16384,u16(offer->data,0));
                negotiated_.peer_record_size_limit=u16(data,0);
                break;
            }
            case 35:
                if (!offer_.extension(35) || !data.empty()) return std::unexpected(Error::protocol);
                ticket_expected_=true;
                break;
            case 23:
                if (!data.empty()) return std::unexpected(Error::protocol);
                extended_master=true; break;
            case 0xff01:
                if (data.size()!=1 || data[0]) return std::unexpected(Error::protocol);
                renegotiation_info=true; break;
            default: return std::unexpected(Error::protocol);
            }
        }
        if (!extended_master || !renegotiation_info) return std::unexpected(Error::protocol);
        auto transcript=Transcript::create(hash_);
        auto client=initial_record();
        if (!transcript || !client || !transcript->append(std::span(*client).subspan(5)))
            return std::unexpected(Error::crypto);
        transcript_.emplace(std::move(*transcript));
        server_random_=hello->random;
        state_=State::certificate;
        return {};
    }

    auto Tls12Client::certificate(std::span<std::uint8_t const> body) -> std::expected<void,Tls12ClientError> {
        if (body.size()<7 || u24(body,0)!=body.size()-3) return std::unexpected(Error::protocol);
        containers::inplace_vector<std::span<std::uint8_t const>,16> chain;
        for (std::size_t offset=3;offset<body.size();) {
            if (body.size()-offset<3 || chain.size()==chain.capacity()) return std::unexpected(Error::protocol);
            auto length=u24(body,offset);
            offset+=3;
            if (!length || length>body.size()-offset) return std::unexpected(Error::protocol);
            chain.push_back(body.subspan(offset,length));
            offset+=length;
        }
        std::vector<std::span<std::uint8_t const>> anchors;
        anchors.reserve(anchors_.size());
        for (auto const& anchor:anchors_) anchors.emplace_back(anchor);
        auto trusted=verify_server_certificate_chain(chain,anchors,kind_,name_,verification_time_,pins_);
        if (!trusted) return std::unexpected(trusted.error()==CertificateTrustError::crypto_error ? Error::crypto : Error::authentication);
        leaf_.assign(chain.front().begin(),chain.front().end());
        anchors_.clear();
        state_=State::key_exchange;
        return {};
    }

    auto Tls12Client::key_exchange(std::span<std::uint8_t const> body) -> std::expected<void,Tls12ClientError> {
        if (body.size()<8 || body[0]!=3) return std::unexpected(Error::protocol);
        auto group=u16(body,1);
        auto curve=crypto::nist_curve(group);
        if (group!=29 && !curve) return std::unexpected(Error::protocol);
        auto public_size=curve ? curve->public_size() : 32;
        auto params_size=4+public_size;
        if (body[3]!=public_size || body.size()<=params_size+4 ||
            u16(body,params_size+2)!=body.size()-params_size-4)
            return std::unexpected(Error::protocol);
        auto scheme=u16(body,params_size);
        auto* offered=offer_.extension(13);
        if (!offered || !std::ranges::contains(signatures,scheme)) return std::unexpected(Error::protocol);
        bool offered_signature=false;
        for (std::size_t i=2;i+1<offered->data.size();i+=2) offered_signature|=u16(offered->data,i)==scheme;
        auto* supported=offer_.extension(10);
        bool offered_group=false;
        if (supported)
            for (std::size_t i=2;i+1<supported->data.size();i+=2) offered_group|=u16(supported->data,i)==group;
        if (!offered_signature || !offered_group || status_expected_) return std::unexpected(Error::protocol);
        std::array<std::uint8_t,68+133> buffer;
        auto signed_data=std::span(buffer).first(64+params_size);
        std::ranges::copy(offer_.random,signed_data.begin());
        std::ranges::copy(server_random_,signed_data.begin()+32);
        std::ranges::copy(body.first(params_size),signed_data.begin()+64);
        auto verified=verify_tls12_key_signature(leaf_,scheme,ecdsa_,body.subspan(params_size+4),signed_data);
        if (!verified) return std::unexpected(verified.error()==CertificateTrustError::crypto_error ? Error::crypto : Error::authentication);
        group_=group;
        server_public_size_=body[3];
        std::ranges::copy(body.subspan(4,public_size),server_public_.begin());
        leaf_.clear();
        state_=State::hello_done;
        return {};
    }

}
