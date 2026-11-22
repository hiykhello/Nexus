module tls.tls12_client;
import std;
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
        auto plain_record(std::uint8_t type,std::span<std::uint8_t const> body) -> crypto::Bytes {
            crypto::Bytes result{type,3,3,static_cast<std::uint8_t>(body.size()>>8),static_cast<std::uint8_t>(body.size())};
            result.insert(result.end(),body.begin(),body.end());
            return result;
        }
    }

    Tls12Client::Tls12Client(ClientHello&& offer,std::vector<crypto::Bytes> anchors,crypto::Bytes name,
        PeerNameKind kind,std::int64_t time,HandshakeDecoder&& messages)
        : offer_(std::move(offer)),anchors_(std::move(anchors)),name_(std::move(name)),kind_(kind),
          verification_time_(time),messages_(std::move(messages)) {}

    auto Tls12Client::create(std::optional<std::string_view> server_name,std::span<std::string_view const> alpn,
        std::vector<crypto::Bytes> anchors,crypto::Bytes name,PeerNameKind kind,std::int64_t time)
        -> std::expected<Tls12Client,Tls12ClientError> {
        auto hello=make_client_hello(server_name,alpn,groups);
        if (!hello || anchors.empty() || name.empty()) return std::unexpected(Error::protocol);
        hello->cipher_suites={0xc02b,0xc02f,0xc02c,0xc030,0x00ff};
        std::erase_if(hello->extensions,[](Extension const& ext) {return ext.type==43 || ext.type==51;});
        for (auto& extension:hello->extensions) if (extension.type==13) {
            extension.data={0,static_cast<std::uint8_t>(2*signatures.size())};
            for (auto signature:signatures) {
                extension.data.push_back(static_cast<std::uint8_t>(signature>>8));
                extension.data.push_back(static_cast<std::uint8_t>(signature));
            }
        }
        hello->extensions.push_back({11,{1,0}});
        hello->extensions.push_back({23,{}});
        return from_offer(std::move(*hello),std::move(anchors),std::move(name),kind,time);
    }

    auto Tls12Client::from_offer(ClientHello offer,std::vector<crypto::Bytes> anchors,crypto::Bytes name,
        PeerNameKind kind,std::int64_t time) -> std::expected<Tls12Client,Tls12ClientError> {
        if (anchors.empty() || name.empty()) return std::unexpected(Error::protocol);
        auto decoder=HandshakeDecoder::create(handshake_limit);
        if (!decoder) return std::unexpected(Error::protocol);
        return Tls12Client(std::move(offer),std::move(anchors),std::move(name),kind,time,std::move(*decoder));
    }

    auto Tls12Client::initial_record() const -> std::expected<crypto::Bytes,Tls12ClientError> {
        auto body=offer_.encode(16380);
        if (!body) return std::unexpected(Error::protocol);
        auto wire=HandshakeDecoder::encode(1,*body,16380);
        if (!wire) return std::unexpected(Error::protocol);
        return plain_record(22,*wire);
    }

    auto Tls12Client::client_flight() -> std::expected<crypto::Bytes,Tls12ClientError> {
        std::optional<crypto::Secret32> x25519;
        std::optional<crypto::EcSecret> ec;
        std::array<std::uint8_t,134> key_body;
        auto server=std::span(server_public_).first(server_public_size_);
        auto generate=[&](auto key,auto& secret) -> std::expected<void,Error> {
            if (!key) return std::unexpected(Error::crypto);
            auto shared=key->agree(server);
            if (!shared) return std::unexpected(shared.error()==crypto::Error::invalid_peer ? Error::protocol : Error::crypto);
            auto public_key=key->public_key();
            if (!public_key) return std::unexpected(Error::crypto);
            auto bytes=[&]() -> std::span<std::uint8_t const> {
                if constexpr (requires { public_key->view(); }) return public_key->view();
                else return *public_key;
            }();
            key_body[0]=static_cast<std::uint8_t>(bytes.size());
            std::ranges::copy(bytes,key_body.begin()+1);
            secret.emplace(std::move(*shared));
            return {};
        };
        auto generated=group_==29 ? generate(crypto::X25519Private::generate(),x25519) :
            generate(crypto::EcPrivate::generate(group_),ec);
        if (!generated) return std::unexpected(generated.error());
        auto exchange=HandshakeDecoder::encode(16,std::span(key_body).first(1+key_body[0]),key_body.size());
        if (!exchange || !transcript_->append(*exchange)) return std::unexpected(Error::crypto);
        auto session_hash=transcript_->snapshot();
        if (!session_hash) return std::unexpected(Error::crypto);
        std::size_t key_size=cipher_==crypto::Aead::aes_128_gcm ? 16 : 32;
        std::size_t iv_size=cipher_==crypto::Aead::chacha20_poly1305 ? 12 : 4;
        std::span<std::uint8_t const> shared=x25519 ? std::span<std::uint8_t const>(x25519->view()) : ec->view();
        auto keys=tls12_keys(hash_,shared,offer_.random,server_random_,*session_hash,key_size,iv_size);
        if (!keys) return std::unexpected(Error::crypto);
        auto block=keys->key_block.view();
        auto write=RecordLayer::create_tls12(RecordDirection::send,cipher_,block.first(key_size),block.subspan(2*key_size,iv_size));
        auto read=RecordLayer::create_tls12(RecordDirection::receive,cipher_,block.subspan(key_size,key_size),block.last(iv_size));
        auto verify=tls12_finished(hash_,keys->master,false,*session_hash);
        if (!write || !read || !verify) return std::unexpected(Error::crypto);
        auto finished=HandshakeDecoder::encode(20,verify->view(),12);
        if (!finished || !transcript_->append(*finished)) return std::unexpected(Error::crypto);
        auto sealed=write->seal(ContentType::handshake,*finished);
        if (!sealed) return std::unexpected(Error::crypto);
        auto peer_limit=std::min<std::size_t>(16384,negotiated_.peer_record_size_limit.value_or(16384));
        crypto::Bytes flight;
        for (auto bytes=std::span(*exchange);!bytes.empty();) {
            auto part=bytes.first(std::min(peer_limit,bytes.size()));
            flight.append_range(plain_record(22,part));
            bytes=bytes.subspan(part.size());
        }
        flight.insert(flight.end(),{20,3,3,0,1,1});
        flight.insert(flight.end(),sealed->begin(),sealed->end());
        master_.emplace(std::move(keys->master));
        write_.emplace(std::move(*write));
        read_.emplace(std::move(*read));
        state_=State::change_cipher;
        return flight;
    }

    auto Tls12Client::server_finished(std::span<std::uint8_t const> body) -> std::expected<void,Tls12ClientError> {
        auto hash=transcript_->snapshot();
        if (!hash) return std::unexpected(Error::crypto);
        auto expected=tls12_finished(hash_,*master_,true,*hash);
        if (!expected) return std::unexpected(Error::crypto);
        if (!crypto::constant_time_equal(expected->view(),body)) return std::unexpected(Error::authentication);
        master_.reset();
        transcript_.reset();
        state_=State::complete;
        return {};
    }

    auto Tls12Client::process(HandshakeMessage const& message) -> std::expected<crypto::Bytes,Tls12ClientError> {
        std::expected<void,Error> accepted;
        if (state_==State::hello && message.type==2) accepted=hello(message.body);
        else if (state_==State::certificate && message.type==11) accepted=certificate(message.body);
        else if (state_==State::key_exchange && message.type==22 && status_expected_) {
            if (message.body.size()<5 || message.body[0]!=1 || u24(message.body,1)!=message.body.size()-4)
                return std::unexpected(Error::protocol);
            status_expected_=false;
        } else if (state_==State::change_cipher && message.type==4 && ticket_expected_) {
            if (message.body.size()<6 || u16(message.body,4)!=message.body.size()-6)
                return std::unexpected(Error::protocol);
            ticket_expected_=false;
        } else if (state_==State::key_exchange && message.type==12) accepted=key_exchange(message.body);
        else if (state_==State::finished && message.type==20) {
            auto finished=server_finished(message.body);
            return finished ? std::expected<crypto::Bytes,Error>{} : std::unexpected(finished.error());
        } else if (state_!=State::hello_done || message.type!=14 || !message.body.empty()) {
            return std::unexpected(Error::protocol);
        }
        if (!accepted) return std::unexpected(accepted.error());
        auto wire=HandshakeDecoder::encode(message.type,message.body,handshake_limit);
        if (!wire || !transcript_->append(*wire)) return std::unexpected(Error::crypto);
        return state_==State::hello_done && message.type==14 ? client_flight() : std::expected<crypto::Bytes,Error>{};
    }

    auto Tls12Client::feed(std::span<std::uint8_t const> input) -> std::expected<Tls12Feed,Tls12ClientError> {
        if (state_==State::complete || state_==State::failed) return std::unexpected(Error::state);
        auto fail=[this](Error error) {state_=State::failed; return std::unexpected(error);};
        auto protected_record=state_==State::finished;
        auto framed=records_.feed(input,protected_record ? RecordFraming::tls12_gcm : RecordFraming::plaintext);
        if (!framed) return fail(Error::protocol);
        Tls12Feed result{framed->consumed,{}};
        if (!framed->record) return result;
        auto bytes=std::span(framed->record->bytes);
        if (bytes[1]!=3 || bytes[2]!=3) return fail(Error::protocol);
        if (state_==State::change_cipher && bytes[0]==20) {
            if (bytes.size()!=6 || bytes[5]!=1 || messages_.pending_bytes() || ticket_expected_) return fail(Error::protocol);
            state_=State::finished;
            return result;
        }
        std::optional<PlaintextRecord> plaintext;
        std::span<std::uint8_t const> body=bytes.subspan(5);
        if (protected_record) {
            auto opened=read_->open(bytes);
            if (!opened || opened->type!=ContentType::handshake) return fail(Error::authentication);
            plaintext.emplace(std::move(*opened));
            body=plaintext->content;
        } else if (bytes[0]!=22) return fail(Error::protocol);
        if (body.size()>read_limit_) return fail(Error::protocol);
        auto messages=messages_.feed(body);
        if (!messages) return fail(Error::protocol);
        for (std::size_t i=0;i<messages->size();++i) {
            auto outbound=process((*messages)[i]);
            if (!outbound) return fail(outbound.error());
            if (!outbound->empty() || state_==State::complete) {
                if (i+1!=messages->size() || messages_.pending_bytes()) return fail(Error::protocol);
                result.outbound=std::move(*outbound);
            }
        }
        return result;
    }

    auto Tls12Client::take_application_records() -> std::expected<ApplicationRecords,Tls12ClientError> {
        if (state_!=State::complete || std::exchange(taken_,true)) return std::unexpected(Error::state);
        auto peer_limit=std::min<std::size_t>(16384,negotiated_.peer_record_size_limit.value_or(16384));
        return ApplicationRecords(std::move(*write_),std::move(*read_),peer_limit+1,read_limit_,ApplicationRole::client);
    }
}
