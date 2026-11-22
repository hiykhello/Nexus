#include <sys/socket.h>
#include <unistd.h>
import std;
import tls.server_flight;
import tls.client_hello_stream;
import tls.client_keys;
import tls.handshake;
import tls.key_share;
static thread_local int fail_after=-1;
static void* watched_server_hello=nullptr;
static bool server_hello_released=false;
static void* watched_secret=nullptr;
static std::size_t watched_secret_size=0;
static bool secret_cleansed=false;
static void* watched_early_secret=nullptr;
static std::size_t watched_early_secret_size=0;
static bool early_secret_cleansed=false;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    if (p && p==watched_server_hello) { server_hello_released=true; watched_server_hello=nullptr; }
    if (p && p==watched_secret) {
        auto bytes=std::span{static_cast<std::uint8_t const*>(p),watched_secret_size};
        secret_cleansed=std::ranges::all_of(bytes,[](auto byte) { return byte==0; }); watched_secret=nullptr;
    }
    if (p && p==watched_early_secret) {
        auto bytes=std::span{static_cast<std::uint8_t const*>(p),watched_early_secret_size};
        early_secret_cleansed=std::ranges::all_of(bytes,[](auto byte) { return byte==0; }); watched_early_secret=nullptr;
    }
    std::free(p);
}
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
namespace t=tls; namespace c = ::crypto;
auto read_file(char const* p) -> c::Bytes { std::ifstream in(p,std::ios::binary); return {std::istreambuf_iterator<char>(in),{}}; }
auto read_exact(int fd,std::span<std::uint8_t> out) -> bool {
    while (!out.empty()) { auto n=::recv(fd,out.data(),out.size(),0); if (n<=0) return false; out=out.subspan(static_cast<std::size_t>(n)); } return true;
}
auto read_record(int fd) -> std::optional<c::Bytes> {
    c::Bytes out(5); if (!read_exact(fd,out)) return {}; auto size=(std::size_t{out[3]}<<8)|out[4]; if (size>16640) return {};
    out.resize(5+size); if (!read_exact(fd,std::span{out}.subspan(5))) return {}; return out;
}
auto send_all(int fd,std::span<std::uint8_t const> bytes) -> bool {
    while (!bytes.empty()) { auto n=::send(fd,bytes.data(),bytes.size(),MSG_NOSIGNAL); if (n<=0) return false; bytes=bytes.subspan(static_cast<std::size_t>(n)); } return true;
}
int main(int argc,char** argv) {
    if (argc!=4 && argc!=5) return 1;
    auto cred=t::ServerCredential::create(read_file(argv[1]),read_file(argv[2])); if (!cred) return 2;
    if (std::string_view(argv[3])=="bad-finished") {
        int failures=0; bool reached_result=false;
        for (int index=0;index<128;++index) {
            auto k=c::X25519Private::generate(); if (!k) return 30;
            auto p=k->public_key(); if (!p) return 31;
            auto s=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{p->begin(),p->end()}}}); if (!s) return 32;
            auto scheme=*cred->scheme(); t::ClientHello h; h.cipher_suites={0x1301}; h.compression_methods={0};
            h.extensions={{43,{2,3,4}},{10,{0,2,0,29}},{13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,*s}};
            auto b=h.encode(); if (!b) return 33; auto w=t::HandshakeDecoder::encode(1,*b); if (!w) return 34;
            auto keys=t::server_handshake_keys(*w,std::span{&scheme,1}); if (!keys) return 35;
            auto peer=t::client_handshake_keys(*w,keys->server_hello,std::move(*k)); if (!peer) return 36;
            auto candidate=t::ServerFlight::create(std::move(*keys),*cred); if (!candidate) return 37;
            c::Bytes bogus(36,0); bogus[0]=20; bogus[3]=32;
            auto record=peer->write.seal(t::ContentType::handshake,bogus); if (!record) return 38;
            bool threw=false; fail_after=index;
            try { auto result=candidate->client_finished(*record); if (!result && result.error()==t::ServerFlightError::invalid_finished) reached_result=true; }
            catch (std::bad_alloc const&) { threw=true; }
            fail_after=-1;
            if (threw) {
                ++failures; auto again=candidate->client_finished(*record);
                if (again || again.error()!=t::ServerFlightError::invalid_state || candidate->take_application_records()) return 39;
            } else if (reached_result) break;
        }
        if (failures<3 || !reached_result) return 40;
        auto key=c::X25519Private::generate(); if (!key) return 20;
        auto pub=key->public_key(); if (!pub) return 21;
        auto share=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{pub->begin(),pub->end()}}}); if (!share) return 22;
        auto scheme=*cred->scheme(); t::ClientHello hello; hello.cipher_suites={0x1301}; hello.compression_methods={0};
        hello.extensions={{43,{2,3,4}},{10,{0,2,0,29}},{13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,*share}};
        auto body=hello.encode(); if (!body) return 23;
        auto wire=t::HandshakeDecoder::encode(1,*body); if (!wire) return 24;
        auto keys=t::server_handshake_keys(*wire,std::span{&scheme,1}); if (!keys) return 25;
        auto peer=t::client_handshake_keys(*wire,keys->server_hello,std::move(*key)); if (!peer) return 26;
        watched_server_hello=keys->server_hello.data(); server_hello_released=false;
        watched_early_secret=const_cast<std::uint8_t*>(keys->handshake_secret.view().data()); watched_early_secret_size=keys->handshake_secret.view().size(); early_secret_cleansed=false;
        watched_secret=const_cast<std::uint8_t*>(keys->client_traffic.view().data()); watched_secret_size=keys->client_traffic.view().size(); secret_cleansed=false;
        auto flight=t::ServerFlight::create(std::move(*keys),*cred); if (!flight) return 27;
        if (!server_hello_released || watched_server_hello || watched_early_secret || !early_secret_cleansed || !watched_secret) return 41;
        c::Bytes bogus(36,0); bogus[0]=20; bogus[3]=32;
        auto record=peer->write.seal(t::ContentType::handshake,bogus); if (!record) return 28;
        auto result=flight->client_finished(*record);
        if (result || result.error()!=t::ServerFlightError::invalid_finished || flight->take_application_records() || watched_secret || !secret_cleansed) return 29;
        auto flood_key=c::X25519Private::generate(); if (!flood_key) return 42;
        auto flood_pub=flood_key->public_key(); if (!flood_pub) return 43;
        auto flood_share=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{flood_pub->begin(),flood_pub->end()}}}); if (!flood_share) return 44;
        hello.extensions.back().data=std::move(*flood_share); auto flood_body=hello.encode(); if (!flood_body) return 45;
        auto flood_wire=t::HandshakeDecoder::encode(1,*flood_body); if (!flood_wire) return 46;
        auto flood_keys=t::server_handshake_keys(*flood_wire,std::span{&scheme,1}); if (!flood_keys) return 47;
        auto flood_peer=t::client_handshake_keys(*flood_wire,flood_keys->server_hello,std::move(*flood_key)); if (!flood_peer) return 48;
        auto flood_flight=t::ServerFlight::create(std::move(*flood_keys),*cred); if (!flood_flight) return 49;
        c::Bytes flood(16384,0); for (std::size_t i=0;i<flood.size();i+=4) flood[i]=20;
        auto flood_record=flood_peer->write.seal(t::ContentType::handshake,flood); if (!flood_record) return 50;
        auto flood_result=flood_flight->client_finished(*flood_record);
        if (flood_result || flood_result.error()!=t::ServerFlightError::invalid_finished || flood_flight->client_finished(*flood_record)) return 51;
        // Check the complete EncryptedExtensions wire encoding at both ALPN
        // length boundaries, including the two-byte length transitions.
        for (std::size_t n:{0u,1u,255u,256u}) {
            auto private_key=c::X25519Private::generate(); if (!private_key) return 52;
            auto public_key=private_key->public_key(); if (!public_key) return 53;
            auto offered=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{public_key->begin(),public_key->end()}}}); if (!offered) return 54;
            hello.extensions.back().data=std::move(*offered); auto encoded=hello.encode(); if (!encoded) return 55;
            auto message=t::HandshakeDecoder::encode(1,*encoded); if (!message) return 56;
            auto server_keys=t::server_handshake_keys(*message,std::span{&scheme,1}); if (!server_keys) return 57;
            auto client_keys=t::client_handshake_keys(*message,server_keys->server_hello,std::move(*private_key)); if (!client_keys) return 58;
            if (n==0) { watched_secret=const_cast<std::uint8_t*>(server_keys->client_traffic.view().data()); watched_secret_size=server_keys->client_traffic.view().size(); secret_cleansed=false; }
            c::Bytes alpn(n,'a'); auto selected=t::ServerFlight::create(std::move(*server_keys),*cred,alpn);
            if (n==256) { if (selected || selected.error()!=t::ServerFlightError::invalid_state) return 59; continue; }
            if (!selected || selected->records().empty()) return 60;
            auto plain=client_keys->read.open(selected->records().front()); if (!plain || plain->type!=t::ContentType::handshake) return 61;
            auto messages=t::HandshakeDecoder::create(1048584); if (!messages) return 62;
            auto decoded=messages->feed(plain->content); if (!decoded || decoded->empty() || decoded->front().type!=8) return 63;
            c::Bytes expected{static_cast<std::uint8_t>((n ? n+7 : 0)>>8),static_cast<std::uint8_t>(n ? n+7 : 0)};
            if (n) {
                expected.insert(expected.end(),{0,16,static_cast<std::uint8_t>((n+3)>>8),static_cast<std::uint8_t>(n+3),
                    static_cast<std::uint8_t>((n+1)>>8),static_cast<std::uint8_t>(n+1),static_cast<std::uint8_t>(n)});
                expected.insert(expected.end(),alpn.begin(),alpn.end());
            }
            if (decoded->front().body!=expected) return 64;
            if (n==0) {
                auto append=[&](auto const& batch) {
                    for (auto const& item:batch) {
                        auto encoded=t::HandshakeDecoder::encode(item.type,item.body,1048584);
                        if (!encoded || !client_keys->transcript.append(*encoded)) return false;
                    }
                    return true;
                };
                if (!append(*decoded)) return 65;
                for (auto const& record:selected->records().subspan(1)) {
                    auto part=client_keys->read.open(record); if (!part) return 66;
                    auto batch=messages->feed(part->content); if (!batch || !append(*batch)) return 67;
                }
                auto digest=client_keys->transcript.snapshot(); if (!digest) return 68;
                auto verify=t::finished_verify_data(client_keys->hash,client_keys->client_traffic.view(),*digest); if (!verify) return 69;
                auto finished=t::HandshakeDecoder::encode(20,verify->view()); if (!finished) return 70;
                auto encrypted=client_keys->write.seal(t::ContentType::handshake,*finished); if (!encrypted) return 71;
                auto accepted=selected->client_finished(*encrypted);
                if (!accepted || !*accepted || watched_secret || !secret_cleansed || !selected->take_application_records()) return 72;
            }
        }
        return 0;
    }
    auto fd=::accept(std::atoi(argv[3]),nullptr,nullptr); if (fd<0) return 3;
    struct Guard { int fd; ~Guard(){ ::close(fd); } } guard{fd};
    timeval timeout{5,0}; ::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    auto decoder=t::ClientHelloStream::create(); std::optional<t::ClientHelloFeed> offer;
    while (!offer) { auto record=read_record(fd); if (!record) return 4; auto part=decoder->feed(*record); if (!part || part->consumed!=record->size()) return 5; if (part->hello) offer=std::move(*part); }
    auto scheme=*cred->scheme(); auto keys=t::server_handshake_keys(offer->message,std::span{&scheme,1}); if (!keys) return 6;
    auto hello=keys->server_hello; auto flight=t::ServerFlight::create(std::move(*keys),*cred); if (!flight || flight->take_application_records()) return 7;
    c::Bytes header{22,3,3,static_cast<std::uint8_t>(hello.size()>>8),static_cast<std::uint8_t>(hello.size())};
    if (!send_all(fd,header) || !send_all(fd,hello)) return 8;
    for (auto const& record:flight->records()) if (!send_all(fd,record)) return 9;
    auto finished=read_record(fd); if (!finished) return 10;
    if (*finished==c::Bytes{20,3,3,0,1,1}) finished=read_record(fd);
    if (!finished) return 11;
    if (argc==5) {
        finished->back()^=1;
        if (flight->client_finished(*finished) || flight->take_application_records() || flight->client_finished(*finished)) return 17;
        return 0;
    }
    auto accepted=flight->client_finished(*finished); if (!accepted || !*accepted) return 11;
    auto app=flight->take_application_records(); if (!app || flight->take_application_records()) return 12;
    auto incoming=read_record(fd); if (!incoming) return 13;
    auto data=app->open(*incoming); if (!data || *data!=c::Bytes({'h','e','l','l','o'})) return 14;
    auto reply=app->seal(*data); if (!reply || !send_all(fd,*reply)) return 15;
    auto close=app->close_notify(); if (!close || !send_all(fd,*close)) return 16;
    return 0;
}
