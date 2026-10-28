#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.tls.server_flight;
import nexus.tls.client_hello_stream;
import nexus.tls.client_keys;
import nexus.tls.handshake;
import nexus.tls.key_share;
namespace t=nexus::tls; namespace c=nexus::crypto;
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
        auto key=c::X25519Private::generate(); if (!key) return 20;
        auto pub=key->public_key(); if (!pub) return 21;
        auto share=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{pub->begin(),pub->end()}}}); if (!share) return 22;
        auto scheme=*cred->scheme(); t::ClientHello hello; hello.cipher_suites={0x1301}; hello.compression_methods={0};
        hello.extensions={{43,{2,3,4}},{10,{0,2,0,29}},{13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,*share}};
        auto body=hello.encode(); if (!body) return 23;
        auto wire=t::HandshakeDecoder::encode(1,*body); if (!wire) return 24;
        auto keys=t::server_handshake_keys(*wire,std::span{&scheme,1}); if (!keys) return 25;
        auto peer=t::client_handshake_keys(*wire,keys->server_hello,std::move(*key)); if (!peer) return 26;
        auto flight=t::ServerFlight::create(std::move(*keys),*cred); if (!flight) return 27;
        c::Bytes bogus(36,0); bogus[0]=20; bogus[3]=32;
        auto record=peer->write.seal(t::ContentType::handshake,bogus); if (!record) return 28;
        auto result=flight->client_finished(*record);
        return !result && result.error()==t::ServerFlightError::invalid_finished && !flight->take_application_records() ? 0 : 29;
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
