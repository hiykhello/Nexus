#include <unistd.h>
#include <errno.h>
import std;
import tls.client_handshake_io;
import tls.handshake;
import tls.key_share;
import tls.server_hello;
import tls.server_hello_stream;
namespace t=tls; namespace c = ::crypto; using Bytes=c::Bytes;
auto io(bool writing, std::span<std::uint8_t> data) -> bool {
    for (std::size_t p=0;p<data.size();) { auto n=writing ? ::write(1,data.data()+p,data.size()-p) : ::read(0,data.data()+p,data.size()-p);
        if (n<0 && errno==EINTR) continue; if (n<=0) return false; p+=static_cast<std::size_t>(n); } return true;
}
auto receive() -> std::optional<Bytes> {
    Bytes record(5); if (!io(false,record)) return {}; auto len=(std::size_t{record[3]}<<8)|record[4];
    if (len>16640) return {}; record.resize(5+len); if (!io(false,std::span{record}.subspan(5))) return {}; return record;
}
int main(int argc,char** argv) {
    if (argc!=4) return 1; auto mode=std::string_view(argv[1]); bool hybrid=mode.starts_with("hybrid"); bool force_retry=mode.ends_with("-retry"); bool expect_failure=std::string_view(argv[3])!="valid"; bool wrong_name=std::string_view(argv[3])=="wrong";
    std::ifstream f(argv[2],std::ios::binary); Bytes root(std::istreambuf_iterator<char>(f),{}); if (root.empty()) return 2;
    auto group=hybrid ? t::x25519_mlkem768_group : std::uint16_t{0x001d};
    t::ClientHello hello; if (!c::random_bytes(hello.random)) return 7; hello.cipher_suites={0x1301,0x1302,0x1303}; hello.compression_methods={0};
    Bytes sni{0,17,0,0,14,'s','e','r','v','e','r','.','e','x','a','m','p','l','e'};
    hello.extensions={{0,sni},{43,{2,3,4}},{10,{0,2,static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}},{51,{0,0}},{13,{0,6,8,4,4,3,8,7}},{16,{0,9,8,'h','t','t','p','/','1','.','1'}}};
    std::array<std::span<std::uint8_t const>,1> anchors{root}; std::string_view host=wrong_name ? "wrong.example" : "server.example";
    auto name=std::span{reinterpret_cast<std::uint8_t const*>(host.data()),host.size()};
    auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto session=t::ClientSessionHandshake::create(std::move(hello),force_retry ? 0 : group,anchors,t::PeerNameKind::dns,name,now); if (!session) return 8;
    auto handshake=t::ClientHandshakeIo::create(std::move(*session),0,1000); if (!handshake) return 9;
    auto flush=[&]() -> bool {
        while (!handshake->pending_output().empty()) {
            auto data=handshake->pending_output().first(std::min<std::size_t>(13,handshake->pending_output().size()));
            auto n=::write(1,data.data(),data.size()); if (n<0 && errno==EINTR) continue;
            if (n<=0 || !handshake->written(static_cast<std::size_t>(n),0)) return false;
        }
        return true;
    };
    if (!flush()) return 10;
    bool saw_retry=false;
    while (!handshake->complete()) {
        auto record=receive(); if (!record) return 14;
        for (std::size_t p=0;p<record->size();) {
            auto length=std::min<std::size_t>(7,record->size()-p);
            auto result=handshake->feed(std::span{*record}.subspan(p,length),0);
            if (!result) return expect_failure && result.error()==t::ClientHandshakeIoError::authentication_failed ? 0 : 15;
            if (!result->consumed) return 15; p+=result->consumed;
            if (!handshake->pending_output().empty()) {
                if (handshake->take_application_records() || handshake->negotiated()) return 35;
                if (handshake->pending_output()[0]==22) { if (saw_retry) return 32; saw_retry=true; }
                if (!flush()) return 16;
            }
        }
    }
    if (saw_retry!=force_retry) return 29;
    if (expect_failure) return 22;
    auto selected=handshake->negotiated(); Bytes expected_alpn{'h','t','t','p','/','1','.','1'};
    if (!selected || !selected->alpn || *selected->alpn!=expected_alpn) return 23;
    auto app=handshake->take_application_records(); if (!app) return 17;
    auto update=app->key_update(true); if (!update || !io(true,*update)) return 27;
    constexpr std::string_view request="GET / HTTP/1.0\r\nHost: server.example\r\n\r\n";
    auto request_bytes=std::span{reinterpret_cast<std::uint8_t const*>(request.data()),request.size()};
    auto outbound=app->seal(request_bytes); if (!outbound || !io(true,*outbound)) return 18;
    Bytes response;
    bool closed=false, update_received=false, ticket_received=false;
    while (!closed) { auto record=receive(); if (!record) return 19; auto event=app->open_event(*record); if (!event) return 20;
        if (event->kind==t::ApplicationEventKind::data) { response.insert(response.end(),event->data.begin(),event->data.end()); if (response.size()>1048576) return 24; }
        else if (event->kind==t::ApplicationEventKind::close_notify) closed=true;
        else if (event->kind==t::ApplicationEventKind::ticket_discarded) ticket_received=true;
        else if (event->kind==t::ApplicationEventKind::key_update) update_received=true;
        else if (event->kind==t::ApplicationEventKind::key_update_requested) { update_received=true; auto response_update=app->key_update(false); if (!response_update || !io(true,*response_update)) return 28; }
        else if (event->kind!=t::ApplicationEventKind::handshake_fragment) return 25;
    }
    if (!update_received || !ticket_received || !app->finish_input()) return 26;
    if (!std::string_view(reinterpret_cast<char const*>(response.data()),response.size()).starts_with("HTTP/1.0 200 ok")) return 21;
    std::cerr << "OpenSSL TLS 1.3 " << argv[1] << " handshake, KeyUpdate, application data and close_notify passed\n";
}
