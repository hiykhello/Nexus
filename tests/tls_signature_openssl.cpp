import std;
import tls.client_handshake_io;
import tls.fingerprint;
import tls.profiles;
import tls.handshake;
import tls.key_share;
import tls.server_hello;
import tls.server_hello_stream;
namespace t=tls; namespace c = ::crypto; using Bytes=c::Bytes;
auto io(bool writing,std::span<std::uint8_t> data) -> bool {
    if (writing) { std::cout.write(reinterpret_cast<char const*>(data.data()),data.size());std::cout.flush();return bool(std::cout); }
    std::cin.read(reinterpret_cast<char*>(data.data()),data.size());return bool(std::cin);
}
auto receive() -> std::optional<Bytes> {
    Bytes record(5); if (!io(false,record)) return {}; auto len=(std::size_t{record[3]}<<8)|record[4];
    if (len>16640) return {}; record.resize(5+len); if (!io(false,std::span{record}.subspan(5))) return {}; return record;
}
int main(int argc,char** argv) {
    if (argc!=6) return 1; auto mode=std::string_view(argv[1]); bool hybrid=mode.starts_with("hybrid"); bool force_retry=mode.ends_with("-retry"); bool expect_failure=std::string_view(argv[3])!="valid"; bool wrong_name=std::string_view(argv[3])=="wrong";
    t::FingerprintConfig config;
    config.profile=std::string_view(argv[4])=="randomized" ? t::Fingerprint::tls13_randomized : t::Fingerprint::tls13_grease;
    config.shares=force_retry ? t::FingerprintShares::retry : mode=="dual" ? t::FingerprintShares::dual : hybrid ? t::FingerprintShares::hybrid : t::FingerprintShares::x25519;
    config.pad_to=1600;
    config.signature_count=1;config.signature_order[0]=static_cast<std::uint16_t>(std::stoul(argv[5],nullptr,0));
    std::array<std::string_view,1> alpn{"http/1.1"};
    std::string_view host=wrong_name ? "wrong.example" : "server.example";
    auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto profile=t::ClientProfile::load(host,argv[2],29,false,alpn); if (!profile) return 8;
    auto handshake=profile->handshake(0,1000,now,config); if (!handshake) return 9;
    auto flush=[&]() -> bool {
        while (!handshake->pending_output().empty()) {
            auto data=handshake->pending_output().first(std::min<std::size_t>(13,handshake->pending_output().size()));
            auto count=data.size();
            std::cout.write(reinterpret_cast<char const*>(data.data()),data.size());std::cout.flush();
            if (!std::cout || !handshake->written(count,0)) return false;
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
