#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import tls.client_handshake_io;
import reality.client;
import tls.application_io;
import vless;
namespace t=tls;
int main(int argc,char** argv) {
    bool emit=argc==8 && std::string_view(argv[6])=="--hello-age";
    if (argc!=6 && !emit) return 1;
    auto port=std::strtoul(argv[1],nullptr,10); if (!port || port>65535) return 2;
    std::string_view hex=argv[2]; if (hex.size()!=64) return 3;
    std::array<std::uint8_t,32> pub{};
    auto nib=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; return -1; };
    for(std::size_t i=0;i<32;++i) { auto a=nib(hex[2*i]),b=nib(hex[2*i+1]); if(a<0||b<0) return 4; pub[i]=static_cast<std::uint8_t>(a*16+b); }
    std::array<std::uint16_t,1> groups{0x001d};
    auto hello=t::make_client_hello(std::string_view(argv[3]),{},groups); if(!hello) return 5;
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (emit) seconds-=std::strtoul(argv[7],nullptr,10);
    reality::Identity id{{1,8,24},static_cast<std::uint32_t>(seconds),{}};
    std::string_view short_id=argv[5]; if (short_id.size()>16 || short_id.size()%2) return 24;
    for (std::size_t i=0;i<short_id.size()/2;++i) { auto a=nib(short_id[2*i]),b=nib(short_id[2*i+1]); if(a<0||b<0) return 24; id.short_id[i]=static_cast<std::uint8_t>(a*16+b); }
    auto session=reality::create_client_session(std::move(*hello),pub,id); if(!session) return 6;
    if (emit) {
        auto initial=session->initial_record();
        if (!initial) return 7;
        std::cout.write(reinterpret_cast<char const*>(initial->data()),initial->size());
        return std::cout ? 0 : 7;
    }
    auto handshake=t::ClientHandshakeIo::create(std::move(*session),0,10000); if(!handshake) return 7;
    int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) return 8;
    timeval timeout{10,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(static_cast<std::uint16_t>(port)); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) { close(fd); return 9; }
    std::array<std::uint8_t,8192> buf{}; std::size_t begin=0,end=0;
    while(!handshake->complete()) {
        auto pending=handshake->pending_output();
        if(!pending.empty()) { auto n=send(fd,pending.data(),pending.size(),MSG_NOSIGNAL); if(n<=0 || !handshake->written(static_cast<std::size_t>(n),1)) { close(fd); return 10; } continue; }
        if(begin==end) { auto n=recv(fd,buf.data(),buf.size(),0); if(n<=0) { close(fd); return 11; } begin=0; end=static_cast<std::size_t>(n); }
        auto step=handshake->feed(std::span{buf}.subspan(begin,end-begin),1);
        if(!step) { auto e=step.error(); close(fd); return e==t::ClientHandshakeIoError::authentication_failed ? 12 : 13; }
        if(!step->consumed) { close(fd); return 14; } begin+=step->consumed;
    }
    auto records=handshake->take_application_records(); if (!records) { close(fd); return 15; }
    t::ApplicationIo app(std::move(*records));
    auto target=std::strtoul(argv[4],nullptr,10); if (!target || target>65535) { close(fd); return 16; }
    vless::TcpRequest request{};
    for (std::size_t i=0;i<request.user.size();++i) request.user[i]=static_cast<std::uint8_t>(i);
    request.port=static_cast<std::uint16_t>(target); request.address={127,0,0,1};
    auto wire=vless::encode_tcp_request(request); if (!wire) { close(fd); return 17; }
    constexpr std::string_view payload="Reality VLESS bidirectional payload";
    wire->insert(wire->end(),payload.begin(),payload.end());
    auto flush=[&]() { while (!app.pending_output().empty()) { auto bytes=app.pending_output(); auto n=send(fd,bytes.data(),bytes.size(),MSG_NOSIGNAL); if (n<=0 || !app.written(static_cast<std::size_t>(n))) return false; } return true; };
    if (!app.send(*wire) || !flush()) { close(fd); return 18; }
    std::vector<std::uint8_t> received;
    while (received.size()<payload.size()+2) {
        if (begin==end) { auto n=recv(fd,buf.data(),buf.size(),0); if (n<=0) { close(fd); return 19; } begin=0; end=static_cast<std::size_t>(n); }
        auto step=app.feed(std::span{buf}.subspan(begin,end-begin));
        if (!step || !step->consumed) { close(fd); return 20; }
        begin+=step->consumed;
        if (step->event && step->event->kind==t::ApplicationEventKind::data) received.insert(received.end(),step->event->data.begin(),step->event->data.end());
        if (!flush()) { close(fd); return 21; }
    }
    auto response=vless::parse_response(received);
    if (response.status!=vless::HeaderStatus::accepted || std::string_view(reinterpret_cast<char const*>(received.data()+response.consumed),received.size()-response.consumed)!=payload) { close(fd); return 22; }
    if (!app.close_notify() || !flush()) { close(fd); return 23; }
    close(fd); return 0;
}
