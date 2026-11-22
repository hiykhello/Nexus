#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import shadowsocks.request;
import shadowsocks.response;
import shadowsocks.frame;
namespace s=shadowsocks;
auto main(int argc,char** argv) -> int {
    if (argc!=4 && argc!=5 && argc!=6) return 1;
    int fd=std::stoi(argv[1]); auto size=static_cast<std::size_t>(std::stoul(argv[2])); auto port=std::stoul(argv[3]);
    if ((size!=16 && size!=32) || port>65535) return 2;
    std::array<std::uint8_t,32> key{},salt{};
    for (std::size_t i=0;i<size;++i) { key[i]=static_cast<std::uint8_t>(i); salt[i]=static_cast<std::uint8_t>(i+100); }
    auto psk=std::span{key}.first(size); auto request_salt=std::span{salt}.first(size);
    std::array<std::uint8_t,7> address{1,127,0,0,1,static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
    std::array<std::uint8_t,5> first{'h','e','l','l','o'},next{'a','g','a','i','n'};
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto request=s::encode_request(psk,request_salt,static_cast<std::uint64_t>(wall),address,{},first);
    if (!request) return 3;
    if (::send(fd,request->wire.data(),request->wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(request->wire.size())) return 4;
    s::FrameEncoder writer(std::move(request->cipher)); auto frame=writer.encode(next);
    if (!frame || ::send(fd,frame->data(),frame->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(frame->size())) return 5;
    auto mode=argc>=5 ? std::string_view(argv[4]) : std::string_view{};
    if (argc==6) {
        char signal; int control=std::stoi(argv[5]);
        if (::read(control,&signal,1)!=1) return 15;
        auto bad=writer.encode(next); if (!bad) return 16;
        if (mode=="length") (*bad)[0]^=1;
        else if (mode=="payload") bad->back()^=1;
        else if (mode=="truncated") bad->pop_back();
        else return 17;
        if (::send(fd,bad->data(),bad->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(bad->size()) || ::shutdown(fd,SHUT_WR)) return 18;
        char byte; auto received=::recv(fd,&byte,1,0);
        return received==0 || (received<0 && errno==ECONNRESET) ? 0 : 19;
    }
    if (!mode.empty() && mode!="half-close" && mode!="half-close-empty") return 13;
    if (!mode.empty() && ::shutdown(fd,SHUT_WR)) return 13;
    if (mode=="half-close-empty") { char byte; return ::recv(fd,&byte,1,0)==0 ? 0 : 14; }
    std::array<std::uint8_t,65536> buffer{}; auto n=::recv(fd,buffer.data(),buffer.size(),0);
    if (n<=0) return 6;
    std::vector<std::uint8_t> pending(buffer.begin(),buffer.begin()+n);
    auto prefix=s::decode_response_prefix(psk,request_salt,pending,static_cast<std::uint64_t>(wall));
    if (!prefix) return 7;
    auto consumed=prefix->consumed, needed=prefix->payload_length+16;
    while (pending.size()-consumed<needed) {
        n=::recv(fd,buffer.data(),buffer.size(),0); if (n<=0) return 8;
        pending.insert(pending.end(),buffer.begin(),buffer.begin()+n);
    }
    auto response=s::decode_response_payload(std::move(*prefix),std::span{pending}.subspan(consumed,needed));
    if (!response) return 9;
    auto payload=std::move(response->payload); s::FrameDecoder reader(std::move(response->cipher));
    std::vector<std::uint8_t> remainder(pending.begin()+consumed+needed,pending.end());
    while (payload.size()<10) {
        if (remainder.empty()) {
            n=::recv(fd,buffer.data(),buffer.size(),0); if (n<=0) return 10;
            remainder.assign(buffer.begin(),buffer.begin()+n);
        }
        auto step=reader.feed(remainder); if (!step) return 11;
        if (step->payload) payload.insert(payload.end(),step->payload->begin(),step->payload->end());
        remainder.erase(remainder.begin(),remainder.begin()+step->consumed);
    }
    if (std::string(payload.begin(),payload.end())!="worldagain") return 12;
    ::close(fd); return 0;
}
