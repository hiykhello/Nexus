#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.shadowsocks.request;
import nexus.shadowsocks.response;
import nexus.shadowsocks.frame;
import nexus.shadowsocks.replay;
namespace s=nexus::shadowsocks;
auto main(int argc,char** argv) -> int {
    if (argc!=3 && argc!=5 && !(argc==4 && std::string_view(argv[3])=="halfclose")) return 1;
    int listener=std::stoi(argv[1]); auto size=static_cast<std::size_t>(std::stoul(argv[2]));
    if (size!=16 && size!=32) return 2;
    int fd=::accept(listener,nullptr,nullptr); if (fd<0) return 3;
    std::array<std::uint8_t,32> key{},salt{};
    for (std::size_t i=0;i<size;++i) { key[i]=static_cast<std::uint8_t>(i); salt[i]=static_cast<std::uint8_t>(i+100); }
    auto psk=std::span{key}.first(size); auto response_salt=std::span{salt}.first(size);
    std::array<std::uint8_t,65536> buf{};
    auto n=::recv(fd,buf.data(),buf.size(),0); if (n<=0) return 4;
    std::vector<std::uint8_t> pending(buf.begin(),buf.begin()+n);
    while (pending.size()<size+27) {
        n=::recv(fd,buf.data(),buf.size(),0); if (n<=0) return 4;
        pending.insert(pending.end(),buf.begin(),buf.begin()+n);
    }
    s::ReplayTable replay(16);
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto prefix=s::decode_request_prefix(psk,pending,static_cast<std::uint64_t>(wall),std::chrono::steady_clock::now(),replay);
    if (!prefix) return 5;
    auto consumed=prefix->consumed; auto needed=prefix->header_length+16;
    while (pending.size()-consumed<needed) {
        n=::recv(fd,buf.data(),buf.size(),0); if (n<=0) return 6;
        pending.insert(pending.end(),buf.begin(),buf.begin()+n);
    }
    auto request=s::decode_request_header(std::move(*prefix),std::span{pending}.subspan(consumed,needed));
    if (!request) return 7;
    std::array<std::uint8_t,7> expected{1,203,0,113,5,1,187};
    if (!std::ranges::equal(request->header.address,expected)) return 8;
    std::vector<std::uint8_t> payload=std::move(request->header.payload);
    s::FrameDecoder reader(std::move(request->cipher));
    std::vector<std::uint8_t> remainder(pending.begin()+consumed+needed,pending.end());
    while (payload.size()<5) {
        if (remainder.empty()) {
            n=::recv(fd,buf.data(),buf.size(),0); if (n<=0) return 9;
            remainder.assign(buf.begin(),buf.begin()+n);
        }
        auto step=reader.feed(remainder); if (!step) return 10;
        if (step->payload) payload.insert(payload.end(),step->payload->begin(),step->payload->end());
        remainder.erase(remainder.begin(),remainder.begin()+step->consumed);
    }
    if (std::string(payload.begin(),payload.end())!="hello") return 11;
    if (argc==4) {
        if (!remainder.empty() || ::recv(fd,buf.data(),1,0)!=0 || !reader.finish()) return 17;
    }
    std::array<std::uint8_t,5> first{'w','o','r','l','d'},next{'a','g','a','i','n'};
    auto response=s::encode_response(psk,response_salt,request->salt,static_cast<std::uint64_t>(wall),first);
    if (!response) return 12;
    // One call for the initial response, as required by SIP022.
    if (::send(fd,response->wire.data(),response->wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(response->wire.size())) return 13;
    s::FrameEncoder writer(std::move(response->cipher)); auto frame=writer.encode(next);
    if (!frame) return 14;
    if (argc==5) {
        if (::send(fd,frame->data(),frame->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(frame->size())) return 14;
        frame=writer.encode(next); if (!frame) return 14;
        char signal; int control=std::stoi(argv[4]);
        if (::read(control,&signal,1)!=1) return 15;
        auto mode=std::string_view(argv[3]);
        if (mode=="length") (*frame)[0]^=1;
        else if (mode=="payload") frame->back()^=1;
        else if (mode=="truncated") frame->pop_back();
        else return 16;
    }
    if (::send(fd,frame->data(),frame->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(frame->size())) return 14;
    ::shutdown(fd,SHUT_WR); ::close(fd); return 0;
}
