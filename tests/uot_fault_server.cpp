#include <sys/socket.h>
#include <unistd.h>
import std;
import shadowsocks.request;
import shadowsocks.response;
import shadowsocks.frame;
import shadowsocks.replay;
import uot;
namespace s=shadowsocks;
namespace u=uot;
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    auto mode=std::string_view(argv[2]); int signal_fd=std::stoi(argv[3]);
    int fd=::accept(std::stoi(argv[1]),nullptr,nullptr); if (fd<0) return 2;
    std::array<std::uint8_t,16> key{},salt{};
    for (std::size_t i=0;i<key.size();++i) {key[i]=i; salt[i]=i+100;}
    std::array<std::uint8_t,65536> buffer{};
    auto n=::recv(fd,buffer.data(),buffer.size(),0); if (n<=0) return 3;
    std::vector<std::uint8_t> pending(buffer.begin(),buffer.begin()+n);
    while (pending.size()<key.size()+27) {
        n=::recv(fd,buffer.data(),buffer.size(),0); if (n<=0) return 4;
        pending.insert(pending.end(),buffer.begin(),buffer.begin()+n);
    }
    s::ReplayTable replay(8);
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto prefix=s::decode_request_prefix(key,pending,static_cast<std::uint64_t>(wall),std::chrono::steady_clock::now(),replay);
    if (!prefix) return 5;
    auto offset=prefix->consumed, length=prefix->header_length+16;
    while (pending.size()-offset<length) {
        n=::recv(fd,buffer.data(),buffer.size(),0); if (n<=0) return 6;
        pending.insert(pending.end(),buffer.begin(),buffer.begin()+n);
    }
    auto decoded=s::decode_request_header(std::move(*prefix),std::span(pending).subspan(offset,length));
    if (!decoded) return 7;
    std::vector<std::uint8_t> address{3,static_cast<std::uint8_t>(u::v2_destination.size())};
    address.insert(address.end(),u::v2_destination.begin(),u::v2_destination.end()); address.insert(address.end(),{0,0});
    if (decoded->header.address!=address) return 8;
    std::vector<std::uint8_t> plain=std::move(decoded->header.payload);
    std::vector<std::uint8_t> rest(pending.begin()+offset+length,pending.end());
    s::FrameDecoder reader(std::move(decoded->cipher));
    u::RequestResult request; u::PacketResult packet;
    for (;;) {
        request=u::parse_request(plain);
        if (request.status==u::Status::accepted) {
            packet=u::parse_packet(false,{},std::span(plain).subspan(request.consumed));
            if (packet.status==u::Status::accepted) break;
            if (packet.status!=u::Status::incomplete) return 9;
        } else if (request.status!=u::Status::incomplete) return 10;
        if (rest.empty()) {
            n=::recv(fd,buffer.data(),buffer.size(),0); if (n<=0) return 11;
            rest.assign(buffer.begin(),buffer.begin()+n);
        }
        auto step=reader.feed(rest); if (!step || !step->consumed) return 12;
        if (step->payload) plain.insert(plain.end(),step->payload->begin(),step->payload->end());
        rest.erase(rest.begin(),rest.begin()+step->consumed);
    }
    if (request.request.connected || packet.destination.family!=u::Family::ipv4 || packet.payload.size()!=5) return 13;
    salt[0]=static_cast<std::uint8_t>(100+packet.destination.bytes[3]);
    auto forged=packet.destination; forged.bytes[3]=forged.bytes[3]==1 ? 2 : 1;
    std::array<std::uint8_t,4> bad{'e','v','i','l'},good{'g','o','o','d'};
    auto fake=u::encode_packet(false,forged,bad); auto real=u::encode_packet(false,packet.destination,good);
    if (!fake || !real) return 14;
    fake->insert(fake->end(),real->begin(),real->end());
    auto response=s::encode_response(key,salt,decoded->salt,static_cast<std::uint64_t>(wall),*fake);
    if (!response || ::send(fd,response->wire.data(),response->wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(response->wire.size())) return 15;
    char signal; if (::read(signal_fd,&signal,1)!=1) return 16;
    if (mode!="valid") {
        s::FrameEncoder writer(std::move(response->cipher));
        std::vector<std::uint8_t> data = mode=="invalid" ? std::vector<std::uint8_t>{0xff} : *real;
        auto frame=writer.encode(data); if (!frame) return 17;
        if (mode=="corrupt") frame->back()^=1;
        else if (mode=="truncated") frame->pop_back();
        else if (mode!="invalid") return 18;
        if (::send(fd,frame->data(),frame->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(frame->size())) return 19;
        ::shutdown(fd,SHUT_WR);
    }
    ::close(fd); return 0;
}
