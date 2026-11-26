#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import packet.fd;
namespace p = ::packet;
static bool fail_packet_allocation=false;
void* operator new(std::size_t size) {
    if (fail_packet_allocation && size==3) { fail_packet_allocation=false; throw std::bad_alloc{}; }
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
struct Pair { int fd[2]{-1,-1}; ~Pair() { for (int n:fd) if (n>=0) ::close(n); } };
int main() {
    Pair pair;
    if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair.fd)) return 1;
    p::MemoryLink link({128,1,128});
    auto invalid=p::FdPump::create(-1,link,128);
    if (invalid || std::get<p::FdError>(invalid.error())!=p::FdError::invalid_fd) return 1;
    Pair blocking; if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,blocking.fd)) return 1;
    auto denied=p::FdPump::create(blocking.fd[0],link,128);
    if (denied || std::get<p::FdError>(denied.error())!=p::FdError::blocking_fd) return 1;
    auto pump=p::FdPump::create(pair.fd[0],link,128); if (!pump) return 1;
    p::Bytes first{1,2,3}, second{4,5};
    if (!link.send(p::Side::first,first) || ::send(pair.fd[1],second.data(),second.size(),0)!=2) return 1;
    auto blocked=pump->step(); if (!blocked.input || !blocked.input_backpressured) return 1;
    auto consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=first) return 1;
    auto retried=pump->step(); if (!retried.input_delivered || retried.input) return 1;
    consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=second) return 1;
    p::Bytes large(129,8);
    if (::send(pair.fd[1],large.data(),large.size(),0)!=129) return 1;
    auto oversized=pump->step();
    if (!oversized.input_error || std::get<p::FdError>(*oversized.input_error)!=p::FdError::packet_too_large) return 1;
    if (::send(pair.fd[1],first.data(),first.size(),0)!=3 || !pump->step().input_delivered) return 1;
    consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=first) return 1;
    if (::send(pair.fd[1],first.data(),first.size(),0)!=3) return 1;
    fail_packet_allocation=true;
    auto failed=pump->step();
    if (fail_packet_allocation || !failed.input || !failed.input_backpressured || failed.input_delivered) return 1;
    auto empty=link.receive(p::Side::second); if (!empty || *empty) return 1;
    auto recovered=pump->step(); if (recovered.input || !recovered.input_delivered) return 1;
    consumed=link.receive(p::Side::second); if (!consumed || !*consumed || **consumed!=first) return 1;
    empty=link.receive(p::Side::second); if (!empty || *empty) return 1;
    p::Bytes filler(100,7); int filled=0;
    while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) ++filled;
    if (!filled || (errno!=EAGAIN && errno!=EWOULDBLOCK) || !link.send(p::Side::second,second)) return 1;
    auto full=pump->step(); if (!full.output_backpressured || full.output_delivered) return 1;
    std::array<std::uint8_t,128> buffer{};
    for (int i=0;i<filled;++i) if (::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=100) return 1;
    auto drained=pump->step();
    if (!drained.output_delivered || ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=2 ||
        !std::ranges::equal(std::span(buffer).first(2),second)) return 1;
    while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) {}
    if (errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    std::weak_ptr<p::TcpGeneration> lifetime;
    {
        auto scoped=p::FdPump::create(pair.fd[0],link,128); if (!scoped) return 1;
        auto token=std::make_shared<p::TcpGeneration>(); lifetime=token;
        if (!link.send(p::Side::second,second,p::PacketKind::ordinary,0,token)) return 1;
        token.reset();
        auto pending=scoped->step(); if (!pending.output_backpressured || lifetime.expired()) return 1;
    }
    if (!lifetime.expired()) return 1;
    while (::recv(pair.fd[1],buffer.data(),buffer.size(),0)>0) {}
    if (errno!=EAGAIN && errno!=EWOULDBLOCK) return 1;
    auto stale=std::make_shared<p::TcpGeneration>(); stale->valid=false;
    if (!link.send(p::Side::second,second,p::PacketKind::ordinary,0,stale)) return 1;
    auto discarded=pump->step();
    if (!discarded.output_discarded || discarded.output_delivered ||
        ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=-1 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 1;
    int filled_again=0;
    while (::send(pair.fd[0],filler.data(),filler.size(),0)==static_cast<ssize_t>(filler.size())) ++filled_again;
    if (!filled_again || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 1;
    auto retry_token=std::make_shared<p::TcpGeneration>();
    if (!link.send(p::Side::second,second,p::PacketKind::ordinary,0,retry_token)) return 1;
    if (!pump->step().output_backpressured) return 1;
    retry_token->valid=false;
    for (int i=0;i<filled_again;++i) if (::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=100) return 1;
    discarded=pump->step();
    if (!discarded.output_discarded || discarded.output_delivered ||
        ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=-1 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 1;
    if (!link.send(p::Side::second,second) || !pump->step().output_delivered ||
        ::recv(pair.fd[1],buffer.data(),buffer.size(),0)!=2 || !std::ranges::equal(std::span(buffer).first(2),second)) return 1;

    // Wave 30D: vnet_hdr 10-byte TX/RX framing + TCPv4 GSO segmentation
    {
        struct VnetHdr { std::uint8_t flags=0, gso_type=0; std::uint16_t hdr_len=0, gso_size=0, csum_start=0, csum_offset=0; };
        static_assert(sizeof(VnetHdr)==10);
        Pair vp;
        if (::socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,vp.fd)) return 1;
        p::MemoryLink vlink({1500,8,65536});
        auto vpump=p::FdPump::create(vp.fd[0],vlink,1500,true);
        if (!vpump || !vpump->vnet_hdr()) return 1;
        // TX: 10-byte zeroed virtio_net_hdr prepended before payload
        p::Bytes tx_pkt{0x45,0x00,0x00,0x14,0,0,0,0,64,6,0,0,10,0,0,1,10,0,0,2};
        if (!vlink.send(p::Side::second,tx_pkt) || !vpump->step().output_delivered) return 1;
        std::array<std::uint8_t,64> wire{};
        auto wn=::recv(vp.fd[1],wire.data(),wire.size(),0);
        if (wn!=static_cast<ssize_t>(sizeof(VnetHdr)+tx_pkt.size())) return 1;
        for (std::size_t i=0;i<sizeof(VnetHdr);++i) if (wire[i]!=0) return 1;
        if (!std::ranges::equal(std::span(wire).subspan(sizeof(VnetHdr),tx_pkt.size()),tx_pkt)) return 1;
        // RX GSO: TCPv4 super-frame with 100-byte payload segmented into 40+40+20 MSS segments
        VnetHdr gso_hdr{.flags=1,.gso_type=1,.hdr_len=40,.gso_size=40,.csum_start=20,.csum_offset=16};
        p::Bytes gso_frame(sizeof(VnetHdr)+40+100,0);
        std::memcpy(gso_frame.data(),&gso_hdr,sizeof(gso_hdr));
        auto* ip=gso_frame.data()+sizeof(VnetHdr);
        ip[0]=0x45; ip[2]=0; ip[3]=140; ip[4]=0x10; ip[5]=0x00; ip[8]=64; ip[9]=6;
        ip[12]=10; ip[15]=1; ip[16]=10; ip[19]=2;
        ip[20]=0x12; ip[21]=0x34; ip[22]=0x00; ip[23]=0x50; // sport=4660 dport=80
        ip[24]=0; ip[25]=0; ip[26]=0x01; ip[27]=0x00;       // seq=256
        ip[32]=0x50; ip[33]=0x19;                           // offset=5, ACK|PSH|FIN
        for (std::size_t i=0;i<100;++i) ip[40+i]=static_cast<std::uint8_t>(i);
        if (::send(vp.fd[1],gso_frame.data(),gso_frame.size(),0)!=static_cast<ssize_t>(gso_frame.size())) return 1;
        auto gres=vpump->step();
        if (!gres.input || !gres.input_delivered) return 1;
        auto s1=vlink.receive(p::Side::second);
        auto s2=vlink.receive(p::Side::second);
        auto s3=vlink.receive(p::Side::second);
        auto s4=vlink.receive(p::Side::second);
        if (!s1||!*s1||!s2||!*s2||!s3||!*s3||!s4||*s4) return 1;
        if ((*s1)->size()!=80 || (*s2)->size()!=80 || (*s3)->size()!=60) return 1;
        // Check IP ID increment, TCP seq increment, FIN/PSH cleared on s1/s2 and preserved on s3
        if ((**s1)[5]!=0x00 || (**s2)[5]!=0x01 || (**s3)[5]!=0x02) return 1;
        if ((**s1)[27]!=0x00 || (**s2)[27]!=40 || (**s3)[27]!=80) return 1;
        if (((**s1)[33]&0x09)!=0 || ((**s2)[33]&0x09)!=0 || ((**s3)[33]&0x09)!=0x09) return 1;
        if ((**s3)[40]!=80 || (**s3)[59]!=99) return 1;

        // P1-5: IPv6 TSO6 super-frame > 65535 bytes (ip6_plen=65500 + 40B IPv6 + 10B vnet_hdr = 65550B)
        int big_buf=262144;
        (void)::setsockopt(vp.fd[0],SOL_SOCKET,SO_RCVBUF,&big_buf,sizeof(big_buf));
        (void)::setsockopt(vp.fd[1],SOL_SOCKET,SO_SNDBUF,&big_buf,sizeof(big_buf));
        p::MemoryLink vlink6({1500,64,131072});
        auto vpump6=p::FdPump::create(vp.fd[0],vlink6,1500,true);
        if (!vpump6) return 1;
        std::size_t tcp6_data=65480; // 20B TCP + 65480B payload => ip6_plen=65500, total IPv6=65540B > 65535B!
        VnetHdr tso6_hdr{.flags=1,.gso_type=4,.hdr_len=60,.gso_size=1440,.csum_start=40,.csum_offset=16};
        p::Bytes tso6(sizeof(VnetHdr)+40+20+tcp6_data,0);
        std::memcpy(tso6.data(),&tso6_hdr,sizeof(tso6_hdr));
        auto* ip6=tso6.data()+sizeof(VnetHdr);
        ip6[0]=0x60; ip6[4]=static_cast<std::uint8_t>(65500u>>8); ip6[5]=static_cast<std::uint8_t>(65500u&0xffu);
        ip6[6]=6; ip6[7]=64; ip6[8]=0xfd; ip6[23]=1; ip6[24]=0xfd; ip6[39]=2;
        ip6[40]=0x12; ip6[41]=0x34; ip6[42]=0x01; ip6[43]=0xbb; ip6[52]=0x50; ip6[53]=0x18;
        ip6[60+tcp6_data-1]=0xa5;
        if (::send(vp.fd[1],tso6.data(),tso6.size(),0)!=static_cast<ssize_t>(tso6.size())) return 1;
        auto g6=vpump6->step();
        if (!g6.input || !g6.input_delivered) return 1;
        std::size_t total_tcp6=0; std::uint8_t last_byte=0;
        while (auto seg=vlink6.receive(p::Side::second)) {
            if (!*seg) break;
            if ((*seg)->size()<60 || (*seg)->size()>1500) return 1;
            total_tcp6+=(*seg)->size()-60;
            last_byte=(**seg).back();
        }
        if (total_tcp6!=tcp6_data || last_byte!=0xa5) return 1;

        // P1-5: truncated IPv4 and IPv6 frames dropped cleanly
        VnetHdr plain_hdr{};
        p::Bytes trunc_v4(sizeof(VnetHdr)+20,0);
        std::memcpy(trunc_v4.data(),&plain_hdr,sizeof(plain_hdr));
        trunc_v4[sizeof(VnetHdr)+0]=0x45; trunc_v4[sizeof(VnetHdr)+2]=0; trunc_v4[sizeof(VnetHdr)+3]=60; // claims 60B, only 20B
        if (::send(vp.fd[1],trunc_v4.data(),trunc_v4.size(),0)!=static_cast<ssize_t>(trunc_v4.size())) return 1;
        auto tv4=vpump6->step();
        if (!tv4.input_error || tv4.input_delivered) return 1;
        p::Bytes trunc_v6(sizeof(VnetHdr)+48,0);
        std::memcpy(trunc_v6.data(),&plain_hdr,sizeof(plain_hdr));
        trunc_v6[sizeof(VnetHdr)+0]=0x60; trunc_v6[sizeof(VnetHdr)+4]=0; trunc_v6[sizeof(VnetHdr)+5]=200; // claims 240B, only 48B
        if (::send(vp.fd[1],trunc_v6.data(),trunc_v6.size(),0)!=static_cast<ssize_t>(trunc_v6.size())) return 1;
        auto tv6=vpump6->step();
        if (!tv6.input_error || tv6.input_delivered) return 1;
    }
    std::cout << "packet descriptor pump preserves packets through backpressure\n";
}
