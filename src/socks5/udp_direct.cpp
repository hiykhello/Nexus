module;
#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
module nexus.socks5.udp_direct;
import std;
import nexus.rules;

namespace nexus::socks5 {
    namespace {
        auto error() -> std::error_code { return {errno,std::generic_category()}; }
        auto address(UdpPeer const& peer) -> sockaddr_in6 {
            sockaddr_in6 addr{}; addr.sin6_family=AF_INET6; addr.sin6_port=htons(peer.port);
            if (peer.address_type==1) {
                addr.sin6_addr.s6_addr[10]=255; addr.sin6_addr.s6_addr[11]=255;
                std::copy_n(peer.address.begin(),4,addr.sin6_addr.s6_addr+12);
            } else std::ranges::copy(peer.address,addr.sin6_addr.s6_addr);
            return addr;
        }
        auto peer(sockaddr_in6 const& addr) -> UdpPeer {
            UdpPeer result{}; result.port=ntohs(addr.sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) {
                result.address_type=1; std::copy_n(addr.sin6_addr.s6_addr+12,4,result.address.begin());
            } else { result.address_type=4; std::copy_n(addr.sin6_addr.s6_addr,16,result.address.begin()); }
            return result;
        }
    }
    UdpDirect::~UdpDirect() { close(); }
    auto UdpDirect::close() noexcept -> void {
        closed_=true;
        if (fd_>=0) { ::close(fd_); fd_=-1; }
    }
    auto UdpDirect::send(UdpDatagram const& packet,UdpPeer candidate) -> std::expected<void,UdpDirectError> {
        if (closed_ || association_.closed()) {
            close(); return std::unexpected(UdpDirectError{Status::association_closed});
        }
        auto prepared=udp_prepare_send(association_,policy_,packet,candidate);
        if (!prepared) return std::unexpected(std::visit([](auto value) -> UdpDirectError { return value; },prepared.error()));
        auto rollback=[&] { (void)association_.finish_send(prepared->token,false); };
        if (fd_<0) {
            auto fd=::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
            if (fd<0) { auto failure=error(); rollback(); return std::unexpected(UdpDirectError{failure}); }
            int off=0;
            if (::setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&off,sizeof(off))<0) {
                auto failure=error(); ::close(fd); rollback(); return std::unexpected(UdpDirectError{failure});
            }
            fd_=fd;
        }
        auto destination=address(prepared->target);
        auto n=::sendto(fd_,packet.data.data(),packet.data.size(),0,reinterpret_cast<sockaddr*>(&destination),sizeof(destination));
        if (n<0 || static_cast<std::size_t>(n)!=packet.data.size()) {
            auto failure=n<0 ? error() : std::make_error_code(std::errc::io_error);
            rollback(); return std::unexpected(UdpDirectError{failure});
        }
        auto committed=association_.finish_send(prepared->token,true);
        if (!committed) return std::unexpected(UdpDirectError{committed.error()});
        return {};
    }
    auto UdpDirect::poll() -> std::expected<std::optional<UdpDirectReply>,UdpDirectError> {
        if (closed_ || association_.closed()) {
            close(); return std::unexpected(UdpDirectError{Status::association_closed});
        }
        if (fd_<0) return std::optional<UdpDirectReply>{};
        std::array<std::uint8_t,65536> bytes{}; sockaddr_in6 from{}; socklen_t length=sizeof(from);
        auto n=::recvfrom(fd_,bytes.data(),bytes.size(),MSG_TRUNC|MSG_PEEK,reinterpret_cast<sockaddr*>(&from),&length);
        if (n<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return std::optional<UdpDirectReply>{};
            return std::unexpected(UdpDirectError{error()});
        }
        std::optional<UdpDirectReply> result;
        auto client=association_.client_peer();
        if (length==sizeof(from) && from.sin6_family==AF_INET6 && !from.sin6_scope_id &&
            static_cast<std::size_t>(n)<=bytes.size() && client) {
            auto source=peer(from);
            if (association_.accepts_reply(source)) {
                UdpDatagram packet; packet.address_type=source.address_type;
                packet.address_length=source.address_type==1 ? 4 : 16; packet.port=source.port;
                std::copy_n(source.address.begin(),packet.address_length,packet.address.begin());
                packet.data=std::span(bytes).first(static_cast<std::size_t>(n));
                if (packet.data.size()+6+packet.address_length<=65507) {
                    auto wire=encode_udp_datagram(packet);
                    if (wire) result=UdpDirectReply{*client,std::move(*wire)};
                }
            }
        }
        auto consumed=::recvfrom(fd_,bytes.data(),bytes.size(),MSG_TRUNC,nullptr,nullptr);
        if (consumed<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return std::optional<UdpDirectReply>{};
            return std::unexpected(UdpDirectError{error()});
        }
        if (consumed!=n) return std::optional<UdpDirectReply>{};
        return result;
    }
}
