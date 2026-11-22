module;
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
module net.udp_socket;
import std;
import platform.ip_address;
import platform.socket_options;

namespace net {
    namespace {
        auto error() -> std::error_code { return {errno,std::generic_category()}; }
        auto address(UdpEndpoint const& peer) -> sockaddr_in6 {
            sockaddr_in6 addr{}; addr.sin6_family=AF_INET6; addr.sin6_port=platform::host_to_net16(peer.port);
            if (peer.family==4) {
                addr.sin6_addr.s6_addr[10]=255; addr.sin6_addr.s6_addr[11]=255;
                std::copy_n(peer.address.begin(),4,addr.sin6_addr.s6_addr+12);
            } else std::ranges::copy(peer.address,addr.sin6_addr.s6_addr);
            return addr;
        }
        auto peer(sockaddr_in6 const& addr) -> UdpEndpoint {
            UdpEndpoint result{}; result.port=platform::net_to_host16(addr.sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) {
                result.family=4; std::copy_n(addr.sin6_addr.s6_addr+12,4,result.address.begin());
            } else { result.family=6; std::copy_n(addr.sin6_addr.s6_addr,16,result.address.begin()); }
            return result;
        }
    }
    UdpSocket::~UdpSocket() { close(); }
    auto UdpSocket::close() noexcept -> void {
        closed_=true;
        discard();
    }
    auto UdpSocket::discard() noexcept -> void {
        if (fd_>=0) { ::close(fd_); fd_=-1; }
    }
    auto UdpSocket::open(bool ipv6_only,std::string const& network_namespace) -> std::expected<void,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if (fd_>=0) return {};
        auto opened=platform::open_physical_socket(true,true,false,network_namespace);
        if (!opened) return std::unexpected(opened.error());
        auto fd=*opened;
        int only=ipv6_only ? 1 : 0;
        if (::setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&only,sizeof(only))<0) {
            auto failure=error(); ::close(fd); return std::unexpected(failure);
        }
        fd_=fd;
        return {};
    }
    auto UdpSocket::local_endpoint() const -> std::expected<UdpEndpoint,std::error_code> {
        if (closed_ || fd_<0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        sockaddr_in6 local{}; socklen_t length=sizeof(local);
        if (::getsockname(fd_,reinterpret_cast<sockaddr*>(&local),&length)<0) return std::unexpected(error());
        if (length!=sizeof(local) || local.sin6_family!=AF_INET6 || local.sin6_scope_id) return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
        if (!local.sin6_port) return std::unexpected(std::make_error_code(std::errc::not_connected));
        return peer(local);
    }
    auto UdpSocket::bind(UdpEndpoint local) -> std::expected<void,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if ((local.family!=4 && local.family!=6) || (local.family==4 && std::ranges::any_of(std::span(local.address).subspan(4),[](auto byte) { return byte!=0; })))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto opened=open(); if (!opened) return opened;
        auto current=local_endpoint();
        if (current) return std::unexpected(std::make_error_code(std::errc::address_in_use));
        if (current.error()!=std::errc::not_connected) return std::unexpected(current.error());
        auto selected=address(local);
        if (::bind(fd_,reinterpret_cast<sockaddr*>(&selected),sizeof(selected))<0) return std::unexpected(error());
        return {};
    }
    auto UdpSocket::send(UdpEndpoint target,std::span<std::uint8_t const> data) -> std::expected<void,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if ((target.family!=4 && target.family!=6) || !target.port ||
            (target.family==4 && std::ranges::any_of(std::span(target.address).subspan(4),[](auto b){return b!=0;})))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto opened=open();
        if (!opened) return std::unexpected(opened.error());
        auto destination=address(target);
        auto n=::sendto(fd_,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&destination),sizeof(destination));
        if (n<0) return std::unexpected(error());
        if (static_cast<std::size_t>(n)!=data.size()) return std::unexpected(std::make_error_code(std::errc::io_error));
        return {};
    }
    auto UdpSocket::receive_impl(std::span<std::uint8_t> buffer,int flags)
        -> std::expected<std::optional<UdpPacket>,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if (fd_<0) return std::optional<UdpPacket>{};
        sockaddr_in6 from{}; socklen_t length=sizeof(from);
        auto n=::recvfrom(fd_,buffer.data(),buffer.size(),flags,reinterpret_cast<sockaddr*>(&from),&length);
        if (n<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return std::optional<UdpPacket>{};
            return std::unexpected(error());
        }
        bool valid=length==sizeof(from) && from.sin6_family==AF_INET6 && !from.sin6_scope_id && static_cast<std::size_t>(n)<=buffer.size();
        return std::optional{UdpPacket{valid ? peer(from) : UdpEndpoint{},static_cast<std::size_t>(n),valid}};
    }
    auto UdpSocket::peek(std::span<std::uint8_t> buffer) -> std::expected<std::optional<UdpPacket>,std::error_code> {
        return receive_impl(buffer,MSG_TRUNC|MSG_PEEK);
    }
    auto UdpSocket::receive(std::span<std::uint8_t> buffer) -> std::expected<std::optional<UdpPacket>,std::error_code> {
        return receive_impl(buffer,MSG_TRUNC);
    }
    auto UdpSocket::consume() -> std::expected<std::optional<std::size_t>,std::error_code> {
        if (closed_ || fd_<0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto n=::recvfrom(fd_,nullptr,0,MSG_TRUNC,nullptr,nullptr);
        if (n<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return std::optional<std::size_t>{};
            return std::unexpected(error());
        }
        return std::optional{static_cast<std::size_t>(n)};
    }
}
