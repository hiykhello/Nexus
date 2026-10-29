module;
#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
module nexus.socks5.udp_ingress;
import std;
import nexus.rules;
namespace nexus::socks5 {
    namespace {
        auto error() -> std::error_code { return {errno,std::generic_category()}; }
        auto address(UdpPeer const& peer) -> sockaddr_in {
            sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(peer.port);
            std::copy_n(peer.address.begin(),4,reinterpret_cast<std::uint8_t*>(&addr.sin_addr)); return addr;
        }
        auto peer(sockaddr_in const& addr) -> UdpPeer {
            UdpPeer result{1,{},ntohs(addr.sin_port)};
            std::copy_n(reinterpret_cast<std::uint8_t const*>(&addr.sin_addr),4,result.address.begin()); return result;
        }
    }
    UdpIngress::~UdpIngress() { close(); }
    auto UdpIngress::close() noexcept -> void {
        closed_=true; pending_.reset(); input_pending_=false; input_size_=0; direct_.close();
        if (fd_>=0) { ::close(fd_); fd_=-1; }
    }
    auto UdpIngress::open(UdpPeer local) -> std::expected<UdpPeer,UdpDirectError> {
        if (closed_ || association_.closed()) return std::unexpected(UdpDirectError{Status::association_closed});
        if (fd_>=0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        if (local.address_type!=1 || std::ranges::all_of(std::span(local.address).first<4>(),[](auto b){return b==0;}) ||
            std::ranges::any_of(std::span(local.address).subspan(4),[](auto b){return b!=0;}))
            return std::unexpected(UdpDirectError{Status::invalid_address});
        int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if (fd<0) return std::unexpected(UdpDirectError{error()});
        auto addr=address(local);
        if (::bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))<0) {
            auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
        }
        socklen_t length=sizeof(addr);
        if (::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&length)<0) {
            auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
        }
        fd_=fd; return peer(addr);
    }
    auto UdpIngress::step() -> std::expected<UdpIngressStep,UdpDirectError> {
        if (closed_ || association_.closed()) { close(); return std::unexpected(UdpDirectError{Status::association_closed}); }
        if (fd_<0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::bad_file_descriptor)});
        UdpIngressStep report;
        if (!input_pending_) {
            sockaddr_in from{}; socklen_t length=sizeof(from);
            auto n=::recvfrom(fd_,input_bytes_.data(),input_bytes_.size(),MSG_TRUNC,reinterpret_cast<sockaddr*>(&from),&length);
            if (n>=0) {
                report.input=true;
                if (static_cast<std::size_t>(n)>input_bytes_.size() || length!=sizeof(from) || from.sin_family!=AF_INET)
                report.input_error=UdpDirectError{Status::too_large};
                else { input_size_=static_cast<std::size_t>(n); input_source_=peer(from); input_pending_=true; }
            } else if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) report.input_error=UdpDirectError{error()};
        }
        if (input_pending_) {
            report.input=true;
            auto packet=association_.admit(input_source_,std::span(input_bytes_).first(input_size_));
            if (!packet) report.input_error=UdpDirectError{packet.error()};
            else if (packet->address_type==3) report.input_error=UdpDirectError{UdpRouteError::unsupported};
            else {
                UdpPeer target{packet->address_type,{},packet->port};
                std::copy_n(packet->address.begin(),packet->address_length,target.address.begin());
                auto sent=direct_.send(*packet,target);
                if (sent) report.forwarded=true;
                else if (auto e=std::get_if<std::error_code>(&sent.error()); e &&
                         (*e==std::errc::resource_unavailable_try_again || *e==std::errc::interrupted))
                    report.input_backpressured=true;
                else report.input_error=sent.error();
            }
            if (!report.input_backpressured) { input_pending_=false; input_size_=0; }
        }
        if (!pending_) {
            auto reply=direct_.poll();
            if (!reply) report.output_error=reply.error();
            else if (*reply) pending_=std::move(**reply);
        }
        if (pending_) {
            auto dest=address(pending_->client);
            auto sent=::sendto(fd_,pending_->wire.data(),pending_->wire.size(),0,reinterpret_cast<sockaddr*>(&dest),sizeof(dest));
            if (sent<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) report.backpressured=true;
            else if (sent<0 || static_cast<std::size_t>(sent)!=pending_->wire.size()) {
                report.output_error=UdpDirectError{sent<0 ? error() : std::make_error_code(std::errc::io_error)}; pending_.reset();
            } else { report.delivered=true; pending_.reset(); }
        }
        return report;
    }
}
