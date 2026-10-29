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
        struct SocketAddress { sockaddr_storage data{}; socklen_t size=0; };
        auto address(UdpPeer const& peer) -> SocketAddress {
            SocketAddress result;
            if (peer.address_type==1) {
                sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(peer.port);
                std::copy_n(peer.address.begin(),4,reinterpret_cast<std::uint8_t*>(&addr.sin_addr));
                std::memcpy(&result.data,&addr,sizeof(addr)); result.size=sizeof(addr);
            } else {
                sockaddr_in6 addr{}; addr.sin6_family=AF_INET6; addr.sin6_port=htons(peer.port);
                std::ranges::copy(peer.address,addr.sin6_addr.s6_addr);
                std::memcpy(&result.data,&addr,sizeof(addr)); result.size=sizeof(addr);
            }
            return result;
        }
        auto peer(sockaddr_storage const& storage,socklen_t length) -> std::optional<UdpPeer> {
            if (storage.ss_family==AF_INET && length==sizeof(sockaddr_in)) {
                sockaddr_in addr{}; std::memcpy(&addr,&storage,sizeof(addr));
                UdpPeer result{1,{},ntohs(addr.sin_port)};
                std::copy_n(reinterpret_cast<std::uint8_t const*>(&addr.sin_addr),4,result.address.begin()); return result;
            }
            if (storage.ss_family==AF_INET6 && length==sizeof(sockaddr_in6)) {
                sockaddr_in6 addr{}; std::memcpy(&addr,&storage,sizeof(addr));
                if (addr.sin6_scope_id || IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) return {};
                UdpPeer result{4,{},ntohs(addr.sin6_port)};
                std::copy_n(addr.sin6_addr.s6_addr,16,result.address.begin()); return result;
            }
            return {};
        }
    }
    UdpIngress::~UdpIngress() { close(); }
    auto UdpIngress::close() noexcept -> void {
        closed_=true; pending_.reset(); input_pending_=false; domain_pending_=false; input_size_=0; direct_.close();
        if (fd_>=0) { ::close(fd_); fd_=-1; }
    }
    auto UdpIngress::open(UdpPeer local) -> std::expected<UdpPeer,UdpDirectError> {
        if (closed_ || association_.closed()) return std::unexpected(UdpDirectError{Status::association_closed});
        if (fd_>=0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        if ((local.address_type!=1 && local.address_type!=4) ||
            std::ranges::all_of(local.address,[](auto b){return b==0;}) ||
            (local.address_type==1 && std::ranges::any_of(std::span(local.address).subspan(4),[](auto b){return b!=0;})) ||
            (local.address_type==4 && std::ranges::all_of(std::span(local.address).first<10>(),[](auto b){return b==0;}) &&
             local.address[10]==255 && local.address[11]==255))
            return std::unexpected(UdpDirectError{Status::invalid_address});
        int fd=::socket(local.address_type==1 ? AF_INET : AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if (fd<0) return std::unexpected(UdpDirectError{error()});
        if (local.address_type==4) {
            int on=1;
            if (::setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof(on))<0) {
                auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
            }
        }
        auto addr=address(local);
        if (::bind(fd,reinterpret_cast<sockaddr*>(&addr.data),addr.size)<0) {
            auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
        }
        sockaddr_storage bound{}; socklen_t length=sizeof(bound);
        if (::getsockname(fd,reinterpret_cast<sockaddr*>(&bound),&length)<0) {
            auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
        }
        auto result=peer(bound,length);
        if (!result) { ::close(fd); return std::unexpected(UdpDirectError{Status::invalid_address}); }
        fd_=fd; return *result;
    }
    auto UdpIngress::step() -> std::expected<UdpIngressStep,UdpDirectError> {
        if (closed_ || association_.closed()) { close(); return std::unexpected(UdpDirectError{Status::association_closed}); }
        if (fd_<0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::bad_file_descriptor)});
        UdpIngressStep report;
        if (!input_pending_) {
            sockaddr_storage from{}; socklen_t length=sizeof(from);
            auto n=::recvfrom(fd_,input_bytes_.data(),input_bytes_.size(),MSG_TRUNC,reinterpret_cast<sockaddr*>(&from),&length);
            if (n>=0) {
                report.input=true;
                auto source=peer(from,length);
                if (static_cast<std::size_t>(n)>input_bytes_.size()) report.input_error=UdpDirectError{Status::too_large};
                else if (!source) report.input_error=UdpDirectError{Status::invalid_address};
                else { input_size_=static_cast<std::size_t>(n); input_source_=*source; input_pending_=true; }
            } else if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) {
                auto failure=error(); close(); return std::unexpected(UdpDirectError{failure});
            }
        }
        if (input_pending_ && !domain_pending_) {
            report.input=true;
            auto packet=association_.admit(input_source_,std::span(input_bytes_).first(input_size_));
            if (!packet) report.input_error=UdpDirectError{packet.error()};
            else if (packet->address_type==3) {
                auto preflight=udp_preflight(policy_,*packet);
                if (std::ranges::find(std::span(packet->address).first(packet->address_length),0)!=
                    std::span(packet->address).first(packet->address_length).end())
                    report.input_error=UdpDirectError{Status::invalid_address};
                else if (!preflight) report.input_error=UdpDirectError{preflight.error()};
                else if (!allow_domains_) report.input_error=UdpDirectError{UdpRouteError::unsupported};
                else { domain_pending_=true; report.domain_pending=true; }
            }
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
            if (!report.input_backpressured && !domain_pending_) { input_pending_=false; input_size_=0; }
        }
        if (domain_pending_) report.domain_pending=true;
        if (!pending_) {
            auto reply=direct_.poll();
            if (!reply) report.output_error=reply.error();
            else if (*reply) pending_=std::move(**reply);
        }
        if (pending_) {
            auto dest=address(pending_->client);
            auto sent=::sendto(fd_,pending_->wire.data(),pending_->wire.size(),0,reinterpret_cast<sockaddr*>(&dest.data),dest.size);
            if (sent<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) report.backpressured=true;
            else if (sent<0 && (errno==EMSGSIZE || errno==ENETUNREACH || errno==EHOSTUNREACH || errno==ECONNREFUSED)) {
                report.output_dropped=true; pending_.reset();
            }
            else if (sent<0 || static_cast<std::size_t>(sent)!=pending_->wire.size()) {
                report.output_error=UdpDirectError{sent<0 ? error() : std::make_error_code(std::errc::io_error)}; pending_.reset();
            } else { report.delivered=true; pending_.reset(); }
        }
        return report;
    }
    auto UdpIngress::pending_domain() const noexcept -> std::optional<UdpDatagram> {
        if (closed_ || association_.closed() || !domain_pending_) return {};
        auto packet=parse_udp_datagram(std::span(input_bytes_).first(input_size_));
        if (!packet || packet->address_type!=3) return {};
        return *packet;
    }
    auto UdpIngress::send_resolved(UdpPeer candidate) -> std::expected<void,UdpDirectError> {
        if (closed_ || association_.closed()) { close(); return std::unexpected(UdpDirectError{Status::association_closed}); }
        auto packet=pending_domain();
        if (!packet) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        auto sent=direct_.send(*packet,candidate);
        if (sent) discard_domain();
        return sent;
    }
    auto UdpIngress::discard_domain() noexcept -> void {
        if (domain_pending_) { domain_pending_=false; input_pending_=false; input_size_=0; }
    }
}
