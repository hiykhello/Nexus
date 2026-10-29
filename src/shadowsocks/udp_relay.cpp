module;
#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
module nexus.shadowsocks.udp_relay;
import std;
namespace nexus::shadowsocks {
    namespace {
        auto failure(UdpRelayError kind) -> UdpRelayFailure { return {kind,{}}; }
        auto system_failure() -> UdpRelayFailure { return {UdpRelayError::system,{errno,std::generic_category()}}; }
        auto valid(UdpPeer const& peer) -> bool {
            return peer.port && std::ranges::any_of(peer.address,[](auto b){return b!=0;}) && (peer.family==6 || (peer.family==4 &&
                std::ranges::none_of(std::span{peer.address}.subspan(4),[](auto b){return b!=0;})));
        }
        auto socket_address(UdpPeer const& peer) -> sockaddr_in6 {
            sockaddr_in6 addr{}; addr.sin6_family=AF_INET6; addr.sin6_port=htons(peer.port);
            if (peer.family==4) {
                addr.sin6_addr.s6_addr[10]=255; addr.sin6_addr.s6_addr[11]=255;
                std::ranges::copy(std::span{peer.address}.first<4>(),addr.sin6_addr.s6_addr+12);
            } else std::ranges::copy(peer.address,addr.sin6_addr.s6_addr);
            return addr;
        }
        auto peer_address(sockaddr_in6 const& addr) -> UdpPeer {
            UdpPeer peer{}; peer.port=ntohs(addr.sin6_port);
            if (IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) {
                peer.family=4; std::ranges::copy(std::span{addr.sin6_addr.s6_addr}.last<4>(),peer.address.begin());
            } else { peer.family=6; std::ranges::copy(addr.sin6_addr.s6_addr,peer.address.begin()); }
            return peer;
        }
    }
    UdpRelay::~UdpRelay() { clear(); }
    auto UdpRelay::close(std::array<std::uint8_t,8> session) noexcept -> void {
        auto it=sockets_.find(session);
        if (it!=sockets_.end()) { ::close(it->second.fd); sockets_.erase(it); }
    }
    auto UdpRelay::clear() noexcept -> void {
        for (auto const& [id,entry]:sockets_) ::close(entry.fd);
        sockets_.clear(); cursor_.reset();
    }
    auto UdpRelay::send(std::array<std::uint8_t,8> session,UdpPeer target,std::span<std::uint8_t const> payload)
        -> std::expected<void,UdpRelayFailure> {
        if (!valid(target) || (target.family==6 && std::ranges::all_of(std::span{target.address}.first<10>(),[](auto byte){return byte==0;}) && target.address[10]==255 && target.address[11]==255))
            return std::unexpected(failure(UdpRelayError::invalid_target));
        auto it=sockets_.find(session);
        bool fresh=it==sockets_.end();
        if (fresh) {
            if (max_targets_==0) return std::unexpected(failure(UdpRelayError::target_limit));
            if (sockets_.size()>=max_sessions_) return std::unexpected(failure(UdpRelayError::session_limit));
            auto [inserted,_]=sockets_.try_emplace(session); it=inserted;
            it->second.fd=::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
            if (it->second.fd<0) { auto e=system_failure(); sockets_.erase(it); return std::unexpected(e); }
            int off=0;
            if (::setsockopt(it->second.fd,IPPROTO_IPV6,IPV6_V6ONLY,&off,sizeof(off))<0) {
                auto e=system_failure(); close(session); return std::unexpected(e);
            }
        }
        auto& targets=it->second.targets;
        if (!targets.contains(target) && targets.size()>=max_targets_) return std::unexpected(failure(UdpRelayError::target_limit));
        std::set<UdpPeer>::iterator position;
        bool added=false;
        try { auto result=targets.insert(target); position=result.first; added=result.second; }
        catch (...) { if (fresh) close(session); throw; }
        auto addr=socket_address(target);
        auto n=::sendto(it->second.fd,payload.data(),payload.size(),0,reinterpret_cast<sockaddr*>(&addr),sizeof(addr));
        if (n<0 || static_cast<std::size_t>(n)!=payload.size()) {
            auto e=n<0 ? system_failure() : UdpRelayFailure{UdpRelayError::system,std::make_error_code(std::errc::io_error)};
            if (added) targets.erase(position);
            if (fresh) close(session);
            return std::unexpected(e);
        }
        return {};
    }
    auto UdpRelay::poll() -> std::expected<std::optional<UdpRelayReply>,UdpRelayFailure> {
        if (sockets_.empty()) return std::optional<UdpRelayReply>{};
        auto it=cursor_ ? sockets_.upper_bound(*cursor_) : sockets_.begin();
        if (it==sockets_.end()) it=sockets_.begin();
        auto count=std::min<std::size_t>(sockets_.size(),64);
        std::array<std::uint8_t,65536> buffer{};
        for (std::size_t i=0;i<count;++i) {
            auto current=it++;
            if (it==sockets_.end()) it=sockets_.begin();
            cursor_=current->first;
            sockaddr_in6 from{}; socklen_t len=sizeof(from);
            auto n=::recvfrom(current->second.fd,buffer.data(),buffer.size(),MSG_TRUNC,reinterpret_cast<sockaddr*>(&from),&len);
            if (n<0) {
                if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) continue;
                auto error=system_failure();
                auto session=current->first;
                close(session);
                return std::unexpected(error);
            }
            if (len!=sizeof(from) || from.sin6_family!=AF_INET6 || from.sin6_scope_id!=0 || static_cast<std::size_t>(n)>buffer.size()) continue;
            auto source=peer_address(from);
            if (!current->second.targets.contains(source)) continue;
            return std::optional{UdpRelayReply{current->first,source,{buffer.begin(),buffer.begin()+n}}};
        }
        return std::optional<UdpRelayReply>{};
    }
}
