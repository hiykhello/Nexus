module shadowsocks.udp_relay;
import std;
namespace shadowsocks {
    namespace {
        auto failure(UdpRelayError kind) -> UdpRelayFailure { return {kind,{}}; }
        auto system_failure(std::error_code error) -> UdpRelayFailure { return {UdpRelayError::system,error}; }
        auto valid(UdpPeer const& peer) -> bool {
            return peer.port && std::ranges::any_of(peer.address,[](auto b){return b!=0;}) && (peer.family==6 || (peer.family==4 &&
                std::ranges::none_of(std::span{peer.address}.subspan(4),[](auto b){return b!=0;})));
        }
        auto endpoint(UdpPeer const& peer) -> net::UdpEndpoint { return {peer.family,peer.address,peer.port}; }
        auto peer(net::UdpEndpoint const& source) -> UdpPeer { return {source.family,source.address,source.port}; }
    }
    UdpRelay::~UdpRelay() { clear(); }
    auto UdpRelay::close(std::array<std::uint8_t,8> session) noexcept -> void {
        auto it=sockets_.find(session);
        if (it!=sockets_.end()) { it->second.socket.close(); sockets_.erase(it); }
    }
    auto UdpRelay::clear() noexcept -> void {
        for (auto& [id,entry]:sockets_) entry.socket.close();
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
            auto [inserted,_]=sockets_.try_emplace(session,binding_); it=inserted;
        }
        auto& targets=it->second.targets;
        if (!targets.contains(target) && targets.size()>=max_targets_) return std::unexpected(failure(UdpRelayError::target_limit));
        std::set<UdpPeer>::iterator position;
        bool added=false;
        try { auto result=targets.insert(target); position=result.first; added=result.second; }
        catch (...) { if (fresh) close(session); throw; }
        auto sent=it->second.socket.send(endpoint(target),payload);
        if (!sent) {
            auto e=system_failure(sent.error());
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
            auto received=current->second.socket.receive(buffer);
            if (!received) {
                auto error=system_failure(received.error());
                auto session=current->first;
                close(session);
                return std::unexpected(error);
            }
            if (!*received || !(**received).valid) continue;
            auto const& packet=**received;
            auto source=peer(packet.source);
            if (!current->second.targets.contains(source)) continue;
            return std::optional{UdpRelayReply{current->first,source,{buffer.begin(),buffer.begin()+packet.size}}};
        }
        return std::optional<UdpRelayReply>{};
    }
}
