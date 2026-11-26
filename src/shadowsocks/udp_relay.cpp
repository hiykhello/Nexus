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
        constexpr auto kNull=udp_detail::IntrusiveU64Table<Entry>::kNull;
        auto found=sockets_.find(udp_detail::id_to_u64(session));
        if (!found) return;
        auto idx=*found;
        if (cursor_==idx) {
            auto next=sockets_.next_of(idx);
            cursor_=(next!=kNull) ? next : (sockets_.head()!=idx ? sockets_.head() : kNull);
        }
        sockets_.at(idx).socket.close();
        sockets_.erase(idx);
        if (sockets_.empty()) cursor_=kNull;
    }
    auto UdpRelay::clear() noexcept -> void {
        constexpr auto kNull=udp_detail::IntrusiveU64Table<Entry>::kNull;
        for (auto cur=sockets_.head();cur!=kNull;cur=sockets_.next_of(cur)) sockets_.at(cur).socket.close();
        sockets_.clear();
        cursor_=kNull;
    }
    auto UdpRelay::send(std::array<std::uint8_t,8> session,UdpPeer target,std::span<std::uint8_t const> payload)
        -> std::expected<void,UdpRelayFailure> {
        if (!valid(target) || (target.family==6 && std::ranges::all_of(std::span{target.address}.first<10>(),[](auto byte){return byte==0;}) && target.address[10]==255 && target.address[11]==255))
            return std::unexpected(failure(UdpRelayError::invalid_target));
        auto const key=udp_detail::id_to_u64(session);
        auto found=sockets_.find(key);
        bool fresh=!found.has_value();
        std::uint32_t idx=0;
        if (fresh) {
            if (max_targets_==0) return std::unexpected(failure(UdpRelayError::target_limit));
            if (sockets_.size()>=max_sessions_) return std::unexpected(failure(UdpRelayError::session_limit));
            idx=sockets_.emplace_back(key,binding_);
        } else {
            idx=*found;
        }
        auto& entry=sockets_.at(idx);
        auto& targets=entry.targets;
        auto pos=std::ranges::lower_bound(targets,target);
        bool const exists=pos!=targets.end() && *pos==target;
        if (!exists && targets.size()>=max_targets_) return std::unexpected(failure(UdpRelayError::target_limit));
        if (!exists) {
            try { pos=targets.insert(pos,target); }
            catch (...) { if (fresh) close(session); throw; }
        }
        auto sent=entry.socket.send(endpoint(target),payload);
        if (!sent) {
            auto e=system_failure(sent.error());
            if (!exists) targets.erase(pos);
            if (fresh) close(session);
            return std::unexpected(e);
        }
        return {};
    }
    auto UdpRelay::poll() -> std::expected<std::optional<UdpRelayReply>,UdpRelayFailure> {
        constexpr auto kNull=udp_detail::IntrusiveU64Table<Entry>::kNull;
        if (sockets_.empty()) return std::optional<UdpRelayReply>{};
        auto cur=cursor_!=kNull ? cursor_ : sockets_.head();
        auto count=std::min<std::size_t>(sockets_.size(),64);
        std::array<std::uint8_t,65536> buffer{};
        for (std::size_t i=0;i<count;++i) {
            auto next=sockets_.next_of(cur);
            if (next==kNull) next=sockets_.head();
            cursor_=next;
            auto& entry=sockets_.at(cur);
            auto const session=udp_detail::u64_to_id(sockets_.key_of(cur));
            auto received=entry.socket.receive(buffer);
            if (!received) {
                auto error=system_failure(received.error());
                close(session);
                return std::unexpected(error);
            }
            if (!*received || !(**received).valid) { cur=next; continue; }
            auto const& packet=**received;
            auto source=peer(packet.source);
            if (!std::ranges::binary_search(entry.targets,source)) { cur=next; continue; }
            return std::optional{UdpRelayReply{session,source,{buffer.begin(),buffer.begin()+packet.size}}};
        }
        return std::optional<UdpRelayReply>{};
    }
}
