module shadowsocks.udp_server;
import std;
import shadowsocks.udp_cipher;
namespace shadowsocks {
    auto UdpServer::receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
        UdpPeer peer,std::chrono::steady_clock::time_point now,std::uint64_t wall,bool allow_new,
        std::optional<UdpRequestIdentity> identity)
        -> std::expected<UdpAccepted,UdpSessionError> {
        return sessions_->receive(psk,wire,peer,now,wall,{listener_generation_,allow_new,identity});
    }
    auto UdpServer::forward(UdpAccepted const& packet,UdpPeer target)
        -> std::expected<void,UdpServerFailure> {
        if (!current(packet)) return std::unexpected(UdpServerFailure{UdpSessionError::missing});
        UdpSessionHandle handle{packet.packet.session_id,packet.generation,packet.owner};
        auto credit=reserve_bytes(handle,true,packet.packet.payload.size(),std::chrono::steady_clock::now());
        if (!credit) return std::unexpected(UdpServerFailure{UdpSessionError::byte_quota});
        auto sent=relay_.send(packet.packet.session_id,target,packet.packet.payload);
        if (sent) credit->complete(packet.packet.payload.size());
        if (!sent) return std::unexpected(UdpServerFailure{sent.error()});
        return {};
    }
    auto UdpServer::tunnel_response(std::span<std::uint8_t const> psk,UdpSessionHandle const& session,UdpPeer source,
        std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point now,std::uint64_t wall)
        -> std::expected<std::optional<UdpResponse>,UdpSessionError> {
        if (!current(session)) return std::unexpected(UdpSessionError::missing);
        if ((source.family!=4 && source.family!=6) || !source.port ||
            std::ranges::all_of(source.address,[](auto b){return b==0;}) ||
            (source.family==4 && std::ranges::any_of(std::span(source.address).subspan(4),[](auto b){return b!=0;})))
            return std::unexpected(UdpSessionError::invalid_peer);
        auto peer=sessions_->peer(session.id);
        if (!peer) return std::unexpected(UdpSessionError::missing);
        auto size=source.family==4 ? 4u : 16u;
        auto address_size=size+3;
        auto framing=udp_cipher_overhead(sessions_->method())+19;
        auto limit=peer->family==4 ? std::size_t{65507} : std::size_t{65527};
        if (payload.size()>limit-framing-address_size) return std::optional<UdpResponse>{};
        std::array<std::uint8_t,19> address{};address[0]=source.family==4 ? 1 : 4;
        std::copy_n(source.address.begin(),size,address.begin()+1);
        address[size+1]=static_cast<std::uint8_t>(source.port>>8);address[size+2]=static_cast<std::uint8_t>(source.port);
        auto response=sessions_->response(psk,session.id,std::span(address).first(address_size),payload,{},now,wall);
        if (!response) return std::unexpected(response.error());
        return std::optional{std::move(*response)};
    }
    auto UdpServer::poll(std::span<std::uint8_t const> psk,std::chrono::steady_clock::time_point now,std::uint64_t wall)
        -> std::expected<std::optional<UdpResponse>,UdpServerFailure> {
        auto result=relay_.poll();
        if (!result) return std::unexpected(UdpServerFailure{result.error()});
        if (!*result) return std::optional<UdpResponse>{};
        auto& reply=**result;
        std::vector<std::uint8_t> address;
        address.reserve(reply.source.family==4 ? 7 : 19);
        address.push_back(reply.source.family==4 ? 1 : 4);
        auto size=reply.source.family==4 ? 4 : 16;
        address.insert(address.end(),reply.source.address.begin(),reply.source.address.begin()+size);
        address.push_back(static_cast<std::uint8_t>(reply.source.port>>8));
        address.push_back(static_cast<std::uint8_t>(reply.source.port));
        // The encrypted datagram must fit the client's IP family as well as
        // the SS-2022 framing. A large upstream reply is a packet-level drop,
        // not a reason to stop unrelated sessions or the listener.
        auto peer=sessions_->peer(reply.session);
        if (peer) {
            auto framing=udp_cipher_overhead(sessions_->method())+19;
            auto limit=peer->family==4 ? std::size_t{65507} : std::size_t{65527};
            if (reply.payload.size()>limit-framing-address.size()) return std::optional<UdpResponse>{};
        }
        auto response=sessions_->response(psk,reply.session,address,reply.payload,{},now,wall);
        if (!response) return std::unexpected(UdpServerFailure{response.error()});
        return std::optional{std::move(*response)};
    }
    auto UdpServer::expire(std::chrono::steady_clock::time_point now,std::uint64_t wall)
        -> std::expected<std::size_t,UdpSessionError> {
        auto expired=sessions_->expire(now,wall,listener_generation_);
        if (!expired) return std::unexpected(expired.error());
        for (auto const& id:*expired) relay_.close(id);
        return expired->size();
    }
}
