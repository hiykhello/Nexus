module nexus.shadowsocks.udp_server;
import std;
namespace nexus::shadowsocks {
    auto UdpServer::receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
        UdpPeer peer,std::chrono::steady_clock::time_point now,std::uint64_t wall)
        -> std::expected<UdpAccepted,UdpSessionError> {
        return sessions_.receive(psk,wire,peer,now,wall);
    }
    auto UdpServer::forward(UdpAccepted const& packet,UdpPeer target)
        -> std::expected<void,UdpServerFailure> {
        if (!sessions_.current(packet)) return std::unexpected(UdpServerFailure{UdpSessionError::missing});
        auto sent=relay_.send(packet.packet.session_id,target,packet.packet.payload);
        if (!sent) return std::unexpected(UdpServerFailure{sent.error()});
        return {};
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
        auto peer=sessions_.peer(reply.session);
        if (peer) {
            constexpr std::size_t framing=32+19; // encrypted header/tag and server body fields
            auto limit=peer->family==4 ? std::size_t{65507} : std::size_t{65527};
            if (reply.payload.size()>limit-framing-address.size()) return std::optional<UdpResponse>{};
        }
        auto response=sessions_.response(psk,reply.session,address,reply.payload,{},now,wall);
        if (!response) return std::unexpected(UdpServerFailure{response.error()});
        return std::optional{std::move(*response)};
    }
    auto UdpServer::expire(std::chrono::steady_clock::time_point now,std::uint64_t wall)
        -> std::expected<std::size_t,UdpSessionError> {
        auto expired=sessions_.expire(now,wall);
        if (!expired) return std::unexpected(expired.error());
        for (auto const& id:*expired) relay_.close(id);
        return expired->size();
    }
}
