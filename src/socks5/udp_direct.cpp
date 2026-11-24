module socks5.udp_direct;
import std;
import rules;

namespace socks5 {
    UdpDirect::~UdpDirect() { close(); }
    auto UdpDirect::close() noexcept -> void { closed_=true; socket_.close(); }
    auto UdpDirect::send(UdpDatagram const& packet,UdpPeer candidate,std::chrono::steady_clock::time_point deadline) -> std::expected<void,UdpDirectError> {
        if (closed_ || association_.closed()) {
            close(); return std::unexpected(UdpDirectError{Status::association_closed});
        }
        if(deadline!=std::chrono::steady_clock::time_point::max() && std::chrono::steady_clock::now()>=deadline)
            return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        auto prepared=udp_prepare_send(association_,policy_,packet,candidate,auth_user_);
        if (!prepared) return std::unexpected(std::visit([](auto value) -> UdpDirectError { return value; },prepared.error()));
        auto rollback=[&] { (void)association_.finish_send(prepared->token,false); };
        if(deadline!=std::chrono::steady_clock::time_point::max() && std::chrono::steady_clock::now()>=deadline) {
            rollback();return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        }
        auto sent=socket_.send(prepared->target,packet.data,deadline);
        if (!sent) { rollback(); return std::unexpected(UdpDirectError{sent.error()}); }
        auto committed=association_.finish_send(prepared->token,true);
        if (!committed) return std::unexpected(UdpDirectError{committed.error()});
        return {};
    }
    auto UdpDirect::send_selected(UdpDatagram const& packet,UdpPeer candidate,std::chrono::steady_clock::time_point deadline) -> std::expected<void,UdpDirectError> {
        if(closed_ || association_.closed()) {close();return std::unexpected(UdpDirectError{Status::association_closed});}
        if(deadline!=std::chrono::steady_clock::time_point::max() && std::chrono::steady_clock::now()>=deadline)
            return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        if(!association_.client_peer())return std::unexpected(UdpDirectError{Status::unauthorized_source});
        auto target=net::udp_validate_candidate(udp_target(packet),udp_endpoint(candidate));
        if(!target)return std::unexpected(UdpDirectError{target.error()});
        auto peer=udp_peer(*target);
        auto token=association_.begin_send(peer);
        if(!token)return std::unexpected(UdpDirectError{token.error()});
        if(deadline!=std::chrono::steady_clock::time_point::max() && std::chrono::steady_clock::now()>=deadline) {
            (void)association_.finish_send(*token,false);return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        }
        auto sent=socket_.send(peer,packet.data,deadline);
        if(!sent) {(void)association_.finish_send(*token,false);return std::unexpected(UdpDirectError{sent.error()});}
        auto committed=association_.finish_send(*token,true);
        if(!committed)return std::unexpected(UdpDirectError{committed.error()});
        return {};
    }
    auto UdpDirect::poll(bool* consumed_packet) -> std::expected<std::optional<UdpDirectReply>,UdpDirectError> {
        if (consumed_packet) *consumed_packet=false;
        if (closed_ || association_.closed()) {
            close(); return std::unexpected(UdpDirectError{Status::association_closed});
        }
        std::array<std::uint8_t,65536> bytes{};
        auto peeked=socket_.peek(bytes);
        if (!peeked) return std::unexpected(UdpDirectError{peeked.error()});
        if (!*peeked) return std::optional<UdpDirectReply>{};
        auto const& received=**peeked;
        std::optional<UdpDirectReply> result;
        auto client=association_.client_peer();
        if (received.valid && client) {
            auto source=received.source;
            if (association_.accepts_reply(source)) {
                UdpDatagram packet; packet.address_type=source.address_type;
                packet.address_length=source.address_type==1 ? 4 : 16; packet.port=source.port;
                std::copy_n(source.address.begin(),packet.address_length,packet.address.begin());
                packet.data=std::span(bytes).first(received.size);
                auto client_limit=client->address_type==1 ? std::size_t{65507} : std::size_t{65527};
                if (packet.data.size()+6+packet.address_length<=client_limit) {
                    auto wire=encode_udp_datagram(packet);
                    if (wire) result=UdpDirectReply{*client,std::move(*wire),packet.data.size()};
                }
            }
        }
        auto consumed=socket_.consume();
        if (!consumed) return std::unexpected(UdpDirectError{consumed.error()});
        if (!*consumed) return std::optional<UdpDirectReply>{};
        if (consumed_packet) *consumed_packet=true;
        if (**consumed!=received.size) return std::optional<UdpDirectReply>{};
        return result;
    }
}
