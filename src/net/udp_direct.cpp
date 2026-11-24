module net.udp_direct;
import std;

namespace net {
    auto UdpDirect::send(UdpTarget packet,UdpEndpoint candidate,std::span<std::uint8_t const> payload,UdpEndpoint const* source,std::optional<std::string_view> auth_user,
                         std::optional<std::chrono::steady_clock::time_point> deadline) -> std::expected<void,UdpDirectError> {
        if (closed_) return std::unexpected(UdpDirectError{UdpAuthorizationError::closed});
        auto target=udp_route(policy_,packet,candidate,source,auth_user);
        if (!target) return std::unexpected(UdpDirectError{target.error()});
        if(deadline && std::chrono::steady_clock::now()>=*deadline)
            return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        auto token=authorization_.begin(*target);
        if (!token) return std::unexpected(UdpDirectError{token.error()});
        auto sent=socket_.send(*target,payload,deadline.value_or(platform::SocketDeadline::max()));
        auto expired=deadline && std::chrono::steady_clock::now()>=*deadline;
        auto finished=authorization_.finish(*token,sent.has_value() && !expired);
        if (!finished) return std::unexpected(UdpDirectError{finished.error()});
        if (!sent) return std::unexpected(UdpDirectError{sent.error()});
        if(expired)return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        return {};
    }
    auto UdpDirect::send_selected(UdpTarget packet,UdpEndpoint candidate,std::span<std::uint8_t const> payload,
                                  std::optional<std::chrono::steady_clock::time_point> deadline) -> std::expected<void,UdpDirectError> {
        if(closed_)return std::unexpected(UdpDirectError{UdpAuthorizationError::closed});
        auto target=udp_validate_candidate(packet,candidate);
        if(!target)return std::unexpected(UdpDirectError{target.error()});
        if(deadline && std::chrono::steady_clock::now()>=*deadline)
            return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        auto token=authorization_.begin(*target);
        if(!token)return std::unexpected(UdpDirectError{token.error()});
        auto sent=socket_.send(*target,payload,deadline.value_or(platform::SocketDeadline::max()));
        auto expired=deadline && std::chrono::steady_clock::now()>=*deadline;
        auto finished=authorization_.finish(*token,sent.has_value() && !expired);
        if(!finished)return std::unexpected(UdpDirectError{finished.error()});
        if(!sent)return std::unexpected(UdpDirectError{sent.error()});
        if(expired)return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        return {};
    }
    auto UdpDirect::poll(std::span<std::uint8_t> buffer,bool* dropped) -> std::expected<std::optional<UdpDirectReply>,UdpDirectError> {
        if (dropped) *dropped=false;
        if (closed_) return std::unexpected(UdpDirectError{UdpAuthorizationError::closed});
        auto packet=socket_.peek(buffer);
        if (!packet) return std::unexpected(UdpDirectError{packet.error()});
        if (!*packet) return std::optional<UdpDirectReply>{};
        auto meta=**packet;
        auto consumed=socket_.consume();
        if (!consumed) return std::unexpected(UdpDirectError{consumed.error()});
        if (!*consumed) return std::optional<UdpDirectReply>{};
        if (**consumed!=meta.size || !meta.valid || !authorization_.accepts(meta.source)) {
            if (dropped) *dropped=true;
            return std::optional<UdpDirectReply>{};
        }
        return std::optional{UdpDirectReply{meta.source,meta.size}};
    }
    auto UdpDirect::native_handles() const noexcept -> std::array<int,2> {
        return closed_ ? std::array{-1,-1} : socket_.native_handles();
    }
    auto UdpDirect::close() noexcept -> void { closed_=true; authorization_.close(); socket_.close(); }
}
