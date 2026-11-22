export module uot.direct;
export import net.udp_direct;
export import socks5.udp_tunnel_authorization;
import rules;
import std;

export namespace uot {
    // UoT supplies framing and target addresses; the direct datagram endpoint
    // owns protocol-independent routing, reply authorization, and socket I/O.
    // Keep the existing SOCKS status values at the UoT boundary.
    using DirectError=std::variant<net::UdpRouteError,socks5::Status,std::error_code>;
    using DirectReply=net::UdpDirectReply;
    class Direct {
        net::UdpDirect direct_;
        static auto error(net::UdpDirectError const& failure) noexcept -> DirectError {
            return std::visit([](auto value) -> DirectError {
                if constexpr (std::same_as<decltype(value),net::UdpAuthorizationError>)
                    return socks5::udp_authorization_status(value);
                else return value;
            },failure);
        }
    public:
        explicit Direct(::rules::RouteMatcher const& policy) noexcept : direct_(policy) {}
        Direct(Direct const&)=delete;
        auto operator=(Direct const&) -> Direct& = delete;
        [[nodiscard]] auto send(net::UdpTarget target,net::UdpEndpoint candidate,std::span<std::uint8_t const> payload,
                                net::UdpEndpoint const* source=nullptr)
            -> std::expected<void,DirectError> {
            auto result=direct_.send(target,candidate,payload,source);
            if (!result) return std::unexpected(error(result.error()));
            return {};
        }
        [[nodiscard]] auto poll(std::span<std::uint8_t> buffer,bool* dropped=nullptr)
            -> std::expected<std::optional<DirectReply>,DirectError> {
            auto result=direct_.poll(buffer,dropped);
            if (!result) return std::unexpected(error(result.error()));
            return std::move(*result);
        }
        auto close() noexcept -> void { direct_.close(); }
    };
    static_assert(sizeof(Direct)==sizeof(net::UdpDirect));
}
