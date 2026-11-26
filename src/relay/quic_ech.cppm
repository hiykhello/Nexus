module relay:quic_ech;
import std;
import config;
import quic.ech_config;
import capy;
import corosio;
import :types;
import :route_interface;
import :session_interface;

namespace relay {
    namespace quic_ech {
        enum class Transport : std::uint8_t { quic, tcp };

        struct Profile {
            std::optional<quic::EchConfig> config;
            std::string dns_name;
            std::string server_name;
            using Result = std::expected<std::optional<quic::EchConfig>, std::string>;

            static auto load(config::QuicEchOptions const&, std::string_view, bool)
                -> std::expected<Profile, std::string>;
            auto resolve(Session&, corosio::io_context&, DnsSlot&, std::optional<std::size_t>, std::uint16_t,
                         Clock::time_point, Transport = Transport::quic) const -> capy::task<Result>;
        };
    }
}
