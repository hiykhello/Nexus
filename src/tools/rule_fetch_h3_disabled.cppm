export module cli.rule_fetch_h3;
import std;
export import nexus.compat;
import cli.rule_fetch_response;
import platform.socket_options;
import proxy;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace cli::rule_fetch {
    inline constexpr bool http3_enabled=false;
    using Http3Resolver=nexus::move_only_function<
        nex::capy::task<std::expected<std::vector<nex::corosio::endpoint>,int>>(std::chrono::steady_clock::time_point)>;

    struct Http3Tunnel {
        std::unique_ptr<proxy::Session> session;
        std::unique_ptr<proxy::PacketTunnel> tunnel;

        ~Http3Tunnel() {
            if (tunnel) tunnel->cancel();
            if (session) session->close();
        }
    };
    using Http3TunnelFactory=nexus::move_only_function<std::unique_ptr<Http3Tunnel>() const>;

    struct Http3Dial {
        nex::corosio::io_context& context;
        tls::ShapedClientProfile const& tls;
        platform::SocketBinding const& binding;
        std::string_view ech_file;
        std::optional<std::size_t> max_udp_payload;
        bool disable_pmtu;
        std::chrono::steady_clock::time_point connect_deadline;
        std::uint16_t port;
    };

    class Http3Pool {
    public:
        auto stop() noexcept -> void {}
        auto request(Http3Resolver,Http3Dial,Http3TunnelFactory,Transfer) -> nex::capy::task<TransferResult> {
            co_return std::unexpected("HTTP/3 rule fetch is unavailable in this build");
        }
    };
}
