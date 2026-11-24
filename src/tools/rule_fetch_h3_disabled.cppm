export module cli.rule_fetch_h3;
import std;
export import functional;
import cli.rule_fetch_response;
import platform.socket_options;
import relay;
import tls.profiles;
import capy;
import corosio;

export namespace cli::rule_fetch {
    inline constexpr bool http3_enabled=false;
    using Http3Resolver=functional::move_only_function<
        capy::task<std::expected<std::vector<corosio::endpoint>,int>>(std::chrono::steady_clock::time_point)>;

    struct Http3Tunnel {
        std::unique_ptr<relay::Session> session;
        std::unique_ptr<relay::PacketTunnel> tunnel;

        ~Http3Tunnel() {
            if (tunnel) tunnel->cancel();
            if (session) session->close();
        }
    };
    using Http3TunnelFactory=functional::move_only_function<std::unique_ptr<Http3Tunnel>() const>;

    struct Http3Dial {
        corosio::io_context& context;
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
        auto request(Http3Resolver,Http3Dial,Http3TunnelFactory,Transfer) -> capy::task<TransferResult> {
            co_return std::unexpected("HTTP/3 rule fetch is unavailable in this build");
        }
    };
}
