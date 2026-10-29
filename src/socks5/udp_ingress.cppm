export module nexus.socks5.udp_ingress;
export import nexus.socks5.udp_direct;
import nexus.rules;
import std;

export namespace nexus::socks5 {
    struct UdpIngressStep {
        bool input=false, forwarded=false, delivered=false, backpressured=false;
        std::optional<UdpDirectError> input_error, output_error;
    };
    // Experimental single-owner driver. The policy and association outlive it.
    // Numeric destinations only; domains are reported unsupported. The caller
    // must drive step, enforce timeouts, and close it with the TCP control session.
    class UdpIngress {
        UdpAssociation& association_;
        UdpDirect direct_;
        int fd_=-1;
        bool closed_=false;
        std::optional<UdpDirectReply> pending_;
    public:
        UdpIngress(UdpAssociation& association, rules::RouteMatcher const& policy) noexcept
            : association_(association),direct_(association,policy) {}
        ~UdpIngress();
        UdpIngress(UdpIngress const&)=delete;
        auto operator=(UdpIngress const&) -> UdpIngress& = delete;
        // local must be an explicit non-wildcard IPv4 address; port 0 requests an ephemeral port.
        [[nodiscard]] auto open(UdpPeer local) -> std::expected<UdpPeer,UdpDirectError>;
        [[nodiscard]] auto step() -> std::expected<UdpIngressStep,UdpDirectError>;
        auto close() noexcept -> void;
    };
}
