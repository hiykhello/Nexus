export module nexus.socks5.udp_ingress;
export import nexus.socks5.udp_direct;
import nexus.rules;
import std;

export namespace nexus::socks5 {
    struct UdpIngressStep {
        bool input=false, forwarded=false, input_backpressured=false, domain_pending=false, delivered=false, backpressured=false;
        std::optional<UdpDirectError> input_error, output_error;
    };
    // Experimental single-owner driver. The policy and association outlive it.
    // Domain resolution is opt-in. The caller must drive step, enforce timeouts,
    // complete or discard a pending domain, and close it with the TCP session.
    class UdpIngress {
        UdpAssociation& association_;
        rules::RouteMatcher const& policy_;
        UdpDirect direct_;
        int fd_=-1;
        bool closed_=false;
        std::array<std::uint8_t,65536> input_bytes_{};
        std::size_t input_size_=0;
        UdpPeer input_source_{};
        bool input_pending_=false;
        bool allow_domains_=false, domain_pending_=false;
        std::optional<UdpDirectReply> pending_;
    public:
        UdpIngress(UdpAssociation& association, rules::RouteMatcher const& policy, bool allow_domains=false) noexcept
            : association_(association),policy_(policy),direct_(association,policy),allow_domains_(allow_domains) {}
        ~UdpIngress();
        UdpIngress(UdpIngress const&)=delete;
        auto operator=(UdpIngress const&) -> UdpIngress& = delete;
        // local must be an explicit non-wildcard IPv4 address; port 0 requests an ephemeral port.
        [[nodiscard]] auto open(UdpPeer local) -> std::expected<UdpPeer,UdpDirectError>;
        // A permanent ingress socket read failure closes the driver and is returned
        // as an error; malformed or unauthorized datagrams are reported per step.
        [[nodiscard]] auto step() -> std::expected<UdpIngressStep,UdpDirectError>;
        // The returned data borrows the driver until completion, discard or close.
        [[nodiscard]] auto pending_domain() const noexcept -> std::optional<UdpDatagram>;
        // Failure leaves the request pending, allowing another candidate or retry.
        [[nodiscard]] auto send_resolved(UdpPeer candidate) -> std::expected<void,UdpDirectError>;
        auto discard_domain() noexcept -> void;
        auto close() noexcept -> void;
    };
}
