export module socks5.udp_ingress;
export import socks5.udp_direct;
import rules;
import std;
import capy;
import corosio;
import net.principal_bytes;
import platform.socket_options;
import net.stream_relay;

export namespace socks5 {
    struct UdpIngressStep {
        bool input=false, forwarded=false, input_backpressured=false, domain_pending=false, route_pending=false, tunnel_pending=false, delivered=false, backpressured=false, output_dropped=false;
        std::optional<UdpDirectError> input_error, output_error;
    };
    struct UdpRouteMetadata {
        std::chrono::steady_clock::time_point deadline{};
        bool quic_inspected=false;
        std::optional<std::string> quic_domain;
        bool quic_matched=false;
        std::chrono::steady_clock::time_point started{};
    };
    struct UdpRouteLookahead {
        UdpDatagram packet;
        UdpPeer source;
        std::chrono::steady_clock::time_point deadline;
    };
    enum class UdpReplyStatus { queued, busy, dropped };
    struct UdpTunnelAlias {
        UdpPeer endpoint;
        std::shared_ptr<void> lease;
    };
    struct UdpTunnelPacket {
        UdpDatagram packet;
        UdpPeer target;
        std::size_t outbound;
        std::chrono::steady_clock::time_point deadline;
        std::optional<UdpTunnelAlias> alias{};
    };
    struct UdpRouteDelivery {
        void* context=nullptr;
        void (*record)(void*,bool,UdpSelection const&) noexcept=nullptr;
        auto operator()(bool ordered,UdpSelection const& route) const noexcept -> void {
            if (record) record(context,ordered,route);
        }
    };
    // Experimental single-owner driver. The policy and association outlive it.
    // Domain resolution is opt-in. The caller must drive step, enforce timeouts,
    // complete or discard a pending domain, and close it with the TCP session.
    class UdpIngress {
        UdpAssociation& association_;
        rules::RouteMatcher const& policy_;
        std::optional<std::string_view> auth_user_;
        UdpDirect direct_;
        net::stream_relay::Delivery delivery_;
        UdpRouteDelivery route_delivery_;
        net::PrincipalBytes const* byte_budget_=nullptr;
        auto reserve_bytes(bool upstream,std::size_t size) const -> std::optional<net::PrincipalBytes::Reservation>;
        auto send_target(UdpDatagram const&,UdpPeer,std::chrono::steady_clock::time_point)
            -> std::expected<void,UdpDirectError>;
        int fd_=-1;
        bool closed_=false, waiting_=false;
        std::uint8_t backpressured_family_=0;
        std::array<std::uint8_t,65536> input_bytes_{};
        std::size_t input_size_=0;
        UdpPeer input_source_{};
        UdpRouteMetadata input_metadata_;
        bool input_pending_=false;
        bool allow_domains_=false, domain_pending_=false, allow_tunnels_=false;
        bool external_route_=false,route_pending_=false;
        struct AliasRelay {
            UdpPeer alias, target;
            std::shared_ptr<void> lease;
            std::unique_ptr<UdpSocket> socket;
            std::chrono::steady_clock::time_point touched;
        };
        std::vector<AliasRelay> aliases_;
        std::size_t next_alias_ = 0;
        bool alias_turn_ = false;
        platform::SocketBinding const* binding_;
        void const* filter_context_ = nullptr;
        bool (*allow_target_)(void const*, UdpPeer const&) noexcept = nullptr;
        struct DeferredRoute { std::vector<std::uint8_t> wire; UdpPeer source; UdpRouteMetadata metadata; };
        std::deque<DeferredRoute> deferred_;
        std::size_t deferred_bytes_=0;
        static constexpr std::size_t deferred_limit_=8, deferred_byte_limit_=256*1024;
        std::vector<std::uint8_t> parked_bytes_;
        UdpPeer parked_source_{};
        UdpRouteMetadata parked_metadata_;
        bool parked_=false,replaying_=false,collecting_=false;
        auto poll_aliases(UdpIngressStep&) -> void;
        auto queue_reply(UdpDatagram) -> std::expected<UdpReplyStatus,UdpDirectError>;
        auto promote_parked() -> void;
        auto read_lookahead(UdpIngressStep&) -> std::expected<void,UdpDirectError>;
        std::optional<UdpSelection> tunnel_;
        std::optional<UdpTunnelAlias> tunnel_alias_;
        std::optional<UdpDirectReply> pending_;
        struct Watch { int fd; corosio::udp_socket socket; };
        std::vector<Watch> watches_;
        capy::async_event changed_,work_;
    public:
        // auth_user is borrowed until this driver and its pending work are destroyed.
        UdpIngress(UdpAssociation& association, rules::RouteMatcher const& policy, bool allow_domains=false, bool allow_tunnels=false,
                   std::optional<std::string_view> auth_user={},platform::SocketBinding const* binding=nullptr,bool external_route=false,
                   net::stream_relay::Delivery delivery={},UdpRouteDelivery route_delivery={}) noexcept
            : association_(association),policy_(policy),auth_user_(auth_user),direct_(association,policy,auth_user,binding),
              delivery_(delivery),route_delivery_(route_delivery),allow_domains_(allow_domains),allow_tunnels_(allow_tunnels),
              external_route_(external_route),binding_(binding) {}
        ~UdpIngress();
        auto set_byte_budget(net::PrincipalBytes const& budget) noexcept -> void {byte_budget_=&budget;}
        // The borrowed context must survive until the association drains.
        auto set_destination_filter(void const* context,
            bool (*allow)(void const*, UdpPeer const&) noexcept) noexcept -> void {
            filter_context_ = context;
            allow_target_ = allow;
        }
        UdpIngress(UdpIngress const&)=delete;
        auto operator=(UdpIngress const&) -> UdpIngress& = delete;
        // local must be an explicit non-wildcard IPv4 or unscoped IPv6 address;
        // port 0 requests an ephemeral port. IPv4-mapped IPv6 is not accepted.
        [[nodiscard]] auto open(UdpPeer local) -> std::expected<UdpPeer,UdpDirectError>;
        // A permanent ingress socket read failure closes the driver and is returned
        // as an error; malformed or unauthorized datagrams are reported per step.
        [[nodiscard]] auto step() -> std::expected<UdpIngressStep,UdpDirectError>;
        // Wait for an ingress or selected direct-reply socket to become ready.
        // This is the only idle wait used by the SOCKS UDP driver.
        auto wait(corosio::io_context&,UdpIngressStep const&,std::chrono::steady_clock::time_point)
            -> capy::task<bool>;
        auto changed() noexcept -> capy::async_event& { return changed_; }
        auto wake() noexcept -> void { work_.set(); changed_.set(); }
        // External routing owns the one admitted datagram until selection or
        // discard. This preserves both packet and authenticated source views.
        [[nodiscard]] auto pending_route() const noexcept -> std::optional<UdpDatagram>;
        [[nodiscard]] auto pending_route_source() const noexcept -> std::optional<UdpPeer> {
            return route_pending_ ? std::optional<UdpPeer>{input_source_} : std::nullopt;
        }
        // A borrowed head remains fixed through DNS, sniff and proxy handoff.
        // Metadata moves with it; replay never grants a fresh deadline.
        [[nodiscard]] auto route_metadata() const noexcept -> UdpRouteMetadata const* {
            return route_pending_ ? &input_metadata_ : nullptr;
        }
        auto limit_route(std::chrono::milliseconds limit) noexcept -> std::chrono::steady_clock::time_point {
            input_metadata_.deadline=std::min(input_metadata_.deadline,input_metadata_.started+limit);
            return input_metadata_.deadline;
        }
        [[nodiscard]] auto remember_route_sniff(std::optional<std::string>,bool matched=false) -> bool;
        // Only step() appends while collecting; the routing coroutine may read
        // and annotate stable tail indices, but cannot consume them yet.
        [[nodiscard]] auto begin_route_lookahead() -> bool;
        auto end_route_lookahead() noexcept -> void {collecting_=false;wake();}
        [[nodiscard]] auto route_lookahead_full() const noexcept -> bool {
            // Legacy defer/replay can leave the overflow packet in current.
            return parked_ || deferred_.size()>=deferred_limit_ || input_size_+deferred_bytes_>deferred_byte_limit_;
        }
        [[nodiscard]] auto lookahead_route(std::size_t) const noexcept -> std::optional<UdpRouteLookahead>;
        [[nodiscard]] auto remember_lookahead_sniff(std::size_t,std::optional<std::string>,bool matched=false) -> bool;
        [[nodiscard]] auto send_selected(UdpPeer candidate,std::size_t outbound,std::optional<std::size_t> rule={})
            -> std::expected<void,UdpDirectError>;
        [[nodiscard]] auto send_alias(UdpDatagram const& domain,UdpPeer target,
            std::shared_ptr<void> lease,std::optional<std::size_t> rule={},
            std::optional<std::size_t> predicate={},std::size_t outbound=0)
            -> std::expected<void,UdpDirectError>;
        auto discard_route() noexcept -> void;
        [[nodiscard]] auto reply_route(std::span<std::uint8_t const>) -> std::expected<UdpReplyStatus,UdpDirectError>;
        // Move an admitted datagram into bounded owned storage while collecting
        // subsequent datagrams. A failed defer leaves the current packet intact.
        // Restore in FIFO order only after sniffing has stopped; restored packets
        // were already admitted and must not be re-admitted or reauthenticated.
        [[nodiscard]] auto defer_route() -> bool;
        // Start replay even when the current packet could not fit in the
        // deferred queue. The current packet is parked behind earlier packets.
        [[nodiscard]] auto begin_deferred_replay() -> bool;
        [[nodiscard]] auto replay_deferred() noexcept -> bool;
        [[nodiscard]] auto deferred_count() const noexcept -> std::size_t { return deferred_.size(); }
        [[nodiscard]] auto deferred_bytes() const noexcept -> std::size_t { return deferred_bytes_; }
        // The returned data borrows the driver until completion, discard or close.
        [[nodiscard]] auto pending_domain() const noexcept -> std::optional<UdpDatagram>;
        // The admitted datagram peer stays fixed while its domain is pending.
        [[nodiscard]] auto pending_domain_source() const noexcept -> std::optional<UdpPeer> {
            return domain_pending_ ? std::optional<UdpPeer>{input_source_} : std::nullopt;
        }
        [[nodiscard]] auto pending_domain_deadline() const noexcept -> std::chrono::steady_clock::time_point {
            return input_metadata_.deadline;
        }
        // Failure leaves the request pending, allowing another candidate or retry.
        [[nodiscard]] auto send_resolved(UdpPeer candidate) -> std::expected<void,UdpDirectError>;
        auto discard_domain() noexcept -> void;
        // Holding this packet also prevents admission of another domain request,
        // serializing its bootstrap lookup with the preceding target lookup.
        // The packet borrows the input buffer until complete_tunnel() or close().
        // This handoff does not authorize replies; each tunnel must maintain its
        // own bounded target authorization and commit only after successful send.
        [[nodiscard]] auto pending_tunnel() const noexcept -> std::optional<UdpTunnelPacket>;
        auto complete_tunnel(bool delivered=false) noexcept -> void;
        // Caller verifies source against the particular tunnel's successful sends.
        // A busy result consumes nothing; queued data is owned until delivered.
        [[nodiscard]] auto queue_tunnel_reply(UdpPeer source, std::span<std::uint8_t const> payload)
            -> std::expected<UdpReplyStatus,UdpDirectError>;
        auto close() noexcept -> void;
    };
}
