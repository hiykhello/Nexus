export module wireguard.port_types;
import std;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.host;
import wireguard.identity;
import wireguard.registry;
import wireguard.routing;

export namespace wireguard {
    enum class PortError { closed,not_open,already_open,clock,configuration,identity,entropy,allocation,io,stale_peer,route,host,endpoint,timeout,queue_full,no_route,policy_exhausted };
    struct PortFailure {
        PortError code;
        std::error_code system;
        std::optional<EndpointFailure> endpoint;
        std::optional<HostFailure> host;
        std::optional<routing::RouteError> route;
        std::optional<identity::Failure> identity;
    };
    struct PortOptions {
        std::size_t business_packets=64,business_bytes=1024*1024;
        std::chrono::milliseconds tick{10};
        bool require_cookie=false,auto_cookie=false;
    };
    struct PortMetrics {
        std::uint64_t received=0,sent=0,dropped=0,delivered=0,send_errors=0,authentication_rejects=0,replay_rejects=0,source_rejects=0,rate_limit_rejects=0;
    };
    struct PortStatus {
        RegistryStatus registry;
        HostQueueStatus ingress;
        std::size_t routes=0,keys=0,delivery_packets=0,delivery_bytes=0,pending_sends=0,business_packets=0,business_bytes=0;
        PortMetrics metrics;
        bool opened=false,stopped=false,automatic_cookie_active=false;
    };
    struct PortProgress {
        std::size_t received=0,sent=0,processed=0;
        bool read_paused=false,write_blocked=false;
        Clock::time_point next_poll;
        std::optional<std::error_code> send_error;
    };
    template<std::size_t Capacity> struct PortPacket {
        PeerHandle peer;
        std::array<std::uint8_t,Capacity> bytes{};
        std::size_t size=0;
        std::uint64_t serial=0;
        std::uint64_t policy_epoch=0;
        [[nodiscard]] auto packet() const noexcept -> std::span<std::uint8_t const> { return std::span(bytes).first(size); }
    };
    // A static test seam only. The ordinary specialization folds this empty
    // result away; it owns no hook object/counter or runtime dispatch.
    struct PortNoHooks {
        static auto before_send(std::optional<PeerHandle>,OutboundKind,std::span<std::uint8_t const>) noexcept -> std::optional<std::error_code> { return {}; }
    };
    struct PortOuterAllowAll {
        [[nodiscard]] constexpr auto allows(EndpointAddress const&) const noexcept -> bool { return true; }
    };
    // The ordinary port erases this stateless wire policy at compile time.
    struct PortStandardWire {};
    struct PortNoSocketPreparation {};
    namespace port_detail {
        // Counts only handshake-shaped UDP packets, not ordinary transport
        // traffic. This is a conservative pressure signal, not authentication
        // or an estimate of actual CPU load. Owned by a single port executor.
        class HandshakePressure {
            static constexpr auto cost=std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(31250000));
            static constexpr auto capacity=cost*32;
            static constexpr auto hold=std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1));
            static_assert(cost>Clock::duration::zero());
            Clock::duration tokens_=capacity;
            std::optional<Clock::time_point> updated_,until_;
        public:
            [[nodiscard]] auto active(Clock::time_point now) const noexcept -> bool {return until_ && now<*until_;}
            auto observe(Clock::time_point now) noexcept -> bool {
                if(updated_) {
                    if(now<*updated_)return active(*updated_);
                    auto elapsed=now-*updated_;
                    tokens_=elapsed>=capacity ? capacity : std::min(capacity,tokens_+elapsed);
                }
                updated_=now;
                if(tokens_>=cost)tokens_-=cost;
                else until_=now.time_since_epoch()>Clock::duration::max()-hold ? Clock::time_point::max() : now+hold;
                return active(now);
            }
        };
        struct StandardWireRestore {};
        struct ProviderWireRestore {
            std::span<std::uint8_t> bytes{};
            ~ProviderWireRestore(){std::ranges::fill(bytes,0);}
        };
        inline auto failure(PortError code,std::error_code system={}) -> std::unexpected<PortFailure> { return std::unexpected(PortFailure{.code=code,.system=system}); }
        inline auto endpoint_failure(EndpointFailure error) -> std::unexpected<PortFailure> { return std::unexpected(PortFailure{.code=PortError::endpoint,.endpoint=error}); }
        inline auto host_failure(HostFailure error) -> std::unexpected<PortFailure> { return std::unexpected(PortFailure{.code=PortError::host,.host=error}); }
        inline auto route_failure(routing::RouteError error) -> std::unexpected<PortFailure> { return std::unexpected(PortFailure{.code=PortError::route,.route=error}); }
        inline auto identity_failure(identity::Failure error) -> std::unexpected<PortFailure> { return std::unexpected(PortFailure{.code=PortError::identity,.identity=error}); }
        inline auto after(Clock::time_point now,Clock::duration delay) noexcept -> Clock::time_point {
            return now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
        }
    }
}
