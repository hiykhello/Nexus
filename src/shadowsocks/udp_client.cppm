export module nexus.shadowsocks.udp_client;
import std;
import nexus.shadowsocks.udp_replay;
export import nexus.shadowsocks.udp_packet;

export namespace nexus::shadowsocks {
    enum class UdpClientError { invalid_key, packet, duplicate, too_old, full, exhausted, time_reversed,
                                missing, random, session_conflict, failed };

    // Experimental serialized owner for one client session. Its creator must
    // guarantee a unique client ID for this PSK, including all other owners,
    // server IDs and restarts. The owner does not provide durable state.
    class UdpClientSession {
        using Clock=std::chrono::steady_clock;
        std::array<std::uint8_t,32> key_{};
        std::size_t key_size_=0;
        std::array<std::uint8_t,8> client_{};
        std::uint64_t next_=0;
        bool exhausted_=false;
        bool clock_failed_=false;
        std::optional<Clock::time_point> last_;
        Clock::time_point anchor_mono_{};
        std::uint64_t anchor_wall_=0;
        std::uint64_t last_wall_=0;
        std::size_t capacity_;
        std::map<std::array<std::uint8_t,8>,UdpReplayWindow> servers_;
        [[nodiscard]] auto advance(Clock::time_point now, std::uint64_t wall) noexcept -> bool;
    public:
        UdpClientSession(std::span<std::uint8_t const> key, std::array<std::uint8_t,8> client,
                         std::size_t server_capacity);
        ~UdpClientSession();
        UdpClientSession(UdpClientSession const&)=delete;
        auto operator=(UdpClientSession const&) -> UdpClientSession& = delete;
        // Consumes the packet ID even when encoding fails. A failed or dropped
        // send must never be retried by reusing its packet ID.
        [[nodiscard]] auto request(std::span<std::uint8_t const> address,
            std::span<std::uint8_t const> payload, std::span<std::uint8_t const> padding,
            Clock::time_point now, std::uint64_t wall) -> std::expected<std::vector<std::uint8_t>,UdpClientError>;
        // The transport must independently verify the remote endpoint. Auth
        // and semantic validation precede allocation and replay updates.
        [[nodiscard]] auto receive(std::span<std::uint8_t const> wire, Clock::time_point now, std::uint64_t wall)
            -> std::expected<UdpPacket,UdpClientError>;
    };

    // Experimental single-key, single-executor owner. Historical IDs are
    // retained until destruction; capacity exhaustion fails closed. An
    // independent owner or a restart is not coordinated by this object.
    // A previously unseen server ID may already have collided with a locally
    // emitted ID before its first response; detection cannot undo that event.
    class UdpClientPool {
        using Clock=std::chrono::steady_clock;
        using Id=std::array<std::uint8_t,8>;
        std::array<std::uint8_t,32> key_{};
        std::size_t key_size_=0, active_limit_, history_limit_, server_limit_;
        std::optional<std::uint64_t> next_;
        bool exhausted_=false, failed_=false;
        std::optional<Clock::time_point> last_;
        Clock::time_point anchor_mono_{};
        std::uint64_t anchor_wall_=0, last_wall_=0;
        std::set<Id> clients_;
        std::map<Id,Id> servers_;
        std::map<Id,std::unique_ptr<UdpClientSession>> active_;
        [[nodiscard]] auto advance(Clock::time_point now, std::uint64_t wall) noexcept -> bool;
    public:
        UdpClientPool(std::span<std::uint8_t const> key, std::size_t active_limit,
                      std::size_t history_limit, std::size_t server_limit);
        ~UdpClientPool();
        UdpClientPool(UdpClientPool const&)=delete;
        auto operator=(UdpClientPool const&) -> UdpClientPool& = delete;
        [[nodiscard]] auto open() -> std::expected<Id,UdpClientError>;
        [[nodiscard]] auto close(Id id) noexcept -> bool;
        [[nodiscard]] auto request(Id id, std::span<std::uint8_t const> address,
            std::span<std::uint8_t const> payload, std::span<std::uint8_t const> padding,
            Clock::time_point now, std::uint64_t wall) -> std::expected<std::vector<std::uint8_t>,UdpClientError>;
        [[nodiscard]] auto receive(Id id, std::span<std::uint8_t const> wire, Clock::time_point now,
            std::uint64_t wall) -> std::expected<UdpPacket,UdpClientError>;
    };
}
