export module nexus.shadowsocks.udp_sessions;
import std;
import nexus.shadowsocks.udp_packet;
import nexus.shadowsocks.udp_replay;
import nexus.shadowsocks.udp_id_reservation;

export namespace nexus::shadowsocks {
    struct UdpPeer {
        // Family is 4 or 6; IPv4 uses the first four address bytes and zeros the rest.
        std::uint8_t family=0;
        std::array<std::uint8_t,16> address{};
        std::uint16_t port=0;
        // Opaque owner-local listener index, used only for client replies.
        std::size_t ingress=0;
        auto operator<=>(UdpPeer const&) const = default;
    };
    enum class UdpSessionError { packet, invalid_peer, time_reversed, duplicate, too_old, full, missing, random, exhausted, key_mismatch,
                                 storage, durability_required, busy, invalid_state, session_id_conflict };
    class UdpServerSessions;
    struct UdpAccepted { UdpPacket packet; bool new_session; std::uint64_t generation; UdpServerSessions const* owner; };
    struct UdpResponse { UdpPeer peer; std::vector<std::uint8_t> wire; };
    struct UdpStoredSession { std::array<std::uint8_t,8> id; UdpReplaySnapshot replay; };
    struct UdpClockSample { std::chrono::steady_clock::time_point monotonic; std::uint64_t wall; };
    // One serialized owner for one PSK across all listeners and workers. The
    // caller must preserve it while that key is active. The first authenticated
    // packet binds the PSK; mismatched keys fail closed. Removing this object or
    // restarting loses replay protection.
    class UdpServerSessions {
        using Clock=std::chrono::steady_clock;
        struct Entry {
            UdpReplayWindow replay; UdpPeer peer; Clock::time_point last; std::uint64_t generation=0;
            std::optional<std::array<std::uint8_t,8>> server_id;
            std::uint64_t next_packet=0; bool exhausted=false;
        };
        std::map<std::array<std::uint8_t,8>,Entry> entries_;
        // Never recycle IDs during this owner's lifetime, including after
        // expiry. The fixed bound prevents unbounded attacker-driven growth.
        std::set<std::array<std::uint8_t,8>> issued_server_ids_;
        std::set<std::array<std::uint8_t,8>> known_client_ids_;
        static constexpr std::size_t max_server_ids_=65536;
        std::size_t capacity_;
        std::array<std::uint8_t,32> key_{};
        std::size_t key_size_=0;
        std::optional<Clock::time_point> last_;
        Clock::time_point anchor_mono_{};
        std::uint64_t anchor_wall_=0;
        std::uint64_t last_wall_=0;
        std::optional<std::uint64_t> next_server_id_;
        bool server_ids_exhausted_=false;
        std::uint64_t next_generation_=1;
        bool generations_exhausted_=false;
        bool durable_=false;
        bool recovered_=false;
        bool storage_failed_=false;
        bool committing_=false;
        std::uint64_t durable_wall_=0;
        std::unique_ptr<UdpIdReservation> durable_ids_;
        using Commit = std::function_ref<bool(std::array<std::uint8_t,8> const&, UdpReplaySnapshot const&, std::uint64_t) noexcept>;
        using IdCommit = std::function_ref<bool(UdpIdWatermark) noexcept>;
        using WallCommit = std::function_ref<bool(std::uint64_t) noexcept>;
        using SampleClock = std::function_ref<std::optional<UdpClockSample>() noexcept>;
        auto allocate_server_id(std::array<std::uint8_t,8> client) -> std::expected<std::array<std::uint8_t,8>,UdpSessionError>;
        auto advance(Clock::time_point now, std::uint64_t wall) -> bool;
        auto receive_impl(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> wire,
            UdpPeer peer, Clock::time_point now, std::uint64_t wall, std::optional<Commit> commit,
            std::optional<SampleClock> sample)
            -> std::expected<UdpAccepted,UdpSessionError>;
        auto response_impl(std::span<std::uint8_t const> psk, std::array<std::uint8_t,8> client,
            std::span<std::uint8_t const> address, std::span<std::uint8_t const> payload,
            std::span<std::uint8_t const> padding, Clock::time_point now, std::uint64_t wall,
            std::optional<IdCommit> commit, std::optional<WallCommit> wall_commit,
            std::optional<SampleClock> sample) -> std::expected<UdpResponse,UdpSessionError>;
    public:
        // Durable mode is experimental: expiry and actual trusted storage are
        // not implemented, so it is not suitable for the live service.
        explicit UdpServerSessions(std::size_t capacity, bool durable=false) : capacity_(capacity), durable_(durable) {}
        ~UdpServerSessions();
        UdpServerSessions(UdpServerSessions const&) = delete;
        auto operator=(UdpServerSessions const&) -> UdpServerSessions& = delete;
        // Restore the complete, trusted state for this PSK exactly once before
        // durable receives. watermark is the persisted global wall-clock high
        // water mark. No session is expired or given a peer during recovery.
        [[nodiscard]] auto restore_durable(std::span<std::uint8_t const> psk,
            std::span<UdpStoredSession const> records, std::uint64_t watermark,
            Clock::time_point now, std::uint64_t wall, UdpIdWatermark ids, std::uint64_t block_size)
            -> std::expected<void,UdpSessionError>;
        // Packet authentication and all header semantics precede replay and peer updates.
        [[nodiscard]] auto receive(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> wire,
            UdpPeer peer, Clock::time_point now, std::uint64_t wall) -> std::expected<UdpAccepted,UdpSessionError>;
        // The synchronous callback must atomically and durably record the
        // snapshot and global wall-clock high water mark, and must not reenter
        // the owner. The stored watermark must never decrease.
        // False, including an ambiguous result, permanently fails this owner.
        // The clock callback supplies a fresh sample after durable commit.
        [[nodiscard]] auto receive_durable(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> wire,
            UdpPeer peer, Clock::time_point now, std::uint64_t wall, Commit commit, SampleClock sample) -> std::expected<UdpAccepted,UdpSessionError>;
        // Generates and consumes a packet ID before encoding; failures do not
        // reuse a nonce. Use the returned peer immediately on the same owner.
        [[nodiscard]] auto response(std::span<std::uint8_t const> psk, std::array<std::uint8_t,8> client,
            std::span<std::uint8_t const> address, std::span<std::uint8_t const> payload,
            std::span<std::uint8_t const> padding, Clock::time_point now, std::uint64_t wall)
            -> std::expected<UdpResponse,UdpSessionError>;
        // Persist the supplied global wall watermark without decreasing it,
        // then sample again after ID reservation and use that time for the response.
        // A missing or reversed sample permanently fails the durable owner.
        [[nodiscard]] auto response_durable(std::span<std::uint8_t const> psk, std::array<std::uint8_t,8> client,
            std::span<std::uint8_t const> address, std::span<std::uint8_t const> payload,
            std::span<std::uint8_t const> padding, Clock::time_point now, std::uint64_t wall,
            IdCommit commit, WallCommit wall_commit, SampleClock sample)
            -> std::expected<UdpResponse,UdpSessionError>;
        // Caller closes the associated relay socket for every returned ID.
        // Never evicts a session before 62 seconds of successful request or response inactivity.
        [[nodiscard]] auto expire(Clock::time_point now, std::uint64_t wall)
            -> std::expected<std::vector<std::array<std::uint8_t,8>>,UdpSessionError>;
        [[nodiscard]] auto peer(std::array<std::uint8_t,8> id) const -> std::optional<UdpPeer>;
        // Revalidate immediately before an external effect. Durable callers must
        // not rely on current() alone after queueing an accepted packet.
        [[nodiscard]] auto authorize_durable(UdpAccepted const& packet, SampleClock sample)
            -> std::expected<void,UdpSessionError>;
        // Valid only during the originating owner's lifetime and for the
        // current incarnation of the session.
        [[nodiscard]] auto current(UdpAccepted const& packet) const noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
    };
}
