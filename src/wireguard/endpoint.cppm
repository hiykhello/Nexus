export module wireguard.endpoint;
import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.admission;
import wireguard.cookie;
import wireguard.crypto;
import wireguard.identity;
import wireguard.initiation;
import wireguard.noise;
import wireguard.routing;
import wireguard.session;

export namespace wireguard {
    using EndpointAddress=net::UdpEndpoint;
    // Common IPv4/IPv6 UDP payload ceiling without jumbo/extension headers.
    // Actual path MTU remains the socket/device host's responsibility.
    inline constexpr std::size_t endpoint_max_outer_payload=65535-20-8;
    inline constexpr std::size_t endpoint_max_inner_mtu=endpoint_max_outer_payload-transport_overhead;
    enum class EndpointError { configuration,closed,clock,invalid_packet,disallowed_source,disallowed_destination,
        source,index_exhausted,index_conflict,stale_attempt,not_due,queue_full,no_key,cookie_secret,protocol };
    struct EndpointFailure { EndpointError code; std::optional<Error> protocol; };
    using AllowedPrefix=routing::Prefix;
    using SourcePolicyView=routing::SourcePolicyView;
    struct InnerPacket {
        std::uint8_t family;
        std::array<std::uint8_t,16> source{},destination{};
        std::span<std::uint8_t const> packet;
    };
    using routing::valid_prefix;
    using routing::prefix_contains;
    [[nodiscard]] auto parse_inner_packet(std::span<std::uint8_t const>) noexcept -> std::expected<InnerPacket,EndpointFailure>;
    struct EndpointConfig {
        Key peer_public{};
        std::vector<AllowedPrefix> allowed_ips;
        std::optional<EndpointAddress> peer;
        std::size_t mtu=1420,queue_packets=64,queue_bytes=1024*1024;
        std::chrono::seconds persistent_keepalive{0};
        bool relay_only=false;
    };
    enum class HandshakeReason { data,rekey,retry,persistent_keepalive,manual,response };
    struct HandshakeRequest {
        std::uint64_t ticket;
        HandshakeReason reason;
        Clock::time_point expires;
    };
    using CookieRequest=admission::CookieRequest;
    enum class OutboundKind { initiation,response,data,keepalive,cookie };
    struct EndpointDatagram {
        std::uint64_t serial;
        EndpointAddress destination;
        std::vector<std::uint8_t> bytes;
        OutboundKind kind;
        bool relay=false;
    };
    struct EndpointPoll {
        std::optional<HandshakeRequest> handshake;
        std::optional<CookieRequest> cookie;
        std::optional<EndpointDatagram> datagram;
        bool gave_up=false;
    };
    struct EndpointReceived {
        std::vector<std::uint8_t> packet;
        std::optional<HandshakeRequest> handshake;
        std::optional<CookieRequest> cookie;
        bool keepalive=false,peer_changed=false,key_confirmed=false,cookie_consumed=false;
    };
    struct EndpointStatus {
        std::optional<EndpointAddress> peer;
        std::optional<std::uint32_t> current,previous,pending,handshake;
        std::uint64_t latest_attempt=0;
        std::size_t queued_packets=0,queued_bytes=0,indexes=0;
    };
    enum class IndexMode { probe,exact };
    struct ReceiverIndex { bool used=false; std::uint32_t value=0; std::uint64_t ticket=0; };
    using ReceiverIndexes=std::array<ReceiverIndex,8>;
    // A stable, single-executor owner for one peer. No socket, clock sampling,
    // entropy source, detached task or global receiver-index registry is hidden
    // here. A multi-peer host must reserve indexes across its whole UDP port.
    class Endpoint {
    public:
        // Only create can make this key. It permits expected's in_place
        // construction of a nonmovable Endpoint without a heap/Impl wrapper.
        class ConstructionKey {
            friend class Endpoint;
            ConstructionKey()=default;
        public:
            ConstructionKey(ConstructionKey&&)=default;
        };
    private:
        using Index=ReceiverIndex;
        struct Generation {
            Session session;
            std::uint32_t index;
            std::uint64_t ticket;
            Clock::time_point born;
            bool initiator,sent_data=false;
            Generation(Session key,std::uint32_t local,std::uint64_t attempt,Clock::time_point now,bool first) noexcept
                : session(std::move(key)),index(local),ticket(attempt),born(now),initiator(first) {}
            Generation(Generation&&)=default;
            auto operator=(Generation&&) -> Generation& = default;
        };
        enum class AttemptPhase { initiation_requested,initiation_sent,response_requested };
        struct Attempt {
            HandshakeRequest request;
            AttemptPhase phase;
            std::optional<Handshake> handshake;
            std::optional<std::uint32_t> index;
            std::optional<EndpointAddress> source;
            Clock::time_point retry{};
            Attempt(HandshakeRequest value,AttemptPhase step) noexcept : request(value),phase(step) {}
        };
        struct QueuedPacket {
            std::vector<std::uint8_t> bytes;
            explicit QueuedPacket(std::span<std::uint8_t const> value) : bytes(value.begin(),value.end()) {}
            ~QueuedPacket() { crypto::cleanse(bytes); }
            QueuedPacket(QueuedPacket const&)=delete;
            auto operator=(QueuedPacket const&) -> QueuedPacket& = delete;
            QueuedPacket(QueuedPacket&&)=default;
            auto operator=(QueuedPacket&& other) noexcept -> QueuedPacket& {
                if (this!=&other) { crypto::cleanse(bytes); bytes=std::move(other.bytes); } return *this;
            }
        };
        struct Sending { std::uint64_t serial,ticket; OutboundKind kind; };
        struct CookieBinding { std::uint64_t ticket; std::uint32_t sender; EndpointAddress destination; };
        struct IndexLease {
            Endpoint& owner; std::uint32_t index; std::uint64_t ticket; bool committed=false;
            ~IndexLease();
        };
        // Attempts borrow identity_; they are closed before identity_ resets.
        std::optional<crypto::X25519Private> identity_;
        CookieAdmission admission_;
        SecretKey psk_;
        EndpointConfig config_;
        TimestampGuard timestamps_;
        std::array<Index,8> indexes_{};
        std::optional<Generation> current_,previous_,pending_;
        std::optional<Attempt> attempt_;
        std::optional<CookieGenerator> cookie_generator_;
        std::optional<CookieBinding> cookie_binding_;
        std::optional<Sending> sending_;
        std::deque<QueuedPacket> queue_;
        std::size_t queued_bytes_=0;
        std::uint64_t latest_=0,serial_=0;
        std::optional<Clock::time_point> observed_,window_,last_handshake_,last_sent_,last_data_sent_,last_received_,last_data_received_;
        Clock::time_point next_persistent_{},next_send_{};
        bool closed_=false,manual_=false,confirmation_=false,keepalive_owed_=false,receipt_owed_=false,send_rekey_=false,receive_rekey_=false;
        static auto valid_address(EndpointAddress const&) noexcept -> bool;
        static auto validate(crypto::X25519Private const&,EndpointConfig&,std::span<std::uint8_t const>) -> std::expected<Key,EndpointFailure>;
        auto observe(Clock::time_point) noexcept -> std::expected<void,EndpointFailure>;
        auto reserve_index(std::uint32_t,std::uint64_t,IndexMode) noexcept -> std::expected<std::uint32_t,EndpointFailure>;
        auto release_index(std::uint32_t,std::uint64_t) noexcept -> void;
        auto clear_attempt(bool release=true) noexcept -> void;
        auto clear_cookie_challenge() noexcept -> void;
        static auto admission_failure(admission::Failure) noexcept -> EndpointFailure;
        auto drop(std::optional<Generation>&) noexcept -> void;
        auto prune(Clock::time_point) noexcept -> void;
        auto note_received(bool data,bool rekey,Clock::time_point) noexcept -> void;
        auto allowed(InnerPacket const&,bool source) const noexcept -> bool;
        auto issue(HandshakeReason,AttemptPhase,Clock::time_point) -> std::expected<HandshakeRequest,EndpointFailure>;
        auto promote_pending() noexcept -> void;
        auto install_current(Session,std::uint32_t,std::uint64_t,Clock::time_point) noexcept -> void;
        auto output(std::vector<std::uint8_t>,OutboundKind,std::uint64_t,EndpointAddress) -> std::expected<EndpointDatagram,EndpointFailure>;
        auto emit_transport(std::span<std::uint8_t const>,OutboundKind,Clock::time_point) -> std::expected<EndpointDatagram,EndpointFailure>;
        auto apply_cookie(std::span<std::uint8_t>,std::uint64_t,EndpointAddress,Clock::time_point) -> std::expected<void,EndpointFailure>;
        auto admit_handshake(std::span<std::uint8_t const>,EndpointAddress,Clock::time_point,bool) -> std::expected<admission::Decision,EndpointFailure>;
        auto receive_cookie(std::span<std::uint8_t const>,EndpointAddress,Clock::time_point) -> std::expected<EndpointReceived,EndpointFailure>;
        auto receive_initiation(AdmittedHandshake,std::optional<EndpointAddress>,Clock::time_point) -> std::expected<EndpointReceived,EndpointFailure>;
        auto receive_opened(OpenedInitiation,std::optional<EndpointAddress>,Clock::time_point) -> std::expected<EndpointReceived,EndpointFailure>;
        auto receive_response(std::span<std::uint8_t const>,std::optional<EndpointAddress>,Clock::time_point) -> std::expected<EndpointReceived,EndpointFailure>;
        auto receive_transport(std::span<std::uint8_t const>,std::optional<EndpointAddress>,Clock::time_point,SourcePolicyView const&) -> std::expected<EndpointReceived,EndpointFailure>;
    public:
        Endpoint(ConstructionKey,crypto::X25519Private,Key local_public,SecretKey,EndpointConfig);
        ~Endpoint();
        Endpoint(Endpoint const&)=delete;
        auto operator=(Endpoint const&) -> Endpoint& = delete;
        Endpoint(Endpoint&&)=delete;
        auto operator=(Endpoint&&) -> Endpoint& = delete;
        [[nodiscard]] static auto create(crypto::X25519Private,EndpointConfig,std::span<std::uint8_t const> psk={})
            -> std::expected<Endpoint,EndpointFailure>;
        [[nodiscard]] static auto emplace_into(std::optional<Endpoint>&,crypto::X25519Private,EndpointConfig,std::span<std::uint8_t const> psk={})
            -> std::expected<void,EndpointFailure>;
        auto close() noexcept -> void;
        // Move the same peer to another carrier while retaining established keys.
        [[nodiscard]] auto change_path(std::optional<EndpointAddress>,bool relay) noexcept -> std::expected<void,EndpointFailure>;
        // Drops staged business IP and invalidates only an unfinished data
        // datagram. Used nonces, keys, handshakes and cookies are unchanged.
        auto discard_business() noexcept -> void;
        // Input/output packets are actual inner IP, not already padded bytes.
        [[nodiscard]] auto enqueue(std::span<std::uint8_t const>,Clock::time_point) -> std::expected<void,EndpointFailure>;
        [[nodiscard]] auto request_handshake(Clock::time_point) -> std::expected<void,EndpointFailure>;
        [[nodiscard]] auto poll(Clock::time_point) -> std::expected<EndpointPoll,EndpointFailure>;
        [[nodiscard]] auto initiate(HandshakeRequest,std::uint32_t index_seed,crypto::X25519Private,Timestamp const&,
            std::chrono::milliseconds jitter,Clock::time_point,IndexMode=IndexMode::probe) -> std::expected<EndpointDatagram,EndpointFailure>;
        [[nodiscard]] auto respond(HandshakeRequest,std::uint32_t index_seed,crypto::X25519Private,Clock::time_point,IndexMode=IndexMode::probe)
            -> std::expected<EndpointDatagram,EndpointFailure>;
        // Secret and reply nonce come from independent host cryptographic
        // entropy. Requiring cookies never runs Noise/DH before MAC2 passes.
        [[nodiscard]] auto rotate_cookie_secret(SecretKey,Clock::time_point) -> std::expected<void,EndpointFailure>;
        [[nodiscard]] auto respond_cookie(CookieRequest,std::span<std::uint8_t const,24> nonce,Clock::time_point)
            -> std::expected<EndpointDatagram,EndpointFailure>;
        // The optional source view is borrowed only for this call. A stale
        // peer generation is rejected; data's global LPM owner is checked
        // after authentication/local source policy and before promotion/roam.
        [[nodiscard]] auto receive(std::span<std::uint8_t const>,EndpointAddress,bool source_allowed,Clock::time_point,bool require_cookie=false,SourcePolicyView={})
            -> std::expected<EndpointReceived,EndpointFailure>;
        [[nodiscard]] auto receive_relay(std::span<const std::uint8_t>,Clock::time_point,SourcePolicyView)
            -> std::expected<EndpointReceived,EndpointFailure>;
        // Shared-identity dispatch must revalidate both public-key and route
        // generations. The move-only token is consumed even on rejection.
        [[nodiscard]] auto receive_selected(SelectedInitiation,PeerKeyView,Clock::time_point,SourcePolicyView)
            -> std::expected<EndpointReceived,EndpointFailure>;
        // The host retains one produced datagram through EAGAIN/backpressure,
        // tests output_valid before sending it, then reports the actual result.
        // Failed sends consume their nonce and never replay an inner packet.
        [[nodiscard]] auto output_valid(std::uint64_t serial) const noexcept -> bool;
        [[nodiscard]] auto complete_send(std::uint64_t serial,bool success,Clock::time_point) -> std::expected<void,EndpointFailure>;
        [[nodiscard]] auto status() const noexcept -> EndpointStatus;
        [[nodiscard]] auto queued_packets() const noexcept -> std::size_t { return queue_.size(); }
        [[nodiscard]] auto queued_bytes() const noexcept -> std::size_t { return queued_bytes_; }
        [[nodiscard]] auto latest_attempt() const noexcept -> std::uint64_t { return latest_; }
        [[nodiscard]] auto receiver_indexes() const noexcept -> ReceiverIndexes;
        [[nodiscard]] auto last_initiation_timestamp() const -> Timestamp { return timestamps_.last(); }
        auto seed_initiation_timestamp(Timestamp const& ts) -> void { timestamps_.seed(ts); }
    };
}
