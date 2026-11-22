export module vision;
import std;

export namespace vision {
    using UserId = std::array<std::uint8_t,16>;
    enum class Command : std::uint8_t { more=0, end=1, direct=2 };
    enum class Status { reading, end, direct, invalid, truncated };
    struct Step { std::size_t consumed=0, written=0; Status status=Status::reading; };
    enum class PrefixStatus { detecting, padded, plain };
    struct PrefixStep { std::size_t consumed=0; PrefixStatus status=PrefixStatus::detecting; };
    // Holds at most the first UUID-length prefix. Once decided, buffered()
    // must be delivered to the selected decoder or plain stream before any
    // unconsumed input. finish() resolves an incomplete prefix as plain.
    class PrefixDetector {
        UserId user_;
        std::array<std::uint8_t,16> bytes_{};
        std::size_t size_=0, offset_=0;
        PrefixStatus status_=PrefixStatus::detecting;
    public:
        explicit PrefixDetector(UserId user) noexcept : user_(user) {}
        [[nodiscard]] auto feed(std::span<std::uint8_t const>) noexcept -> PrefixStep;
        [[nodiscard]] auto finish() noexcept -> PrefixStatus;
        [[nodiscard]] auto buffered() const noexcept -> std::span<std::uint8_t const> { return std::span(bytes_).subspan(offset_,size_-offset_); }
        [[nodiscard]] auto consume(std::size_t count) noexcept -> bool;
        [[nodiscard]] auto status() const noexcept -> PrefixStatus { return status_; }
    };
    // This encodes one block. Callers choose padding and include the user ID on
    // the first block of each direction. Direct mode requires a transport-level
    // handoff; this module never bypasses TLS itself.
    [[nodiscard]] auto encode_block(std::optional<UserId> const&, Command,
        std::span<std::uint8_t const> content, std::span<std::uint8_t const> padding)
        -> std::expected<std::vector<std::uint8_t>,Status>;
    // Incremental, bounded decoder for a stream known to begin with a Vision
    // block. Output backpressure leaves input unconsumed; a terminal command
    // stops at the block boundary so the caller retains subsequent bytes.
    class Decoder {
        UserId user_;
        std::array<std::uint8_t,5> header_{};
        std::size_t prefix_=0, header_size_=0, content_=0, padding_=0;
        Command command_=Command::more;
        bool completed_=false;
        Status status_=Status::reading;
    public:
        explicit Decoder(UserId user) noexcept : user_(user) {}
        [[nodiscard]] auto feed(std::span<std::uint8_t const>, std::span<std::uint8_t>) noexcept -> Step;
        [[nodiscard]] auto finish() noexcept -> Status;
        [[nodiscard]] auto status() const noexcept -> Status { return status_; }
    };
    enum class ReceiveStatus { detecting, padded, plain, direct, closed, invalid, truncated };
    struct ReceiveStep { std::size_t consumed=0, written=0; ReceiveStatus status=ReceiveStatus::detecting; };
    // Mirrors the pinned Xray filter's first-eight-buffer heuristic. Feed the
    // actual directional chunks in executor order; this is a traffic heuristic,
    // not TLS authentication or a general TLS parser.
    class TrafficFilter {
        int remaining_=8;
        std::int32_t server_remaining_=0;
        std::uint16_t cipher_=0;
        bool tls_=false,tls12_=false,direct_=false;
    public:
        auto observe(std::span<std::uint8_t const>) noexcept -> void;
        [[nodiscard]] auto remaining() const noexcept -> int { return remaining_; }
        [[nodiscard]] auto is_tls() const noexcept -> bool { return tls_; }
        [[nodiscard]] auto tls12_or_later() const noexcept -> bool { return tls12_; }
        [[nodiscard]] auto direct_eligible() const noexcept -> bool { return direct_; }
        [[nodiscard]] auto cipher() const noexcept -> std::uint16_t { return cipher_; }
    };
    // Tests complete TLS application record framing as Xray does, including
    // its empty-input result. The writer must separately require nonempty data.
    [[nodiscard]] auto complete_application_records(std::span<std::uint8_t const>) noexcept -> bool;
    enum class SendStatus { padding, plain, direct, pending, failed };
    enum class SendError { invalid_state, invalid_size, invalid_random };
    enum class RandomError { invalid_bound, source_failure, exhausted };
    // Source fills two bytes from a cryptographically secure generator and
    // returns success. Rejection sampling removes modulo bias; bounded retry
    // makes a broken source fail instead of looping indefinitely.
    template<class Source>
    [[nodiscard]] auto uniform_padding_random(std::size_t bound,Source&& source) -> std::expected<std::size_t,RandomError> {
        if (!bound || bound>65536) return std::unexpected(RandomError::invalid_bound);
        auto limit=65536u-(65536u % bound);
        for (unsigned attempt=0;attempt<128;++attempt) {
            std::array<std::uint8_t,2> bytes{};
            if (!source(std::span(bytes))) return std::unexpected(RandomError::source_failure);
            auto value=(std::size_t{bytes[0]}<<8)|bytes[1];
            if (value<limit) return value%bound;
        }
        return std::unexpected(RandomError::exhausted);
    }
    struct SendBlock { std::vector<std::uint8_t> wire; Command command=Command::more; bool padded=false; };
    struct LargePlan { std::size_t split=0; std::array<std::size_t,2> random_bounds{}; };
    // The filter is shared by both directions and observed externally in
    // executor order. Each prepare handles one chunk of at most 8171 bytes;
    // callers must hold the sole writer and commit after the full wire write.
    // random_value must be uniformly sampled in [0, random_bound()).
    class Sender {
        UserId user_;
        bool first_=true;
        SendStatus state_=SendStatus::padding, next_=SendStatus::padding;
    public:
        explicit Sender(UserId user) noexcept : user_(user) {}
        [[nodiscard]] auto random_bound(TrafficFilter const&,std::size_t size,bool initial=false) const noexcept -> std::size_t;
        [[nodiscard]] auto prepare(TrafficFilter const&,std::span<std::uint8_t const>,std::size_t random_value,bool initial=false)
            -> std::expected<SendBlock,SendError>;
        // One Xray-sized input buffer (8171..8192 bytes). The plan and prepare
        // must use identical input and filter state, under the same writer.
        [[nodiscard]] auto plan_large(TrafficFilter const&,std::span<std::uint8_t const>) const noexcept -> std::expected<LargePlan,SendError>;
        [[nodiscard]] auto prepare_large(TrafficFilter const&,std::span<std::uint8_t const>,std::array<std::size_t,2>)
            -> std::expected<SendBlock,SendError>;
        [[nodiscard]] auto commit(bool written) noexcept -> bool;
        [[nodiscard]] auto status() const noexcept -> SendStatus { return state_; }
    };
    // One direction of Vision plaintext carried by TLS. A direct result stops
    // exactly at the switch boundary; the caller owns all unconsumed bytes and
    // the transport handoff. EOF is signalled only after all input is fed.
    class Receiver {
        PrefixDetector prefix_;
        Decoder decoder_;
        ReceiveStatus status_=ReceiveStatus::detecting;
        bool eof_=false;
    public:
        explicit Receiver(UserId user) noexcept : prefix_(user),decoder_(user) {}
        [[nodiscard]] auto feed(std::span<std::uint8_t const>,std::span<std::uint8_t>) noexcept -> ReceiveStep;
        [[nodiscard]] auto finish() noexcept -> ReceiveStatus;
        [[nodiscard]] auto status() const noexcept -> ReceiveStatus { return status_; }
    };
}
