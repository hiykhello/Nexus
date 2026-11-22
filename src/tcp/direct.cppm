export module tcp.direct;
export import tcp.engine;
import std;

export namespace tcp {
    enum class DirectError { blocked, invalid_target, policy_error, full, duplicate, not_found, not_established, time_reversed, connect_timeout };
    using DirectFailure = std::variant<DirectError, EngineError, ConnectionError, std::error_code>;
    struct DirectStep {
        std::optional<ConnectionId> id;
        bool connected = false, retired = false, read_backpressured = false;
        std::size_t to_upstream = 0, from_upstream = 0;
        std::optional<packet::DeviceError> output_error;
        std::optional<DirectFailure> error;
    };
    // Linux IPv4, single owner. All referenced objects outlive this instance.
    class Direct4 {
        struct Flow {
            ConnectionId id;
            std::uint64_t started;
            int fd;
            bool connecting, local_eof = false, shutdown_sent = false, remote_eof = false;
            std::optional<DirectFailure> failure;
            std::array<std::uint8_t, 16384> buffer{};
            std::size_t begin = 0, end = 0;
            // Upstream bytes remain owned across a failed queue allocation.
            std::array<std::uint8_t, 16384> incoming{};
            std::size_t incoming_size = 0;
            Flow(ConnectionId i, std::uint64_t time, int f, bool c);
            Flow(Flow const&) = delete;
            auto operator=(Flow const&) -> Flow& = delete;
            ~Flow();
        };
        ConnectionTable& table;
        MemoryEngine& engine;
        rules::Matcher policy;
        std::size_t limit;
        std::optional<std::uint32_t> socket_mark;
        std::list<Flow> flows;
        ConnectionId cursor = 0;
        std::uint64_t now = 0;
        bool initialized = false;
    public:
        Direct4(ConnectionTable& table, MemoryEngine& engine, rules::Matcher policy, std::size_t limit,
                std::optional<std::uint32_t> socket_mark = {});
        ~Direct4();
        Direct4(Direct4 const&) = delete;
        auto operator=(Direct4 const&) -> Direct4& = delete;
        // Time is monotonic milliseconds; pending connects time out after 10 seconds.
        // Immediate socket failures are returned and retained for reset on step.
        [[nodiscard]] auto start(ConnectionId id, std::uint64_t now) -> std::expected<void, DirectFailure>;
        [[nodiscard]] auto step(std::uint64_t now) -> std::expected<DirectStep, DirectError>;
        [[nodiscard]] auto close(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t;
        auto admission_limit(std::size_t value) noexcept -> void { limit = value; }
    };
    // Linux IPv6, single owner. All referenced objects outlive this instance.
    class Direct6 {
        struct Flow {
            ConnectionId id;
            std::uint64_t started;
            int fd;
            bool connecting, local_eof = false, shutdown_sent = false, remote_eof = false;
            std::optional<DirectFailure> failure;
            std::array<std::uint8_t, 16384> buffer{};
            std::size_t begin = 0, end = 0;
            // Upstream bytes remain owned across a failed queue allocation.
            std::array<std::uint8_t, 16384> incoming{};
            std::size_t incoming_size = 0;
            Flow(ConnectionId i, std::uint64_t time, int f, bool c);
            Flow(Flow const&) = delete;
            auto operator=(Flow const&) -> Flow& = delete;
            ~Flow();
        };
        ConnectionTable6& table;
        MemoryEngine6& engine;
        rules::Matcher policy;
        std::size_t limit;
        std::optional<std::uint32_t> socket_mark;
        std::list<Flow> flows;
        ConnectionId cursor = 0;
        std::uint64_t now = 0;
        bool initialized = false;
    public:
        Direct6(ConnectionTable6& table, MemoryEngine6& engine, rules::Matcher policy, std::size_t limit,
                std::optional<std::uint32_t> socket_mark = {});
        ~Direct6();
        Direct6(Direct6 const&) = delete;
        auto operator=(Direct6 const&) -> Direct6& = delete;
        // Time is monotonic milliseconds; pending connects time out after 10 seconds.
        // Immediate socket failures are returned and retained for reset on step.
        [[nodiscard]] auto start(ConnectionId id, std::uint64_t now) -> std::expected<void, DirectFailure>;
        [[nodiscard]] auto step(std::uint64_t now) -> std::expected<DirectStep, DirectError>;
        [[nodiscard]] auto close(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t;
        auto admission_limit(std::size_t value) noexcept -> void { limit = value; }
    };
}
