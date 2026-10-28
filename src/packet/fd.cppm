export module nexus.packet.fd;
export import nexus.packet;
import std;

export namespace nexus::packet {
    enum class FdError { invalid_fd, blocking_fd, invalid_limit, end_of_file, packet_too_large, partial_write };
    using FdFailure = std::variant<FdError, DeviceError, std::error_code>;
    struct FdStep {
        bool input = false, input_delivered = false, input_backpressured = false;
        bool output_delivered = false, output_backpressured = false;
        std::optional<FdFailure> input_error, output_error;
    };
    // Borrows a nonblocking, packet-preserving descriptor and the link's first side.
    // Neither descriptor nor link may be closed or replaced during a step.
    // Caller handles SIGPIPE where the descriptor can generate it.
    class FdPump {
        int fd_;
        MemoryLink* link_;
        std::size_t mtu_;
        Bytes buffer_;
        std::optional<Bytes> input_, output_;
        FdPump(int fd, MemoryLink& link, std::size_t mtu);
    public:
        ~FdPump();
        FdPump(FdPump&&) noexcept;
        auto operator=(FdPump&&) noexcept -> FdPump&;
        FdPump(FdPump const&) = delete;
        auto operator=(FdPump const&) -> FdPump& = delete;
        [[nodiscard]] static auto create(int fd, MemoryLink& link, std::size_t mtu)
            -> std::expected<FdPump, FdFailure>;
        [[nodiscard]] auto step() -> FdStep;
    };
}
