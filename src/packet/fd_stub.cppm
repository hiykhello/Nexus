export module packet.fd;
export import packet;
import std;

export namespace packet {
    enum class FdError { invalid_fd, blocking_fd, invalid_limit, end_of_file, packet_too_large, partial_write };
    template<class DeviceFailure> using FdFailureFor = std::variant<FdError, DeviceFailure, std::error_code>;
    template<class DeviceFailure> struct FdStepFor {
        bool input = false, input_delivered = false, input_backpressured = false;
        bool output_delivered = false, output_backpressured = false, output_discarded = false;
        std::optional<FdFailureFor<DeviceFailure>> input_error, output_error;
    };
    using FdFailure = FdFailureFor<DeviceError>;
    using FdStep = FdStepFor<DeviceError>;

    class FdPump {
    public:
        using OutputValidator = bool (*)(void*, QueuedPacket const&) noexcept;
        [[nodiscard]] static auto create(int, MemoryLink&, std::size_t) -> std::expected<FdPump, FdFailure> {
            return std::unexpected(FdFailure{FdError::invalid_fd});
        }
        [[nodiscard]] auto step(OutputValidator = nullptr, void* = nullptr) -> FdStep {
            return {.input_error = FdFailure{FdError::invalid_fd}};
        }
    };

    template<class Device, std::size_t Capacity>
    class StaticFdPump {
        static_assert(Capacity > 0 && Capacity <= 65535);
    public:
        class Setup {};
        using Failure = FdFailureFor<typename Device::Failure>;
        using Step = FdStepFor<typename Device::Failure>;
        [[nodiscard]] static auto prepare(int, std::size_t) noexcept -> std::expected<Setup, Failure> {
            return std::unexpected(Failure{FdError::invalid_fd});
        }
        [[nodiscard]] static auto create(int, Device&, std::size_t) -> std::expected<StaticFdPump, Failure> {
            return std::unexpected(Failure{FdError::invalid_fd});
        }
        [[nodiscard]] auto step() -> Step { return {.input_error = Failure{FdError::invalid_fd}}; }
        [[nodiscard]] auto pending() const noexcept -> bool { return false; }
        auto clear() noexcept -> void {}
    };
}
