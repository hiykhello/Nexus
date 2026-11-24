export module packet.tun_pump;
export import packet;
import std;

export namespace packet {
    enum class TunPumpError { invalid_limit, packet_too_large, invalid_device };

    template<class DeviceFailure>
    using TunPumpFailureFor = std::variant<TunPumpError, DeviceError, DeviceFailure>;

    template<class DeviceFailure>
    struct TunPumpStepFor {
        bool input = false, input_delivered = false, input_backpressured = false;
        bool output_delivered = false, output_backpressured = false, output_discarded = false;
        std::optional<TunPumpFailureFor<DeviceFailure>> input_error, output_error;
    };

    namespace tun_pump_detail {
        template<class T>
        struct VariantFailure;

        template<class... Ts>
        struct VariantFailure<std::variant<Ts...>> {
            using type = std::variant<TunPumpError, DeviceError, Ts...>;
        };

        template<class T>
        inline auto is_retryable_error(T const& error) noexcept -> bool {
            if constexpr (requires { T::retryable(error); }) return T::retryable(error);
            return std::visit([]<class Alt>(Alt const& value) noexcept -> bool {
                if constexpr (std::same_as<Alt, std::error_code>) {
                    if (value == std::errc::resource_unavailable_try_again ||
                        value == std::errc::operation_would_block ||
                        value == std::errc::interrupted ||
                        value == std::errc::no_buffer_space)
                        return true;
#if defined(_WIN32)
                    // WintunAllocateSendPacket reports ERROR_BUFFER_OVERFLOW (111) when the send ring is full.
                    if (value.category() == std::system_category() && value.value() == 111)
                        return true;
#endif
                    return false;
                } else {
                    return false;
                }
            }, error);
        }
    }

    // Cross-platform non-blocking packet pump bridging DarwinTun/WindowsTun (or a mock)
    // to a packet::MemoryLink without POSIX fd assumptions.
    template<class Tun>
    class TunDevicePump {
        static auto infer_failure() -> decltype(std::declval<Tun&>().write_packet(std::span<std::uint8_t const>{}).error());
    public:
        using DeviceFailure = std::remove_cvref_t<decltype(infer_failure())>;
        using Failure = std::conditional_t<
            requires { typename tun_pump_detail::VariantFailure<DeviceFailure>::type; },
            TunPumpError,
            DeviceFailure>;
    private:
        using CombinedFailure = TunPumpFailureFor<DeviceFailure>;
    public:
        using Step = TunPumpStepFor<DeviceFailure>;
        using OutputValidator = bool (*)(void*, QueuedPacket const&) noexcept;

    private:
        Tun* tun_ = nullptr;
        MemoryLink* link_ = nullptr;
        std::size_t mtu_ = 0;
        Bytes buffer_;
        std::size_t input_size_ = 0;
        std::optional<QueuedPacket> output_;

        TunDevicePump(Tun& tun, MemoryLink& link, std::size_t mtu)
            : tun_(&tun), link_(&link), mtu_(mtu), buffer_(mtu + 1) {}

        template<class X>
        static auto to_failure(X&& value) -> CombinedFailure {
            return CombinedFailure{std::forward<X>(value)};
        }

    public:
        TunDevicePump(TunDevicePump const&) = delete;
        auto operator=(TunDevicePump const&) -> TunDevicePump& = delete;
        TunDevicePump(TunDevicePump&&) noexcept = default;
        auto operator=(TunDevicePump&&) noexcept -> TunDevicePump& = default;

        [[nodiscard]] static auto create(Tun& tun, MemoryLink& link, std::size_t mtu)
            -> std::expected<TunDevicePump, TunPumpError> {
            if (mtu < 68 || mtu > 65535) return std::unexpected(TunPumpError::invalid_limit);
            return TunDevicePump(tun, link, mtu);
        }

        [[nodiscard]] auto step(OutputValidator validator = nullptr, void* context = nullptr) -> Step {
            Step result;
            if (!output_) {
                auto packet = link_->receive_packet(Side::first);
                if (!packet) result.output_error = to_failure(packet.error());
                else if (*packet) output_ = std::move(**packet);
            }
            if (output_ && ((output_->generation && !output_->generation->valid) ||
                            (validator && !validator(context, *output_)))) {
                output_.reset();
                result.output_discarded = true;
            }
            if (output_) {
                if (output_->bytes.empty() || output_->bytes.size() > mtu_) {
                    result.output_error = to_failure(TunPumpError::packet_too_large);
                    output_.reset();
                } else {
                    auto written = tun_->write_packet(output_->bytes);
                    if (!written) {
                        if (tun_pump_detail::is_retryable_error(written.error())) result.output_backpressured = true;
                        else {
                            result.output_error = to_failure(written.error());
                            output_.reset();
                        }
                    } else {
                        result.output_delivered = true;
                        output_.reset();
                    }
                }
            }
            if (!input_size_) {
                auto read = tun_->read_packet(buffer_);
                if (!read) {
                    result.input_error = to_failure(read.error());
                } else if (*read) {
                    if (**read == 0 || **read > mtu_) result.input_error = to_failure(TunPumpError::packet_too_large);
                    else { result.input = true; input_size_ = **read; }
                }
            }
            if (input_size_) {
                try {
                    auto sent = link_->send(Side::first, std::span(buffer_).first(input_size_));
                    if (sent) { result.input_delivered = true; input_size_ = 0; }
                    else if (sent.error() == DeviceError::queue_full) result.input_backpressured = true;
                    else { result.input_error = to_failure(sent.error()); input_size_ = 0; }
                } catch (std::bad_alloc const&) {
                    result.input_backpressured = true;
                }
            }
            return result;
        }

        [[nodiscard]] auto pending() const noexcept -> bool { return input_size_ != 0 || output_.has_value(); }
        auto clear() noexcept -> void { std::ranges::fill(buffer_, 0); input_size_ = 0; output_.reset(); }
    };
}
