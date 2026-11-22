export module quic.transport_parameters;
import std;

export namespace quic {
    inline constexpr std::size_t max_parameter_bytes=65535,inline_parameter_ids=64,max_parameter_ids=max_parameter_bytes/2;
    enum class ParameterBlockError { malformed,duplicate,allocation_failed };
    // Checks only tuple framing and unique full 62-bit IDs, including unknown
    // IDs. The QUIC transport remains the sole validator of parameter values,
    // roles, required parameters and connection-ID binding.
    // Up to 64 IDs uses stack storage. Larger blocks allocate exactly one ID
    // array after a bounded counting pass, then sort without further allocation.
    [[nodiscard]] auto validate_parameter_block(std::span<std::uint8_t const> input) noexcept -> std::expected<void,ParameterBlockError>;
}
