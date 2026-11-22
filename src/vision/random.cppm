export module vision.random;
import std;
import vision;

export namespace vision {
    // Uses the project's pinned libcrypto CSPRNG. Failure leaves the Sender
    // unchanged; sample immediately before preparing its padded block.
    [[nodiscard]] auto secure_padding_random(std::size_t bound) -> std::expected<std::size_t,RandomError>;
    struct SecureSendError { std::optional<SendError> send; std::optional<RandomError> random; };
    [[nodiscard]] auto prepare_secure(Sender& sender,TrafficFilter const& filter,std::span<std::uint8_t const> bytes,bool initial=false)
        -> std::expected<SendBlock,SecureSendError>;
    [[nodiscard]] auto prepare_large_secure(Sender& sender,TrafficFilter const& filter,std::span<std::uint8_t const> bytes)
        -> std::expected<SendBlock,SecureSendError>;
}
