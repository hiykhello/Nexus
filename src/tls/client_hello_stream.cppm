export module tls.client_hello_stream;
export import tls.hello;
export import memory.budget;
import tls.handshake;
import tls.record_stream;
import std;

export namespace tls {
    enum class ClientHelloStreamError { invalid_state, invalid_record, invalid_message, truncated, budget_exceeded };
    struct ClientHelloFeed {
        std::size_t consumed = 0;
        // Declared before the parsed hello so its reservation outlives it.
        // A caller moving hello out must retain or transfer this reservation
        // until the moved value is destroyed or separately accounted for.
        std::optional<memory::Budget::Reservation> parsed_reservation;
        std::optional<ClientHello> hello;
        // Exact handshake encoding, including its four-byte header, for the transcript.
        std::vector<std::uint8_t> message;
        bool compatibility_ccs = false;
        ClientHelloFeed() = default;
        ClientHelloFeed(ClientHelloFeed&&) noexcept = default;
        auto operator=(ClientHelloFeed&& other) noexcept -> ClientHelloFeed& {
            if (this!=&other) {
                hello.reset(); parsed_reservation.reset();
                consumed=other.consumed; parsed_reservation=std::move(other.parsed_reservation);
                hello=std::move(other.hello); message=std::move(other.message); compatibility_ccs=other.compatibility_ccs;
            }
            return *this;
        }
    };
    // Receives one initial ClientHello; no retry, early data or PSK policy is implied.
    class ClientHelloStream {
        enum class State { reading, complete, failed } state_=State::reading;
        RecordStream records_;
        HandshakeDecoder messages_;
        bool allow_ccs_=false, ccs_seen_=false;
        explicit ClientHelloStream(HandshakeDecoder&& messages, bool allow_ccs) noexcept;
    public:
        [[nodiscard]] static auto create(std::size_t max_body_size=65535, bool allow_ccs=false) -> std::expected<ClientHelloStream,ClientHelloStreamError>;
        ClientHelloStream(ClientHelloStream const&)=delete;
        auto operator=(ClientHelloStream const&) -> ClientHelloStream& = delete;
        ClientHelloStream(ClientHelloStream&&) noexcept;
        auto operator=(ClientHelloStream&&) noexcept -> ClientHelloStream&;
        // Consumes at most one record; the caller retains the unconsumed suffix.
        // Logical payload plus one Extension object per possible four-byte
        // extension header. This does not account for container capacity.
        [[nodiscard]] static constexpr auto parsed_charge(std::size_t body_size) noexcept -> std::size_t {
            return body_size+(body_size/4)*sizeof(Extension);
        }
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input, std::shared_ptr<memory::Budget> budget = {}) -> std::expected<ClientHelloFeed,ClientHelloStreamError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientHelloStreamError>;
    };
}
