export module tls.tls12_client;
import std;
import tls.hello;
import tls.handshake;
import tls.transcript;
import tls.schedule;
import tls.client_flight;
import tls.record_stream;
import tls.record;
import tls.encrypted_extensions;

export namespace tls {
    enum class Tls12ClientError { state, protocol, authentication, crypto };
    struct Tls12Feed { std::size_t consumed; crypto::Bytes outbound; };
    // One full handshake, using ECDHE and AES-GCM with Extended Master Secret.
    // Identity and trust data are owned until the authenticated connection is ready.
    class Tls12Client {
        enum class State { hello,certificate,key_exchange,hello_done,change_cipher,finished,complete,failed } state_=State::hello;
        ClientHello offer_;
        std::vector<crypto::Bytes> anchors_;
        crypto::Bytes name_;
        PeerNameKind kind_;
        std::int64_t verification_time_;
        std::array<std::uint8_t,32> server_random_{};
        std::array<std::uint8_t,133> server_public_{};
        std::uint16_t group_=0;
        std::uint8_t server_public_size_=0;
        std::vector<std::array<std::uint8_t,32>> pins_;
        bool ecdsa_=false,ticket_expected_=false,status_expected_=false;
        std::uint16_t read_limit_=16384;
        crypto::Hash hash_=crypto::Hash::sha256;
        crypto::Aead cipher_=crypto::Aead::aes_128_gcm;
        crypto::Bytes leaf_;
        RecordStream records_;
        HandshakeDecoder messages_;
        std::optional<Transcript> transcript_;
        std::optional<Secret> master_;
        std::optional<RecordLayer> write_,read_;
        EncryptedExtensions negotiated_;
        bool taken_=false;
        Tls12Client(ClientHello&&,std::vector<crypto::Bytes>,crypto::Bytes,PeerNameKind,std::int64_t,HandshakeDecoder&&);
        auto hello(std::span<std::uint8_t const>) -> std::expected<void,Tls12ClientError>;
        auto certificate(std::span<std::uint8_t const>) -> std::expected<void,Tls12ClientError>;
        auto key_exchange(std::span<std::uint8_t const>) -> std::expected<void,Tls12ClientError>;
        auto client_flight() -> std::expected<crypto::Bytes,Tls12ClientError>;
        auto server_finished(std::span<std::uint8_t const>) -> std::expected<void,Tls12ClientError>;
        auto process(HandshakeMessage const&) -> std::expected<crypto::Bytes,Tls12ClientError>;
    public:
        auto set_certificate_pins(std::span<std::array<std::uint8_t,32> const> pins) -> void { pins_.assign(pins.begin(),pins.end()); }
        Tls12Client(Tls12Client&&) noexcept=default;
        auto operator=(Tls12Client&&) noexcept -> Tls12Client& = default;
        [[nodiscard]] static auto create(std::optional<std::string_view> server_name,std::span<std::string_view const> alpn,
            std::vector<crypto::Bytes> anchors,crypto::Bytes name,PeerNameKind kind,std::int64_t verification_time)
            -> std::expected<Tls12Client,Tls12ClientError>;
        [[nodiscard]] static auto from_offer(ClientHello offer,std::vector<crypto::Bytes> anchors,crypto::Bytes name,
            PeerNameKind kind,std::int64_t time) -> std::expected<Tls12Client,Tls12ClientError>;
        [[nodiscard]] auto initial_record() const -> std::expected<crypto::Bytes,Tls12ClientError>;
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<Tls12Feed,Tls12ClientError>;
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const& { return negotiated_; }
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,Tls12ClientError>;
    };
}
