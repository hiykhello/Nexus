export module tls.ech_server;
export import tls.hello;
import crypto;
import std;

export namespace tls {
    struct EchServerKeyEntry {
        std::uint8_t config_id = 0;
        std::uint8_t maximum_name_length = 0;
        std::string public_name;
        std::vector<std::pair<std::uint16_t, std::uint16_t>> suites;
        crypto::Bytes config_wire;
        std::array<std::uint8_t, 32> private_key{};

        EchServerKeyEntry() = default;
        EchServerKeyEntry(EchServerKeyEntry const&) = delete;
        auto operator=(EchServerKeyEntry const&) -> EchServerKeyEntry& = delete;
        EchServerKeyEntry(EchServerKeyEntry&& other) noexcept
            : config_id(other.config_id), maximum_name_length(other.maximum_name_length),
              public_name(std::move(other.public_name)), suites(std::move(other.suites)),
              config_wire(std::move(other.config_wire)), private_key(other.private_key) {
            crypto::cleanse(other.private_key);
        }
        auto operator=(EchServerKeyEntry&& other) noexcept -> EchServerKeyEntry& {
            if (this != &other) {
                crypto::cleanse(private_key);
                config_id = other.config_id;
                maximum_name_length = other.maximum_name_length;
                public_name = std::move(other.public_name);
                suites = std::move(other.suites);
                config_wire = std::move(other.config_wire);
                private_key = other.private_key;
                crypto::cleanse(other.private_key);
            }
            return *this;
        }
        ~EchServerKeyEntry() { crypto::cleanse(private_key); }
    };

    class EchServerKeys {
        std::vector<EchServerKeyEntry> entries_;
        crypto::Bytes retry_configs_wire_;
    public:
        EchServerKeys() = default;
        EchServerKeys(std::vector<EchServerKeyEntry>&& entries, crypto::Bytes&& retry_wire) noexcept
            : entries_(std::move(entries)), retry_configs_wire_(std::move(retry_wire)) {}
        EchServerKeys(EchServerKeys const&) = delete;
        auto operator=(EchServerKeys const&) -> EchServerKeys& = delete;
        EchServerKeys(EchServerKeys&&) noexcept = default;
        auto operator=(EchServerKeys&&) noexcept -> EchServerKeys& = default;
        ~EchServerKeys() = default;

        [[nodiscard]] auto empty() const noexcept -> bool { return entries_.empty(); }
        [[nodiscard]] auto entries() const noexcept -> std::span<EchServerKeyEntry const> { return entries_; }
        [[nodiscard]] auto retry_configs_wire() const noexcept -> std::span<std::uint8_t const> {
            return retry_configs_wire_;
        }
    };

    // Parse ECH server keys from in-memory text/PEM/binary representation.
    // Supports:
    //  - `nexus generate ech-keypair` text ("PrivateKey: <b64>\nEchConfigList: <b64>")
    //  - PEM "ECH KEYS" (RFC/draft binary container) or "ECH PRIVATE KEY" + "ECH CONFIG"
    //  - Raw binary [32-byte X25519 private key][ECHConfigList]
    [[nodiscard]] auto parse_ech_server_keys(std::span<std::uint8_t const> bytes)
        -> std::expected<std::shared_ptr<EchServerKeys const>, std::string>;

    // Load ECH server keys from an owner-readable private key file.
    [[nodiscard]] auto load_ech_server_keys_file(std::string_view path)
        -> std::expected<std::shared_ptr<EchServerKeys const>, std::string>;

    enum class EchProcessStatus : std::uint8_t {
        not_offered,
        accepted,
        rejected_send_retry_configs,
        protocol_error,
        crypto_error
    };

    struct EchProcessResult {
        EchProcessStatus status = EchProcessStatus::not_offered;
        std::optional<ClientHello> inner_hello;
        crypto::Bytes inner_message;
        std::string sni;
    };

    // Per-connection ECH state supporting both initial ClientHello and HRR retry.
    class EchServerContext {
        struct Impl;
        struct Deleter { auto operator()(Impl* p) const noexcept -> void; };
        std::unique_ptr<Impl, Deleter> impl_;
        std::shared_ptr<EchServerKeys const> keys_;
        bool accepted_ = false;
        bool rejected_offered_ = false;
    public:
        EchServerContext() = default;
        explicit EchServerContext(std::shared_ptr<EchServerKeys const> keys) noexcept
            : keys_(std::move(keys)) {}
        EchServerContext(EchServerContext const&) = delete;
        auto operator=(EchServerContext const&) -> EchServerContext& = delete;
        EchServerContext(EchServerContext&&) noexcept = default;
        auto operator=(EchServerContext&&) noexcept -> EchServerContext& = default;
        ~EchServerContext() = default;

        [[nodiscard]] auto has_keys() const noexcept -> bool { return keys_ && !keys_->empty(); }
        [[nodiscard]] auto accepted() const noexcept -> bool { return accepted_; }
        [[nodiscard]] auto rejected_offered() const noexcept -> bool { return rejected_offered_; }
        [[nodiscard]] auto retry_configs() const noexcept -> std::span<std::uint8_t const> {
            return (rejected_offered_ && keys_) ? keys_->retry_configs_wire() : std::span<std::uint8_t const>{};
        }
        [[nodiscard]] auto process_client_hello(ClientHello const& outer,
                                                std::span<std::uint8_t const> outer_message,
                                                bool is_retry) -> EchProcessResult;
        auto reset() noexcept -> void { impl_.reset(); accepted_ = false; rejected_offered_ = false; }
    };

    [[nodiscard]] auto extract_client_hello_sni_view(ClientHello const& hello) noexcept -> std::string_view;
    [[nodiscard]] auto extract_client_hello_sni(ClientHello const& hello) -> std::string;

    // Install RFC 9460 §7.2 8-byte `ech accept confirmation` into ServerHello random[24..32).
    [[nodiscard]] auto apply_ech_accept_confirmation(std::span<std::uint8_t const> first_inner,
                                                     std::span<std::uint8_t const> retry_hello,
                                                     std::span<std::uint8_t const> second_inner,
                                                     std::span<std::uint8_t const> server_hello_wire)
        -> std::expected<crypto::Bytes, std::string>;

    // Install RFC 9460 §7.2 8-byte `hrr ech accept confirmation` into HRR extension 0xfe0d.
    [[nodiscard]] auto apply_ech_hrr_confirmation(std::span<std::uint8_t const> first_inner,
                                                  std::span<std::uint8_t const> hrr_wire)
        -> std::expected<crypto::Bytes, std::string>;
}
