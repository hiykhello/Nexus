export module tls.handshake_secrets;
export import tls.schedule;
export import tls.transcript;
import tls.resumption_policy;
import std;

export namespace tls {
    struct CipherSpec { crypto::Hash hash; crypto::Aead algorithm; std::size_t key_bytes; };
    [[nodiscard]] auto cipher_spec(std::uint16_t suite) noexcept -> std::expected<CipherSpec,crypto::Error>;
    // Exact Hello messages are already included in this unauthenticated epoch.
    // Each transport derives its own keys from these shared TLS secrets.
    struct HandshakeSecrets {
        std::uint16_t cipher_suite;
        crypto::Hash hash;
        Transcript transcript;
        Secret handshake_secret,client_traffic,server_traffic;
    };
    struct TrafficSecretView {
        std::uint16_t cipher_suite;
        crypto::Hash hash;
        std::span<std::uint8_t const> client,server;
    };
    struct TrafficSecrets {
        std::uint16_t cipher_suite;
        crypto::Hash hash;
        Secret client,server,exporter;
    };
    template<class... Recovery>
    inline auto application_traffic_secrets(std::uint16_t suite,crypto::Hash hash,
        std::span<std::uint8_t const> handshake,std::span<std::uint8_t const> server_finished_hash,Recovery&... recovery)
        -> std::expected<TrafficSecrets,crypto::Error> {
        using Policy=RecoveryPolicy<Recovery...>;
        auto spec=cipher_spec(suite);
        if (!spec) return std::unexpected(spec.error());
        if (spec->hash!=hash) return std::unexpected(crypto::Error::invalid_key);
        auto master=master_secret(hash,handshake);if (!master) return std::unexpected(master.error());
        auto client=derive_secret(hash,master->view(),"c ap traffic",server_finished_hash);
        if (!client) return std::unexpected(client.error());
        auto server=derive_secret(hash,master->view(),"s ap traffic",server_finished_hash);
        if (!server) return std::unexpected(server.error());
        auto exporter=exporter_master_secret(hash,master->view(),server_finished_hash);
        if (!exporter) return std::unexpected(exporter.error());
        if constexpr(Policy::enabled) {
            auto retained=recovery_policy(recovery...).retain_master(std::move(*master),hash);
            if (!retained) return std::unexpected(crypto::Error::backend_failure);
        }
        return TrafficSecrets{suite,hash,std::move(*client),std::move(*server),std::move(*exporter)};
    }
}
