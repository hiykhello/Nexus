export module hysteria2.client_profile;
import std;
import hysteria2.credential;
import hysteria2.transport_options;
import quic.tls_client;
import quic.optional_client_resumption;
import quic.ech_config;
import tls.profiles;
import tls.certificate_trust;
import tls.fingerprint;
import corosio;

export namespace hysteria2 {
    // A profile outlives its active QUIC sessions. The authentication headers
    // and certificate policy borrow the credential and trust data it owns.
    class ClientProfile {
        tls::ClientProfile tls_;
        Password password_;
        std::optional<SalamanderKey> salamander_;
        TransportOptions options_;
        tls::Fingerprint fingerprint_=tls::Fingerprint::native;
#ifdef NEXUS_QUIC_RESUMPTION
        std::vector<std::span<std::uint8_t const>> anchors_;
#endif
        ClientProfile(tls::ClientProfile tls,Password password,std::optional<SalamanderKey> salamander,
            TransportOptions options,tls::Fingerprint fingerprint);
    public:
        ClientProfile(ClientProfile const&)=delete;
        auto operator=(ClientProfile const&) -> ClientProfile& = delete;
        class CertificatePolicy {
            ClientProfile const& profile_;
        public:
            explicit CertificatePolicy(ClientProfile const& profile) noexcept:profile_(profile) {}
            auto operator()(std::span<std::span<std::uint8_t const> const> chain) const
                -> std::expected<void,tls::CertificateTrustError>;
        };
#ifdef NEXUS_QUIC_RESUMPTION
        using Tickets=tls::ResumptionCache<>;
        using Tls=quic::SelectableTlsClient<CertificatePolicy,Tickets>;
#else
        struct Tickets {};
        using Tls=quic::TlsClient<CertificatePolicy>;
#endif
        static auto load(std::string_view server_name,std::string_view ca_file,std::string_view password_file,
            std::uint16_t key_share=0x001d,bool hybrid_only=false,TransportOptions options={},
            std::optional<std::string_view> salamander_file={},
            tls::Fingerprint fingerprint=tls::Fingerprint::native,
            std::span<std::array<std::uint8_t,32> const> pins={})
            -> std::expected<std::unique_ptr<ClientProfile>,std::string>;

        [[nodiscard]] auto tls_client(corosio::endpoint const& peer,quic::EchConfig const* ech=nullptr,
            Tickets* tickets=nullptr) const -> std::expected<std::unique_ptr<Tls>,std::string>;

        [[nodiscard]] auto tls_client(quic::EchConfig const* ech = nullptr) const -> std::expected<std::unique_ptr<Tls>,std::string> {
            return tls_client(corosio::endpoint{},ech);
        }
        [[nodiscard]] auto credential() const noexcept -> std::string_view {return password_.view();}
        [[nodiscard]] auto transport() const noexcept -> TransportOptions const& {return options_;}
    };
}
