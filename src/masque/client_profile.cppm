export module masque.client_profile;
import std;
import quic.tls_client;
import quic.optional_client_resumption;
import quic.ech_config;
import hysteria2.transport_options;
import tls.profiles;
import tls.fingerprint;
import tls.certificate_trust;
import platform.ip_address;
import nexus.thirdparty.corosio;

export namespace masque {
#ifdef NEXUS_QUIC_RESUMPTION
    using HttpTicketCache=quic::SharedResumptionCache<>;
    inline constexpr bool http_ticket_recovery=true;
#else
    struct HttpTicketCache {};
    inline constexpr bool http_ticket_recovery=false;
#endif

    class ClientProfile {
        tls::ClientProfile tls_;
        std::string authority_;
        std::string bearer_header_;
        hysteria2::TransportOptions options_;
        tls::Fingerprint fingerprint_ = tls::Fingerprint::native;
#ifdef NEXUS_QUIC_RESUMPTION
        std::shared_ptr<HttpTicketCache> tickets_;
        std::vector<std::span<std::uint8_t const>> anchors_;
        std::optional<platform::IpAddress> ip_identity_;

#endif

        ClientProfile(tls::ClientProfile tls, std::string authority, std::string bearer_header,
                      hysteria2::TransportOptions opts,tls::Fingerprint fp,
                      std::shared_ptr<HttpTicketCache> tickets={});

    public:
        ~ClientProfile();
        ClientProfile(ClientProfile const&) = delete;
        auto operator=(ClientProfile const&) -> ClientProfile& = delete;

        class CertificatePolicy {
            ClientProfile const& profile_;
        public:
            explicit CertificatePolicy(ClientProfile const& p) noexcept : profile_(p) {}
            auto operator()(std::span<std::span<std::uint8_t const> const> chain) const
                -> std::expected<void, tls::CertificateTrustError>;
        };

#ifdef NEXUS_QUIC_RESUMPTION
        using Tls=quic::SelectableTlsClient<CertificatePolicy,HttpTicketCache>;
#else
        using Tls=quic::TlsClient<CertificatePolicy>;
#endif

        static auto load(
            std::string_view server_name,
            std::string_view ca_file,
            std::string_view authority,
            std::string_view bearer_file,
            std::uint16_t key_share = 0x001d,
            bool hybrid_only = false,
            hysteria2::TransportOptions options = {},
            tls::Fingerprint fingerprint = tls::Fingerprint::native,
            std::span<std::array<std::uint8_t,32> const> pins = {}) -> std::expected<std::unique_ptr<ClientProfile>, std::string>;

        static auto for_http(tls::ClientProfile const& tls, std::string_view authority,
                             hysteria2::TransportOptions options,
                             tls::Fingerprint fingerprint=tls::Fingerprint::native,
                             std::shared_ptr<HttpTicketCache> tickets={}) -> ClientProfile;

        [[nodiscard]] auto tls_client(nex::corosio::endpoint const& peer,quic::EchConfig const* ech) const
            -> std::expected<std::unique_ptr<Tls>,std::string>;

        auto authority() const noexcept -> std::string_view { return authority_; }
        auto authorization() const noexcept -> std::string_view { return bearer_header_; }
        auto transport() const noexcept -> hysteria2::TransportOptions const& { return options_; }
    };

}
