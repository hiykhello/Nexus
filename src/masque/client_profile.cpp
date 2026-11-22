module masque.client_profile;
import std;
import crypto;
import rulefile;
import quic.ech_config;
import quic.optional_client_resumption;
import platform.ip_address;
import tls.fingerprint;
import tls.profiles;
import tls.certificate_trust;
import nexus.thirdparty.corosio;

namespace masque {
    ClientProfile::ClientProfile(tls::ClientProfile tls,std::string authority,std::string bearer_header,
        hysteria2::TransportOptions options,tls::Fingerprint fingerprint,std::shared_ptr<HttpTicketCache> tickets)
        :tls_(std::move(tls)),authority_(std::move(authority)),bearer_header_(std::move(bearer_header)),
         options_(options),fingerprint_(fingerprint)
#ifdef NEXUS_QUIC_RESUMPTION
        ,tickets_(std::move(tickets))
#endif
    {
#ifdef NEXUS_QUIC_RESUMPTION
        if (tickets_) {
            anchors_.reserve(tls_.anchors.size());
            for (auto const& anchor:tls_.anchors) anchors_.emplace_back(anchor);
            ip_identity_=platform::parse_ip_address(tls_.server_name);
        }
#else
        (void)tickets;
#endif
    }

    ClientProfile::~ClientProfile() {
        crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(bearer_header_.data()), bearer_header_.size()));
    }

    auto ClientProfile::CertificatePolicy::operator()(std::span<std::span<std::uint8_t const> const> chain) const
        -> std::expected<void, tls::CertificateTrustError> {
        std::vector<std::span<std::uint8_t const>> anchors;
        anchors.reserve(profile_.tls_.anchors.size());
        for (auto const& c : profile_.tls_.anchors) anchors.emplace_back(c);
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto const& name = profile_.tls_.server_name;
        auto ip = platform::parse_ip_address(name);
        auto identity = ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(name.data()), name.size());
        return tls::verify_server_certificate_chain(
            chain, anchors, ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns, identity, now, profile_.tls_.certificate_pins);
    }

    auto ClientProfile::load(
        std::string_view server_name,
        std::string_view ca_file,
        std::string_view authority,
        std::string_view bearer_file,
        std::uint16_t key_share,
        bool hybrid_only,
        hysteria2::TransportOptions options,
        tls::Fingerprint fingerprint,
        std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<std::unique_ptr<ClientProfile>, std::string> {
        if (!options.valid() || authority.empty() || authority.size() > 255 ||
            static_cast<std::uint8_t>(fingerprint) > static_cast<std::uint8_t>(tls::Fingerprint::random))
            return std::unexpected("invalid MASQUE client options");
        constexpr std::array<std::string_view, 1> alpn{"h3"};
        auto tls = tls::ClientProfile::load(server_name, ca_file, key_share, hybrid_only, alpn);
        if (!tls) return std::unexpected(tls.error());
        tls->certificate_pins.assign(pins.begin(), pins.end());
        std::shared_ptr<HttpTicketCache> tickets;
        if constexpr (http_ticket_recovery) tickets=std::make_shared<HttpTicketCache>();
        auto token = rulefile::read_password_file(bearer_file);
        if (!token || token->empty()) return std::unexpected("invalid MASQUE bearer-file");
        auto auth_header = "Bearer " + *token;
        crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(token->data()), token->size()));
        return std::unique_ptr<ClientProfile>(new ClientProfile(
            std::move(*tls), std::string(authority), std::move(auth_header), options, fingerprint,std::move(tickets)));
    }

    auto ClientProfile::for_http(tls::ClientProfile const& tls, std::string_view authority,
                         hysteria2::TransportOptions options,
                         tls::Fingerprint fingerprint,
                         std::shared_ptr<HttpTicketCache> tickets) -> ClientProfile {
        return ClientProfile(tls,std::string(authority),{},options,fingerprint,std::move(tickets));
    }

    auto ClientProfile::tls_client(nex::corosio::endpoint const& peer,quic::EchConfig const* ech) const
        -> std::expected<std::unique_ptr<ClientProfile::Tls>,std::string> {
        constexpr std::array<std::string_view, 1> alpn{"h3"};
        auto sni = platform::parse_ip_address(tls_.server_name)
            ? std::optional<std::string_view>{} : std::optional<std::string_view>{tls_.server_name};
        auto config = tls::make_profile_fingerprint_config(
            fingerprint_, tls_.key_share, tls_.hybrid_only, tls::HandshakeTransport::quic);
        auto shaped = tls::make_fingerprint_hello(
            sni, alpn, config, tls::HandshakeTransport::quic, std::span<std::uint8_t const>{},{},ech!=nullptr);
        if (!shaped) return std::unexpected("cannot create MASQUE ClientHello");
#ifdef NEXUS_QUIC_RESUMPTION
        if (tickets_ && !ech && tls_.certificate_pins.empty()) {
            auto const& name=tls_.server_name;
            auto identity=ip_identity_ ? ip_identity_->view() :
                std::span(reinterpret_cast<std::uint8_t const*>(name.data()),name.size());
            auto now=std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto setup=quic::ClientResumptionSetup<HttpTicketCache>::create(std::move(shaped->hello),
                shaped->initial_groups(),anchors_,ip_identity_ ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,
                identity,now,"h3",*tickets_,quic::ticket_peer_scope(peer));
            if (!setup) return std::unexpected("cannot initialize HTTP/3 ticket recovery");
            return std::make_unique<Tls>(std::move(*setup));
        }
#else
        (void)peer;
#endif
        auto client=std::make_unique<Tls>(std::move(shaped->hello),shaped->initial_groups(),CertificatePolicy{*this},"h3");
        if (ech && !client->enable_ech(*ech)) return std::unexpected("cannot initialize MASQUE ECH");
        return client;
    }

}
