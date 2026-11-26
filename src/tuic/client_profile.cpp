module tuic.client;
import std;
import crypto;
import rulefile;
import tuic.wire;
import quic.tls_client;
import quic.optional_client_resumption;
import quic.ech_config;
import tls.profiles;
import tls.fingerprint;
import tls.certificate_trust;
import platform.ip_address;
import corosio;

namespace tuic {
    ClientProfile::ClientProfile(tls::ClientProfile tls,std::array<std::uint8_t,16> uuid,std::string password,
        ClientTransportOptions options,tls::Fingerprint fingerprint)
        :tls_(std::move(tls)),uuid_(uuid),password_(std::move(password)),options_(options),fingerprint_(fingerprint) {
#ifdef NEXUS_QUIC_RESUMPTION
        anchors_.reserve(tls_.anchors.size());
        for (auto const& anchor:tls_.anchors) anchors_.emplace_back(anchor);
#endif
    }

    ClientProfile::~ClientProfile() {
        crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(password_.data()),password_.size()));
    }

    auto ClientProfile::CertificatePolicy::operator()(std::span<std::span<std::uint8_t const> const> chain) const
        -> std::expected<void,tls::CertificateTrustError> {
        std::vector<std::span<std::uint8_t const>> anchors;
        anchors.reserve(profile_.tls_.anchors.size());
        for (auto const& certificate:profile_.tls_.anchors) anchors.emplace_back(certificate);
        auto now=std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto const& name=profile_.tls_.server_name;
        auto ip=platform::parse_ip_address(name);
        auto identity=ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(name.data()),name.size());
        return tls::verify_server_certificate_chain(chain,anchors,ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,identity,now,profile_.tls_.certificate_pins);
    }

    auto ClientProfile::load(std::string_view server_name,std::string_view ca_file,std::string_view uuid_file,
        std::string_view password_file,std::uint16_t key_share,bool hybrid_only,ClientTransportOptions options,
        tls::Fingerprint fingerprint,std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<std::unique_ptr<ClientProfile>,std::string> {
        if (!options.valid() || static_cast<std::uint8_t>(fingerprint)>static_cast<std::uint8_t>(tls::Fingerprint::random))
            return std::unexpected("invalid TUIC transport or TLS fingerprint option");
        constexpr std::array<std::string_view,1> alpn{"h3"};
        auto tls=tls::ClientProfile::load(server_name,ca_file,key_share,hybrid_only,alpn);
        if (!tls) return std::unexpected(tls.error());
        tls->certificate_pins.assign(pins.begin(),pins.end());
        auto raw_uuid=rulefile::read_password_file(uuid_file);
        if (!raw_uuid) return std::unexpected("TUIC UUID: "+raw_uuid.error());
        auto uuid=parse_uuid(*raw_uuid);
        crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(raw_uuid->data()),raw_uuid->size()));
        if (!uuid) return std::unexpected("invalid TUIC UUID format");
        auto password=rulefile::read_password_file(password_file);
        if (!password) return std::unexpected("TUIC password: "+password.error());
        return std::unique_ptr<ClientProfile>(new ClientProfile(
            std::move(*tls),*uuid,std::move(*password),options,fingerprint));
    }

    auto ClientProfile::tls_client(corosio::endpoint const& peer,quic::EchConfig const* ech) const
        -> std::expected<std::unique_ptr<Tls>,std::string> {
        constexpr std::array<std::string_view,1> alpn{"h3"};
        auto ip=platform::parse_ip_address(tls_.server_name);
        auto const& name=tls_.server_name;
        auto sni=ip ? std::optional<std::string_view>{} : std::optional<std::string_view>{name};
        auto config=tls::make_profile_fingerprint_config(
            fingerprint_,tls_.key_share,tls_.hybrid_only,tls::HandshakeTransport::quic);
        auto shaped=tls::make_fingerprint_hello(
            sni,alpn,config,tls::HandshakeTransport::quic,std::span<std::uint8_t const>{},{},ech!=nullptr);
        if (!shaped) return std::unexpected("cannot create TUIC ClientHello");
#ifdef NEXUS_QUIC_RESUMPTION
        if (!ech && peer.port() && tls_.certificate_pins.empty()) {
            auto identity=ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(name.data()),name.size());
            auto now=std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto setup=quic::ClientResumptionSetup<Tickets>::create(std::move(shaped->hello),shaped->initial_groups(),
                anchors_,ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,identity,now,"h3",tickets_,
                quic::ticket_peer_scope(peer),options_.zero_rtt_handshake);
            if (!setup) return std::unexpected("cannot initialize TUIC TLS recovery");
            return std::make_unique<Tls>(std::move(*setup));
        }
#else
        (void)peer;
#endif
        auto client=std::make_unique<Tls>(std::move(shaped->hello),shaped->initial_groups(),CertificatePolicy{*this},"h3");
        if (ech && !client->enable_ech(*ech)) return std::unexpected("cannot initialize TUIC ECH");
        return client;
    }
}
