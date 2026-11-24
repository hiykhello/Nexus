module hysteria2.client_profile;
import std;
import crypto;
import rulefile;
import hysteria2.credential;
import hysteria2.transport_options;
import quic.tls_client;
import quic.optional_client_resumption;
import quic.ech_config;
import tls.profiles;
import tls.certificate_trust;
import tls.hello_config;
import tls.fingerprint;
import platform.ip_address;
import corosio;

namespace hysteria2 {
    ClientProfile::ClientProfile(tls::ClientProfile tls,Password password,std::optional<SalamanderKey> salamander,TransportOptions options,
        tls::Fingerprint fingerprint)
        :tls_(std::move(tls)),password_(std::move(password)),salamander_(std::move(salamander)),options_(options),fingerprint_(fingerprint) {
        if(salamander_)options_.salamander_password=salamander_->bytes();
#ifdef NEXUS_QUIC_RESUMPTION
        anchors_.reserve(tls_.anchors.size());
        for (auto const& anchor:tls_.anchors) anchors_.emplace_back(anchor);
#endif
    }

    auto ClientProfile::CertificatePolicy::operator()(std::span<std::span<std::uint8_t const> const> chain) const
        -> std::expected<void,tls::CertificateTrustError> {
        std::vector<std::span<std::uint8_t const>> anchors;
        anchors.reserve(profile_.tls_.anchors.size());
        for (auto const& certificate:profile_.tls_.anchors) anchors.emplace_back(certificate);
        auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto const& name=profile_.tls_.server_name;
        auto ip=platform::parse_ip_address(name);
        auto identity=ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(name.data()),name.size());
        return tls::verify_server_certificate_chain(chain,anchors,ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,identity,now,profile_.tls_.certificate_pins);
    }

    auto ClientProfile::load(std::string_view server_name,std::string_view ca_file,std::string_view password_file,
        std::uint16_t key_share,bool hybrid_only,TransportOptions options,
        std::optional<std::string_view> salamander_file,
        tls::Fingerprint fingerprint,
        std::span<std::array<std::uint8_t,32> const> pins)
        -> std::expected<std::unique_ptr<ClientProfile>,std::string> {
        if (static_cast<std::uint8_t>(fingerprint)>static_cast<std::uint8_t>(tls::Fingerprint::random))
            return std::unexpected("invalid TLS fingerprint configuration");
        if (!options.valid() || (salamander_file && options.max_udp_payload_size && *options.max_udp_payload_size<1208))
            return std::unexpected("invalid Hysteria2 transport options");
        constexpr std::array<std::string_view,1> alpn{"h3"};
        auto tls=tls::ClientProfile::load(server_name,ca_file,key_share,hybrid_only,alpn);
        if (!tls) return std::unexpected(tls.error());
        tls->certificate_pins.assign(pins.begin(),pins.end());
        auto secret=rulefile::read_password_file(password_file);
        if (!secret) return std::unexpected(secret.error());
        struct Wipe {std::string& value;~Wipe(){crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(value.data()),value.size()));}} wipe{*secret};
        auto password=Password::create(std::span(reinterpret_cast<std::uint8_t const*>(secret->data()),secret->size()));
        if (!password) return std::unexpected("invalid Hysteria2 password");
        std::optional<SalamanderKey> salamander;
        if(salamander_file){
            auto value=rulefile::read_password_file(*salamander_file);
            if(!value)return std::unexpected(value.error());
            Wipe clear{*value};
            auto key=SalamanderKey::create(std::span(reinterpret_cast<std::uint8_t const*>(value->data()),value->size()));
            if(!key)return std::unexpected(key.error());
            salamander.emplace(std::move(*key));
        }
        return std::unique_ptr<ClientProfile>(new ClientProfile(std::move(*tls),std::move(*password),std::move(salamander),options,fingerprint));
    }
    auto ClientProfile::tls_client(corosio::endpoint const& peer,quic::EchConfig const* ech,
        Tickets* tickets) const -> std::expected<std::unique_ptr<Tls>,std::string> {
        constexpr std::array<std::string_view,1> alpn{"h3"};
        auto make = [&](tls::ClientHello hello, std::span<const std::uint16_t> groups)
            -> std::expected<std::unique_ptr<Tls>, std::string> {
#ifdef NEXUS_QUIC_RESUMPTION
            if (tickets && !ech && tls_.certificate_pins.empty()) {
                auto const& name=tls_.server_name;
                auto ip=platform::parse_ip_address(name);
                auto identity=ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(name.data()),name.size());
                auto now=std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                auto setup=quic::ClientResumptionSetup<Tickets>::create(std::move(hello),groups,anchors_,
                    ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,identity,now,"h3",*tickets,
                    quic::ticket_peer_scope(peer));
                if (!setup) return std::unexpected("cannot initialize Hysteria2 TLS recovery");
                return std::make_unique<Tls>(std::move(*setup));
            }
#else
            (void)peer; (void)tickets;
#endif
            auto client = std::make_unique<Tls>(std::move(hello), groups, CertificatePolicy{*this}, "h3");
            if (ech && !client->enable_ech(*ech)) return std::unexpected("cannot initialize Hysteria2 ECH");
            return client;
        };
        if (fingerprint_!=tls::Fingerprint::native) {
            auto sni=platform::parse_ip_address(tls_.server_name) ? std::optional<std::string_view>{} : std::optional<std::string_view>{tls_.server_name};
            auto config=tls::make_profile_fingerprint_config(fingerprint_,tls_.key_share,tls_.hybrid_only,tls::HandshakeTransport::quic);
            auto shaped=tls::make_fingerprint_hello(sni,alpn,config,tls::HandshakeTransport::quic,std::span<std::uint8_t const>{},{},ech!=nullptr);
            if (!shaped) return std::unexpected("cannot create Hysteria2 ClientHello");
            return make(std::move(shaped->hello), shaped->initial_groups());
        }
        std::array<std::uint16_t,2> group_storage{tls_.key_share,0x001d};
        auto count=tls_.key_share==0x11ec && !tls_.hybrid_only ? 2u : 1u;
        auto groups=std::span(group_storage).first(count);
        auto sni=platform::parse_ip_address(tls_.server_name) ? std::optional<std::string_view>{} : std::optional<std::string_view>{tls_.server_name};
        auto hello=tls::make_client_hello(sni,alpn,groups);
        if (!hello) return std::unexpected("cannot create Hysteria2 ClientHello");
        return make(std::move(*hello), groups);
    }
}
