export module vless.client_profile;
import std;
import config;
import rulefile;
import vless;
import crypto;
import reality.client;
import tls.certificate_trust;
import tls.client_handshake_io;
import tls.encrypted_extensions;
import tls.fingerprint;
import tls.outbound_fragment;
import tls.tls12_client;
import httpupgrade;
import platform.ip_address;
import quic.ech_config;

export namespace vless::detail {
    // Prepared once before accepting clients. The CA bundle is a snapshot; every
    // handshake gets fresh random values, current verification time and its own deadline.
    struct ClientProfile {
        std::string host;
        std::uint16_t port;
        std::array<std::uint8_t,16> user;
        std::string server_name;
        std::vector<crypto::Bytes> anchors;
        config::TlsKeyExchange key_exchange;
        std::optional<config::VlessOutbound::Reality> reality;
        bool vision=false;
        std::optional<httpupgrade::Profile> transport;
        config::TlsFingerprint fingerprint=config::TlsFingerprint::native;
        std::optional<std::uint16_t> record_size_limit;
        std::vector<std::array<std::uint8_t,32>> certificate_pins;
        bool packetaddr=false,fixed_udp=false;
        tls::OutboundFragmentOptions tls_fragment{};
        std::vector<std::string> custom_alpn;

        [[nodiscard]] auto accepts_alpn(tls::EncryptedExtensions const* negotiated) const noexcept -> bool {
            return !transport || (negotiated && negotiated->alpn &&
                std::ranges::equal(*negotiated->alpn,std::string_view("http/1.1")));
        }

        [[nodiscard]] auto handshake(std::uint64_t now, std::uint64_t deadline,
                                     std::int64_t verification_time,
                                     std::span<std::string_view const> application_protocols={},
                                     quic::EchConfig const* ech=nullptr) const
            -> std::expected<tls::ClientHandshakeIo, std::string> {
            constexpr std::array<std::uint16_t,1> classical{0x001d};
            constexpr std::array<std::uint16_t,2> hybrid{0x11ec,0x001d};
            constexpr std::array<std::uint16_t,1> hybrid_only{0x11ec};
            auto use_hybrid=key_exchange!=config::TlsKeyExchange::x25519;
            auto groups=key_exchange==config::TlsKeyExchange::x25519_mlkem768_only ? std::span<std::uint16_t const>{hybrid_only} :
                use_hybrid ? std::span<std::uint16_t const>{hybrid} : std::span<std::uint16_t const>{classical};
            constexpr std::array<std::string_view,1> h1{"http/1.1"};
            std::array<std::string_view,16> custom_alpn_views{};
            std::size_t custom_alpn_count=std::min(custom_alpn.size(),custom_alpn_views.size());
            for (std::size_t i=0;i<custom_alpn_count;++i) custom_alpn_views[i]=custom_alpn[i];
            auto alpn=!application_protocols.empty() ? application_protocols :
                custom_alpn_count ? std::span<std::string_view const>(custom_alpn_views).first(custom_alpn_count) :
                transport ? std::span<std::string_view const>(h1) : std::span<std::string_view const>{};
            // Reality authenticates its cover name through SNI. Only ordinary
            // PKI TLS can use a numeric address as the certificate identity.
            auto ip=reality ? std::optional<platform::IpAddress>{} : platform::parse_ip_address(server_name);
            if (ech && (reality || ip)) return std::unexpected("VLESS ECH requires ordinary TLS with a DNS server-name");
            auto sni=ip ? std::optional<std::string_view>{} : std::optional<std::string_view>{server_name};
            if (fingerprint==config::TlsFingerprint::tls12) {
                if (ech) return std::unexpected("VLESS ECH requires TLS 1.3");
                if (reality || vision || use_hybrid || record_size_limit)
                    return std::unexpected("VLESS TLS 1.2 requires ordinary TLS, X25519 and the default record size");
                auto identity=ip ? crypto::Bytes(ip->view().begin(),ip->view().end()) : crypto::Bytes(server_name.begin(),server_name.end());
                auto session=tls::Tls12Client::create(sni,alpn,anchors,std::move(identity),
                    ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,verification_time);
                if (!session) return std::unexpected("invalid VLESS TLS 1.2 configuration");
                session->set_certificate_pins(certificate_pins);
                auto io=tls::ClientHandshakeIo::create(std::move(*session),now,deadline);
                if (!io) return std::unexpected("invalid TLS handshake deadline");
                io->set_fragment_options(tls_fragment);
                return std::move(*io);
            }
            if (fingerprint!=config::TlsFingerprint::native || record_size_limit) {
                auto resolved=tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
                if (!resolved) return std::unexpected("invalid TLS fingerprint configuration");
                auto primary=use_hybrid ? std::uint16_t{0x11ec} : std::uint16_t{0x001d};
                auto shape_config=tls::make_profile_fingerprint_config(*resolved,primary,
                    key_exchange==config::TlsKeyExchange::x25519_mlkem768_only,tls::HandshakeTransport::tcp,record_size_limit);
                if ((vision && !reality) || ech) shape_config.allow_tls12=false;
                if (reality && key_exchange==config::TlsKeyExchange::x25519_mlkem768 && !shape_config.group_count) {
                    shape_config.group_count=2;
                    shape_config.group_order={hybrid[0],hybrid[1]};
                    shape_config.key_share_count=2;
                    shape_config.key_share_groups=hybrid;
                }
                // Reality authenticates the peer with an Ed25519 credential.
                constexpr std::uint16_t ed25519=0x0807;
                auto shape=tls::make_fingerprint_hello(sni,alpn,shape_config,tls::HandshakeTransport::tcp,{},
                    reality ? std::optional{ed25519} : std::nullopt,ech!=nullptr);
                if (!shape) return std::unexpected("invalid TLS fingerprint configuration");
                if (reality) {
                    if (verification_time<0 || static_cast<std::uint64_t>(verification_time)>std::numeric_limits<std::uint32_t>::max()) return std::unexpected("invalid Reality time");
                    reality::Identity identity{{1,8,24},static_cast<std::uint32_t>(verification_time),reality->short_id};
                    auto session=reality::create_client_session(std::move(shape->hello),shape->initial_groups(),reality->public_key,identity);
                    if (!session) return std::unexpected("invalid Reality client configuration");
                    auto io=tls::ClientHandshakeIo::create(std::move(*session),now,deadline);
                    if (!io) return std::unexpected("invalid TLS handshake deadline");
                    io->set_fragment_options(tls_fragment);
                    return std::move(*io);
                }
                auto name=ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(server_name.data()),server_name.size());
                auto scope=std::format("vless:{}:{}",host,port);
                auto target=std::span(reinterpret_cast<std::uint8_t const*>(scope.data()),scope.size());
                auto io=tls::ClientHandshakeIo::create(std::move(shape->hello),shape->initial_groups(),anchors,
                    ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,name,verification_time,now,deadline,
                    vision || !verification_time ? std::span<std::uint8_t const>{} : target,certificate_pins,ech);
                if (!io) return std::unexpected("invalid TLS handshake deadline");
                io->set_fragment_options(tls_fragment);
                return std::move(*io);
            }
            auto hello=tls::make_client_hello(sni,alpn,groups);
            if (!hello) return std::unexpected("invalid TLS server name or ClientHello");
            if (reality) {
                if (verification_time<0 || static_cast<std::uint64_t>(verification_time)>std::numeric_limits<std::uint32_t>::max()) return std::unexpected("invalid Reality time");
                reality::Identity identity{{1,8,24},static_cast<std::uint32_t>(verification_time),reality->short_id};
                auto session=reality::create_client_session(std::move(*hello),groups,reality->public_key,identity);
                if (!session) return std::unexpected("invalid Reality client configuration");
                auto io=tls::ClientHandshakeIo::create(std::move(*session),now,deadline);
                if (!io) return std::unexpected("invalid TLS handshake deadline");
                io->set_fragment_options(tls_fragment);
                return std::move(*io);
            }
            auto identity=ip ? crypto::Bytes(ip->view().begin(),ip->view().end()) : crypto::Bytes(server_name.begin(),server_name.end());
            auto scope=std::format("vless:{}:{}",host,port);
            auto target=std::span(reinterpret_cast<std::uint8_t const*>(scope.data()),scope.size());
            auto io=tls::ClientHandshakeIo::create(std::move(*hello),groups,anchors,
                ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns,identity,verification_time,now,deadline,
                vision || !verification_time ? std::span<std::uint8_t const>{} : target,certificate_pins,ech);
            if (!io) return std::unexpected("invalid TLS handshake deadline");
            io->set_fragment_options(tls_fragment);
            return std::move(*io);
        }

        [[nodiscard]] static auto load(config::VlessOutbound const& config)
            -> std::expected<ClientProfile, std::string> {
            if (config.key_exchange!=config::TlsKeyExchange::x25519 && config.key_exchange!=config::TlsKeyExchange::x25519_mlkem768 && config.key_exchange!=config::TlsKeyExchange::x25519_mlkem768_only)
                return std::unexpected("invalid TLS key exchange");
            if (config.host.empty() || config.host.size()>253 || !config.port ||
                std::ranges::any_of(config.host,[](unsigned char c) { return c<33 || c>126; }) ||
                (!config.reality && (config.ca_file.empty() || config.ca_file.front()!='/' || config.ca_file.find('\0')!=std::string::npos)) ||
                (config.reality && !config.ca_file.empty()))
                return std::unexpected("invalid VLESS server or CA path");
            auto secret=rulefile::read_password_file(config.uuid_file);
            if (!secret) return std::unexpected("UUID file: " + secret.error());
            auto user=parse_user_id(*secret);
            std::fill(secret->begin(),secret->end(),'\0');
            if (!user) return std::unexpected("UUID file must contain a canonical UUID");
            std::vector<crypto::Bytes> anchors;
            if (!config.reality) { auto loaded=tls::load_trust_bundle(config.ca_file); if (!loaded) return std::unexpected("cannot load TLS CA bundle"); anchors=std::move(*loaded); }
            ClientProfile profile{config.host,config.port,*user,config.server_name,std::move(anchors),config.key_exchange,config.reality,config.vision};
            profile.fingerprint=config.fingerprint;profile.record_size_limit=config.record_size_limit;
            profile.certificate_pins=config.certificate_sha256;
            profile.packetaddr=config.packetaddr;
            profile.fixed_udp=config.fixed_udp;
            profile.tls_fragment={
                .enabled=config.tls_fragment.enabled,
                .record_fragment=config.tls_fragment.record_fragment,
                .min_bytes=config.tls_fragment.min_bytes,
                .max_bytes=config.tls_fragment.max_bytes,
                .fallback_delay_ms=config.tls_fragment.fallback_delay_ms,
            };
            profile.custom_alpn=config.alpn;
            if (config.transport) {
                if (config.vision || config.reality) return std::unexpected("HTTPUpgrade requires ordinary VLESS TLS");
                auto const& options=*config.transport;
                std::vector<httpupgrade::Field> headers;
                headers.reserve(options.headers.size());
                for (auto const& field:options.headers) headers.push_back({field.name,field.value});
                std::string default_host=config.server_name;
                if (options.host.empty()) if (auto ip=platform::parse_ip_address(default_host);ip && ip->size==16)
                    default_host="["+default_host+"]";
                auto compiled=httpupgrade::Profile::client(options.host.empty() ? default_host : options.host,options.path,headers,options.websocket,options.max_early_data,options.early_data_header_name);
                if (!compiled) return std::unexpected("invalid HTTPUpgrade client profile");
                profile.transport.emplace(std::move(*compiled));
            }
            // Validate the identity and the complete TLS configuration before listening.
            auto validation=profile.handshake(0,1,0);
            if (!validation) return std::unexpected(validation.error());
            return profile;
        }
    };
}
