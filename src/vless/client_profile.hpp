// Private implementation. Import config, rulefile, vless and
// tls.client_handshake_io and reality.client before including this file.
#pragma once

namespace vless::detail {
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

        [[nodiscard]] auto handshake(std::uint64_t now, std::uint64_t deadline,
                                     std::int64_t verification_time) const
            -> std::expected<tls::ClientHandshakeIo, std::string> {
            constexpr std::array<std::uint16_t,1> classical{0x001d};
            constexpr std::array<std::uint16_t,2> hybrid{0x11ec,0x001d};
            constexpr std::array<std::uint16_t,1> hybrid_only{0x11ec};
            auto use_hybrid=key_exchange!=config::TlsKeyExchange::x25519;
            auto groups=key_exchange==config::TlsKeyExchange::x25519_mlkem768_only ? std::span<std::uint16_t const>{hybrid_only} :
                use_hybrid ? std::span<std::uint16_t const>{hybrid} : std::span<std::uint16_t const>{classical};
            auto hello=tls::make_client_hello(server_name,{},groups);
            if (!hello) return std::unexpected("invalid TLS server name or ClientHello");
            if (reality) {
                if (verification_time<0 || static_cast<std::uint64_t>(verification_time)>std::numeric_limits<std::uint32_t>::max()) return std::unexpected("invalid Reality time");
                reality::Identity identity{{1,8,24},static_cast<std::uint32_t>(verification_time),reality->short_id};
                auto session=reality::create_client_session(std::move(*hello),groups,reality->public_key,identity);
                if (!session) return std::unexpected("invalid Reality client configuration");
                auto io=tls::ClientHandshakeIo::create(std::move(*session),now,deadline);
                if (!io) return std::unexpected("invalid TLS handshake deadline");
                return std::move(*io);
            }
            tls::ClientTlsConfig config{std::move(*hello),anchors,
                crypto::Bytes(server_name.begin(),server_name.end()),tls::PeerNameKind::dns,verification_time,use_hybrid ? std::uint16_t{0x11ec} : std::uint16_t{0x001d}};
            auto session=tls::ClientSessionHandshake::create(std::move(config));
            if (!session) return std::unexpected("invalid TLS client configuration");
            auto io=tls::ClientHandshakeIo::create(std::move(*session),now,deadline);
            if (!io) return std::unexpected("invalid TLS handshake deadline");
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
            // Validate the identity and the complete TLS configuration before listening.
            auto validation=profile.handshake(0,1,0);
            if (!validation) return std::unexpected(validation.error());
            return profile;
        }
    };
}
