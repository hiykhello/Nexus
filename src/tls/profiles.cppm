export module tls.profiles;
import std;
import tls.tls12_client;
import rulefile;
import crypto;
import tls.certificate_trust;
import tls.client_handshake_io;
import tls.fingerprint;
import tls.server_handshake_io;
import platform.ip_address;
export import quic.ech_config;

export namespace tls {
    // Protocol-independent, immutable TLS configuration. File loading happens
    // before listeners start; every attempt gets fresh handshake randomness.
    struct ClientProfile {
        std::string server_name;
        std::vector<crypto::Bytes> anchors;
        std::uint16_t key_share=0x001d;
        bool hybrid_only=false;
        std::vector<std::string> alpn;
        std::vector<std::array<std::uint8_t,32>> certificate_pins;
        OutboundFragmentOptions tls_fragment{};

        auto handshake(std::uint64_t now,std::uint64_t deadline,std::int64_t verification_time,
            std::span<std::uint8_t const> target={},quic::EchConfig const* ech=nullptr) const -> std::expected<ClientHandshakeIo,std::string>;
        // Explicit policy replaces the legacy key_share selection for this
        // attempt. It borrows this immutable identity and stores no policy in
        // the default profile, so native profile layout and behavior stay exact.
        auto handshake(std::uint64_t now,std::uint64_t deadline,std::int64_t verification_time,
            FingerprintConfig const& fingerprint,std::span<std::uint8_t const> target={},quic::EchConfig const* ech=nullptr) const
            -> std::expected<ClientHandshakeIo,std::string>;
        static auto load(std::string_view name,std::string_view ca,std::uint16_t key_share=0x001d,
            bool hybrid_only=false,std::span<std::string_view const> alpn={})
            -> std::expected<ClientProfile,std::string>;
    };

    // A directly owned policy for protocol connectors that opt into shaping.
    // Legacy ClientProfile users retain their original layout and behavior.
    class ShapedClientProfile {
        ClientProfile profile_;
        Fingerprint selected_;
        std::optional<std::uint16_t> record_size_limit_;
        ShapedClientProfile(ClientProfile profile,Fingerprint selected,std::optional<std::uint16_t> limit)
            :profile_(std::move(profile)),selected_(selected),record_size_limit_(limit) {}
    public:
        static auto create(ClientProfile profile,Fingerprint selected,std::optional<std::uint16_t> limit={})
            -> std::expected<ShapedClientProfile,std::string>;
        [[nodiscard]] auto profile() const noexcept -> ClientProfile const& { return profile_; }
        [[nodiscard]] auto fingerprint() const noexcept -> Fingerprint { return selected_; }
        [[nodiscard]] auto make_quic_hello(std::span<std::string_view const> alpn) const
            -> std::expected<FingerprintHello,std::string>;
        auto handshake(std::uint64_t now,std::uint64_t deadline,std::int64_t verification_time,
            std::span<std::uint8_t const> target={},quic::EchConfig const* ech=nullptr) const -> std::expected<ClientHandshakeIo,std::string>;
    };

    auto make_server_handshake(ServerCredential const& credential,std::uint64_t now,std::uint64_t deadline,
        std::shared_ptr<memory::Budget> budget={},std::string_view required_alpn={},
        std::shared_ptr<EchServerKeys const> ech_keys={})
        -> std::expected<ServerHandshakeIo,std::string>;
    auto make_server_handshake(ServerCredential const& credential,std::uint64_t now,std::uint64_t deadline,
        std::shared_ptr<memory::Budget> budget,std::span<std::string_view const> alpn_preferences,bool allow_no_alpn=true,
        std::shared_ptr<EchServerKeys const> ech_keys={})
        -> std::expected<ServerHandshakeIo,std::string>;
    auto load_server_credential(std::string_view certificate_path,std::string_view private_key_path)
        -> std::expected<ServerCredential,std::string>;
}

module :private;

namespace tls {
    auto ClientProfile::handshake(std::uint64_t now,std::uint64_t deadline,std::int64_t verification_time,
        std::span<std::uint8_t const> target,quic::EchConfig const* ech) const -> std::expected<ClientHandshakeIo,std::string> {
        std::array<std::uint16_t,1> classical{key_share};
        constexpr std::array<std::uint16_t,1> hybrid_only_groups{0x11ec};
        constexpr std::array<std::uint16_t,2> hybrid{0x11ec,0x001d};
        if ((key_share!=0x001d && key_share!=0x11ec && !crypto::nist_curve(key_share)) || (hybrid_only && key_share!=0x11ec))
            return std::unexpected("invalid TLS key exchange");
        auto groups=key_share!=0x11ec ? std::span<std::uint16_t const>{classical} : hybrid_only ?
            std::span<std::uint16_t const>{hybrid_only_groups} : std::span<std::uint16_t const>{hybrid};
        if (alpn.size()>16) return std::unexpected("too many TLS application protocols");
        std::array<std::string_view,16> protocols{};
        for (std::size_t index=0;index<alpn.size();++index) protocols[index]=alpn[index];
        auto ip=platform::parse_ip_address(server_name);
        if (ech && ip) return std::unexpected("TLS ECH requires a DNS server-name");
        auto sni=ip ? std::optional<std::string_view>{} : std::optional<std::string_view>{server_name};
        auto hello=make_client_hello(sni,std::span(protocols).first(alpn.size()),groups);
        if (!hello) return std::unexpected("invalid TLS server name or ClientHello");
        auto identity=ip ? crypto::Bytes(ip->view().begin(),ip->view().end()) : crypto::Bytes(server_name.begin(),server_name.end());
        auto io=ClientHandshakeIo::create(std::move(*hello),groups,anchors,ip ? PeerNameKind::ip : PeerNameKind::dns,
            identity,verification_time,now,deadline,target,certificate_pins,ech);
        if (!io) return std::unexpected("invalid TLS handshake deadline");
        io->set_fragment_options(tls_fragment);
        return std::move(*io);
    }

    auto ClientProfile::handshake(std::uint64_t now,std::uint64_t deadline,std::int64_t verification_time,
        FingerprintConfig const& fingerprint,std::span<std::uint8_t const> target,quic::EchConfig const* ech) const
        -> std::expected<ClientHandshakeIo,std::string> {
        if (alpn.size()>16) return std::unexpected("too many TLS application protocols");
        std::array<std::string_view,16> protocols{};
        for (std::size_t index=0;index<alpn.size();++index) protocols[index]=alpn[index];
        auto ip=platform::parse_ip_address(server_name);
        if (ech && ip) return std::unexpected("TLS ECH requires a DNS server-name");
        auto sni=ip ? std::optional<std::string_view>{} : std::optional<std::string_view>{server_name};
        if (fingerprint.profile==Fingerprint::tls12) {
            if (ech) return std::unexpected("TLS ECH requires TLS 1.3");
            if (key_share!=29 || hybrid_only || fingerprint.record_size_limit)
                return std::unexpected("TLS 1.2 requires X25519 and the default record size");
            auto identity=ip ? crypto::Bytes(ip->view().begin(),ip->view().end()) : crypto::Bytes(server_name.begin(),server_name.end());
            auto session=Tls12Client::create(sni,std::span(protocols).first(alpn.size()),anchors,std::move(identity),
                ip ? PeerNameKind::ip : PeerNameKind::dns,verification_time);
            if (!session) return std::unexpected("invalid TLS 1.2 configuration");
            session->set_certificate_pins(certificate_pins);
            auto io=ClientHandshakeIo::create(std::move(*session),now,deadline);
            if (!io) return std::unexpected("invalid TLS handshake deadline");
            io->set_fragment_options(tls_fragment);
            return std::move(*io);
        }
        auto fp=fingerprint;
        if (ech) fp.allow_tls12=false;
        auto shape=make_fingerprint_hello(sni,std::span(protocols).first(alpn.size()),fp,HandshakeTransport::tcp,{},{},ech!=nullptr);
        if (!shape) return std::unexpected("invalid TLS fingerprint configuration");
        auto name=ip ? ip->view() : std::span(reinterpret_cast<std::uint8_t const*>(server_name.data()),server_name.size());
        auto io=ClientHandshakeIo::create(std::move(shape->hello),shape->initial_groups(),anchors,
            ip ? PeerNameKind::ip : PeerNameKind::dns,name,verification_time,now,deadline,target,certificate_pins,ech);
        if (!io) return std::unexpected("invalid TLS handshake deadline");
        io->set_fragment_options(tls_fragment);
        return std::move(*io);
    }

    auto ClientProfile::load(std::string_view name,std::string_view ca,std::uint16_t key_share,
        bool hybrid_only,std::span<std::string_view const> alpn) -> std::expected<ClientProfile,std::string> {
        if (!ca.empty() && (ca.front()!='/' || ca.find('\0')!=ca.npos))
            return std::unexpected("TLS CA path must be absolute");
        auto anchors=ca.empty() ? load_system_trust_bundle() : load_trust_bundle(ca);
        if (!anchors) return std::unexpected(ca.empty() ? "cannot load system TLS CA bundle" : "cannot load TLS CA bundle");
        ClientProfile profile{std::string(name),std::move(*anchors),key_share,hybrid_only};
        if (alpn.size()>16) return std::unexpected("too many TLS application protocols");
        for (auto value:alpn) profile.alpn.emplace_back(value);
        if (auto checked=profile.handshake(0,1,0); !checked) return std::unexpected(checked.error());
        return profile;
    }

    auto ShapedClientProfile::create(ClientProfile profile,Fingerprint selected,std::optional<std::uint16_t> limit)
        -> std::expected<ShapedClientProfile,std::string> {
        if(static_cast<std::uint8_t>(selected)>static_cast<std::uint8_t>(Fingerprint::tls12))
            return std::unexpected("invalid TLS fingerprint configuration");
        ShapedClientProfile result(std::move(profile),selected,limit);
        if(selected!=Fingerprint::native || limit) {
            auto checked=result.handshake(0,1,0);
            if(!checked)return std::unexpected(checked.error());
        }
        return result;
    }

    auto ShapedClientProfile::make_quic_hello(std::span<std::string_view const> alpn) const
        -> std::expected<FingerprintHello,std::string> {
        if (alpn.empty()) return std::unexpected("QUIC ClientHello requires ALPN");
        auto sni=platform::parse_ip_address(profile_.server_name)
            ? std::optional<std::string_view>{}
            : std::optional<std::string_view>{profile_.server_name};
        auto config=make_profile_fingerprint_config(selected_,profile_.key_share,profile_.hybrid_only,HandshakeTransport::quic);
        auto hello=make_fingerprint_hello(sni,alpn,config,HandshakeTransport::quic,std::span<std::uint8_t const>{});
        if (!hello) return std::unexpected("invalid QUIC ClientHello fingerprint configuration");
        return std::move(*hello);
    }

    auto ShapedClientProfile::handshake(std::uint64_t now,std::uint64_t deadline,std::int64_t verification_time,
        std::span<std::uint8_t const> target,quic::EchConfig const* ech) const -> std::expected<ClientHandshakeIo,std::string> {
        if(selected_==Fingerprint::native && !record_size_limit_)return profile_.handshake(now,deadline,verification_time,target,ech);
        auto config=make_profile_fingerprint_config(selected_,profile_.key_share,profile_.hybrid_only,HandshakeTransport::tcp,record_size_limit_);
        return profile_.handshake(now,deadline,verification_time,config,target,ech);
    }

    auto make_server_handshake(ServerCredential const& credential,std::uint64_t now,std::uint64_t deadline,
        std::shared_ptr<memory::Budget> budget,std::string_view required_alpn,std::shared_ptr<EchServerKeys const> ech_keys)
        -> std::expected<ServerHandshakeIo,std::string> {
        std::optional<memory::Budget::Reservation> reservation;
        if (budget) {
            auto size=credential.certificate().size();
            for (auto const& certificate:credential.chain()) size+=certificate.size()+sizeof(crypto::Bytes);
            reservation=memory::Budget::reserve(budget,size);
            if (!reservation) return std::unexpected("TLS handshake budget exceeded");
        }
        auto copy=credential.clone();
        if (!copy) return std::unexpected("cannot retain TLS credential");
        auto handshake=ServerHandshakeIo::create(std::move(*copy),now,deadline,required_alpn,ServerCredential::max_certificate_list_size,
            std::move(budget),std::move(reservation));
        if (!handshake) return std::unexpected(handshake.error()==ServerHandshakeIoError::budget_exceeded ?
            "TLS handshake budget exceeded" : "invalid TLS handshake options");
        if (ech_keys) handshake->set_ech_keys(std::move(ech_keys));
        return std::move(*handshake);
    }

    auto make_server_handshake(ServerCredential const& credential,std::uint64_t now,std::uint64_t deadline,
        std::shared_ptr<memory::Budget> budget,std::span<std::string_view const> alpn_preferences,bool allow_no_alpn,
        std::shared_ptr<EchServerKeys const> ech_keys)
        -> std::expected<ServerHandshakeIo,std::string> {
        std::optional<memory::Budget::Reservation> reservation;
        if (budget) {
            auto size=credential.certificate().size();
            for (auto const& certificate:credential.chain()) size+=certificate.size()+sizeof(crypto::Bytes);
            reservation=memory::Budget::reserve(budget,size);
            if (!reservation) return std::unexpected("TLS handshake budget exceeded");
        }
        auto copy=credential.clone();
        if (!copy) return std::unexpected("cannot retain TLS credential");
        auto handshake=ServerHandshakeIo::create_alpn(std::move(*copy),now,deadline,alpn_preferences,allow_no_alpn,
            ServerCredential::max_certificate_list_size,std::move(budget),std::move(reservation));
        if (!handshake) return std::unexpected(handshake.error()==ServerHandshakeIoError::budget_exceeded ?
            "TLS handshake budget exceeded" : "invalid TLS handshake options");
        if (ech_keys) handshake->set_ech_keys(std::move(ech_keys));
        return std::move(*handshake);
    }

    auto load_server_credential(std::string_view certificate_path,std::string_view private_key_path)
        -> std::expected<ServerCredential,std::string> {
        auto certificate=rulefile::read_regular_file(certificate_path);
        if (!certificate) return std::unexpected("certificate file: "+certificate.error());
        auto key=rulefile::read_private_file(private_key_path);
        if (!key) return std::unexpected("private key file: "+key.error());
        auto cert_bytes=std::span(reinterpret_cast<std::uint8_t const*>(certificate->data()),certificate->size());
        auto key_bytes=key->bytes();
        auto loaded=ServerCredential::create_file_contents(cert_bytes,{reinterpret_cast<std::uint8_t const*>(key_bytes.data()),key_bytes.size()});
        if (!loaded) return std::unexpected("invalid or mismatched TLS credential");
        return std::move(*loaded);
    }
}
