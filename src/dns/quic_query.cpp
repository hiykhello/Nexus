module dns.quic_query;
import std;
import crypto;
import dns.corosio_query;
import dns.input_budget;
import net.datagram_driver;
import net.udp_connect;
import platform.socket_options;
import quic.cid_registry;
import quic.connection;
import quic.datagram_port;
import quic.datagram_session;
import quic.transport_memory;
import tls.fingerprint;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.thirdparty.ngtcp2;
import quic.tls_client;
import tls.certificate_trust;


namespace dns::doq_detail {
    constexpr bool supports_early_data=false;
    struct TicketCache {};
    auto make_ticket_cache() noexcept -> TicketCache {
        return {};
    }

    struct Profile {
        tls::ClientProfile tls;
        platform::SocketBinding binding;
        std::chrono::milliseconds connect_timeout;
        QuicDnsDatagramFactory datagram;
    };

    struct CertificatePolicy {
        tls::ClientProfile const& profile;

        auto operator()(std::span<std::span<std::uint8_t const> const> certificates) const
            -> std::expected<void, tls::CertificateTrustError> {
            std::vector<std::span<std::uint8_t const>> anchors;
            anchors.reserve(profile.anchors.size());
            for (auto const& certificate : profile.anchors) anchors.emplace_back(certificate);
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto const& server = profile.server_name;
            auto name = std::span(reinterpret_cast<std::uint8_t const*>(server.data()), server.size());
            return tls::verify_server_certificate_chain(certificates, anchors, tls::PeerNameKind::dns, name, now);
        }
    };
    using Tls = quic::TlsClient<CertificatePolicy>;

    auto make_profile(tls::ClientProfile identity, platform::SocketBinding socket, std::chrono::milliseconds timeout,
        bool early_data,QuicDnsDatagramFactory datagram)
        -> std::expected<std::shared_ptr<Profile const>, std::string> {
        if (early_data) return std::unexpected("DoQ early-data requires dns-quic-resumption");
        return std::make_shared<Profile const>(Profile{std::move(identity), std::move(socket), timeout,std::move(datagram)});
    }

    auto initialize_tls(std::optional<Tls>& session, tls::FingerprintHello hello, Profile const& profile,
        nex::corosio::endpoint const&, TicketCache const&,bool) -> bool {
        session.emplace(std::move(hello.hello), hello.initial_groups(), CertificatePolicy{profile.tls}, "doq");
        return true;
    }
}

#include "quic_query_runtime.hpp"
