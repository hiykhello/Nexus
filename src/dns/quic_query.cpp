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
import capy;
import corosio;
import ngtcp2;
import quic.tls_client;
import tls.certificate_trust;
import dns.quic_query_runtime;

namespace dns::doq_detail {
    struct NoResumptionPolicy {
        static constexpr bool supports_early_data = false;
        struct TicketCache {};
        static auto make_ticket_cache() noexcept -> TicketCache { return {}; }

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

        static auto make_profile(tls::ClientProfile identity, platform::SocketBinding socket, std::chrono::milliseconds timeout,
            bool early_data, QuicDnsDatagramFactory datagram)
            -> std::expected<std::shared_ptr<Profile const>, std::string> {
            if (early_data) return std::unexpected("DoQ early-data requires dns-quic-resumption");
            return std::make_shared<Profile const>(Profile{std::move(identity), std::move(socket), timeout, std::move(datagram)});
        }

        static auto initialize_tls(std::optional<Tls>& session, tls::FingerprintHello hello, Profile const& profile,
            corosio::endpoint const&, TicketCache const&, bool) -> bool {
            session.emplace(std::move(hello.hello), hello.initial_groups(), CertificatePolicy{profile.tls}, "doq");
            return true;
        }
    };
}

namespace dns {
    auto stop_quic_queries(corosio::io_context& context) noexcept -> void {
        doq_detail::stop_quic_queries_with<doq_detail::NoResumptionPolicy>(context);
    }
    auto resume_quic_queries(corosio::io_context& context) noexcept -> void {
        doq_detail::resume_quic_queries_with<doq_detail::NoResumptionPolicy>(context);
    }
    auto make_quic_query(std::string_view server_name, std::string_view ca_file, platform::SocketBinding binding,
        std::chrono::milliseconds connect_timeout, bool early_data, QuicDnsDatagramFactory datagram)
        -> std::expected<detail::ProtectedQuery, std::string> {
        return doq_detail::make_quic_query_with<doq_detail::NoResumptionPolicy>(
            server_name, ca_file, std::move(binding), connect_timeout, early_data, std::move(datagram));
    }
}
