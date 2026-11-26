module;
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>
module relay;
import std;
import rulefile;
import crypto;
import shadowtls.v3;
import shadowtls.stream;
import relay.stream_relay;
import capy;
import corosio;

namespace relay {
    namespace {
        struct StlsInboundProfile {
            std::string handshake_host;
            std::uint16_t handshake_port = 0;
            std::string target_host;
            std::uint16_t target_port = 0;
            std::vector<std::string> passwords;
            std::vector<std::string> names;
            bool strict_tls13 = true;
            std::vector<shadowtls::SniHandshakeEntry> handshake_for_server_name;
            shadowtls::WildcardSniMode wildcard_sni = shadowtls::WildcardSniMode::off;

            ~StlsInboundProfile() {
                for (auto& p : passwords)
                    crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(p.data()), p.size()));
            }
        };

        auto is_blocked_wildcard_endpoint(io::endpoint const& ep) noexcept -> bool {
            if (ep.address().is_v4()) return shadowtls::is_blocked_wildcard_ipv4(ep.address().to_v4().to_bytes());
            return shadowtls::is_blocked_wildcard_ipv6(ep.address().to_v6().to_bytes());
        }

        auto dial_host_port(Session& session, io::io_context& context, std::string host, std::uint16_t port,
                            io::tcp_socket& sock, Clock::time_point deadline, bool reject_private_ips = false)
            -> capy::task<bool> {
            DnsSlot slot;
            auto eps = co_await resolve_local_owned(session, context, slot, std::move(host), port, deadline);
            if (!eps || eps->empty() || session.closed) co_return false;
            for (auto const& ep : *eps) {
                if (!ep.port() || ep.address().is_unspecified()) continue;
                if (reject_private_ips && is_blocked_wildcard_endpoint(ep)) continue;
                sock.close();
                if (sock.open(ep.address().family())) continue;
                auto [err] = co_await io::timeout(sock.connect(ep), deadline);
                if (!err) co_return true;
            }
            co_return false;
        }

        auto serve_shadowtls(Session& session, io::io_context& context, rules::RouteMatcher const&,
                             StlsInboundProfile const& profile) -> capy::task<> {
            auto finish = [&] { session.close(); session.done = true; };
            auto deadline = session.started + std::chrono::seconds(15);

            shadowtls::TlsRecordReader reader;
            std::array<std::uint8_t, 16640> rx{};
            std::vector<std::uint8_t> first_rec;
            std::vector<std::uint8_t> leftover;
            while (first_rec.empty()) {
                auto [ec, n] = co_await io::timeout(
                    session.client.read_some(capy::mutable_buffer(rx.data(), rx.size())), deadline);
                if (ec || !n || session.closed) { finish(); co_return; }
                auto step = reader.feed(std::span(rx).first(n));
                if (step.status == shadowtls::RecordStatus::malformed || step.status == shadowtls::RecordStatus::too_large) {
                    finish(); co_return;
                }
                if (step.status == shadowtls::RecordStatus::complete) {
                    first_rec.assign(step.record.begin(), step.record.end());
                    leftover.assign(rx.begin() + static_cast<std::ptrdiff_t>(step.consumed),
                                    rx.begin() + static_cast<std::ptrdiff_t>(n));
                    reader.consume();
                }
            }

            std::vector<std::string_view> views;
            views.reserve(profile.passwords.size());
            for (auto const& p : profile.passwords) views.push_back(p);
            auto matched = shadowtls::verify_client_hello(first_rec, views);
            auto const sni = shadowtls::extract_client_hello_sni(first_rec);
            auto chosen = shadowtls::select_handshake_target(
                sni ? std::optional<std::string_view>{*sni} : std::nullopt,
                matched.has_value(),
                profile.handshake_host, profile.handshake_port,
                profile.handshake_for_server_name, profile.wildcard_sni);
            auto const hs_deadline = chosen.is_wildcard
                ? std::min(deadline, Clock::now() + std::chrono::seconds(5))
                : deadline;

            io::tcp_socket hs_sock(context);
            std::stop_callback stop_hs(session.stop.get_token(), [&]() noexcept { hs_sock.close(); });
            if (session.closed ||
                !co_await dial_host_port(session, context, std::move(chosen.host), chosen.port,
                                         hs_sock, hs_deadline, chosen.is_wildcard)) {
                finish(); co_return;
            }
            if (!matched) {
                session.relaying = true;
                session.touched = Clock::now();
                co_await shadowtls::relay_plain_tls(session.client, hs_sock, first_rec, leftover, deadline);
                hs_sock.close();
                finish();
                co_return;
            }

            if (*matched<profile.names.size() && !session.admit_principal(profile.names[*matched])) {finish(); co_return;}
            auto established = co_await shadowtls::handshake_server(
                session.client, hs_sock, profile.passwords, first_rec, leftover,
                *matched, deadline, profile.strict_tls13);
            hs_sock.close();
            if (!established || session.closed) { finish(); co_return; }

            session.begin_traffic(TrafficProtocol::shadowtls,profile.target_port);
            if (!co_await dial_host_port(session, context, profile.target_host, profile.target_port, session.target, deadline)) {
                finish(); co_return;
            }

            session.select_traffic_path(ConnectPath::direct);
            shadowtls::VerifiedSocket<io::tcp_socket> verified(
                session.client, std::move(established->stream),
                std::move(established->unread_wire), std::move(established->initial_payload));
            session.relaying = true;
            session.touched = Clock::now();
            std::stop_callback stop(session.stop.get_token(),[&]() noexcept {verified.cancel();});
            (void)co_await capy::when_all(stream_relay::direction(session,stream_relay::upload(session,verified)),
                stream_relay::direction(session,stream_relay::download(session,verified)));
            finish();
        }
    }

    auto make_shadowtls_inbound_factory(std::string_view handshake_host, std::uint16_t handshake_port,
        std::string_view target_host, std::uint16_t target_port,
        std::span<std::string const> password_files, std::span<std::string const> names,
        bool strict_tls13,
        std::span<std::pair<std::string, config::FallbackTarget> const> handshake_for_server_name,
        std::string_view wildcard_sni) -> std::expected<InboundFactory, std::string> {
        if (handshake_host.empty() || !handshake_port || target_host.empty() || !target_port ||
            password_files.empty() || password_files.size() > 64 || (!names.empty() && names.size() != password_files.size()) ||
            handshake_for_server_name.size() > 64)
            return std::unexpected("invalid ShadowTLS inbound configuration");
        auto mode = shadowtls::parse_wildcard_sni_mode(wildcard_sni);
        if (!mode) return std::unexpected("invalid ShadowTLS wildcard-sni mode");
        auto profile = std::make_unique<StlsInboundProfile>();
        profile->handshake_host = std::string(handshake_host);
        profile->handshake_port = handshake_port;
        profile->target_host = std::string(target_host);
        profile->target_port = target_port;
        profile->strict_tls13 = strict_tls13;
        profile->wildcard_sni = *mode;
        profile->handshake_for_server_name.reserve(handshake_for_server_name.size());
        for (auto const& [sni, target] : handshake_for_server_name) {
            if (sni.empty() || sni.size() > 253 || target.host.empty() || target.host.size() > 253 || !target.port)
                return std::unexpected("invalid ShadowTLS handshake-for-server-name entry");
            std::string norm;
            norm.reserve(sni.size());
            for (unsigned char c : sni)
                norm.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c));
            if (std::ranges::any_of(profile->handshake_for_server_name, [&](auto const& e) { return e.server_name == norm; }))
                return std::unexpected("duplicate ShadowTLS handshake-for-server-name entry");
            profile->handshake_for_server_name.push_back({std::move(norm), target.host, target.port});
        }
        profile->names.assign(names.begin(), names.end());
        for (auto const& f : password_files) {
            auto p = rulefile::read_password_file(f);
            if (!p || p->empty()) return std::unexpected("invalid ShadowTLS password file");
            profile->passwords.push_back(std::move(*p));
        }
        return InboundFactory{[profile = std::move(profile)](Session& s, io::io_context& ctx, rules::RouteMatcher const& policy) {
            return serve_shadowtls(s, ctx, policy, *profile);
        }};
    }
}
