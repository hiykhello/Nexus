module relay;
import std;
import trojan;
import trojan.auth;
import trojan.stream;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import tls.byte_stream;
import tls.profiles;
import tls.server_credential;
import tls.corosio_application;
import tls.corosio_server_handshake;
import tls.client_flight;
import capy;
import corosio;
import config;
import rules;
import :transport_helpers;
import :trojan_inbound_common;

namespace relay {
    namespace {
        using WsStream = websocket::VlessByteStream<corosio::tcp_socket>;
        using Incoming = trojan::detail::Inbound<corosio::tcp_socket, WsStream>;

        auto serve(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
            trojan_in::TrojanInboundProfile const& profile) -> capy::task<> {
            auto fail = [&] { session.close(); session.done = true; };
            auto deadline = session.started + std::chrono::seconds(10);
            auto milliseconds = [](auto value) {
                return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
            };
            auto start = milliseconds(session.started), end = milliseconds(deadline);
            if (start < 0 || end <= start) { fail(); co_return; }
            auto budget = std::make_shared<memory::Budget>(8u * 1024 * 1024);
            std::string_view req_alpn = profile.grpc ? "h2" : profile.transport ? "http/1.1" : "";
            auto handshake = tls::make_server_handshake(profile.credential, start, end, budget, req_alpn);
            if (!handshake) { fail(); co_return; }
            auto established = co_await tls::detail::server_handshake(session.client, *handshake, budget);
            if (!established || session.closed) { fail(); co_return; }
            tls::detail::ApplicationConnection<corosio::tcp_socket> connection(
                session.client, std::move(established->records), std::move(established->unread));
            if (!established->release_unread_reservation()) { fail(); co_return; }
#ifdef NEXUS_ENABLE_KTLS
            if (!profile.grpc && !profile.transport)
                (void)connection.try_enable_ktls(tls::ApplicationRole::server);
#endif
            if (profile.grpc) {
                co_await trojan_in::serve_trojan_grpc(session, context, policy, profile, connection);
                fail(); co_return;
            }
            Incoming incoming(connection, profile.users);
            if (profile.transport) {
                if (!co_await transport_detail::handshake_ws_or_hu(incoming.stream(), *profile.transport, deadline) ||
                    session.closed) {
                    fail(); co_return;
                }
            }
            auto erased = trojan_in::TrojanInboundRef::from(incoming);
            co_await trojan_in::serve_trojan_stream(session, context, policy, profile, erased, deadline);
            fail();
        }
    }

    auto make_trojan_inbound_factory(std::string_view certificate, std::string_view key,
        std::span<std::string const> passwords, std::span<std::string const> names,
        std::optional<HttpUpgradeTransport> transport, std::optional<GrpcTransport> grpc_cfg,
        std::optional<config::InboundMultiplexConfig> multiplex) -> std::expected<InboundFactory, std::string> {
        if (passwords.empty() || passwords.size() > 64 || (!names.empty() && names.size() != passwords.size()))
            return std::unexpected("invalid Trojan users");
        if (transport && grpc_cfg) return std::unexpected("Trojan inbound accepts at most one transport");
        for (std::size_t i = 0; i < names.size(); ++i)
            if (names[i].empty() || names[i].size() > 255 || names[i].find('\0') != std::string::npos ||
                std::ranges::contains(names.first(i), names[i]))
                return std::unexpected("invalid or duplicate Trojan user name");
        auto credential = tls::load_server_credential(certificate, key);
        if (!credential) return std::unexpected(credential.error());
        auto profile = std::make_unique<trojan_in::TrojanInboundProfile>(std::move(*credential));
        profile->multiplex = std::move(multiplex);
        if (transport) {
            auto compiled = transport_detail::compile_httpupgrade(*transport, false, {});
            if (!compiled) return std::unexpected(compiled.error());
            profile->transport = std::move(*compiled);
        }
        if (grpc_cfg) {
            auto compiled = transport_detail::compile_grpc(*grpc_cfg, false, {});
            if (!compiled) return std::unexpected(compiled.error());
            profile->grpc = std::move(*compiled);
        }
        for (auto const& path : passwords) {
            auto password = trojan::PasswordKey::load(path);
            if (!password) return std::unexpected(password.error());
            if (trojan::authenticate(profile->users, password->view()))
                return std::unexpected("duplicate Trojan password");
            profile->users.push_back(std::move(*password));
        }
        profile->names.assign(names.begin(), names.end());
        return InboundFactory{[profile = std::move(profile)](Session& session, corosio::io_context& context,
            rules::RouteMatcher const& policy) {
            return serve(session, context, policy, *profile);
        }};
    }
}
