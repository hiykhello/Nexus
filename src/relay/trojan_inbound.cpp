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
import tls.server_handshake_io;
import tls.ech_server;
import tls.corosio_application;
import tls.server_handshake_io;
import tls.corosio_server_handshake;
import tls.client_flight;
import capy;
import corosio;
import config;
import rules;
import :transport_helpers;
import :trojan_inbound_common;
import :trojan_fallback;

namespace relay {
    namespace {
        using WsStream = websocket::VlessByteStream<corosio::tcp_socket>;
        using Incoming = trojan::detail::Inbound<corosio::tcp_socket, WsStream>;

        auto serve(Session& session, corosio::io_context& context, rules::RouteProgram const& policy,
            trojan_in::TrojanInboundProfile const& profile) -> capy::task<> {
            auto fail = [&] { session.close(); session.done = true; };
            auto deadline = session.started + std::chrono::seconds(10);
            auto milliseconds = [](auto value) {
                return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
            };
            auto start = milliseconds(session.started), end = milliseconds(deadline);
            if (start < 0 || end <= start) { fail(); co_return; }
            auto budget = std::make_shared<memory::Budget>(8u * 1024 * 1024);
            std::optional<tls::ServerCredential> dyn_cred;
            tls::ServerCredential const* active_cred = nullptr;
            if (profile.atomic_credential) {
                auto cur = profile.atomic_credential->clone_current();
                if (!cur) { fail(); co_return; }
                dyn_cred.emplace(std::move(*cur));
                active_cred = &*dyn_cred;
            } else if (profile.credential) {
                active_cred = &*profile.credential;
            } else {
                fail(); co_return;
            }
            std::expected<tls::ServerHandshakeIo, std::string> handshake = std::unexpected(std::string{});
            if (!profile.grpc && !profile.transport && (!profile.fallback_for_alpn.empty() || !profile.alpn.empty())) {
                std::vector<std::string_view> alpn_prefs;
                alpn_prefs.reserve(profile.alpn.size() + profile.fallback_for_alpn.size());
                for (auto const& a : profile.alpn) alpn_prefs.push_back(a);
                for (auto const& [alpn, _] : profile.fallback_for_alpn)
                    if (!std::ranges::contains(alpn_prefs, std::string_view{alpn})) alpn_prefs.push_back(alpn);
                handshake = tls::make_server_handshake(*active_cred, start, end, budget, alpn_prefs, true, profile.ech_keys);
            } else if (!profile.alpn.empty()) {
                std::vector<std::string_view> alpn_prefs;
                alpn_prefs.reserve(profile.alpn.size());
                for (auto const& a : profile.alpn) alpn_prefs.push_back(a);
                handshake = tls::make_server_handshake(*active_cred, start, end, budget, alpn_prefs, true, profile.ech_keys);
            } else {
                std::string_view req_alpn = profile.grpc ? "h2" : profile.transport ? "http/1.1" : "";
                handshake = tls::make_server_handshake(*active_cred, start, end, budget, req_alpn, profile.ech_keys);
            }
            if (!handshake) { fail(); co_return; }
            auto established = co_await tls::detail::server_handshake(session.client, *handshake, budget);
            if (!established || session.closed) { fail(); co_return; }
            auto const alpn_span = handshake->negotiated_alpn();
            std::string_view const negotiated_alpn(
                reinterpret_cast<char const*>(alpn_span.data()), alpn_span.size());
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
            if (!profile.transport && (profile.fallback || !profile.fallback_for_alpn.empty())) {
                tls::detail::ByteStream<corosio::tcp_socket> tls_stream(connection);
                auto probed = co_await trojan_in::probe_trojan_header(tls_stream, profile.users, deadline);
                if (session.closed) { fail(); co_return; }
                if (probed.fallback) {
                    if (auto const* target = trojan_in::select_fallback_target(
                            profile.fallback, profile.fallback_for_alpn, negotiated_alpn)) {
                        co_await trojan_in::relay_trojan_fallback(
                            session, context, tls_stream, *target, std::move(probed.bytes), deadline);
                    }
                    fail(); co_return;
                }
                if (probed.accepted) {
                    trojan_in::PrefixedTlsStream prefixed(tls_stream, std::move(probed.bytes));
                    auto erased = trojan_in::TrojanInboundRef::from(prefixed);
                    co_await trojan_in::serve_trojan_stream(
                        session, context, policy, profile, erased, deadline, std::move(probed.accepted));
                }
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
        std::optional<config::InboundMultiplexConfig> multiplex,
        std::optional<config::FallbackTarget> fallback,
        std::span<std::pair<std::string, config::FallbackTarget> const> fallback_for_alpn,
        InboundTlsRuntime const& tls_rt)
        -> std::expected<InboundFactory, std::string> {
        if (passwords.empty() || passwords.size() > max_tunnel_outbounds || (!names.empty() && names.size() != passwords.size()))
            return std::unexpected("invalid Trojan users");
        if (transport && grpc_cfg) return std::unexpected("Trojan inbound accepts at most one transport");
        if (fallback && (fallback->host.empty() || fallback->host.size() > 253 || !fallback->port))
            return std::unexpected("invalid Trojan fallback target");
        if (fallback_for_alpn.size() > 1024)
            return std::unexpected("Trojan fallback-for-alpn accepts at most 1024 entries");
        std::unordered_set<std::string_view> seen_alpn;
        seen_alpn.reserve(fallback_for_alpn.size());
        for (auto const& [alpn, target] : fallback_for_alpn) {
            if (alpn.empty() || alpn.size() > 255 || target.host.empty() || target.host.size() > 253 || !target.port ||
                !seen_alpn.insert(alpn).second)
                return std::unexpected("invalid or duplicate Trojan fallback-for-alpn entry");
        }
        std::unordered_set<std::string_view> seen_names;
        seen_names.reserve(names.size());
        for (auto const& n : names)
            if (n.empty() || n.size() > 255 || n.find('\0') != std::string::npos || !seen_names.insert(n).second)
                return std::unexpected("invalid or duplicate Trojan user name");
        auto profile = std::make_unique<trojan_in::TrojanInboundProfile>();
        if (tls_rt.atomic_credential) {
            profile->atomic_credential = std::static_pointer_cast<tls::AtomicServerCredential>(tls_rt.atomic_credential);
        } else {
            auto credential = tls::load_server_credential(certificate, key);
            if (!credential) return std::unexpected(credential.error());
            profile->credential.emplace(std::move(*credential));
        }
        profile->alpn = tls_rt.alpn;
        if (!tls_rt.ech_key_file.empty()) {
            auto ech = tls::load_ech_server_keys_file(tls_rt.ech_key_file);
            if (!ech) return std::unexpected("Trojan ECH key: " + ech.error());
            profile->ech_keys = std::move(*ech);
        }
        profile->multiplex = std::move(multiplex);
        profile->fallback = std::move(fallback);
        profile->fallback_for_alpn.assign(fallback_for_alpn.begin(), fallback_for_alpn.end());
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
        std::vector<trojan::PasswordKey> loaded_users;
        loaded_users.reserve(passwords.size());
        for (auto const& path : passwords) {
            auto password = trojan::PasswordKey::load(path);
            if (!password) return std::unexpected(password.error());
            loaded_users.push_back(std::move(*password));
        }
        auto table = trojan::UserTable::create(std::move(loaded_users));
        if (!table) return std::unexpected(std::move(table.error()));
        profile->users = std::move(*table);
        profile->names.assign(names.begin(), names.end());
        return InboundFactory{[profile = std::move(profile)](Session& session, corosio::io_context& context,
            rules::RouteProgram const& policy) {
            return serve(session, context, policy, *profile);
        }};
    }
}
