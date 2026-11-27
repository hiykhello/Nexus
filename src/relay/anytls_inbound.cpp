module;
#include <proxy/proxy_macros.h>

module relay;
import std;
import proxy.v4;
import anytls;
import anytls.auth;
import anytls.padding;
import anytls.session;
import anytls.writer;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.connection;
import platform.ip_address;
import tls.profiles;
import tls.server_credential;
import tls.server_handshake_io;
import tls.ech_server;
import tls.byte_stream;
import tls.corosio_application;
import tls.corosio_server_handshake;
import tls.client_flight;
import relay.stream_relay;
import relay.dns_state;
import sniff.tcp;
import sniff.tcp_io;
import net.stream_datagrams;
import platform.stream_peer;
import rules;
import socks5;
import uot;
import capy;
import corosio;
import :transport_helpers;

namespace relay {
    namespace {
        using Application = tls::detail::ApplicationConnection<corosio::tcp_socket>;
        using TlsStream = websocket::VlessByteStream<corosio::tcp_socket>;

        struct Profile {
            std::optional<tls::ServerCredential> credential;
            std::shared_ptr<tls::AtomicServerCredential> atomic_credential;
            std::vector<std::string> alpn;
            std::shared_ptr<tls::EchServerKeys const> ech_keys;
            anytls::UserTable users;
            std::vector<std::string> names;
            std::optional<httpupgrade::Profile> transport;
            std::optional<transport_detail::GrpcSettings> grpc;
        };

        struct ParentGuard {
            Session& session;
            ~ParentGuard() { session.done = true; session.close(); }
        };

        PRO_DEF_MEM_DISPATCH(AnyTlsLowerRead, read);
        PRO_DEF_MEM_DISPATCH(AnyTlsLowerSend, send);
        PRO_DEF_MEM_DISPATCH(AnyTlsLowerCancel, cancel);

        struct LowerStreamFacade : pro::facade_builder
            ::add_convention<AnyTlsLowerRead, capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>>(std::span<std::uint8_t>, anytls::Deadline)>
            ::add_convention<AnyTlsLowerSend, capy::task<bool>(std::span<std::uint8_t const>, anytls::Deadline)>
            ::add_convention<AnyTlsLowerCancel, void() noexcept>
            ::build {};

        struct ErasedLowerStream {
            pro::proxy_view<LowerStreamFacade> view;

            template<class LowerStream>
            static auto from(LowerStream& lower) noexcept -> ErasedLowerStream {
                return {pro::make_proxy_view<LowerStreamFacade>(lower)};
            }

            auto read(std::span<std::uint8_t> b, anytls::Deadline d = {}) { return view->read(b, d); }
            auto send(std::span<std::uint8_t const> b, anytls::Deadline d = {}) { return view->send(b, d); }
            auto cancel() noexcept -> void { if (view) view->cancel(); }
        };

        using Protocol = anytls::Session<ErasedLowerStream>;

        struct Incoming {
            Protocol& protocol;
            Session& parent;
            anytls::StreamChannel<ErasedLowerStream> channel;

            Incoming(Protocol& owner, Session& connection, std::uint32_t id)
                : protocol(owner), parent(connection), channel(owner, id) {}

            auto read(std::span<std::uint8_t> bytes, anytls::Deadline deadline = {}) {
                parent.touched = Clock::now();
                return channel.read(bytes, deadline ? deadline : Clock::now() + std::chrono::seconds(300));
            }
            auto send(std::span<std::uint8_t const> bytes, anytls::Deadline deadline = {}) {
                parent.touched = Clock::now();
                return channel.send(bytes, deadline ? deadline : Clock::now() + std::chrono::seconds(300));
            }
            auto close_output(anytls::Deadline deadline = {}) { return channel.close_output(deadline); }
            auto cancel() noexcept -> void { channel.cancel(); }
            auto peer_closed() const noexcept -> bool {
                return parent.closed || protocol.stream_closed(channel.id()) ||
                       platform::stream_peer_closed(parent.client.native_handle());
            }
        };

        struct ChildGuard {
            Session& session;
            Protocol& protocol;
            std::uint32_t id;
            ~ChildGuard() {
                auto* owner = &protocol;
                auto stream = id;
                session.close();
                owner->cancel_stream(stream);
            }
        };

        auto exact(Incoming& incoming, std::span<std::uint8_t> output, Clock::time_point deadline) -> capy::task<bool> {
            while (!output.empty()) {
                auto received = co_await incoming.read(output, deadline);
                if (!received || !*received || *received > output.size()) co_return false;
                output = output.subspan(*received);
            }
            co_return true;
        }

        auto destination(Incoming& incoming, Clock::time_point deadline) -> capy::task<std::optional<net::ProxyAddress>> {
            std::array<std::uint8_t, 259> bytes{};
            if (!co_await exact(incoming, std::span(bytes).first(1), deadline)) co_return std::nullopt;
            std::size_t prefix = 1, remaining = 0;
            if (bytes[0] == 1) remaining = 6;
            else if (bytes[0] == 4) remaining = 18;
            else if (bytes[0] == 3) {
                if (!co_await exact(incoming, std::span(bytes).subspan(1, 1), deadline) || !bytes[1]) co_return std::nullopt;
                prefix = 2; remaining = std::size_t(bytes[1]) + 2;
            } else co_return std::nullopt;
            if (!co_await exact(incoming, std::span(bytes).subspan(prefix, remaining), deadline)) co_return std::nullopt;
            auto parsed = net::parse_proxy_address(std::span(bytes).first(prefix + remaining), net::AddressWire::socks);
            co_return parsed.status == net::DatagramStatus::accepted ? std::optional(parsed.address) : std::nullopt;
        }

        auto watch_stream(Session& child, Protocol& protocol, std::uint32_t id) -> capy::task<capy::results<>> {
            if (co_await protocol.wait_stream_closed(id)) child.close();
            co_return capy::results<>{};
        }

        auto sniff_stream(void* stream, sniff::TcpSniffer& sniffer, Clock::time_point deadline)
            -> capy::task<sniff::TcpReadResult> {
            auto& incoming = *static_cast<Incoming*>(stream);
            std::array<std::uint8_t, 4096> bytes{};
            for (;;) {
                auto state = sniffer.limit();
                if (state.status != sniff::TcpStatus::need_more) co_return {sniff::TcpReadStop::classified, state, {}};
                if (Clock::now() >= deadline) co_return {sniff::TcpReadStop::deadline, state, {}};
                auto count = co_await incoming.read(std::span(bytes).first(std::min(bytes.size(), sniffer.remaining())), deadline);
                if (!count) {
                    if (count.error() == anytls::SessionError::timeout)
                        co_return {sniff::TcpReadStop::deadline, sniffer.current(), {}};
                    co_return {sniff::TcpReadStop::io_error, sniffer.current(), std::make_error_code(std::errc::io_error)};
                }
                if (!*count) co_return {sniff::TcpReadStop::eof, sniffer.finish(), {}};
                auto step = sniffer.feed(std::span(bytes).first(*count));
                if (step.consumed != *count)
                    co_return {sniff::TcpReadStop::io_error, step, std::make_error_code(std::errc::protocol_error)};
            }
        }

        auto dial_stream(Session& child, corosio::io_context& context, rules::RouteMatcher const& policy,
            socks5::Request const& target, Incoming& incoming) -> capy::task<capy::results<std::uint8_t>> {
            std::uint8_t code = 1;
            if (child.ordered_tcp) {
                auto connected = co_await route_ordered_stream_tcp(child, context, target, &incoming, &sniff_stream);
                if (connected) code = 0;
            } else code = co_await dial_destination(child, context, policy, target);
            co_return capy::results<std::uint8_t>{std::make_error_code(std::errc::operation_canceled), code};
        }

        auto datagrams(Session& child, corosio::io_context& context, rules::RouteMatcher const& policy,
            Incoming& incoming, Clock::time_point deadline) -> capy::task<> {
            if (child.ordered_tcp && !child.ordered_tcp->udp) {
                (void)co_await incoming.protocol.acknowledge(incoming.channel.id(), false, deadline);
                co_return;
            }
            uot::RequestDecoder request;
            std::array<std::uint8_t, 4096> bytes{};
            std::size_t begin = 0, end = 0;
            while (!child.closed && !request.request()) {
                auto received = co_await incoming.read(bytes, deadline);
                if (!received || !*received || *received > bytes.size()) co_return;
                auto fed = request.feed(std::span(bytes).first(*received));
                if (fed.status != uot::Status::incomplete && fed.status != uot::Status::accepted) co_return;
                if (request.request()) { begin = fed.consumed; end = *received; }
            }
            if (child.closed || !request.request() ||
                !co_await incoming.protocol.acknowledge(incoming.channel.id(), true, deadline)) co_return;
            auto config = *request.request();
            child.begin_traffic(TrafficProtocol::anytls_uot, config.connected ? config.destination.port : 0);
            child.select_traffic_path(ConnectPath::datagrams);
            child.relaying = true; child.touched = Clock::now();
            auto resolver = [&](std::string name, std::uint16_t port, Clock::time_point limit) {
                return resolve_udp_domain(child, context, std::move(name), port, limit);
            };
            auto source = source_endpoint(child, child.ordered_tcp || policy.needs_source() || child.dns_requirements().source);
            auto router = child.ordered_tcp ? ordered_datagram_router(child, context, source)
                                            : net::stream_datagrams::OrderedRouter{};
            net::stream_datagrams::Server state(child, context, incoming, policy, resolver,
                {net::AddressWire::uot, config.connected, false}, config.destination, source, std::move(router));
            try { (void)co_await capy::when_all(net::stream_datagrams::tasks(state, std::span(bytes).subspan(begin, end - begin))); }
            catch (...) { child.close(); state.cancel(); throw; }
        }

        auto serve_stream(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy,
            Protocol& protocol, std::uint32_t id) -> capy::task<> {
            auto lease = parent.quota ? parent.quota->try_acquire() : std::nullopt;
            if (parent.quota && !lease) {
                (void)co_await protocol.acknowledge(id, false, Clock::now() + std::chrono::seconds(5));
                protocol.release(id); co_return;
            }
            Session child(context);
            child.quota = std::move(lease);
            init_multiplexed_child(child, parent, Clock::now() + std::chrono::seconds(10));
            if (!child.admit_principal_child(parent)) {
                (void)co_await protocol.acknowledge(id, false, Clock::now() + std::chrono::seconds(5));
                protocol.release(id); co_return;
            }
            Incoming incoming(protocol, parent, id);
            ChildGuard guard{child, protocol, id};
            std::stop_callback cancel_channel(child.stop.get_token(), [&]() noexcept { incoming.cancel(); });
            std::stop_callback stop(parent.stop.get_token(), [&]() noexcept { child.close(); });
            if (child.closed) co_return;
            auto address = co_await destination(incoming, child.handshake_deadline);
            if (!address || child.closed) co_return;
            auto host = std::string_view(reinterpret_cast<char const*>(address->bytes.data()), address->length);
            if (address->family == net::ProxyAddressFamily::domain && host == uot::v2_destination) {
                co_await datagrams(child, context, policy, incoming, child.handshake_deadline); co_return;
            }
            socks5::Request target; target.status = socks5::Status::accepted;
            target.address_type = address->family == net::ProxyAddressFamily::ipv4 ? 1
                                : address->family == net::ProxyAddressFamily::ipv6 ? 4 : 3;
            target.address_length = address->length; target.port = address->port;
            std::copy_n(address->bytes.begin(), address->length, target.address.begin());
            child.begin_traffic(TrafficProtocol::anytls, target.port);
            auto [signal, code, watched] = co_await capy::when_all(
                dial_stream(child, context, policy, target, incoming), watch_stream(child, protocol, id));
            (void)signal; (void)watched;
            if (child.closed) co_return;
            if (!co_await protocol.acknowledge(id, !code, child.handshake_deadline) || code) co_return;
            child.relaying = true; child.touched = Clock::now();
            (void)co_await capy::when_all(
                stream_relay::direction(child, stream_relay::upload(child, incoming)),
                stream_relay::direction(child, stream_relay::download(child, incoming)));
        }

        auto worker(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy,
            Protocol& protocol) -> capy::task<capy::results<>> {
            while (!parent.closed) {
                auto accepted = co_await protocol.accept();
                if (!accepted) break;
                co_await serve_stream(parent, context, policy, protocol, *accepted);
            }
            co_return capy::results<>{};
        }

        auto run_protocol(Session& parent, Protocol& protocol, bool close_parent) -> capy::task<capy::results<>> {
            struct Guard { Session& p; bool active; ~Guard() { if (active) { p.done = true; p.close(); } } } g{parent, close_parent};
            co_return co_await protocol.run();
        }

        auto serve_anytls_lower(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy,
            Profile const& profile, ErasedLowerStream& lower, Clock::time_point deadline, bool close_parent,
            unsigned workers_n) -> capy::task<> {
            auto padding = anytls::PaddingScheme::parse(anytls::default_padding_scheme);
            if (!padding) co_return;
            Protocol protocol(lower, *padding, false);
            auto accepted = co_await protocol.start_server(profile.users, deadline);
            if (!accepted || parent.closed || *accepted >= profile.users.size()) co_return;
            if (!profile.names.empty() && !parent.admit_principal(profile.names[*accepted])) co_return;
            parent.relaying = true; parent.touched = Clock::now();
            std::vector<capy::task<capy::results<>>> tasks;
            tasks.reserve(workers_n + 1); tasks.push_back(run_protocol(parent, protocol, close_parent));
            for (unsigned i = 0; i < workers_n; ++i) tasks.push_back(worker(parent, context, policy, protocol));
            (void)co_await capy::when_all(std::move(tasks));
        }

        auto serve(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy, Profile const& profile)
            -> capy::task<> {
            ParentGuard guard{parent};
            auto deadline = parent.started + std::chrono::seconds(10);
            auto milliseconds = [](auto value) {
                return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
            };
            auto start = milliseconds(parent.started), end = milliseconds(deadline);
            if (start < 0 || end <= start) co_return;
            auto budget = std::make_shared<memory::Budget>(8u * 1024 * 1024);
            std::optional<tls::ServerCredential> dyn_cred;
            tls::ServerCredential const* active_cred = nullptr;
            if (profile.atomic_credential) {
                auto cur = profile.atomic_credential->clone_current();
                if (!cur) co_return;
                dyn_cred.emplace(std::move(*cur));
                active_cred = &*dyn_cred;
            } else if (profile.credential) {
                active_cred = &*profile.credential;
            } else {
                co_return;
            }
            std::expected<tls::ServerHandshakeIo, std::string> handshake = std::unexpected(std::string{});
            if (!profile.alpn.empty()) {
                std::vector<std::string_view> prefs;
                prefs.reserve(profile.alpn.size());
                for (auto const& p : profile.alpn) prefs.push_back(p);
                handshake = tls::make_server_handshake(*active_cred, start, end, budget, prefs, true, profile.ech_keys);
            } else {
                std::string_view req_alpn = profile.grpc ? "h2" : profile.transport ? "http/1.1" : "";
                handshake = tls::make_server_handshake(*active_cred, start, end, budget, req_alpn, profile.ech_keys);
            }
            if (!handshake) co_return;
            auto established = co_await tls::detail::server_handshake(parent.client, *handshake, budget);
            if (!established || parent.closed) co_return;
            Application application(parent.client, std::move(established->records), std::move(established->unread));
            if (!established->release_unread_reservation()) co_return;
            if (profile.grpc) {
                using Lower = tls::detail::ByteStream<corosio::tcp_socket>;
                using Channel = grpc::MultiplexChannel<Lower, 16, grpc::detail::ByteStreamReadPolicy>;
                Lower lower(application);
                auto proto = grpc::MultiplexSession<16>::create(
                    grpc::Role::server, profile.grpc->request, grpc::ResponsePolicy::standard, profile.grpc->limits);
                if (!proto) co_return;
                Channel channel(lower, std::move(*proto));
                parent.relaying = true; parent.touched = Clock::now();
                auto run_ch = [&]() -> capy::task<capy::results<>> { co_return co_await channel.run(); };
                auto rpc_worker = [&]() -> capy::task<capy::results<>> {
                    while (!parent.closed) {
                        if (auto ticket = channel.accept()) {
                            typename Channel::Stream rpc(channel, *ticket);
                            transport_detail::GrpcByteStream<typename Channel::Stream> adapted{rpc, &parent};
                            auto erased = ErasedLowerStream::from(adapted);
                            try {
                                co_await serve_anytls_lower(
                                    parent, context, policy, profile, erased,
                                    Clock::now() + std::chrono::seconds(10), false, 8);
                            } catch (...) {}
                            rpc.cancel();
                            continue;
                        }
                        if (!co_await channel.wait_change()) break;
                    }
                    co_return capy::results<>{};
                };
                std::vector<capy::task<capy::results<>>> tasks;
                tasks.reserve(17); tasks.push_back(run_ch());
                for (unsigned i = 0; i < 16; ++i) tasks.push_back(rpc_worker());
                try { (void)co_await capy::when_all(std::move(tasks)); } catch (...) { channel.cancel(); }
                co_return;
            }
            TlsStream lower(application);
#ifdef NEXUS_ENABLE_KTLS
            if (!profile.transport)
                (void)application.try_enable_ktls(tls::ApplicationRole::server);
#endif
            if (profile.transport) {
                if (!co_await transport_detail::handshake_ws_or_hu(lower, *profile.transport, deadline) || parent.closed)
                    co_return;
            }
            auto erased = ErasedLowerStream::from(lower);
            co_await serve_anytls_lower(parent, context, policy, profile, erased, deadline, true, 64);
        }
    }

    auto make_anytls_inbound_factory(std::string_view certificate, std::string_view key,
        std::span<std::string const> passwords, std::span<std::string const> names,
        std::optional<HttpUpgradeTransport> transport, std::optional<GrpcTransport> grpc_cfg,
        InboundTlsRuntime const& tls_rt)
        -> std::expected<InboundFactory, std::string> {
        if (passwords.empty() || passwords.size() > max_tunnel_outbounds || (!names.empty() && names.size() != passwords.size()))
            return std::unexpected("invalid AnyTLS users");
        if (transport && grpc_cfg) return std::unexpected("AnyTLS inbound accepts at most one transport");
        std::unordered_set<std::string_view> seen_names;
        seen_names.reserve(names.size());
        for (auto const& n : names)
            if (n.empty() || n.size() > 255 || n.find('\0') != std::string::npos || !seen_names.insert(n).second)
                return std::unexpected("invalid or duplicate AnyTLS user name");
        auto profile = std::make_unique<Profile>();
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
            if (!ech) return std::unexpected("AnyTLS ECH key: " + ech.error());
            profile->ech_keys = std::move(*ech);
        }
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
        std::vector<anytls::PasswordKey> loaded_users;
        loaded_users.reserve(passwords.size());
        for (auto const& path : passwords) {
            auto password = anytls::PasswordKey::load(path);
            if (!password) return std::unexpected(password.error());
            loaded_users.push_back(std::move(*password));
        }
        auto table = anytls::UserTable::create(std::move(loaded_users));
        if (!table) return std::unexpected(std::move(table.error()));
        profile->users = std::move(*table);
        profile->names.assign(names.begin(), names.end());
        return InboundFactory{[profile = std::move(profile)](Session& session, corosio::io_context& context,
            rules::RouteMatcher const& policy) {
            return serve(session, context, policy, *profile);
        }};
    }
}
