// Listener configuration shared by initial startup and staged TCP reloads.
export module cli.proxy_listener;
import std;
import cli.dns_message_runtime;
import cli.dns_transports;
import cli.outbounds;
import cli.proxy_run_state;
import cli.route_files;
import config;
import corosio;
import functional;
import relay;
import relay.principal_limits;
import rulefile;

export namespace cli::run_detail {
    struct Listener {
        std::unique_ptr<relay::Server> server;
        std::uint16_t port;
        relay::Inbound inbound;
        bool ipv6 = false, hy2 = false, masque = false, tuic = false, tun = false;
        std::string host, unix_path;
        std::optional<std::array<std::uint8_t, 16>> address;
        bool routed_tun = false;
        std::size_t packet_slots = 0;
        config::ListenOptions listen{};
    };

    inline auto convert_inbound(config::Inbound type) -> relay::Inbound {
        switch (type) {
        case config::Inbound::tproxy: return relay::Inbound::tproxy;
        case config::Inbound::redirect: return relay::Inbound::redirect;
        case config::Inbound::mixed: return relay::Inbound::mixed;
        case config::Inbound::http: return relay::Inbound::http;
        case config::Inbound::fixed_tcp: return relay::Inbound::fixed_tcp;
        case config::Inbound::fixed_udp: return relay::Inbound::fixed_udp;
        case config::Inbound::vless: return relay::Inbound::vless;
        case config::Inbound::shadowsocks: return relay::Inbound::shadowsocks;
        case config::Inbound::snell: return relay::Inbound::snell;
        case config::Inbound::anytls: return relay::Inbound::anytls;
        case config::Inbound::shadowtls: return relay::Inbound::shadowtls;
        case config::Inbound::trojan: return relay::Inbound::trojan;
        case config::Inbound::naive: return relay::Inbound::naive;
        default: return relay::Inbound::socks5;
        }
    }

    inline auto uses_transparent_metadata(config::InboundConfig const& entry) noexcept -> bool {
        return entry.type == config::Inbound::redirect || entry.type == config::Inbound::tproxy ||
            (entry.tun && !entry.tun->connect_ip_outbound);
    }

    inline auto make_listener(std::unique_ptr<relay::Server> server, config::InboundConfig const& entry) -> Listener {
        Listener listener{std::move(server), entry.port, convert_inbound(entry.type), entry.listen_ipv6};
        listener.host = entry.listen_host;
        listener.address = entry.listen_address;
        listener.unix_path = entry.unix_path;
        listener.hy2 = entry.hysteria2.has_value();
        listener.masque = entry.masque.has_value();
        listener.tuic = entry.tuic.has_value();
        listener.tun = entry.tun.has_value();
        if (entry.hysteria2) listener.host = entry.hysteria2->listen_host;
        if (entry.masque) listener.host = entry.masque->listen_host;
        if (entry.tuic) listener.host = entry.tuic->listen_host;
        if (entry.snell) {
            listener.host = entry.snell->listen_host;
            listener.address = entry.snell->listen_address;
        }
        if (entry.http && entry.http->has_tls) {
            listener.host = entry.http->listen_host;
            listener.address = entry.http->listen_address;
        }
        if (entry.naive) {
            listener.host = entry.naive->listen_host;
            listener.address = entry.naive->listen_address;
        }
        if (entry.shadowtls) listener.address = entry.shadowtls->listen_address;
        if (entry.redirect_address) {
            listener.address = entry.redirect_address;
            listener.host = entry.redirect_host;
        }
        if (entry.fixed_udp) {
            listener.address = entry.fixed_udp->listen_address;
            listener.host = entry.fixed_udp->listen_host;
        }
        listener.routed_tun = entry.tun && !entry.tun->connect_ip_outbound;
        if (listener.routed_tun) listener.packet_slots = 2 * entry.tun->tcp_flows;
        listener.listen = entry.listen;
        return listener;
    }

    inline auto reloadable_tcp(config::Config const& config) -> bool {
        return std::ranges::none_of(config.inbounds, [](auto const& entry) {
            return !entry.unix_path.empty() || (entry.fixed_tcp && !entry.fixed_tcp->unix_path.empty()) || entry.fixed_udp || entry.hysteria2 || entry.masque || entry.tuic || entry.tun ||
                entry.transparent_udp || (entry.vless && entry.vless->xhttp &&
                    entry.vless->xhttp->endpoint.version == xhttp::HttpVersion::http3) ||
                (entry.http && entry.http->http3) ||
                (entry.naive && entry.naive->protocol != config::NaiveProtocol::h2);
        });
    }

    inline auto uses_native_udp(config::Config const& config) -> bool {
        return (!config.ordered_tcp || config.ordered_tcp->udp) &&
            std::ranges::any_of(config.inbounds, [](auto const& entry) { return entry.shadowsocks.has_value(); });
    }

    inline auto native_udp_dns_readers(config::Config const& config) -> std::size_t {
        if (!uses_native_udp(config)) return 0;
        auto native_outbound = std::ranges::any_of(config.shadowsocks_outbounds, [](auto const& entry) {
            return entry.config.udp_native;
        });
        return config.ordered_tcp || native_outbound || uses_proxy_dns(config.dns) ? 2 : 1;
    }

    inline auto configure_native_udp(auto& udp, config::Config const& config, RouteFiles const& files,
        std::vector<Listener> const& listeners, std::span<DnsProtection const> protections, bool traffic_stats) -> std::expected<void, std::string> {
        auto parent = std::ranges::find_if(config.inbounds, [](auto const& entry) { return entry.shadowsocks.has_value(); });
        auto* server = parent == config.inbounds.end() ? nullptr : listeners[parent - config.inbounds.begin()].server.get();
        std::vector<relay::Server*> traffic;
        auto named_users = std::ranges::any_of(config.inbounds, [](auto const& entry) {
            return entry.shadowsocks && !entry.shadowsocks->users.empty();
        });
        if (uses_native_udp(config) && (traffic_stats || named_users)) {
            traffic.reserve(listeners.size());
            for (std::size_t index = 0; index < listeners.size(); ++index)
                traffic.push_back(config.inbounds[index].shadowsocks ? listeners[index].server.get() : nullptr);
        }
        return udp.configure(config, files.data, files.indices, files.ordered, server, traffic, protections);
    }

    inline auto same_tcp_binding(Listener const& first, Listener const& second) noexcept -> bool {
        if (first.port != second.port || first.ipv6 != second.ipv6 || first.listen != second.listen) return false;
        std::array<std::uint8_t, 16> loopback{};
        if (first.ipv6) loopback.back() = 1;
        else { loopback.front() = 127; loopback[3] = 1; }
        return first.address.value_or(loopback) == second.address.value_or(loopback);
    }

    struct TcpGeneration {
        std::unique_ptr<relay::SharedDnsGeneration> dns;
        std::vector<Listener> listeners;
        std::shared_ptr<relay::RouteSnapshots> routes;
        std::unique_ptr<DnsMessageRuntime> messages;
    };

    struct RetiredTcpGeneration {
        std::unique_ptr<relay::SharedDnsGeneration> dns;
        std::vector<Listener> listeners;
        std::unique_ptr<DnsMessageRuntime> messages;
        functional::move_only_function<bool()> poll_udp;
        std::chrono::steady_clock::time_point deadline;
        ~RetiredTcpGeneration() { for (auto& l : listeners) if (l.server) l.server->set_detour_target(nullptr); }

        auto poll(bool shared_driven = false) -> bool {
            if (std::chrono::steady_clock::now() >= deadline) return true;
            bool complete = true;
            for (auto& listener : listeners) {
                if (!shared_driven && !listener.server->drained()) listener.server->poll(std::chrono::milliseconds(0));
                complete &= listener.server->drained();
            }
            if (messages) complete &= messages->drained();
            if (poll_udp) complete &= poll_udp();
            return complete;
        }
    };

    inline auto configure_listener(relay::Server& server, config::Config const& config, config::InboundConfig const& entry,
        std::vector<DnsProtection> const& dns_transports, RouteFiles const& route_files, auto const& indexed_routes,
        std::shared_ptr<relay::SnellReplayRegistry>& snell_replay,
        functional::function_ref<void(std::span<std::uint8_t const>, std::span<relay::ShadowsocksUserKey const>)> remember_ss,
        relay::PrincipalRegistry& principals) -> std::expected<void, std::string> {
        if (!entry.user_limits.empty()) {
            constexpr auto unlimited = std::numeric_limits<std::size_t>::max();
            std::vector<relay::PrincipalLimits> limits;
            limits.reserve(entry.user_limits.size());
            for (auto const& user : entry.user_limits) {
                auto rate = user.bytes_per_second.value_or(0);
                auto burst = user.burst_bytes.value_or(rate ? std::clamp(rate, 16384u, 16u * 1024 * 1024) : 0u);
                limits.push_back({user.name, user.connections.value_or(unlimited), user.streams.value_or(unlimited),
                    {user.byte_quota, rate, burst}});
            }
            if (!server.set_principal_policy(principals.prepare(entry.name, limits)))
                return std::unexpected("cannot set principal policy");
        }
        if (entry.listen.configured()) {
            if (auto ok = server.set_listen_options(entry.listen); !ok)
                return std::unexpected("listen options: " + ok.error());
        }
        if (config.sessions_per_listener && !server.set_session_limit(*config.sessions_per_listener)) {
            return std::unexpected("cannot set session limit");
        }
        if (entry.fixed_tcp && !(entry.fixed_tcp->unix_path.empty() ?
            server.set_fixed_tcp_target(entry.fixed_tcp->host, entry.fixed_tcp->port) :
            server.set_fixed_unix_target(entry.fixed_tcp->unix_path))) {
            return std::unexpected("invalid fixed-tcp target");
        }
        if (entry.fixed_udp && !server.set_fixed_udp_target(entry.fixed_udp->target_host, entry.fixed_udp->target_port, entry.fixed_udp->idle_timeout_ms)) {
            return std::unexpected("invalid fixed-udp target");
        }
        if (auto outbounds = cli::configure_outbounds(server, config, dns_transports); !outbounds) return outbounds;
        if (entry.transparent_udp && !server.enable_transparent_udp()) {
            return std::unexpected("TPROXY UDP is unavailable in this build");
        }
        if (entry.shadowtls) {
            std::vector<std::string> files, names;
            for (auto const& u : entry.shadowtls->users) { files.push_back(u.password_file); names.push_back(u.username); }
            auto prepared = server.prepare_shadowtls_inbound(entry.shadowtls->handshake_host, entry.shadowtls->handshake_port,
                entry.shadowtls->target_host, entry.shadowtls->target_port, files, names, entry.shadowtls->strict_tls13);
            if (!prepared) { return std::unexpected("ShadowTLS inbound: " + prepared.error()); }
        }
        if (entry.shadowsocks) {
            auto const& inbound = *entry.shadowsocks;
            auto file = ::rulefile::read_private_file(inbound.key_file);
            if (!file) { return std::unexpected("shadowsocks inbound key: " + file.error()); }
            SecretKey key;
            auto size = inbound.method == "2022-blake3-aes-128-gcm" ? 16U : 32U;
            auto bytes = std::span(key.bytes).first(size);
            if (!decode_key(file->bytes(), bytes)) { return std::unexpected("shadowsocks inbound key: invalid base64 or key length"); }
            std::vector<std::unique_ptr<SecretKey>> keys;
            std::vector<relay::ShadowsocksUserKey> users;
            for (auto const& user : inbound.users) {
                auto file = ::rulefile::read_private_file(user.key_file);
                auto secret = std::make_unique<SecretKey>();
                auto key = std::span(secret->bytes).first(size);
                if (!file || !decode_key(file->bytes(), key)) {
                    return std::unexpected("shadowsocks user key: invalid private file, base64 or key length");
                }
                users.push_back({user.name, key});
                keys.push_back(std::move(secret));
            }
            auto result = server.prepare_shadowsocks_inbound(bytes, users,
                inbound.method == "2022-blake3-chacha20-poly1305" ? relay::ShadowsocksCipher::chacha20 : relay::ShadowsocksCipher::aes,
                inbound.multiplex);
            if (!result) { return std::unexpected("shadowsocks inbound: " + result.error()); }
            remember_ss(bytes, users);
        }
        if (entry.vless) {
            if (entry.vless->xhttp && config.workers != 1) return std::unexpected("VLESS XHTTP inbound requires one worker");
            std::vector<std::string> users;
            std::vector<std::string> names;
            for (auto const& user : entry.vless->users) { users.push_back(user.uuid_file); names.push_back(user.name); }
            std::optional<relay::RealityInbound> reality;
            if (entry.vless->reality) {
                auto const& cfg = *entry.vless->reality;
                reality.emplace(relay::RealityInbound{cfg.private_key_file, cfg.certificate_file, cfg.signing_key_file,
                    cfg.fallback_host, cfg.fallback_port, cfg.server_names, cfg.short_ids, cfg.max_time_difference_seconds, cfg.fallback_resolver_index});
            }
            auto result = server.prepare_vless_inbound(entry.vless->certificate_file, entry.vless->private_key_file, users, entry.vless->vision, std::move(reality), names, entry.vless->transport, entry.vless->grpc, entry.vless->xhttp, entry.vless->multiplex);
            if (!result) { return std::unexpected("VLESS inbound: " + result.error()); }
        }
        if (auto const& ip = entry.udp_advertise_ip) {
            if (ip->size == 16) server.set_udp_advertise({corosio::ipv6_address(ip->bytes), 1});
            else {
                corosio::ipv4_address::bytes_type ipv4{};
                std::ranges::copy(ip->view(), ipv4.begin());
                server.set_udp_advertise({corosio::ipv4_address(ipv4), 1});
            }
        }
        if (entry.password_auth) {
            auto password = ::rulefile::read_password_file(entry.password_auth->password_file);
            if (!password) { return std::unexpected("authentication: " + password.error()); }
            auto result = server.set_socks5_credentials(entry.password_auth->username, *password);
            if (!result) { return std::unexpected("authentication: " + result.error()); }
        }
        if (entry.http && entry.http->has_tls) {
            auto prepared = server.prepare_http_modern_inbound(*entry.http);
            if (!prepared) { return std::unexpected("HTTP TLS inbound: " + prepared.error()); }
        }
        if (entry.naive) {
            auto prepared = server.prepare_naive_inbound(*entry.naive);
            if (!prepared) { return std::unexpected("NaiveProxy inbound: " + prepared.error()); }
        }
        if (entry.trojan) {
            std::vector<std::string> users, names;
            for (auto const& user : entry.trojan->users) { users.push_back(user.password_file); names.push_back(user.name); }
            auto prepared = server.prepare_trojan_inbound(entry.trojan->certificate_file, entry.trojan->private_key_file, users, names, entry.trojan->transport, entry.trojan->grpc, entry.trojan->multiplex);
            if (!prepared) { return std::unexpected("Trojan inbound: " + prepared.error()); }
        }
        if (entry.anytls) {
            std::vector<std::string> users, names;
            for (auto const& user : entry.anytls->users) { users.push_back(user.password_file); names.push_back(user.name); }
            auto prepared = server.prepare_anytls_inbound(entry.anytls->certificate_file, entry.anytls->private_key_file, users, names, entry.anytls->transport, entry.anytls->grpc);
            if (!prepared) { return std::unexpected("AnyTLS inbound: " + prepared.error()); }
        }
        if (entry.snell) {
            std::optional<std::string_view> user; if (entry.snell->user_file) user = *entry.snell->user_file;
            if (!snell_replay) snell_replay = relay::create_snell_replay_registry();
            auto prepared = server.prepare_snell_inbound(entry.snell->psk_file, user, entry.snell->replay_window_seconds, snell_replay, entry.snell->http_obfs);
            if (!prepared) { return std::unexpected("Snell inbound: " + prepared.error()); }
        }
        auto result = server.set_indexed_routes(indexed_routes, config.default_outbound, entry.name);
        if (!result) { return std::unexpected("invalid routing: " + result.error()); }
        if (config.ordered_tcp) {
            auto const& program = *config.ordered_tcp;
            auto configured = server.set_ordered_tcp(route_files.ordered, config.default_outbound, program.sniff_timeout_ms, program.skip_unknown, program.udp);
            if (!configured) { return std::unexpected("invalid tcp-program: " + configured.error()); }
        }
        return {};
    }

    inline auto wire_listener_detours(config::Config const& cfg, std::vector<Listener>& listeners) noexcept -> void {
        for (std::size_t i = 0; i < cfg.inbounds.size() && i < listeners.size(); ++i) {
            if (cfg.inbounds[i].detour_index && *cfg.inbounds[i].detour_index < listeners.size())
                listeners[i].server->set_detour_target(listeners[*cfg.inbounds[i].detour_index].server.get());
        }
    }

    inline auto clear_listener_detours(std::vector<Listener>& listeners) noexcept -> void {
        for (auto& l : listeners) if (l.server) l.server->set_detour_target(nullptr);
    }

    inline auto init_run_listeners(config::Config const& cfg, unsigned workers, std::vector<Listener>& listeners,
        std::unique_ptr<corosio::io_context>& shared_io) -> std::expected<void, std::string> {
        auto is_ord = [](config::InboundConfig const& e) { return !e.hysteria2 && !e.masque && !e.tuic && !e.tun; };
        auto mk = [&](config::InboundConfig const& e) {
            return (workers == 1 && shared_io && is_ord(e)) ? relay::Server::create_shared(*shared_io) : relay::Server::create();
        };
        if (workers == 1 && std::ranges::any_of(cfg.inbounds, is_ord)) {
            auto sio = relay::make_shared_io_context();
            if (!sio) return std::unexpected(sio.error().message());
            shared_io = std::move(*sio);
            if (is_ord(cfg.inbounds.front())) {
                auto first = relay::Server::create_shared(*shared_io);
                if (!first) return std::unexpected(first.error().message());
                listeners.front().server = std::move(*first);
            }
        }
        listeners.front() = make_listener(std::move(listeners.front().server), cfg.inbounds.front());
        for (auto const& entry : std::span(cfg.inbounds).subspan(1)) {
            auto next = mk(entry);
            if (!next) return std::unexpected(next.error().message());
            listeners.push_back(make_listener(std::move(*next), entry));
        }
        wire_listener_detours(cfg, listeners);
        return {};
    }
}
