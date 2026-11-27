module relay;
import std;
import config;
import proxy.v4;

namespace relay {
    auto Server::add_wireguard(config::WireGuardOutbound const& cfg) -> std::expected<std::size_t, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_WIREGUARD
        if (outbounds.size() >= max_tunnel_outbounds) return std::unexpected("too many tunnel outbounds");
        if (cfg.bootstrap_index && (!dns_routing || *cfg.bootstrap_index >= dns_routing->resolver_count()))
            return std::unexpected("invalid bootstrap resolver");
        auto factory = make_wireguard_factory(cfg);
        if (!factory) return std::unexpected(factory.error());
        auto index = outbounds.size() + 2;
        outbounds.push_back(std::move(*factory));
        if (cfg.bootstrap_index && (!max_bootstrap_index || *cfg.bootstrap_index > *max_bootstrap_index))
            max_bootstrap_index = cfg.bootstrap_index;
        return index;
#else
        (void)cfg;
        return std::unexpected("WireGuard outbound is not available in this build");
#endif
    }

    auto Server::add_wireguard(std::string_view host, std::uint16_t port, std::string_view private_key_file,
        std::string_view peer_public_key_file, std::optional<std::string_view> preshared_key_file,
        bool has_v4, std::array<std::uint8_t, 4> local_v4, bool has_v6, std::array<std::uint8_t, 16> local_v6,
        bool warp, std::array<std::uint8_t, 3> reserved, std::uint16_t mtu, std::uint16_t keepalive_s,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, TcpSocketOptions options)
        -> std::expected<std::size_t, std::string> {
        config::WireGuardOutbound cfg;
        cfg.host = std::string(host);
        cfg.port = port;
        cfg.private_key_file = std::string(private_key_file);
        cfg.peer_public_key_file = std::string(peer_public_key_file);
        if (preshared_key_file) cfg.preshared_key_file = std::string(*preshared_key_file);
        cfg.has_v4 = has_v4; cfg.local_v4 = local_v4;
        cfg.has_v6 = has_v6; cfg.local_v6 = local_v6;
        cfg.warp = warp; cfg.reserved = reserved;
        cfg.mtu = mtu; cfg.keepalive_s = keepalive_s;
        cfg.bootstrap_index = bootstrap;
        cfg.connect_timeout_ms = timeout_ms;
        cfg.tcp_options = std::move(options);
        return add_wireguard(cfg);
    }
}
