module relay;
import std;
import proxy.v4;
import config;

namespace relay {
    auto Server::add_openvpn(config::OpenVpnOutbound const& cfg) -> std::expected<std::size_t, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_OPENVPN
        if (outbounds.size() >= 256) return std::unexpected("too many tunnel outbounds");
        if (cfg.bootstrap_index && (!dns_routing || *cfg.bootstrap_index >= dns_routing->resolver_count()))
            return std::unexpected("invalid bootstrap resolver");
        auto factory = make_openvpn_factory(cfg);
        if (!factory) return std::unexpected(factory.error());
        auto index = outbounds.size() + 2;
        outbounds.push_back(std::move(*factory));
        if (cfg.bootstrap_index && (!max_bootstrap_index || *cfg.bootstrap_index > *max_bootstrap_index))
            max_bootstrap_index = cfg.bootstrap_index;
        return index;
#else
        (void)cfg;
        return std::unexpected("OpenVPN outbound is not available in this build");
#endif
    }
}
