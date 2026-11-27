module relay;
import std;
import config;
import proxy.v4;

namespace relay {
    auto Server::add_tor(config::TorServiceConfig const& cfg, std::uint32_t timeout_ms)
        -> std::expected<std::size_t, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_TOR
        if (outbounds.size() >= max_tunnel_outbounds) return std::unexpected("too many tunnel outbounds");
        auto factory = make_tor_factory(cfg, timeout_ms);
        if (!factory) return std::unexpected(std::move(factory.error()));
        auto index = outbounds.size() + 2;
        outbounds.push_back(std::move(*factory));
        return index;
#else
        (void)cfg; (void)timeout_ms;
        return std::unexpected("Tor outbound requires the tor build feature");
#endif
    }
}
