module relay;
import std;
import proxy.v4;
import config;

namespace relay {
    auto Server::add_naive(config::NaiveOutbound const& cfg) -> std::expected<std::size_t, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_NAIVE
        if (outbounds.size() >= max_tunnel_outbounds) return std::unexpected("too many tunnel outbounds");
        if (cfg.bootstrap_index && (!dns_routing || *cfg.bootstrap_index >= dns_routing->resolver_count()))
            return std::unexpected("invalid bootstrap resolver");
        auto factory = make_naive_factory(cfg, dns_routing.has_value());
        if (!factory) return std::unexpected(factory.error());
        auto index = outbounds.size() + 2;
        outbounds.push_back(std::move(*factory));
        if (cfg.bootstrap_index && (!max_bootstrap_index || *cfg.bootstrap_index > *max_bootstrap_index))
            max_bootstrap_index = cfg.bootstrap_index;
        return index;
#else
        (void)cfg;
        return std::unexpected("NaiveProxy outbound is not available in this build");
#endif
    }

    auto Server::prepare_naive_inbound(config::NaiveInbound const& cfg) -> std::expected<void, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing inbound");
#ifdef NEXUS_ENABLE_NAIVE
        bool want_tcp = (cfg.protocol == config::NaiveProtocol::h2 || cfg.protocol == config::NaiveProtocol::both);
        bool want_h3 = (cfg.protocol == config::NaiveProtocol::h3 || cfg.protocol == config::NaiveProtocol::both);
        if (want_tcp) {
            auto prepared = make_naive_h2_inbound_factory(cfg, inbound_tls_runtime);
            if (!prepared) return std::unexpected(prepared.error());
            naive_inbound = std::move(*prepared);
        } else {
            naive_inbound = {};
        }
        if (want_h3) {
            if (auto prepared = prepare_modern_h3_naive(cfg); !prepared) {
                naive_inbound = {};
                return prepared;
            }
        } else {
            modern_h3_inbound.reset();
        }
        naive_tcp_enabled = want_tcp;
        naive_h3_enabled = want_h3;
        return {};
#else
        (void)cfg;
        return std::unexpected("NaiveProxy inbound is not available in this build");
#endif
    }

    auto Server::prepare_http_modern_inbound(config::HttpInbound const& cfg) -> std::expected<void, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing inbound");
#ifdef NEXUS_ENABLE_NAIVE
        if (!cfg.has_tls) {
            http_modern_inbound = {};
            http_modern_tcp_enabled = false;
            http_modern_h3_enabled = false;
            return {};
        }
        bool want_tcp = cfg.http2 || !cfg.http3;
        bool want_h3 = cfg.http3;
        if (want_tcp) {
            auto prepared = make_http_modern_inbound_factory(cfg, credentials, inbound_tls_runtime);
            if (!prepared) return std::unexpected(prepared.error());
            http_modern_inbound = std::move(*prepared);
        } else {
            http_modern_inbound = {};
        }
        if (want_h3) {
            if (auto prepared = prepare_modern_h3_http(cfg, credentials); !prepared) {
                http_modern_inbound = {};
                return prepared;
            }
        } else {
            modern_h3_inbound.reset();
        }
        http_modern_tcp_enabled = want_tcp;
        http_modern_h3_enabled = want_h3;
        return {};
#else
        (void)cfg;
        return std::unexpected("TLS HTTP/2/3 inbound is not available in this build");
#endif
    }
}
