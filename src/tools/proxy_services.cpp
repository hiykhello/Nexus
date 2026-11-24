module cli.proxy_services;
import std;
import config;
import logging;
import logging.cli;

namespace cli {
    auto OptionalServicesRuntime::start(config::ServicesConfig const& cfg, logging::Runtime& logs, ServiceHooks hooks)
        -> std::expected<void, std::string> {
        stop();
        auto add = [&](auto const& opt, auto init_fn) -> std::expected<void, std::string> {
            if (!opt) return {};
            auto h = init_fn(*opt, logs);
            if (!h) { stop(); return std::unexpected(std::move(h.error())); }
            services_.push_back(std::move(*h));
            return {};
        };
        if (cfg.memory_watchdog) {
            auto h = init_watchdog_service(*cfg.memory_watchdog, logs, std::move(hooks.watchdog));
            if (!h) { stop(); return std::unexpected(std::move(h.error())); }
            services_.push_back(std::move(*h));
        }
        if (auto ok = add(cfg.sni_demux, init_sni_demux_service); !ok) return ok;
        if (cfg.acme) {
            auto h = init_acme_service(*cfg.acme, logs, std::move(hooks.acme));
            if (!h) { stop(); return std::unexpected(std::move(h.error())); }
            services_.push_back(std::move(*h));
        }
        if (auto ok = add(cfg.reverse_tunnel, init_reverse_tunnel_service); !ok) return ok;
        if (auto ok = add(cfg.bridge, init_bridge_service); !ok) return ok;
        if (cfg.tor) {
            auto h = init_tor_service(*cfg.tor, logs, std::move(hooks.tor));
            if (!h) { stop(); return std::unexpected(std::move(h.error())); }
            services_.push_back(std::move(*h));
        }
        if (auto ok = add(cfg.derp_server, init_derp_server_service); !ok) return ok;
        return {};
    }

    auto OptionalServicesRuntime::poll(std::uint64_t now_ms, logging::Runtime& logs) noexcept -> void {
        for (auto& svc : services_) {
            if (svc.tick && svc.state) svc.tick(svc.state.get(), now_ms, logs);
        }
    }

    auto OptionalServicesRuntime::stop() noexcept -> void {
        while (!services_.empty()) services_.pop_back();
    }
}
