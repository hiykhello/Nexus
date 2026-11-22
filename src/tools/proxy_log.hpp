#pragma once

namespace cli::run_detail {
    auto print_traffic(proxy::TrafficSnapshot const& snapshot,std::size_t listener,std::uint16_t port) -> void {
        using proxy::ConnectPath;
        std::cerr << std::format("traffic listener={} listen-port={} active={} upload={} download={}\n",
            listener,port,snapshot.active.size(),snapshot.bytes.upload,snapshot.bytes.download);
        for (auto const& row : snapshot.active) {
            auto path=row.path==ConnectPath::direct ? "direct" : row.path==ConnectPath::tunnel ? "tunnel" :
                row.path==ConnectPath::datagrams ? "datagrams" : "dialing";
            std::cerr << std::format("connection listener={} listen-port={} id={} protocol={} path={}"
                " source-port={} destination-port={} can-close={} upload={} download={}\n",
                listener,port,row.id,proxy::traffic_protocol_name(row.protocol),path,
                row.source ? row.source->port : 0,row.destination_port,row.can_close ? 1 : 0,
                row.bytes.upload,row.bytes.download);
        }
    }
    auto emit_traffic_snapshot(std::vector<Listener> const& listeners) -> void {
        proxy::TrafficBytes total;
        std::size_t active=0;
        for (std::size_t index=0;index<listeners.size();++index) {
            auto const& listener=listeners[index];
            auto snapshot=listener.server->traffic_snapshot();
            print_traffic(snapshot,index,listener.port);
            active+=snapshot.active.size();
            total.upload+=snapshot.bytes.upload;
            total.download+=snapshot.bytes.download;
        }
        std::cerr << std::format("traffic-total active={} upload={} download={}\n",active,total.upload,total.download);
    }

    auto report_ready(logging::Runtime& logs, std::vector<Listener> const& listeners, unsigned workers, bool traffic_stats) -> void {
        logs.emit(traffic_stats ? logging::Level::debug : logging::Level::info,logging::Domain::core,100,{.generation=1},
            "proxy started with {} listeners and {} workers per listener",listeners.size(),workers);
        for (auto const& listener : listeners) {
            if (!listener.unix_path.empty()) {std::cout << "Fixed TCP listening on " << listener.unix_path << '\n'; continue;}
            if (listener.tun) { std::cout << "TUN listening on " << listener.host << '\n'; continue; }
            std::cout << (listener.masque ? "MASQUE" : listener.hy2 ? "Hysteria2" : listener.tuic ? "TUIC" : listener.inbound==proxy::Inbound::fixed_tcp ? "Fixed TCP" : listener.inbound==proxy::Inbound::naive ? "NaiveProxy" : listener.inbound==proxy::Inbound::http ? "HTTP" : listener.inbound == proxy::Inbound::mixed ? "Mixed" : listener.inbound == proxy::Inbound::vless ? "VLESS/TLS" : listener.inbound == proxy::Inbound::shadowsocks ? "SS-2022" : listener.inbound==proxy::Inbound::trojan ? "Trojan/TLS" : listener.inbound==proxy::Inbound::anytls ? "AnyTLS" : listener.inbound==proxy::Inbound::snell ? "Snell" : listener.inbound==proxy::Inbound::shadowtls ? "ShadowTLS" : listener.inbound==proxy::Inbound::redirect ? "Redirect TCP" : listener.inbound==proxy::Inbound::tproxy ? "TPROXY TCP" : "SOCKS5")
                      << " listening on " << ((listener.hy2 || listener.masque || listener.tuic || listener.address) ? (listener.ipv6 ? "["+listener.host+"]:" : listener.host+":") : (listener.ipv6 ? "[::1]:" : "127.0.0.1:")) << listener.port << '\n';
        }
    }

    auto log_detail(logging::Runtime const& logs, std::string_view detail) noexcept -> std::string_view {
        constexpr std::array<std::string_view,13> public_diagnostics{
            "DNS over TLS is unavailable in this build", "DNS over HTTPS is unavailable in this build",
            "DNS over HTTP/3 is unavailable in this build", "DNS over QUIC is unavailable in this build",
            "FakeIP requires the dns-fakeip build feature", "shadowsocks UDP is not available in this build",
            "NTP is not available in this build",
            "selector state directory cannot be locked", "selector state directory must be owned by the process user and private",
            "selector state instance lock must be a private regular file", "selector state has an unsupported or damaged format",
            "selector state contains invalid or duplicate choices",
            "selector state does not match a configured manual group and member"
        };
        for (auto message : public_diagnostics)
            if (detail==message || (detail.starts_with("DNS ") && detail.ends_with(message))) return message;
        return logs.private_text(detail);
    }

    auto log_failure(logging::Runtime const& logs, logging::Domain domain, std::string_view event,
                     std::string_view detail = {}) -> int {
        if (detail.empty()) logs.emit(logging::Level::error,domain,106,{},"{}",event);
        else logs.emit(logging::Level::error,domain,106,{},"{}: {}",event,log_detail(logs,detail));
        return 1;
    }

    auto reload_logging_and_routes(logging::Runtime& logs, std::string_view path, bool config_is_dir,
                                   std::uint64_t previous, std::uint64_t const& generation,
                                   auto&& routes) -> bool {
        using logging::Domain;
        using logging::Level;
        auto reload=[&]() -> std::expected<void,std::string> {
            auto input=cli::read_config_source(path,config_is_dir);
            if (!input) return std::unexpected(std::move(input.error()));
            auto config=config::parse_kdl(*input);
            if (!config) return std::unexpected(std::move(config.error()));
            auto options=config->log.value_or(logging::Config{});
            auto validated=logs.validate_reload(options,path,config->log_protected_paths);
            if (!validated) return validated;
            auto opened=logs.reopen();
            if (!opened) {
                logs.emit(Level::error,Domain::core,107,{.generation=generation},
                    "log reopen failed: {}",opened.error().message());
                return std::unexpected("cannot reopen log sink");
            }
            auto result=routes(*input,std::move(*config));
            if (result) logs.apply_levels(options);
            return result;
        };
        try {
            auto result=reload();
            if (!result) {
                logs.emit(Level::warn,Domain::route,103,{.generation=generation},
                    "traffic rule reload failed: {}",logs.private_text(result.error()));
                return false;
            }
            if (previous!=generation)
                logs.emit(Level::info,Domain::route,102,{.generation=generation},"listeners reloaded generation={}",generation);
            else logs.emit(Level::info,Domain::route,102,{.generation=generation},"traffic rules reloaded");
            return true;
        } catch (std::bad_alloc const&) {
            logs.emit(Level::error,Domain::route,103,{.generation=generation},"traffic rule reload failed: out of memory");
        } catch (std::system_error const& error) {
            logs.emit(Level::error,Domain::route,103,{.generation=generation},
                "traffic rule reload failed: {}",error.code().message());
        }
        return false;
    }

    auto report_exit(logging::Runtime const& logs, bool failed, bool udp_failed, std::uint64_t generation,
                     std::vector<Listener> const& listeners,
                     auto& masque, auto& hy2, auto& tuic, auto& tun) -> int {
        using logging::Domain;
        if (!failed) {
            logs.emit(logging::Level::info,Domain::core,105,{.generation=generation},"proxy stopped");
            return 0;
        }
        if (auto error=masque.failure()) return log_failure(logs,Domain::quic,"MASQUE listener failed",*error);
        if (auto error=hy2.failure()) return log_failure(logs,Domain::quic,"Hysteria2 listener failed",*error);
        if (auto error=tuic.failure()) return log_failure(logs,Domain::quic,"TUIC listener failed",*error);
        if (auto error=tun.failure()) return log_failure(logs,Domain::tun,"TUN listener failed",*error);
        if (udp_failed) {
            logs.emit(logging::Level::error,Domain::proxy,106,{},"shadowsocks UDP listener failed");
        } else {
            for (auto const& listener : listeners) if (auto failure=listener.server->failure()) {
                logs.emit(logging::Level::error,Domain::proxy,106,{},"proxy: {} {}",
                    proxy::describe(failure->kind),failure->system_error ? failure->system_error.message() : "");
                return 1;
            }
            logs.emit(logging::Level::error,Domain::proxy,106,{},"proxy worker failed");
        }
        return 1;
    }
}
