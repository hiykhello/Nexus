// Logging, readiness reporting, and config reload diagnostic helpers for CLI host.
export module cli.proxy_log;
import std;
import cli.proxy_listener;
import cli.route_files;
import config;
import logging;
import logging.cli;
import relay;

export namespace cli::run_detail {
    inline auto print_traffic(relay::TrafficSnapshot const& snapshot, std::size_t listener, std::uint16_t port) -> void {
        using relay::ConnectPath;
        std::cerr << std::format("traffic listener={} listen-port={} active={} upload={} download={}\n",
            listener, port, snapshot.active.size(), snapshot.bytes.upload, snapshot.bytes.download);
        for (auto const& row : snapshot.active) {
            auto path = row.path == ConnectPath::direct ? "direct" : row.path == ConnectPath::tunnel ? "tunnel" :
                row.path == ConnectPath::datagrams ? "datagrams" : "dialing";
            std::cerr << std::format("connection listener={} listen-port={} id={} protocol={} path={}"
                " source-port={} destination-port={} can-close={} upload={} download={}\n",
                listener, port, row.id, relay::traffic_protocol_name(row.protocol), path,
                row.source ? row.source->port : 0, row.destination_port, row.can_close ? 1 : 0,
                row.bytes.upload, row.bytes.download);
        }
    }

    inline auto emit_traffic_snapshot(std::vector<Listener> const& listeners) -> void {
        relay::TrafficBytes total;
        std::size_t active = 0;
        for (std::size_t index = 0; index < listeners.size(); ++index) {
            auto const& listener = listeners[index];
            auto snapshot = listener.server->traffic_snapshot();
            print_traffic(snapshot, index, listener.port);
            active += snapshot.active.size();
            total.upload += snapshot.bytes.upload;
            total.download += snapshot.bytes.download;
        }
        std::cerr << std::format("traffic-total active={} upload={} download={}\n", active, total.upload, total.download);
    }

    inline auto report_ready(logging::Runtime& logs, std::vector<Listener> const& listeners, unsigned workers, bool traffic_stats,
                             std::optional<unsigned> workers_clamped_from = {}, unsigned host_parallelism = 0) -> void {
        if (workers_clamped_from)
            logs.emit(logging::Level::warn, logging::Domain::core, 100, {.generation = 1},
                "configured workers {} clamped to host parallelism {}", *workers_clamped_from, host_parallelism ? host_parallelism : workers);
        logs.emit(traffic_stats ? logging::Level::debug : logging::Level::info, logging::Domain::core, 100, {.generation = 1},
            "proxy started with {} listeners and {} workers per listener", listeners.size(), workers);
        for (auto const& listener : listeners) {
            if (!listener.unix_path.empty()) { std::cout << "Fixed TCP listening on " << listener.unix_path << '\n'; continue; }
            if (listener.tun) { std::cout << "TUN listening on " << listener.host << '\n'; continue; }
            std::cout << (listener.masque ? "MASQUE" : listener.hy2 ? "Hysteria2" : listener.tuic ? "TUIC" : listener.inbound == relay::Inbound::fixed_tcp ? "Fixed TCP" : listener.inbound == relay::Inbound::naive ? "NaiveProxy" : listener.inbound == relay::Inbound::http ? "HTTP" : listener.inbound == relay::Inbound::mixed ? "Mixed" : listener.inbound == relay::Inbound::vless ? "VLESS/TLS" : listener.inbound == relay::Inbound::shadowsocks ? "SS-2022" : listener.inbound == relay::Inbound::trojan ? "Trojan/TLS" : listener.inbound == relay::Inbound::anytls ? "AnyTLS" : listener.inbound == relay::Inbound::snell ? "Snell" : listener.inbound == relay::Inbound::shadowtls ? "ShadowTLS" : listener.inbound == relay::Inbound::redirect ? "Redirect TCP" : listener.inbound == relay::Inbound::tproxy ? "TPROXY TCP" : "SOCKS5")
                      << " listening on " << ((listener.hy2 || listener.masque || listener.tuic || listener.address) ? (listener.ipv6 ? "[" + listener.host + "]:" : listener.host + ":") : (listener.ipv6 ? "[::1]:" : "127.0.0.1:")) << listener.port << '\n';
        }
    }

    inline auto log_detail(logging::Runtime const& logs, std::string_view detail) noexcept -> std::string_view {
        constexpr std::array<std::string_view, 13> public_diagnostics{
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
            if (detail == message || (detail.starts_with("DNS ") && detail.ends_with(message))) return message;
        return logs.private_text(detail);
    }

    inline auto log_failure(logging::Runtime const& logs, logging::Domain domain, std::string_view event,
                            std::string_view detail = {}) -> int {
        if (detail.empty()) logs.emit(logging::Level::error, domain, 106, {}, "{}", event);
        else logs.emit(logging::Level::error, domain, 106, {}, "{}: {}", event, log_detail(logs, detail));
        return 1;
    }

    struct RunArgs {
        bool help = false, traffic_stats = false, is_cfg = false, config_is_dir = false;
        unsigned port = 0;
        std::string config_path, host_override_path, rule_format, rule_path;
    };

    inline auto parse_run_args(int argc, char** argv) -> std::expected<RunArgs, int> {
        constexpr std::string_view run_usage =
            "usage: nexus run [--traffic-stats] <loopback-port> [kdl|beve|srs|nxmm <block-rules>]\n"
            "       nexus run [--traffic-stats] [--host-override <file>] (--config|-c <config.kdl> | --config-dir|-C <dir>)\n";
        if (argc == 2 && std::string_view(argv[1]) == "--help") { std::cout << run_usage; return RunArgs{.help = true}; }
        RunArgs out{};
        bool has_host_override = false;
        std::vector<std::string_view> pos;
        for (int i = 1; i < argc; ++i) {
            std::string_view arg(argv[i]);
            if (arg == "--traffic-stats") { out.traffic_stats = true; continue; }
            if (arg == "--config" || arg == "-c" || arg == "--config-dir" || arg == "-C") {
                if (out.is_cfg || i + 1 >= argc || std::string_view(argv[i + 1]).empty()) {
                    std::cerr << "--config/-c/--config-dir/-C accepts exactly one path\n"; return std::unexpected(2);
                }
                out.is_cfg = true;
                out.config_is_dir = (arg == "--config-dir" || arg == "-C");
                out.config_path = argv[++i];
                continue;
            }
            if (arg == "--host-override") {
                if (has_host_override || i + 1 >= argc || std::string_view(argv[i + 1]).empty()) {
                    std::cerr << "--host-override accepts exactly one non-empty path\n"; return std::unexpected(2);
                }
                has_host_override = true;
                out.host_override_path = argv[++i];
                continue;
            }
            if (arg.starts_with('-')) { std::cerr << run_usage; return std::unexpected(2); }
            pos.push_back(arg);
        }
        if (out.is_cfg) {
            if (!pos.empty()) { std::cerr << "--config/-c/--config-dir/-C accepts exactly one path\n"; return std::unexpected(2); }
            return out;
        }
        if (has_host_override) { std::cerr << "--host-override requires --config or --config-dir\n"; return std::unexpected(2); }
        if (pos.size() != 1 && pos.size() != 3) { std::cerr << run_usage; return std::unexpected(2); }
        auto [end, error] = std::from_chars(pos[0].data(), pos[0].data() + pos[0].size(), out.port);
        if (error != std::errc{} || end != pos[0].data() + pos[0].size() || out.port == 0 || out.port > 65535) {
            std::cerr << "port must be an integer from 1 to 65535\n";
            return std::unexpected(2);
        }
        if (pos.size() == 3) {
            if (pos[1] != "kdl" && pos[1] != "beve" && pos[1] != "srs" && pos[1] != "nxmm") {
                std::cerr << "rule format must be kdl, beve, srs or nxmm\n";
                return std::unexpected(2);
            }
            out.rule_format = std::string(pos[1]);
            out.rule_path = std::string(pos[2]);
        }
        return out;
    }

    inline auto protect_host_override_path(std::vector<std::string>& protected_paths, std::string_view host_override_path)
        -> std::expected<void, std::string> {
        if (host_override_path.empty()) return {};
        std::filesystem::path resolved(host_override_path);
        if (resolved.is_relative()) if (auto wd = cli::working_directory()) resolved = *wd / resolved;
        std::error_code ec;
        auto abs = std::filesystem::absolute(resolved, ec);
        if (ec) return std::unexpected("cannot resolve host-override path for log files");
        protected_paths.push_back(abs.string());
        return {};
    }

    inline auto reload_logging_and_routes(logging::Runtime& logs, std::string_view path, bool config_is_dir,
                                          std::uint64_t previous, std::uint64_t const& generation,
                                          auto&& routes, auto&& prepare_source,
                                          std::string_view host_override_path = {}) -> bool {
        using logging::Domain;
        using logging::Level;
        auto reload = [&]() -> std::expected<void, std::string> {
            auto raw = cli::read_config_source(path, config_is_dir, host_override_path);
            if (!raw) return std::unexpected(std::move(raw.error()));
            auto input = prepare_source(*raw);
            if (!input) return std::unexpected(std::move(input.error()));
            auto config = config::parse_kdl(*input);
            if (!config) return std::unexpected(std::move(config.error()));
            if (auto ok = protect_host_override_path(config->log_protected_paths, host_override_path); !ok) return ok;
            auto options = config->log.value_or(logging::Config{});
            auto validated = logs.validate_reload(options, path, config->log_protected_paths);
            if (!validated) return validated;
            auto opened = logs.reopen();
            if (!opened) {
                logs.emit(Level::error, Domain::core, 107, {.generation = generation},
                    "log reopen failed: {}", opened.error().message());
                return std::unexpected("cannot reopen log sink");
            }
            auto result = routes(*input, std::move(*config));
            if (result) logs.apply_levels(options);
            return result;
        };
        try {
            auto result = reload();
            if (!result) {
                logs.emit(Level::warn, Domain::route, 103, {.generation = generation},
                    "traffic rule reload failed: {}", logs.private_text(result.error()));
                return false;
            }
            if (previous != generation)
                logs.emit(Level::info, Domain::route, 102, {.generation = generation}, "listeners reloaded generation={}", generation);
            else logs.emit(Level::info, Domain::route, 102, {.generation = generation}, "traffic rules reloaded");
            return true;
        } catch (std::bad_alloc const&) {
            logs.emit(Level::error, Domain::route, 103, {.generation = generation}, "traffic rule reload failed: out of memory");
        } catch (std::system_error const& error) {
            logs.emit(Level::error, Domain::route, 103, {.generation = generation},
                "traffic rule reload failed: {}", error.code().message());
        } catch (std::out_of_range const& error) {
            logs.emit(Level::error, Domain::route, 103, {.generation = generation},
                "traffic rule reload failed: {}", logs.private_text(error.what()));
        }
        return false;
    }

    inline auto reload_logging_and_routes(logging::Runtime& logs, std::string_view path, bool config_is_dir,
                                          std::uint64_t previous, std::uint64_t const& generation,
                                          auto&& routes, std::string_view host_override_path = {}) -> bool {
        return reload_logging_and_routes(logs, path, config_is_dir, previous, generation, routes,
            [](std::string_view raw) -> std::expected<std::string, std::string> { return std::string(raw); },
            host_override_path);
    }

    inline auto report_exit(logging::Runtime& logs, bool failed, bool udp_failed, std::uint64_t generation,
                            std::vector<Listener> const& listeners,
                            auto& masque, auto& hy2, auto& tuic, auto& tun) -> int {
        using logging::Domain;
        if (!failed) {
            logs.emit(logging::Level::info, Domain::core, 105, {.generation = generation}, "proxy stopped");
            return 0;
        }
        if (auto error = masque.failure()) return log_failure(logs, Domain::quic, "MASQUE listener failed", *error);
        if (auto error = hy2.failure()) return log_failure(logs, Domain::quic, "Hysteria2 listener failed", *error);
        if (auto error = tuic.failure()) return log_failure(logs, Domain::quic, "TUIC listener failed", *error);
        if (auto error = tun.failure()) return log_failure(logs, Domain::tun, "TUN listener failed", *error);
        if (udp_failed) {
            logs.emit(logging::Level::error, Domain::proxy, 106, {}, "shadowsocks UDP listener failed");
        } else {
            for (auto const& listener : listeners) if (auto failure = listener.server->failure()) {
                logs.emit(logging::Level::error, Domain::proxy, 106, {}, "proxy: {} {}",
                    relay::describe(failure->kind), failure->system_error ? failure->system_error.message() : "");
                return 1;
            }
            logs.emit(logging::Level::error, Domain::proxy, 106, {}, "proxy worker failed");
        }
        return 1;
    }
}
