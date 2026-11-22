module logging.cli;
import std;
import logging;

namespace logging {
    namespace {
        namespace fs = std::filesystem;

        auto has_file(Config const& config) noexcept -> bool {
            return std::ranges::any_of(config.sinks, [](auto const& sink) { return sink.kind == SinkKind::file; });
        }

        auto contains_path(fs::path const& directory, fs::path const& path) -> bool {
            auto result = std::ranges::mismatch(directory, path);
            return result.in1 == directory.end();
        }

        auto validate_paths(Config const& config, std::string_view config_path,
                            std::span<std::string const> protected_paths) -> std::expected<void, std::string> {
            if (!has_file(config)) return {};
            std::error_code error;
            auto source = fs::absolute(fs::path(config_path), error);
            if (error) return std::unexpected("cannot resolve configuration path for log files");
            auto base = source.parent_path();
            std::vector<fs::path> protected_names;
            auto protect = [&](fs::path const& path) -> void {
                protected_names.push_back(path.lexically_normal());
                auto canonical = fs::weakly_canonical(path, error);
                if (!error && canonical != protected_names.back()) protected_names.push_back(std::move(canonical));
            };
            protect(source);
            for (auto const& path : protected_paths) protect(base / path);
            std::vector<fs::path> output_names;
            for (auto const& sink : config.sinks) {
                if (sink.kind != SinkKind::file) continue;
                output_names.emplace_back(sink.path);
                if (!sink.max_size_bytes) continue;
                output_names.emplace_back(sink.path + ".rotate");
                for (std::size_t index = 1; index < sink.max_files; ++index)
                    output_names.emplace_back(sink.path + "." + std::to_string(index));
            }
            auto overlaps = [](fs::path const& a, fs::path const& b) {
                return contains_path(a, b) || contains_path(b, a);
            };
            for (std::size_t index = 0; index < output_names.size(); ++index) {
                auto const& path = output_names[index];
                auto conflict = [&](fs::path const& other) { return overlaps(path, other); };
                if (std::ranges::any_of(protected_names, conflict) ||
                    std::ranges::any_of(std::span(output_names).first(index), conflict))
                    return std::unexpected("log file or rotation path conflicts with another configured path");
            }
            return {};
        }

        auto open_sinks(Config const& config) -> std::expected<Sink, std::string> {
            if (!journald_available() && std::ranges::any_of(config.sinks, [](auto const& destination) {
                return destination.kind == SinkKind::journald;
            })) return std::unexpected("log sink journald is unavailable in this build");
            std::vector<Sink> sinks;
            for (auto const& destination : config.sinks) {
                if (destination.kind == SinkKind::off) continue;
                if (destination.kind == SinkKind::journald) {
                    sinks.push_back(journald_sink());
                    continue;
                }
                auto sink = destination.kind == SinkKind::stderr ? stderr_sink() :
                    file_sink({destination.path, destination.max_size_bytes, destination.max_files});
                if (!sink) return std::unexpected(std::format("cannot open log {} sink: {}",
                    destination.kind == SinkKind::stderr ? "stderr" : "file", sink.error().message()));
                sinks.push_back(std::move(*sink));
            }
            return combine_sinks(std::move(sinks));
        }
    }

    Runtime::~Runtime() { shutdown(); }

    auto Runtime::start(this Runtime& self, Config config, std::string_view config_path,
                        std::span<std::string const> protected_paths) -> std::expected<void, std::string> {
        auto valid = validate_paths(config, config_path, protected_paths);
        if (!valid) return valid;
        auto sink = open_sinks(config);
        if (!sink) return std::unexpected(sink.error());
        auto logger = Logger::start(std::move(*sink), 1, config.settings);
        if (!logger) return std::unexpected(std::format("cannot start log writer: {}", logger.error().message()));
        self.config_ = std::move(config);
        self.logger_ = std::move(*logger);
        self.producer_ = self.logger_->producer(0);
        self.apply_levels(self.config_);
        return {};
    }

    auto Runtime::validate_reload(this Runtime const& self, Config const& config, std::string_view config_path,
                                  std::span<std::string const> protected_paths) -> std::expected<void, std::string> {
        if (config.settings != self.config_.settings || config.sinks != self.config_.sinks)
            return std::unexpected("log sinks, format, timestamp and privacy changes require restart");
        return validate_paths(config, config_path, protected_paths);
    }

    auto Runtime::reopen(this Runtime& self) -> SinkResult {
        if (!has_file(self.config_)) return {};
        return self.logger_->reopen();
    }

    auto Runtime::apply_levels(this Runtime&, Config const& config) noexcept -> void {
        for (std::size_t index = 0; index < domain_count; ++index)
            set_level(static_cast<Domain>(index), config.domains[index].value_or(config.level));
        set_ring_level(config.settings.ring_capacity ? config.ring_level : Level::off);
    }

    auto Runtime::query_logs(this Runtime const& self, LogRingQuery const& query) -> LogRingSnapshot {
        if (!self.logger_) return {};
        return self.logger_->snapshot_logs(query);
    }

    auto Runtime::clear_ring(this Runtime& self) -> void {
        if (self.logger_) self.logger_->clear_ring();
    }

    auto Runtime::control_logs(this Runtime const& self, std::span<std::string_view const> args)
        -> std::expected<std::string, std::string> {
        if (!self.logger_) return std::unexpected("log-ring-unavailable");
        LogRingQuery query{};
        std::string search_owned;
        for (auto arg : args) {
            if (arg.starts_with("since=")) {
                auto v = arg.substr(6);
                std::uint64_t n = 0;
                auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
                if (ec != std::errc{} || end != v.data() + v.size()) return std::unexpected("invalid-since");
                query.since_seq = n;
            } else if (arg.starts_with("limit=")) {
                auto v = arg.substr(6);
                std::size_t n = 0;
                auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
                if (ec != std::errc{} || end != v.data() + v.size() || !n || n > 2048) return std::unexpected("invalid-limit");
                query.limit = n;
            } else if (arg.starts_with("level=")) {
                auto lvl = parse_level(arg.substr(6));
                if (!lvl) return std::unexpected("invalid-level");
                query.min_level = *lvl;
            } else if (arg.starts_with("domain=")) {
                auto dom = parse_domain(arg.substr(7));
                if (!dom) return std::unexpected("invalid-domain");
                query.domain = *dom;
            } else if (arg.starts_with("search=")) {
                search_owned.assign(arg.substr(7));
                query.search = search_owned;
            } else {
                return std::unexpected("invalid-logs-argument");
            }
        }
        auto snap = self.logger_->snapshot_logs(query);
        std::string out = std::format("latest={} evicted={} count={}\n", snap.latest_seq, snap.evicted, snap.entries.size());
        for (auto const& e : snap.entries) {
            auto line = std::format("seq={} ts={} level={} domain={} event={} session={} msg={:?}\n",
                e.seq, e.wall_epoch_ns, name(e.level), name(e.domain), e.event_code, e.context.session_id, e.message);
            if (out.size() + line.size() >= 60 * 1024) break;
            out += line;
        }
        return out;
    }

    auto Runtime::control(this Runtime& self, bool administrator, std::span<std::string_view const> args)
        -> std::expected<std::string, std::string> {
        if (!args.empty()) {
            if (!administrator) return std::unexpected("permission-denied");
            if (args.size() != 2) return std::unexpected("usage log-level global|DOMAIN LEVEL");
            auto level = parse_level(args[1]);
            if (!level) return std::unexpected("invalid-level");
            if (args[0] == "global") set_level(*level);
            else if (auto domain = parse_domain(args[0])) set_level(*domain, *level);
            else return std::unexpected("invalid-domain");
        }
        std::string result;
        for (std::size_t index = 0; index < domain_count; ++index) {
            auto domain = static_cast<Domain>(index);
            result += std::format("{}={}\n", name(domain), name(get_level(domain)));
        }
        auto snapshot = self.logger_->diagnostics();
        std::uint64_t dropped = 0;
        for (auto const& domain : snapshot.dropped)
            for (auto count : domain) dropped += count;
        result += std::format("dropped={} sink-errors={} queued={} queue-high-water={}\n",
            dropped, snapshot.sink_errors, snapshot.undrained, snapshot.queue_high_water.front());
        return result;
    }

    auto Runtime::shutdown(this Runtime& self) -> void {
        if (!self.logger_) return;
        (void)self.logger_->drain(Clock::now() + std::chrono::seconds(2));
        self.producer_.reset();
        self.logger_.reset();
    }
}
