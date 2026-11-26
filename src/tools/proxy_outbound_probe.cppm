// Ad-hoc single-outbound delay prober with bounded queue and TTL result cache.
export module cli.proxy_outbound_probe;

import std;
import cli.proxy_group_health;
import cli.proxy_run_state;
import config;
import functional;
import relay;
import rules;

export namespace cli::run_detail {
    class AdHocOutboundProber {
        using Clock = std::chrono::steady_clock;

        enum class State : std::uint8_t { pending, up, down };

        struct Entry {
            std::uint64_t id = 0;
            std::string outbound;
            std::string resolved;
            std::string url;
            std::uint32_t timeout_ms = kDefaultTimeoutMs;
            State state = State::pending;
            std::optional<std::uint32_t> latency_ms;
            std::optional<std::uint16_t> status_code;
            Clock::time_point enqueued_at{};
            Clock::time_point completed_at{};
            std::shared_ptr<relay::OutboundProbe> probe;
        };

        std::uint64_t next_id_ = 1;
        std::optional<Entry> active_;
        std::deque<Entry> queue_;
        std::deque<Entry> results_;

        auto reap(Clock::time_point now) noexcept -> void {
            while (!results_.empty() && now - results_.front().completed_at >= kResultTtl)
                results_.pop_front();
        }

        auto store_completed(Entry&& entry) -> void {
            while (results_.size() >= kMaxResults) results_.pop_front();
            results_.push_back(std::move(entry));
        }

        static auto format_entry(Entry const& e) -> std::string {
            std::string_view st = e.state == State::pending ? "pending" : (e.state == State::up ? "up" : "down");
            auto out = std::format("id={} outbound={} resolved={} state={}",
                e.id, control_name(e.outbound), control_name(e.resolved), st);
            if (e.latency_ms) out += std::format(" latency-ms={}", *e.latency_ms);
            if (e.status_code) out += std::format(" status-code={}", *e.status_code);
            out += std::format(" url={}\n", e.url);
            return out;
        }

    public:
        static constexpr std::size_t kMaxPending = 16;
        static constexpr std::size_t kMaxResults = 64;
        static constexpr auto kResultTtl = std::chrono::seconds(60);
        static constexpr auto kMaxQueueWait = std::chrono::seconds(60);
        static constexpr std::string_view kDefaultUrl = "https://www.gstatic.com/generate_204";
        static constexpr std::uint32_t kDefaultTimeoutMs = 5000;
        static constexpr std::uint32_t kMinTimeoutMs = 200;
        static constexpr std::uint32_t kMaxTimeoutMs = 30000;

        [[nodiscard]] auto has_pending() const noexcept -> bool {
            return active_.has_value() || !queue_.empty();
        }

        auto enqueue(config::Config const& cfg, std::string_view tag, std::string_view url_arg,
            std::optional<std::uint32_t> timeout_ms, std::string_view mode_arg, bool supported)
            -> std::expected<std::string, std::string> {
            auto now = Clock::now();
            reap(now);
            if (!supported) return std::unexpected("probe-unavailable");
            if (tag.empty()) return std::unexpected("unknown-outbound");

            auto idx = config::configured_outbound_index(cfg, tag);
            if (!idx) return std::unexpected("unknown-outbound");
            if (*idx == 1) return std::unexpected("cannot-probe-block");
            auto leaf_sv = config::selected_outbound(cfg, tag);
            std::string resolved = leaf_sv.empty() ? std::string(tag) : std::string(leaf_sv);

            auto probe_mode = relay::OutboundProbeMode::http;
            auto cfg_mode = config::OutboundProbeMode::http;
            if (mode_arg.empty() || mode_arg == "http") {
                probe_mode = relay::OutboundProbeMode::http;
                cfg_mode = config::OutboundProbeMode::http;
            } else if (mode_arg == "h2-ping") {
                probe_mode = relay::OutboundProbeMode::h2_ping;
                cfg_mode = config::OutboundProbeMode::h2_ping;
            } else {
                return std::unexpected("invalid-mode");
            }

            std::string_view url = url_arg.empty() ? kDefaultUrl : url_arg;
            auto parsed = parse_probe_target(url, cfg_mode);
            if (!parsed) return std::unexpected("invalid-probe-url");
            if (probe_mode == relay::OutboundProbeMode::h2_ping && !parsed->use_tls)
                return std::unexpected("invalid-mode");

            std::uint32_t clamped_timeout = std::clamp(timeout_ms.value_or(kDefaultTimeoutMs), kMinTimeoutMs, kMaxTimeoutMs);
            if (queue_.size() + (active_ ? 1u : 0u) >= kMaxPending)
                return std::unexpected("probe-busy");

            auto matcher = rules::RouteMatcher::compile({}, *idx, 2 + cfg.tunnel_count());
            if (!matcher) return std::unexpected("probe-unavailable");

            auto probe = std::make_shared<relay::OutboundProbe>();
            probe->route = std::move(*matcher);
            probe->target = parsed->target;
            probe->request = std::move(parsed->request);
            probe->mode = probe_mode;
            probe->use_tls = parsed->use_tls;
            probe->tls_server_name = std::move(parsed->host);
            if (cfg.certificate && !cfg.certificate->ca_file.empty())
                probe->tls_ca_file = cfg.certificate->ca_file;
            probe->deadline = now + std::chrono::milliseconds(clamped_timeout);

            Entry entry{};
            entry.id = next_id_++;
            entry.outbound = std::string(tag);
            entry.resolved = std::move(resolved);
            entry.url = std::string(url);
            entry.timeout_ms = clamped_timeout;
            entry.state = State::pending;
            entry.enqueued_at = now;
            entry.probe = std::move(probe);

            auto reply = std::format("id={} outbound={} resolved={} state=pending\n",
                entry.id, control_name(entry.outbound), control_name(entry.resolved));
            queue_.push_back(std::move(entry));
            return reply;
        }

        auto result(std::uint64_t id) -> std::expected<std::string, std::string> {
            reap(Clock::now());
            if (active_ && active_->id == id) return format_entry(*active_);
            for (auto const& e : queue_) if (e.id == id) return format_entry(e);
            for (auto const& e : results_) if (e.id == id) return format_entry(e);
            return std::unexpected("unknown-probe");
        }

        auto poll(functional::function_ref<bool(std::shared_ptr<relay::OutboundProbe>)> enqueue_fn) -> void {
            auto now = Clock::now();
            reap(now);
            if (active_) {
                auto measurement = active_->probe->result.load(std::memory_order_acquire);
                if (measurement != 0) {
                    auto code = active_->probe->status_code.load(std::memory_order_relaxed);
                    active_->state = measurement > 1 ? State::up : State::down;
                    if (measurement > 1) active_->latency_ms = measurement - 2;
                    if (code) active_->status_code = code;
                    active_->completed_at = now;
                    active_->probe.reset();
                    store_completed(std::move(*active_));
                    active_.reset();
                } else if (now >= active_->probe->deadline + std::chrono::seconds(1)) {
                    active_->state = State::down;
                    active_->completed_at = now;
                    active_->probe.reset();
                    store_completed(std::move(*active_));
                    active_.reset();
                }
            }
            while (!active_ && !queue_.empty()) {
                auto& front = queue_.front();
                if (now >= front.enqueued_at + kMaxQueueWait) {
                    front.state = State::down;
                    front.completed_at = now;
                    front.probe.reset();
                    store_completed(std::move(front));
                    queue_.pop_front();
                    continue;
                }
                front.probe->deadline = now + std::chrono::milliseconds(front.timeout_ms);
                if (enqueue_fn(front.probe)) {
                    active_ = std::move(front);
                    queue_.pop_front();
                }
                break;
            }
        }
    };

    template<class Listeners>
    [[nodiscard]] inline auto listeners_support_outbound_probe(Listeners const& listeners) noexcept -> bool {
        return std::ranges::any_of(listeners, [](auto const& item) {
            return !item.masque && (!item.tun || item.routed_tun);
        });
    }

    template<class Listeners, class TunRuntime, class Hy2Runtime, class TuicRuntime>
    inline auto queue_probe_on_listeners(Listeners const& listeners, TunRuntime& tun, Hy2Runtime& hy2,
        TuicRuntime& tuic, std::shared_ptr<relay::OutboundProbe> probe) -> bool {
        for (std::size_t i = 0; i < listeners.size(); ++i) {
            auto const& l = listeners[i];
            if (l.masque || (l.tun && !l.routed_tun)) continue;
            bool ok = false;
            if (l.routed_tun) ok = tun.queue_outbound_probe(i, probe);
            else if (l.hy2) ok = hy2.queue_outbound_probe(i, probe);
            else if (l.tuic) ok = tuic.queue_outbound_probe(i, probe);
            else if (l.server) ok = l.server->queue_outbound_probe(probe);
            if (ok) return true;
        }
        return false;
    }
}
