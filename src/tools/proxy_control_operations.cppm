// Process-local operation state and bounded control event history.
export module cli.proxy_control_operations;
import std;

export namespace cli::run_detail {
    inline auto control_number(std::string_view text) noexcept -> std::optional<std::uint64_t> {
        std::uint64_t value;
        auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (error != std::errc{} || end != text.data() + text.size()) return {};
        return value;
    }

    class ControlOperations {
    public:
        enum class EventKind {
            reload_queued, reload_succeeded, reload_failed, selector_changed,
            close_queued, cache_cleared, network_changed, probe_triggered, mode_changed
        };

    private:
        enum class State { pending, succeeded, failed };
        struct Event {
            EventKind kind{};
            std::uint64_t generation = 0;
            std::uint64_t operation = 0;
        };
        struct Reload {
            std::uint64_t id = 0;
            std::uint64_t generation = 0;
            State state = State::pending;
        };

        std::array<Reload, 64> reloads_{};
        std::array<Event, 128> events_{};
        std::uint64_t event_sequence_ = 0;
        std::uint64_t last_ = 0;
        std::uint64_t generation_ = 1;
        Reload* pending_ = nullptr;
        std::string fallback_instance_;

        static auto generate_instance_id() -> std::string {
            static std::atomic<std::uint64_t> seq{0};
            std::uint64_t a = 0, b = 0;
            try {
                std::random_device rd;
                a = (std::uint64_t{rd()} << 32) | rd();
                b = (std::uint64_t{rd()} << 32) | rd();
            } catch (...) {}
            auto now = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            auto n = seq.fetch_add(1, std::memory_order_relaxed) + 1;
            a ^= now ^ (n * 0x9e3779b97f4a7c15ull);
            b ^= (now << 17) ^ (n * 0xbf58476d1ce4e5b9ull);
            return std::format("{:016x}{:016x}", a, b);
        }

        auto event_name(EventKind kind) const noexcept -> std::string_view {
            switch (kind) {
            case EventKind::reload_queued: return "reload-queued";
            case EventKind::reload_succeeded: return "reload-succeeded";
            case EventKind::reload_failed: return "reload-failed";
            case EventKind::selector_changed: return "selector-changed";
            case EventKind::close_queued: return "connection-close-queued";
            case EventKind::cache_cleared: return "cache-cleared";
            case EventKind::network_changed: return "network-changed";
            case EventKind::probe_triggered: return "probe-triggered";
            case EventKind::mode_changed: return "mode-changed";
            }
            std::unreachable();
        }

    public:
        ControlOperations() : fallback_instance_(generate_instance_id()) {}
        [[nodiscard]] auto resolve_instance(std::string_view local_instance) const noexcept -> std::string_view {
            return local_instance.empty() ? std::string_view(fallback_instance_) : local_instance;
        }
        [[nodiscard]] auto generation() const noexcept -> std::uint64_t { return generation_; }
        [[nodiscard]] auto pending() const noexcept -> bool { return pending_ != nullptr; }
        auto published() noexcept -> void { ++generation_; }

        auto record(EventKind kind, std::uint64_t operation = 0) noexcept -> void {
            events_[++event_sequence_ % events_.size()] = {kind, generation_, operation};
        }

        auto events(std::span<std::string_view const> args, std::string_view instance) const
            -> std::expected<std::string, std::string> {
            auto cursor = args.size() >= 2 ? control_number(args[1]) : std::optional<std::uint64_t>{0};
            if (!cursor) return std::unexpected("invalid-event-cursor");
            if (*cursor > event_sequence_ || (args.size() == 3 && args[2] != instance))
                return std::unexpected("stale-event-cursor");
            auto first = event_sequence_ > events_.size() ? event_sequence_ - events_.size() + 1 : 1;
            auto start = std::max(*cursor + 1, first);
            auto end = std::min(event_sequence_ + 1, start + 32);
            auto result = std::format("instance={} next={} latest={} gap={}\n",
                instance, end - 1, event_sequence_, start != *cursor + 1 ? 1 : 0);
            for (auto id = start; id < end; ++id) {
                auto const& event = events_[id % events_.size()];
                result += std::format("id={} event={} control-generation={}", id, event_name(event.kind), event.generation);
                if (event.operation) result += std::format(" operation={}", event.operation);
                result += '\n';
            }
            return result;
        }

        auto queue_reload() -> std::expected<std::string, std::string> {
            if (pending_) return std::unexpected("reload-busy");
            auto id = last_ + 1;
            auto response = std::format("id={} state=pending\n", id);
            auto& operation = reloads_[id % reloads_.size()];
            operation = {id, generation_, State::pending};
            pending_ = &operation;
            last_ = id;
            record(EventKind::reload_queued, id);
            return response;
        }

        auto finish_reload(bool success) noexcept -> void {
            if (success) published();
            record(success ? EventKind::reload_succeeded : EventKind::reload_failed, pending_ ? pending_->id : 0);
            if (!pending_) return;
            pending_->state = success ? State::succeeded : State::failed;
            pending_->generation = generation_;
            pending_ = nullptr;
        }

        auto operation(std::string_view argument) const -> std::expected<std::string, std::string> {
            auto id = control_number(argument);
            if (!id || !*id) return std::unexpected("invalid-id");
            auto const& record = reloads_[*id % reloads_.size()];
            if (record.id != *id) return std::unexpected("unknown-operation");
            auto state = record.state == State::pending ? "pending" :
                record.state == State::succeeded ? "succeeded" : "failed";
            auto response = std::format("id={} action=reload state={} control-generation={}\n",
                record.id, state, record.generation);
            if (record.state == State::failed) response += "reason=reload-failed\n";
            return response;
        }
    };
}
