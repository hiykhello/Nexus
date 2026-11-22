export module logging;
import std;
export import logging.core;
export import logging.sink;

export namespace logging {
    inline constexpr std::size_t queue_capacity = 128;
    inline constexpr std::size_t max_producers = 64;
    // Reserved for writer-generated drop reports.
    inline constexpr std::uint32_t dropped_event_code = std::numeric_limits<std::uint32_t>::max();

    enum class Submit : std::uint8_t { accepted, filtered, dropped, closed, busy };

    struct Diagnostics {
        DropCounts dropped{};
        std::array<std::size_t, max_producers> queue_high_water{};
        std::size_t producer_count = 0;
        std::size_t undrained = 0;
        std::uint64_t sink_errors = 0;
        std::optional<std::int64_t> last_success_ns;
    };

    struct DrainResult {
        bool completed;
        Diagnostics diagnostics;
    };

    struct LogRingEntry {
        std::uint64_t seq = 0;
        std::int64_t wall_epoch_ns = 0;
        std::int64_t monotonic_ns = 0;
        Level level = Level::info;
        Domain domain = Domain::core;
        std::uint32_t event_code = 0;
        Context context{};
        std::string message;
    };

    struct LogRingQuery {
        std::uint64_t since_seq = 0;
        std::optional<Level> min_level;
        std::optional<Domain> domain;
        std::string_view search;
        std::size_t limit = 256;
    };

    struct LogRingSnapshot {
        std::uint64_t latest_seq = 0;
        std::uint64_t evicted = 0;
        std::vector<LogRingEntry> entries;
    };

    class Logger;
    struct ProducerState;

    // A handle borrows its logger. Use one producer index per producing
    // thread and end all handle use before destroying the logger.
    class Producer {
        friend class Logger;
        ProducerState* state_;
        Privacy privacy_;
        Producer(ProducerState* state, Privacy privacy) noexcept : state_(state), privacy_(privacy) {}

        auto reserve(this Producer const& self, Domain domain, Level level) noexcept
            -> std::expected<LogSlot*, Submit>;
        auto publish(this Producer const& self) noexcept -> void;
        auto release(this Producer const& self, bool committed) noexcept -> void;

    public:
        // Use at call sites for private identifiers such as usernames,
        // destinations and full client IPs. Never pass credentials as text.
        auto private_text(this Producer const& self, std::string_view value) noexcept -> std::string_view {
            return self.privacy_ == Privacy::verbose ? value : "<redacted>";
        }

        // The logger allocates no formatting storage. Caller-supplied
        // formatters must also be allocation-free on hot paths.
        template<class... Args>
        auto log(this Producer const& self, Domain domain, Level level, std::uint32_t event_code,
                 Context context, std::format_string<Args...> format, Args&&... args) -> Submit {
            if (!self.state_ || !enabled_any(domain, level)) return Submit::filtered;
            auto slot = self.reserve(domain, level);
            if (!slot) return slot.error();

            struct Reservation {
                Producer const& producer;
                bool committed = false;
                ~Reservation() { producer.release(committed); }
            } reservation{self};
            auto& entry = **slot;
            stamp(entry);
            entry.level = level;
            entry.domain = domain;
            entry.event_code = event_code;
            entry.context = context;
            auto result = std::format_to_n(entry.message.data(), entry.message.size(),
                                           format, std::forward<Args>(args)...);
            entry.message_size = static_cast<std::uint16_t>(result.out - entry.message.data());
            entry.truncated = result.size > static_cast<std::ptrdiff_t>(entry.message.size());
            self.publish();
            reservation.committed = true;
            return Submit::accepted;
        }
    };

    class Logger {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit Logger(std::unique_ptr<Impl> impl) noexcept;

    public:
        // With no sink, submissions short-circuit and no writer or queues are started.
        [[nodiscard]] static auto start(Sink sink, std::size_t producers, Settings settings = {})
            -> std::expected<std::unique_ptr<Logger>, std::error_code>;
        ~Logger();
        [[nodiscard]] auto producer(this Logger const& self, std::size_t index) noexcept -> std::optional<Producer>;
        [[nodiscard]] auto diagnostics(this Logger const& self) noexcept -> Diagnostics;
        // Control-thread operation. Flushes the writer's snapshot before reopening.
        [[nodiscard]] auto reopen(this Logger& self) -> SinkResult;
        // Closes ingress permanently and waits until the deadline. A timed-out
        // sink write is still owned by the writer. Destruction joins the writer
        // and can wait for a blocked sink to return.
        [[nodiscard]] auto drain(this Logger& self, Clock::time_point deadline) -> DrainResult;
        [[nodiscard]] auto snapshot_logs(this Logger const& self, LogRingQuery const& query = {}) -> LogRingSnapshot;
        auto clear_ring(this Logger& self) -> void;
    };
}
