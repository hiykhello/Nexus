export module logging.cli;
import std;
import logging;

export namespace logging {
    class Runtime {
        static constexpr std::size_t kProducers = max_producers;
        Config config_;
        std::unique_ptr<Logger> logger_;
        mutable std::array<std::optional<Producer>, kProducers> producers_{};
        mutable std::array<std::atomic<bool>, kProducers> producer_ready_{};
        std::uint64_t runtime_id_ = 0;
        mutable std::atomic<std::size_t> next_slot_{0};
        mutable std::mutex slot_mutex_;
        mutable std::mutex overflow_mutex_;

        [[nodiscard]] auto producer_for_thread(this Runtime const& self, bool& overflow) noexcept -> Producer const*;

    public:
        ~Runtime();
        [[nodiscard]] auto start(this Runtime& self, Config config, std::string_view config_path = {},
                                 std::span<std::string const> protected_paths = {}) -> std::expected<void, std::string>;
        [[nodiscard]] auto validate_reload(this Runtime const& self, Config const& config, std::string_view config_path,
                                           std::span<std::string const> protected_paths) -> std::expected<void, std::string>;
        [[nodiscard]] auto reopen(this Runtime& self) -> SinkResult;
        auto apply_levels(this Runtime& self, Config const& config) noexcept -> void;
        [[nodiscard]] auto control(this Runtime& self, bool administrator, std::span<std::string_view const> args)
            -> std::expected<std::string, std::string>;
        [[nodiscard]] auto control_logs(this Runtime const& self, std::span<std::string_view const> args)
            -> std::expected<std::string, std::string>;
        [[nodiscard]] auto query_logs(this Runtime const& self, LogRingQuery const& query = {}) -> LogRingSnapshot;
        auto clear_ring(this Runtime& self) -> void;
        auto shutdown(this Runtime& self) -> void;

        template<class... Args>
        auto emit(this Runtime const& self, Level level, Domain domain, std::uint32_t event, Context context,
                  std::format_string<Args...> format, Args&&... args) -> void {
            bool overflow = false;
            auto* producer = self.producer_for_thread(overflow);
            if (!producer) return;
            if (!overflow) {
                (void)producer->log(domain, level, event, context, format, std::forward<Args>(args)...);
                return;
            }
            std::lock_guard lock(self.overflow_mutex_);
            (void)producer->log(domain, level, event, context, format, std::forward<Args>(args)...);
        }

        auto private_text(this Runtime const& self, std::string_view value) noexcept -> std::string_view {
            return self.logger_ && self.config_.settings.privacy == Privacy::verbose ? value : "<redacted>";
        }
    };
}
