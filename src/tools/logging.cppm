export module logging.cli;
import std;
import logging;

export namespace logging {
    class Runtime {
        Config config_;
        std::unique_ptr<Logger> logger_;
        std::optional<Producer> producer_;

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
            if (self.producer_) {
                (void)self.producer_->log(domain, level, event, context, format, std::forward<Args>(args)...);
            }
        }

        auto private_text(this Runtime const& self, std::string_view value) noexcept -> std::string_view {
            return self.producer_ ? self.producer_->private_text(value) : "<redacted>";
        }
    };
}
