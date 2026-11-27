module;
#include <proxy/proxy_macros.h>
export module logging.sink;
import std;
import proxy.v4;
import logging.core;

export namespace logging {
    // Write receives borrowed complete lines for the duration of the call.
    // The logger calls the sink serially from its writer thread.
    using SinkResult = std::expected<void, std::error_code>;
    struct SinkRecord {
        std::string_view line;
        Level level = Level::info;
        Domain domain = Domain::core;
        std::uint32_t event_code = 0;
        Context context{};
    };
    PRO_DEF_MEM_DISPATCH(SinkWrite, write);
    PRO_DEF_MEM_DISPATCH(SinkReopen, reopen);
    struct SinkFacade : pro::facade_builder
        ::add_convention<SinkWrite, SinkResult(std::span<SinkRecord const>) noexcept>
        ::add_convention<SinkReopen, SinkResult() noexcept>::build {};

    using Sink = pro::proxy<SinkFacade>;
    inline constexpr std::size_t batch_capacity = 32;

    struct FileOptions {
        std::filesystem::path path;
        std::uint64_t max_size_bytes = 0; // Zero disables size rotation.
        std::size_t max_files = 1;        // Includes the current file.
    };

    [[nodiscard]] auto off_sink() noexcept -> Sink;
    [[nodiscard]] auto stderr_sink(int fd = 2) -> std::expected<Sink, std::error_code>;
    [[nodiscard]] auto file_sink(FileOptions options) -> std::expected<Sink, std::error_code>;
    [[nodiscard]] auto journald_available() noexcept -> bool;
    [[nodiscard]] auto journald_sink() -> Sink;
    [[nodiscard]] auto combine_sinks(std::vector<Sink> sinks) -> Sink;
    [[nodiscard]] auto write_batch(Sink& sink, std::span<SinkRecord const> records) noexcept -> SinkResult;
    [[nodiscard]] auto write_batch(Sink& sink, std::span<std::string_view const> lines) noexcept -> SinkResult;
    [[nodiscard]] auto reopen_sink(Sink& sink) noexcept -> SinkResult;

    // Cross-platform rotation state machine used by the Windows file sink.
    // Preserves the active log intact if shifting backups or moving current -> .1 fails.
    template<class Handle, class ErrorCode, class Ops>
    [[nodiscard]] inline auto rotate_file_ops(
        std::filesystem::path const& dir,
        std::span<std::string const> names,
        std::string const& temp_name,
        Handle& active_handle,
        std::uint64_t& active_size,
        Ops&& ops) noexcept -> ErrorCode {
        if (names.empty()) return ops.invalid_arg();
        std::uint64_t dummy_sz = 0;
        ErrorCode err = ops.ok();
        auto temp_path = dir / temp_name;
        Handle next = ops.open_append(temp_path, true, dummy_sz, err);
        if (!next) return err;
        auto cleanup_temp = [&]() noexcept {
            ops.close(next);
            ops.remove(temp_path);
        };
        for (std::size_t idx = names.size() - 1; idx > 1; --idx) {
            auto src = dir / names[idx - 1];
            auto dst = dir / names[idx];
            ErrorCode move_err = ops.ok();
            if (!ops.move_replace(src, dst, move_err) && !ops.is_not_found(move_err)) {
                cleanup_temp();
                return move_err;
            }
        }
        if (active_handle) {
            ops.close(active_handle);
            active_handle = Handle{};
        }
        auto cur = dir / names[0];
        auto recover_active = [&]() noexcept {
            std::uint64_t recovered_sz = 0;
            ErrorCode reopen_err = ops.ok();
            if (Handle recovered = ops.open_append(cur, false, recovered_sz, reopen_err)) {
                active_handle = recovered;
                active_size = recovered_sz;
            }
        };
        if (names.size() > 1) {
            auto bak = dir / names[1];
            ErrorCode bak_err = ops.ok();
            if (!ops.move_replace(cur, bak, bak_err)) {
                cleanup_temp();
                recover_active();
                return bak_err;
            }
        }
        ErrorCode replace_err = ops.ok();
        if (!ops.move_replace(temp_path, cur, replace_err)) {
            cleanup_temp();
            recover_active();
            return replace_err;
        }
        active_handle = next;
        active_size = 0;
        return ops.ok();
    }
}
