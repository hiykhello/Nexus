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
}
