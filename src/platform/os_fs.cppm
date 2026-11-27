export module platform.os_fs;
import std;

export namespace platform {
    [[nodiscard]] auto sync_native_handle(std::uintptr_t handle) noexcept -> int;
    // On Windows, FlushFileBuffers on a non-writable directory handle returns ERROR_ACCESS_DENIED (5)
    // or ERROR_INVALID_FUNCTION (1); durability for atomic replace is provided by FlushFileBuffers
    // on the temp file + MoveFileExW(..., MOVEFILE_WRITE_THROUGH). Real I/O faults and all regular-file
    // errors must still fail.
    [[nodiscard]] constexpr auto classify_windows_flush_result(
        bool flush_ok, bool is_directory, std::uint32_t win32_error) noexcept -> bool {
        if (flush_ok) return true;
        constexpr std::uint32_t kErrorInvalidFunction = 1u;
        constexpr std::uint32_t kErrorAccessDenied = 5u;
        return is_directory && (win32_error == kErrorAccessDenied || win32_error == kErrorInvalidFunction);
    }
    [[nodiscard]] auto atomic_replace_path(std::filesystem::path const& source,
        std::filesystem::path const& destination) -> std::error_code;
    [[nodiscard]] auto is_reparse_or_symlink(std::filesystem::path const& path) noexcept
        -> std::expected<bool, std::error_code>;

    [[nodiscard]] inline auto normalize_windows_pipe_name(std::string_view name) -> std::optional<std::string> {
        if (name.empty() || name.contains('\0')) return std::nullopt;
        constexpr std::string_view kPrefix = "\\\\.\\pipe\\";
        auto eq_ci = [](char a, char b) noexcept {
            auto lo = [](unsigned char c) noexcept {
                return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c + ('a' - 'A')) : c;
            };
            return lo(static_cast<unsigned char>(a)) == lo(static_cast<unsigned char>(b));
        };
        std::string_view suffix = name;
        if (name.size() >= kPrefix.size() && std::ranges::equal(name.substr(0, kPrefix.size()), kPrefix, eq_ci)) {
            suffix = name.substr(kPrefix.size());
        } else if (name.starts_with("\\\\") || name.starts_with("//")) {
            return std::nullopt;
        }
        if (suffix.empty() || suffix.size() > 200 || suffix == "." || suffix == "..") return std::nullopt;
        for (unsigned char c : suffix) {
            if (c < 0x20 || c == 0x7f || c == '\\' || c == '/' || c == ':') return std::nullopt;
        }
        std::string out(kPrefix);
        out.append(suffix);
        return out;
    }
}
