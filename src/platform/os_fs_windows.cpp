module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

module platform.os_fs;
import std;

namespace platform {
    auto sync_native_handle(std::uintptr_t handle) noexcept -> int {
        HANDLE h = reinterpret_cast<HANDLE>(handle);
        if (!h || h == INVALID_HANDLE_VALUE) {
            ::SetLastError(ERROR_INVALID_HANDLE);
            return -1;
        }
        if (::FlushFileBuffers(h)) return 0;
        DWORD const err = ::GetLastError();
        BY_HANDLE_FILE_INFORMATION info{};
        bool const is_dir = ::GetFileInformationByHandle(h, &info) != 0 &&
            (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (classify_windows_flush_result(false, is_dir, static_cast<std::uint32_t>(err))) return 0;
        ::SetLastError(err);
        return -1;
    }

    auto atomic_replace_path(std::filesystem::path const& source,
        std::filesystem::path const& destination) -> std::error_code {
        if (source.empty() || destination.empty()) return std::make_error_code(std::errc::invalid_argument);
        if (::MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return {};
        return {static_cast<int>(::GetLastError()), std::system_category()};
    }

    auto is_reparse_or_symlink(std::filesystem::path const& path) noexcept
        -> std::expected<bool, std::error_code> {
        if (path.empty()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        DWORD attrs = ::GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            DWORD err = ::GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return false;
            return std::unexpected(std::error_code{static_cast<int>(err), std::system_category()});
        }
        return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    }
}
