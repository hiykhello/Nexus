module;
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

module platform.os_fs;
import std;

namespace platform {
    auto sync_native_handle(std::uintptr_t handle) noexcept -> int {
        int fd = static_cast<int>(handle);
        if (fd < 0) {
            errno = EBADF;
            return -1;
        }
#if defined(__APPLE__) && defined(F_FULLFSYNC)
        if (::fcntl(fd, F_FULLFSYNC) == 0) return 0;
#endif
        int result;
        do { result = ::fsync(fd); } while (result < 0 && errno == EINTR);
        return result;
    }

    auto atomic_replace_path(std::filesystem::path const& source,
        std::filesystem::path const& destination) -> std::error_code {
        if (source.empty() || destination.empty()) return std::make_error_code(std::errc::invalid_argument);
        if (::rename(source.c_str(), destination.c_str()) == 0) return {};
        return {errno, std::generic_category()};
    }

    auto is_reparse_or_symlink(std::filesystem::path const& path) noexcept
        -> std::expected<bool, std::error_code> {
        if (path.empty()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        struct stat info{};
        if (::lstat(path.c_str(), &info) == 0) return S_ISLNK(info.st_mode);
        if (errno == ENOENT) return false;
        return std::unexpected(std::error_code{errno, std::generic_category()});
    }
}
