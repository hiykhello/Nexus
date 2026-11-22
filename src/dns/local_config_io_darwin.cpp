module;
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
module dns.local_config;
import std;

namespace dns::detail {
    auto read_local_config_file(std::string_view path, std::size_t max_bytes)
        -> std::expected<std::string, LocalConfigError> {
        if (path.empty() || path.find('\0') != path.npos) return std::unexpected(LocalConfigError::io_error);
        std::string filename(path);
        int fd = ::open(filename.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) return std::unexpected(LocalConfigError::io_error);
        struct Guard {
            int fd;
            ~Guard() { ::close(fd); }
        } guard{fd};
        struct stat status{};
        if (::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) return std::unexpected(LocalConfigError::io_error);
        std::string data;
        std::array<char, 4096> chunk{};
        for (;;) {
            auto read = ::read(fd, chunk.data(), chunk.size());
            if (read < 0 && errno == EINTR) continue;
            if (read < 0) return std::unexpected(LocalConfigError::io_error);
            if (!read) break;
            auto count = static_cast<std::size_t>(read);
            if (count > max_bytes - data.size()) return std::unexpected(LocalConfigError::too_large);
            data.append(chunk.data(), count);
        }
        struct stat after{};
        auto same_times = [](struct stat const& a, struct stat const& b) noexcept -> bool {
            return a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
                   a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
        };
        if (::fstat(fd, &after) != 0 || status.st_size != after.st_size || !same_times(status, after))
            return std::unexpected(LocalConfigError::io_error);
        return data;
    }
}
