module;
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
export module state.file;
import std;
import state.core;
import platform.os_fs;

export namespace state {
    class File {
        int fd_;
    public:
        explicit File(int fd) noexcept : fd_(fd) {}
        File(File&& other) noexcept : fd_(other.release()) {}
        auto operator=(this File& self, File&& other) noexcept -> File& {
            std::swap(self.fd_, other.fd_);
            return self;
        }
        ~File() { if (fd_ >= 0) ::close(fd_); }
        auto get(this File const& self) noexcept -> int { return self.fd_; }
        auto release(this File& self) noexcept -> int { return std::exchange(self.fd_, -1); }
    };

    auto open_directory(std::filesystem::path const& path) -> std::expected<File, StateError>;
    auto open_private_directory(std::filesystem::path const& path) -> std::expected<File, StateError>;
    auto ensure_private_directory(std::filesystem::path const& path) -> std::expected<void, StateError>;
    struct DirectoryEntry { std::string name; std::uint64_t size; bool private_file; };
    auto directory_entries(int directory, std::function_ref<bool(std::string_view)> accept)
        -> std::expected<std::vector<DirectoryEntry>, StateError>;

    auto failure(Stage stage, int number, bool replaced = false) noexcept -> std::unexpected<StateError> {
        return std::unexpected(StateError{stage, {number, std::generic_category()}, replaced});
    }

    auto private_regular(struct stat const& info) noexcept -> bool {
        return S_ISREG(info.st_mode) && info.st_nlink == 1 && info.st_uid == ::geteuid() &&
            (info.st_mode & 07777) == 0600;
    }

    auto sync_file(int fd) noexcept -> int {
        return platform::sync_native_handle(static_cast<std::uintptr_t>(fd));
    }
}
