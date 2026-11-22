module;
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
export module state.file;
import std;
import nexus.compat;
import state.core;
import platform.os_fs;

export namespace state {
    using NativeHandle = int;
    inline constexpr NativeHandle invalid_handle = -1;
    [[nodiscard]] constexpr auto valid_handle(NativeHandle handle) noexcept -> bool { return handle >= 0; }

    class File {
        int fd_;
    public:
        explicit File(int fd = -1) noexcept : fd_(fd) {}
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
    auto directory_entries(NativeHandle directory, nexus::function_ref<bool(std::string_view)> accept)
        -> std::expected<std::vector<DirectoryEntry>, StateError>;

    auto open_dir_read(NativeHandle dir, std::string_view name, bool require_private, Stage stage)
        -> std::expected<File, StateError>;
    auto open_dir_append(NativeHandle dir, std::string_view name, Stage stage)
        -> std::expected<File, StateError>;
    auto open_dir_stage(NativeHandle dir, std::string_view name, Stage stage)
        -> std::expected<File, StateError>;
    auto dir_entry_exists(NativeHandle dir, std::string_view name, Stage stage)
        -> std::expected<bool, StateError>;
    auto handle_size(NativeHandle handle, Stage stage) -> std::expected<std::uint64_t, StateError>;
    auto read_handle(NativeHandle handle, std::span<std::byte> out, Stage stage) -> std::expected<std::size_t, StateError>;
    auto read_handle_at(NativeHandle handle, std::uint64_t offset, std::span<std::byte> out, Stage stage)
        -> std::expected<std::size_t, StateError>;
    auto write_handle_all(NativeHandle handle, std::span<std::byte const> data, Stage stage)
        -> std::expected<void, StateError>;
    auto truncate_handle(NativeHandle handle, std::uint64_t size, Stage stage) -> std::expected<void, StateError>;
    auto close_file(File& file, Stage stage) -> std::expected<void, StateError>;
    auto unlink_dir_file(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<void, StateError>;
    auto rename_dir_file(NativeHandle dir, std::string_view from, std::string_view to, bool noreplace, Stage stage)
        -> std::expected<void, StateError>;
    auto same_directory_entry(NativeHandle held_dir, NativeHandle parent_dir, std::string_view name)
        -> std::expected<bool, StateError>;
    auto read_dir_file(NativeHandle dir, std::string_view name, std::size_t max_bytes, bool require_private)
        -> std::expected<std::vector<std::byte>, StateError>;
    auto write_dir_file_atomic(NativeHandle dir, std::string_view name, std::string_view tmp_prefix,
                               std::span<std::byte const> data, Stage stage) -> std::expected<void, StateError>;

    auto failure(Stage stage, int number, bool replaced = false) noexcept -> std::unexpected<StateError> {
        return std::unexpected(StateError{stage, {number, std::generic_category()}, replaced});
    }

    auto private_regular(struct stat const& info) noexcept -> bool {
        return S_ISREG(info.st_mode) && info.st_nlink == 1 && info.st_uid == ::geteuid() &&
            (info.st_mode & 07777) == 0600;
    }

    auto sync_file(NativeHandle fd) noexcept -> int {
        return platform::sync_native_handle(static_cast<std::uintptr_t>(fd));
    }
    auto sync_handle(NativeHandle fd, Stage stage, bool replaced = false) noexcept -> std::expected<void, StateError>;
}
