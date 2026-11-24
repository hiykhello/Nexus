module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
module state.file;
import std;
import functional;

namespace state {
    auto open_directory(std::filesystem::path const& path) -> std::expected<File, StateError> {
        if (path.empty() || path.native().contains('\0')) return failure(Stage::directory, EINVAL);
        constexpr auto flags_dir = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
        File directory(::open(path.is_absolute() ? "/" : ".", flags_dir));
        if (directory.get() < 0) return failure(Stage::directory, errno);
        for (auto const& part : path.relative_path()) {
            if (part.empty() || part == ".") continue;
            File next(::openat(directory.get(), part.c_str(), flags_dir));
            if (next.get() < 0) return failure(Stage::directory, errno);
            directory = std::move(next);
        }
        return directory;
    }

    auto open_private_directory(std::filesystem::path const& path) -> std::expected<File, StateError> {
        auto directory = open_directory(path);
        if (!directory) return std::unexpected(directory.error());
        struct stat info{};
        if (::fstat(directory->get(), &info) < 0) return failure(Stage::directory, errno);
        if (info.st_uid != ::geteuid() || (info.st_mode & 07777) != 0700) return failure(Stage::directory, EACCES);
        return directory;
    }

    auto ensure_private_directory(std::filesystem::path const& path) -> std::expected<void, StateError> {
        auto existing = open_private_directory(path);
        if (existing) return {};
        if (existing.error().os != std::errc::no_such_file_or_directory) return std::unexpected(existing.error());
        auto name = path.filename();
        if (name.empty() || name == "." || name == "..") return failure(Stage::directory, EINVAL);
        auto parent = open_directory(path.parent_path());
        if (!parent) return std::unexpected(parent.error());
        if (::mkdirat(parent->get(), name.c_str(), 0700) < 0 && errno != EEXIST)
            return failure(Stage::directory, errno);
        if (sync_file(parent->get()) < 0) return failure(Stage::sync_directory, errno);
        existing = open_private_directory(path);
        if (!existing) return std::unexpected(existing.error());
        return {};
    }

    auto directory_entries(NativeHandle directory, functional::function_ref<bool(std::string_view)> accept)
        -> std::expected<std::vector<DirectoryEntry>, StateError> {
        File scan(::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (scan.get() < 0) return failure(Stage::scan, errno);
        auto* raw = ::fdopendir(scan.get());
        if (!raw) return failure(Stage::scan, errno);
        (void)scan.release();
        auto close = [](DIR* stream) { ::closedir(stream); };
        std::unique_ptr<DIR, decltype(close)> stream(raw, close);
        std::vector<DirectoryEntry> result;
        for (;;) {
            errno = 0;
            auto const* row = ::readdir(stream.get());
            if (!row) {
                if (errno) return failure(Stage::scan, errno);
                return result;
            }
            if (!accept(row->d_name)) continue;
            struct stat info{};
            if (::fstatat(directory, row->d_name, &info, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno == ENOENT) continue;
                return failure(Stage::scan, errno);
            }
            if (result.size() == 4096) return std::unexpected(StateError{Stage::capacity});
            result.push_back({row->d_name, static_cast<std::uint64_t>(info.st_size), private_regular(info)});
        }
    }

    auto open_dir_read(NativeHandle dir, std::string_view name, bool require_private, Stage stage)
        -> std::expected<File, StateError> {
        std::string zname(name);
        File fd(::openat(dir, zname.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
        if (fd.get() < 0) return failure(stage, errno);
        struct stat info{};
        if (::fstat(fd.get(), &info) < 0) return failure(stage, errno);
        if (require_private ? !private_regular(info) : !S_ISREG(info.st_mode)) return failure(stage, EACCES);
        return fd;
    }

    auto open_dir_append(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<File, StateError> {
        std::string zname(name);
        constexpr auto flags = O_RDWR | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        File fd(::openat(dir, zname.c_str(), flags));
        if (fd.get() < 0 && errno == ENOENT) {
            fd = File(::openat(dir, zname.c_str(), flags | O_CREAT | O_EXCL, 0600));
            if (fd.get() < 0) return failure(stage, errno);
            if (::fchmod(fd.get(), 0600) < 0 || sync_file(fd.get()) < 0 || sync_file(dir) < 0)
                return failure(Stage::sync_directory, errno);
        }
        if (fd.get() < 0) return failure(stage, errno);
        struct stat info{};
        if (::fstat(fd.get(), &info) < 0) return failure(stage, errno);
        if (!private_regular(info)) return failure(stage, EACCES);
        return fd;
    }

    auto open_dir_stage(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<File, StateError> {
        std::string zname(name);
        File fd(::openat(dir, zname.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (fd.get() < 0) return failure(stage, errno);
        if (::fchmod(fd.get(), 0600) < 0) return failure(stage, errno);
        return fd;
    }

    auto dir_entry_exists(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<bool, StateError> {
        std::string zname(name);
        struct stat info{};
        if (::fstatat(dir, zname.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0) return true;
        if (errno == ENOENT) return false;
        return failure(stage, errno);
    }

    auto handle_size(NativeHandle handle, Stage stage) -> std::expected<std::uint64_t, StateError> {
        struct stat info{};
        if (::fstat(handle, &info) < 0) return failure(stage, errno);
        return static_cast<std::uint64_t>(info.st_size);
    }

    auto read_handle(NativeHandle handle, std::span<std::byte> out, Stage stage) -> std::expected<std::size_t, StateError> {
        std::size_t total = 0;
        while (total < out.size()) {
            auto count = ::read(handle, out.data() + total, out.size() - total);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return failure(stage, errno);
            if (count == 0) break;
            total += static_cast<std::size_t>(count);
        }
        return total;
    }

    auto read_handle_at(NativeHandle handle, std::uint64_t offset, std::span<std::byte> out, Stage stage)
        -> std::expected<std::size_t, StateError> {
        std::size_t total = 0;
        while (total < out.size()) {
            auto count = ::pread(handle, out.data() + total, out.size() - total, static_cast<off_t>(offset + total));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return failure(stage, errno);
            if (count == 0) break;
            total += static_cast<std::size_t>(count);
        }
        return total;
    }

    auto write_handle_all(NativeHandle handle, std::span<std::byte const> data, Stage stage)
        -> std::expected<void, StateError> {
        while (!data.empty()) {
            auto count = ::write(handle, data.data(), data.size());
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return failure(stage, count == 0 ? EIO : errno);
            data = data.subspan(static_cast<std::size_t>(count));
        }
        return {};
    }

    auto truncate_handle(NativeHandle handle, std::uint64_t size, Stage stage) -> std::expected<void, StateError> {
        if (::ftruncate(handle, static_cast<off_t>(size)) < 0 || sync_file(handle) < 0) return failure(stage, errno);
        return {};
    }

    auto close_file(File& file, Stage stage) -> std::expected<void, StateError> {
        int fd = file.release();
        if (fd >= 0 && ::close(fd) < 0) return failure(stage, errno);
        return {};
    }

    auto unlink_dir_file(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<void, StateError> {
        std::string zname(name);
        if (::unlinkat(dir, zname.c_str(), 0) < 0 && errno != ENOENT) return failure(stage, errno);
        return {};
    }

    auto rename_dir_file(NativeHandle dir, std::string_view from, std::string_view to, bool noreplace, Stage stage)
        -> std::expected<void, StateError> {
        std::string zfrom(from), zto(to);
#if defined(__APPLE__)
        int rc = noreplace ? ::renameatx_np(dir, zfrom.c_str(), dir, zto.c_str(), RENAME_EXCL)
                           : ::renameat(dir, zfrom.c_str(), dir, zto.c_str());
#else
        int rc = noreplace ? ::renameat2(dir, zfrom.c_str(), dir, zto.c_str(), RENAME_NOREPLACE)
                           : ::renameat(dir, zfrom.c_str(), dir, zto.c_str());
#endif
        if (rc < 0) return failure(stage, errno);
        return {};
    }

    auto same_directory_entry(NativeHandle held_dir, NativeHandle parent_dir, std::string_view name)
        -> std::expected<bool, StateError> {
        std::string zname(name);
        struct stat held{}, named{};
        if (::fstat(held_dir, &held) < 0 || ::fstatat(parent_dir, zname.c_str(), &named, AT_SYMLINK_NOFOLLOW) < 0)
            return failure(Stage::directory, errno);
        return held.st_dev == named.st_dev && held.st_ino == named.st_ino;
    }

    auto sync_handle(NativeHandle fd, Stage stage, bool replaced) noexcept -> std::expected<void, StateError> {
        if (sync_file(fd) < 0) return failure(stage, errno, replaced);
        return {};
    }

    auto read_dir_file(NativeHandle dir, std::string_view name, std::size_t max_bytes, bool require_private)
        -> std::expected<std::vector<std::byte>, StateError> {
        auto fd = open_dir_read(dir, name, require_private, Stage::open);
        if (!fd) return std::unexpected(fd.error());
        auto sz = handle_size(fd->get(), Stage::read);
        if (!sz) return std::unexpected(sz.error());
        if (*sz > max_bytes) return std::unexpected(StateError{Stage::format});
        std::vector<std::byte> out(static_cast<std::size_t>(*sz));
        auto got = read_handle(fd->get(), out, Stage::read);
        if (!got) return std::unexpected(got.error());
        if (*got != out.size()) return std::unexpected(StateError{Stage::format});
        std::byte probe{};
        auto extra = read_handle(fd->get(), std::span(&probe, 1), Stage::read);
        if (!extra) return std::unexpected(extra.error());
        if (*extra != 0) return std::unexpected(StateError{Stage::format});
        return out;
    }

    auto write_dir_file_atomic(NativeHandle dir, std::string_view name, std::string_view tmp_prefix,
                               std::span<std::byte const> data, Stage stage) -> std::expected<void, StateError> {
        auto cleared = unlink_dir_file(dir, tmp_prefix, Stage::remove_stage);
        if (!cleared) return cleared;
        auto staged = open_dir_stage(dir, tmp_prefix, Stage::create_stage);
        if (!staged) return std::unexpected(staged.error());
        auto written = write_handle_all(staged->get(), data, Stage::write);
        if (written && sync_file(staged->get()) < 0) written = failure(Stage::sync_stage, errno);
        auto closed = close_file(*staged, Stage::close_stage);
        if (!written) { (void)unlink_dir_file(dir, tmp_prefix, Stage::remove_stage); return written; }
        if (!closed) { (void)unlink_dir_file(dir, tmp_prefix, Stage::remove_stage); return closed; }
        auto moved = rename_dir_file(dir, tmp_prefix, name, false, stage);
        if (!moved) { (void)unlink_dir_file(dir, tmp_prefix, Stage::remove_stage); return moved; }
        if (sync_file(dir) < 0) return failure(Stage::sync_directory, errno, true);
        return {};
    }
}
