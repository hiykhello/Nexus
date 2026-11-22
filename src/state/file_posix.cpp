module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
module state.file;
import std;

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

    auto directory_entries(int directory, std::function_ref<bool(std::string_view)> accept)
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
}
