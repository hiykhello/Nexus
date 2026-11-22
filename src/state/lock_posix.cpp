module;
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
module state.lock;
import std;
import state.core;
import state.file;

namespace state {
    InstanceLock::InstanceLock(InstanceLock&& other) noexcept
        : directory_(std::exchange(other.directory_, -1)), lock_(std::exchange(other.lock_, -1)) {}
    InstanceLock::~InstanceLock() {
        if (lock_ >= 0) ::close(lock_);
        if (directory_ >= 0) ::close(directory_);
    }

    namespace {
        auto lock_directory(File directory, bool readonly_cache = false) -> std::expected<std::pair<int, int>, StateError> {
            struct stat info{};
            if (::fstat(directory.get(), &info) < 0) return failure(Stage::directory, errno);
            if (info.st_uid != ::geteuid() || ((info.st_mode & 07777) != 0700 &&
                !(readonly_cache && (info.st_mode & 07777) == 0500)))
                return failure(Stage::directory, EACCES);
            // Older selector processes lock the directory inode.
            if (::flock(directory.get(), LOCK_EX | LOCK_NB) < 0) return failure(Stage::lock, errno);

            constexpr char name[] = "instance.lock";
            constexpr auto flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
            int raw = ::openat(directory.get(), name, flags);
            bool created = false;
            if (raw < 0 && errno == ENOENT) {
                raw = ::openat(directory.get(), name, flags | O_CREAT | O_EXCL, 0600);
                created = raw >= 0;
            }
            if (raw < 0) return failure(Stage::lock_file, errno);
            File lock(raw);
            if (created && ::fchmod(lock.get(), 0600) < 0) return failure(Stage::lock_file, errno);
            if (::fstat(lock.get(), &info) < 0) return failure(Stage::lock_file, errno);
            if (!private_regular(info)) return failure(Stage::lock_file, EACCES);
            if (::flock(lock.get(), LOCK_EX | LOCK_NB) < 0) return failure(Stage::lock, errno);
            return std::pair(directory.release(), lock.release());
        }
    }

    auto InstanceLock::open(std::filesystem::path const& path) -> std::expected<InstanceLock, StateError> {
        auto directory = open_directory(path);
        if (!directory) return std::unexpected(directory.error());
        auto locked = lock_directory(std::move(*directory));
        if (!locked) return std::unexpected(locked.error());
        return InstanceLock(locked->first, locked->second);
    }

    auto InstanceLock::open_rulesets(std::filesystem::path const& root) -> std::expected<InstanceLock, StateError> {
        return open_child(root, "rulesets");
    }

    auto InstanceLock::open_child(std::filesystem::path const& root, std::string const& name) -> std::expected<InstanceLock, StateError> {
        if (name.empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0'))
            return failure(Stage::directory, EINVAL);
        auto parent = open_directory(root);
        if (!parent) return std::unexpected(parent.error());
        struct stat info{};
        if (::fstat(parent->get(), &info) < 0) return failure(Stage::directory, errno);
        if (info.st_uid != ::geteuid() || (info.st_mode & 07777) != 0700)
            return failure(Stage::directory, EACCES);
        // The parent can be a read-only cache root when its child already exists.
        constexpr auto flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
        int fd = ::openat(parent->get(), name.c_str(), flags);
        if (fd < 0 && errno == ENOENT) {
            if (::mkdirat(parent->get(), name.c_str(), 0700) < 0 && errno != EEXIST)
                return failure(Stage::directory, errno);
            if (sync_file(parent->get()) < 0) return failure(Stage::sync_directory, errno);
            fd = ::openat(parent->get(), name.c_str(), flags);
        }
        if (fd < 0) return failure(Stage::directory, errno);
        auto locked = lock_directory(File(fd), name == "rulesets");
        if (!locked) return std::unexpected(locked.error());
        InstanceLock instance(locked->first, locked->second);
        struct stat held{}, named{};
        if (::fstat(instance.directory(), &held) < 0 ||
            ::fstatat(parent->get(), name.c_str(), &named, AT_SYMLINK_NOFOLLOW) < 0)
            return failure(Stage::directory, errno);
        if (held.st_dev != named.st_dev || held.st_ino != named.st_ino)
            return failure(Stage::directory, ESTALE);
        return instance;
    }
}
