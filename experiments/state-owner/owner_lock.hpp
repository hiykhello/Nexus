#pragma once
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

// Experimental Linux-only lock. The private directory and lock inode must not
// be renamed, removed or replaced while any owner may exist.
class OwnerLock {
    int fd_ = -1;
    int dir_ = -1;
    explicit OwnerLock(int fd, int dir = -1) : fd_(fd), dir_(dir) {}
public:
    OwnerLock(OwnerLock const&) = delete;
    OwnerLock& operator=(OwnerLock const&) = delete;
    OwnerLock(OwnerLock&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)), dir_(std::exchange(other.dir_, -1)) {}
    ~OwnerLock() { if (fd_ >= 0) ::close(fd_); if (dir_ >= 0) ::close(dir_); }

    // Borrowed for operations relative to the very directory containing the
    // locked inode; valid only for this owner's lifetime. Do not close it.
    int directory_fd() const noexcept { return dir_; }

    // A caller-owned, pre-existing private directory; no symlink as final
    // component. Returns errno on failure, including EWOULDBLOCK on conflict.
    static std::pair<OwnerLock, int> acquire(char const* directory) {
        int dir = ::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dir < 0) return {OwnerLock(-1), errno};
        struct stat d{};
        if (::fstat(dir, &d) < 0) { int e=errno; ::close(dir); return {OwnerLock(-1), e}; }
        if (d.st_uid != ::geteuid() || (d.st_mode & 07777) != 0700) {
            ::close(dir); return {OwnerLock(-1), EACCES};
        }
        int fd = ::openat(dir, "owner.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
        if (fd < 0) { int e=errno; ::close(dir); return {OwnerLock(-1), e}; }
        struct stat file{}, name{};
        if (::fstat(fd, &file) < 0) {
            int e=errno; ::close(fd); ::close(dir); return {OwnerLock(-1), e};
        }
        if (!S_ISREG(file.st_mode) || file.st_uid != ::geteuid() || (file.st_mode & 07777) != 0600 || file.st_nlink != 1) {
            ::close(fd); ::close(dir); return {OwnerLock(-1), EACCES};
        }
        if (::flock(fd, LOCK_EX | LOCK_NB) < 0) {
            int e=errno; ::close(fd); ::close(dir); return {OwnerLock(-1), e};
        }
        if (::fstatat(dir, "owner.lock", &name, AT_SYMLINK_NOFOLLOW) < 0) {
            int e=errno; ::close(fd); ::close(dir); return {OwnerLock(-1), e};
        }
        if (name.st_dev != file.st_dev || name.st_ino != file.st_ino || name.st_nlink != 1) {
            ::close(fd); ::close(dir); return {OwnerLock(-1), ESTALE};
        }
        return {OwnerLock(fd, dir), 0};
    }
};
