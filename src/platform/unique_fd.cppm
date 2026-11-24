module;
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

export module platform.unique_fd;
import std;

export namespace platform {
    class UniqueFd {
        int fd_ = -1;

        static auto close_raw(int fd) noexcept -> int {
#ifdef _WIN32
            return ::_close(fd);
#else
            return ::close(fd);
#endif
        }

    public:
        constexpr UniqueFd() noexcept = default;
        constexpr explicit UniqueFd(int fd) noexcept : fd_(fd) {}
        UniqueFd(UniqueFd const&) = delete;
        auto operator=(UniqueFd const&) -> UniqueFd& = delete;

        constexpr UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
        auto operator=(UniqueFd&& other) noexcept -> UniqueFd& {
            if (this != &other) reset(other.release());
            return *this;
        }

        ~UniqueFd() {
            if (fd_ >= 0) (void)close_raw(fd_);
        }

        [[nodiscard]] constexpr auto get() const noexcept -> int { return fd_; }
        [[nodiscard]] constexpr auto valid() const noexcept -> bool { return fd_ >= 0; }
        [[nodiscard]] constexpr explicit operator bool() const noexcept { return fd_ >= 0; }

        [[nodiscard]] constexpr auto release() noexcept -> int { return std::exchange(fd_, -1); }

        auto reset(int fd = -1) noexcept -> void {
            if (fd_ >= 0 && fd_ != fd) (void)close_raw(fd_);
            fd_ = fd;
        }

        auto close() noexcept -> bool {
            if (fd_ < 0) return true;
            return close_raw(std::exchange(fd_, -1)) == 0;
        }
    };
}
