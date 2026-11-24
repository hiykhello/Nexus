module;
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#endif

module packet.tun_darwin;
import std;

namespace packet {
#if defined(__APPLE__)
    namespace {
        auto parse_utun_unit(std::string_view name) noexcept -> std::optional<std::uint32_t> {
            if (name.empty()) return 0u; // kernel allocates lowest free utunN when unit == 0
            if (!name.starts_with("utun") || name.size() == 4) return std::nullopt;
            std::uint32_t unit = 0;
            auto digits = name.substr(4);
            auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), unit);
            if (ec != std::errc{} || ptr != digits.data() + digits.size() ||
                unit == std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
            return unit + 1u; // sc_unit = utunN + 1
        }
        auto net_u32(std::uint32_t v) noexcept -> std::uint32_t {
            if constexpr (std::endian::native == std::endian::little) return std::byteswap(v);
            return v;
        }
    }

    auto DarwinTun::open(DarwinTunConfig const& cfg) -> std::expected<DarwinTun, DarwinTunFailure> {
        auto unit = parse_utun_unit(cfg.name);
        if (!unit) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_name});
        int fd = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
        auto guard = [fd]() noexcept { if (fd >= 0) ::close(fd); };
        struct ctl_info info{};
        std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
        if (::ioctl(fd, CTLIOCGINFO, &info) < 0) {
            int err = errno; guard();
            return std::unexpected(DarwinTunFailure{std::error_code{err, std::generic_category()}});
        }
        struct sockaddr_ctl addr{};
        addr.sc_len = sizeof(addr);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = *unit;
        if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            int err = errno; guard();
            return std::unexpected(DarwinTunFailure{std::error_code{err, std::generic_category()}});
        }
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || ::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            int err = errno; guard();
            return std::unexpected(DarwinTunFailure{std::error_code{err, std::generic_category()}});
        }
        char ifname[64]{};
        socklen_t ifname_len = sizeof(ifname);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
            int err = errno; guard();
            return std::unexpected(DarwinTunFailure{std::error_code{err, std::generic_category()}});
        }
        return DarwinTun(fd, std::string(ifname));
    }

    auto DarwinTun::attach(int fd, DarwinTunFdOwnership ownership, bool has_af_header)
        -> std::expected<DarwinTun, DarwinTunFailure> {
        if (fd < 0) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
        int status = ::fcntl(fd, F_GETFL, 0);
        if (status < 0) return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
        if ((status & O_ACCMODE) != O_RDWR)
            return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
        int orig_fd = fd;
        std::optional<int> restore_flags;
        if (!(status & O_NONBLOCK)) {
            if (::fcntl(fd, F_SETFL, status | O_NONBLOCK) < 0)
                return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
            restore_flags = status;
        }
        auto rollback_flags = [&]() noexcept {
            if (restore_flags) (void)::fcntl(orig_fd, F_SETFL, *restore_flags);
        };
        if (ownership == DarwinTunFdOwnership::borrow) {
            fd = ::fcntl(orig_fd, F_DUPFD_CLOEXEC, 0);
            if (fd < 0) {
                int err = errno;
                rollback_flags();
                return std::unexpected(DarwinTunFailure{std::error_code{err, std::generic_category()}});
            }
        } else {
            int fflags = ::fcntl(fd, F_GETFD, 0);
            if (fflags < 0 || ::fcntl(fd, F_SETFD, fflags | FD_CLOEXEC) < 0) {
                int err = errno;
                rollback_flags();
                return std::unexpected(DarwinTunFailure{std::error_code{err, std::generic_category()}});
            }
        }
        char ifname[64]{};
        socklen_t ifname_len = sizeof(ifname);
        if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0 || ifname[0] == '\0')
            return DarwinTun(fd, "utun-ext", has_af_header, restore_flags);
        return DarwinTun(fd, std::string(ifname), has_af_header, restore_flags);
    }

    auto DarwinTun::read_packet(std::span<std::uint8_t> out)
        -> std::expected<std::optional<std::size_t>, DarwinTunFailure> {
        if (fd_ < 0) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
        if (!has_af_header_) {
            ssize_t n = 0;
            do { n = ::read(fd_, out.data(), out.size()); } while (n < 0 && errno == EINTR);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return std::optional<std::size_t>{};
                return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
            }
            if (n == 0) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
            return std::optional<std::size_t>{static_cast<std::size_t>(n)};
        }
        std::uint32_t af = 0;
        struct iovec iov[2]{{&af, sizeof(af)}, {out.data(), out.size()}};
        ssize_t n = 0;
        do { n = ::readv(fd_, iov, 2); } while (n < 0 && errno == EINTR);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return std::optional<std::size_t>{};
            return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
        }
        if (n == 0) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
        if (static_cast<std::size_t>(n) <= sizeof(af)) return std::optional<std::size_t>{};
        return std::optional<std::size_t>{static_cast<std::size_t>(n) - sizeof(af)};
    }

    auto DarwinTun::write_packet(std::span<std::uint8_t const> ip_packet) -> std::expected<void, DarwinTunFailure> {
        if (fd_ < 0) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
        if (ip_packet.empty()) return std::unexpected(DarwinTunFailure{DarwinTunError::invalid_device});
        if (!has_af_header_) {
            ssize_t n = 0;
            do { n = ::write(fd_, ip_packet.data(), ip_packet.size()); } while (n < 0 && errno == EINTR);
            if (n < 0) return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
            if (static_cast<std::size_t>(n) != ip_packet.size())
                return std::unexpected(DarwinTunFailure{std::make_error_code(std::errc::io_error)});
            return {};
        }
        std::uint32_t af = net_u32((ip_packet[0] >> 4) == 6 ? static_cast<std::uint32_t>(AF_INET6)
                                                            : static_cast<std::uint32_t>(AF_INET));
        struct iovec iov[2]{{&af, sizeof(af)}, {const_cast<std::uint8_t*>(ip_packet.data()), ip_packet.size()}};
        ssize_t n = 0;
        do { n = ::writev(fd_, iov, 2); } while (n < 0 && errno == EINTR);
        if (n < 0) return std::unexpected(DarwinTunFailure{std::error_code{errno, std::generic_category()}});
        if (static_cast<std::size_t>(n) != ip_packet.size() + sizeof(af))
            return std::unexpected(DarwinTunFailure{std::make_error_code(std::errc::io_error)});
        return {};
    }

    auto DarwinTun::close() noexcept -> void {
        if (fd_ >= 0) {
            if (restore_flags_) (void)::fcntl(fd_, F_SETFL, *restore_flags_);
            ::close(fd_);
            fd_ = -1;
        }
        restore_flags_.reset();
    }
#else
    auto DarwinTun::open(DarwinTunConfig const&) -> std::expected<DarwinTun, DarwinTunFailure> {
        return std::unexpected(DarwinTunFailure{DarwinTunError::unsupported});
    }
    auto DarwinTun::attach(int, DarwinTunFdOwnership, bool) -> std::expected<DarwinTun, DarwinTunFailure> {
        return std::unexpected(DarwinTunFailure{DarwinTunError::unsupported});
    }
    auto DarwinTun::read_packet(std::span<std::uint8_t>)
        -> std::expected<std::optional<std::size_t>, DarwinTunFailure> {
        return std::unexpected(DarwinTunFailure{DarwinTunError::unsupported});
    }
    auto DarwinTun::write_packet(std::span<std::uint8_t const>) -> std::expected<void, DarwinTunFailure> {
        return std::unexpected(DarwinTunFailure{DarwinTunError::unsupported});
    }
    auto DarwinTun::close() noexcept -> void {}
#endif
}
