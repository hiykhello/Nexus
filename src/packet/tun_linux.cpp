module;
#include <cerrno>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
module nexus.packet.tun_linux;
import std;

namespace nexus::packet {
    static_assert(IFNAMSIZ==16);
    LinuxTun::LinuxTun(LinuxTun&& other) noexcept
        : fd_(std::exchange(other.fd_,-1)), name_(std::exchange(other.name_,{})) {}
    auto LinuxTun::operator=(LinuxTun&& other) noexcept -> LinuxTun& {
        if (this!=&other) { close(); fd_=std::exchange(other.fd_,-1); name_=std::exchange(other.name_,{}); }
        return *this;
    }
    LinuxTun::~LinuxTun() { close(); }
    auto LinuxTun::close() noexcept -> void {
        if (fd_>=0) { ::close(fd_); fd_=-1; }
        name_.fill(0);
    }
    auto LinuxTun::name() const noexcept -> std::string_view { return {name_.data(),std::char_traits<char>::length(name_.data())}; }
    auto LinuxTun::create(std::string_view name) -> std::expected<LinuxTun,TunFailure> {
        if (name.size()>=IFNAMSIZ || name.find('\0')!=name.npos || name.find('%')!=name.npos)
            return std::unexpected(TunFailure{TunError::invalid_name});
        int fd=::open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);
        if (fd<0) return std::unexpected(TunFailure{std::error_code{errno,std::generic_category()}});
        ifreq request{};
        std::copy(name.begin(),name.end(),request.ifr_name);
        request.ifr_flags=IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL;
        if (::ioctl(fd,TUNSETIFF,&request)<0) {
            auto error=std::error_code{errno,std::generic_category()}; ::close(fd);
            return std::unexpected(TunFailure{error});
        }
        std::array<char,16> assigned{};
        std::copy_n(request.ifr_name,IFNAMSIZ-1,assigned.begin());
        return LinuxTun(fd,assigned);
    }
}
