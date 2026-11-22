module;
#include <cerrno>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
module packet.tun_linux;
import std;

namespace packet {
    static_assert(IFNAMSIZ==16);
    LinuxTun::LinuxTun(LinuxTun&& other) noexcept
        : fd_(std::exchange(other.fd_,-1)),name_(std::exchange(other.name_,{})),
          network_claimed_(std::exchange(other.network_claimed_,false)),network_claimable_(other.network_claimable_) {
        other.invalidate();
    }
    auto LinuxTun::operator=(LinuxTun&& other) noexcept -> LinuxTun& {
        if (this!=&other) {
            close();
            invalidate();
            fd_=std::exchange(other.fd_,-1);
            name_=std::exchange(other.name_,{});
            network_claimed_=std::exchange(other.network_claimed_,false);
            network_claimable_=other.network_claimable_;
            other.invalidate();
        }
        return *this;
    }
    LinuxTun::~LinuxTun() { close(); }
    auto LinuxTun::close() noexcept -> void {
        if (fd_>=0) { ::close(fd_); fd_=-1; invalidate(); }
        name_.fill(0);
    }
    auto LinuxTun::name() const noexcept -> std::string_view { return {name_.data(),std::char_traits<char>::length(name_.data())}; }
    namespace {
        auto namespace_id(char const* path) -> std::expected<std::uint64_t,TunFailure> {
            std::array<char,64> name{}; auto count=::readlink(path,name.data(),name.size());
            if (count<0) return std::unexpected(TunFailure{std::error_code{errno,std::generic_category()}});
            auto view=std::string_view(name.data(),static_cast<std::size_t>(count));
            if (count==static_cast<std::ptrdiff_t>(name.size()) || !view.starts_with("net:[") || !view.ends_with(']'))
                return std::unexpected(TunFailure{TunError::invalid_device});
            view.remove_prefix(5); view.remove_suffix(1); std::uint64_t value=0;
            auto parsed=std::from_chars(view.data(),view.data()+view.size(),value);
            if (parsed.ec!=std::errc{} || parsed.ptr!=view.data()+view.size() || !value) return std::unexpected(TunFailure{TunError::invalid_device});
            return value;
        }
    }
    auto LinuxTun::inspect() const -> std::expected<TunIdentity,TunFailure> {
        if (fd_<0) return std::unexpected(TunFailure{std::make_error_code(std::errc::bad_file_descriptor)});
        ifreq request{};
        if (::ioctl(fd_,TUNGETIFF,&request)<0) return std::unexpected(TunFailure{std::error_code{errno,std::generic_category()}});
        if ((request.ifr_flags&(IFF_TUN|IFF_TAP|IFF_NO_PI|IFF_PERSIST))!=(IFF_TUN|IFF_NO_PI) ||
            !std::ranges::equal(name_,std::span(request.ifr_name,IFNAMSIZ))) return std::unexpected(TunFailure{TunError::invalid_device});
        int ns=::ioctl(fd_,TUNGETDEVNETNS);
        if (ns<0) return std::unexpected(TunFailure{std::error_code{errno,std::generic_category()}});
        std::array<char,64> path{}; constexpr std::string_view prefix="/proc/self/fd/";
        std::ranges::copy(prefix,path.begin()); auto end=std::to_chars(path.data()+prefix.size(),path.data()+path.size()-1,ns);
        if (end.ec!=std::errc{}) { ::close(ns); return std::unexpected(TunFailure{TunError::invalid_device}); }
        auto original=namespace_id(path.data()); ::close(ns); if (!original) return std::unexpected(original.error());
        auto current=namespace_id("/proc/self/ns/net"); if (!current) return std::unexpected(current.error());
        if (*original!=*current) return std::unexpected(TunFailure{TunError::wrong_namespace});
        return TunIdentity{fd_,*original,name_};
    }
    auto LinuxTun::claim_network() & -> std::expected<NetworkToken,TunFailure> {
        if (network_claimed_) return std::unexpected(TunFailure{TunError::already_claimed});
        if (!network_claimable_ || !generation_ || generation_==std::numeric_limits<std::uint64_t>::max())
            return std::unexpected(TunFailure{TunError::invalid_device});
        auto checked=inspect(); if (!checked) return std::unexpected(checked.error());
        network_claimed_=true; return NetworkToken(*this,*checked);
    }
    auto LinuxTun::NetworkToken::inspect() const -> std::expected<TunIdentity,TunFailure> {
        if (native_handle()<0) return std::unexpected(TunFailure{std::make_error_code(std::errc::bad_file_descriptor)});
        auto current=owner_->inspect(); if (!current) return current;
        if (current->namespace_id!=identity_.namespace_id || current->name!=identity_.name)
            return std::unexpected(TunFailure{TunError::invalid_device});
        return current;
    }
    auto LinuxTun::create(std::string_view name) -> std::expected<LinuxTun,TunFailure> {
        return create(name, TunCreateOptions{});
    }
    auto LinuxTun::create(std::string_view name, TunCreateOptions options) -> std::expected<LinuxTun,TunFailure> {
        if (name.size()>=IFNAMSIZ || name.find('\0')!=name.npos || name.find('%')!=name.npos)
            return std::unexpected(TunFailure{TunError::invalid_name});
        int fd=::open("/dev/net/tun",O_RDWR|O_NONBLOCK|O_CLOEXEC);
        if (fd<0) return std::unexpected(TunFailure{std::error_code{errno,std::generic_category()}});
        ifreq request{};
        std::copy(name.begin(),name.end(),request.ifr_name);
        request.ifr_flags=IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL;
        if (options.vnet_hdr) request.ifr_flags|=IFF_VNET_HDR;
        if (options.multi_queue) request.ifr_flags|=IFF_MULTI_QUEUE;
        if (::ioctl(fd,TUNSETIFF,&request)<0) {
            auto error=std::error_code{errno,std::generic_category()}; ::close(fd);
            return std::unexpected(TunFailure{error});
        }
        if (options.vnet_hdr) {
            int hdr_sz = 10; // sizeof(virtio_net_hdr)
            (void)::ioctl(fd, TUNSETVNETHDRSZ, &hdr_sz);
            unsigned int offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
            (void)::ioctl(fd, TUNSETOFFLOAD, offload);
        }
        std::array<char,16> assigned{};
        std::copy_n(request.ifr_name,IFNAMSIZ-1,assigned.begin());
        return LinuxTun(fd,assigned);
    }

    auto LinuxTun::attach(int fd,TunFdOwnership ownership) -> std::expected<LinuxTun,TunFailure> {
        auto system_error=[] {return TunFailure{std::error_code(errno,std::generic_category())};};
        int status=::fcntl(fd,F_GETFL);
        if (status<0) return std::unexpected(system_error());
        if ((status&(O_ACCMODE|O_NONBLOCK))!=(O_RDWR|O_NONBLOCK))
            return std::unexpected(TunFailure{TunError::invalid_device});
        ifreq request{};
        if (::ioctl(fd,TUNGETIFF,&request)<0) return std::unexpected(system_error());
        if ((request.ifr_flags&(IFF_TUN|IFF_TAP|IFF_NO_PI|IFF_VNET_HDR))!=(IFF_TUN|IFF_NO_PI))
            return std::unexpected(TunFailure{TunError::invalid_device});
        if (ownership==TunFdOwnership::borrow) {
            fd=::fcntl(fd,F_DUPFD_CLOEXEC,0);
            if (fd<0) return std::unexpected(system_error());
        } else {
            int flags=::fcntl(fd,F_GETFD);
            if (flags<0 || ::fcntl(fd,F_SETFD,flags|FD_CLOEXEC)<0) return std::unexpected(system_error());
        }
        std::array<char,16> assigned{};
        std::copy_n(request.ifr_name,IFNAMSIZ-1,assigned.begin());
        return LinuxTun(fd,assigned,false);
    }
}
