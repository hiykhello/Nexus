import std;
import platform.netlink_abi;
import platform.netlink_socket;
import platform.ipv4_reverse_path;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network_view;
import packet.tun_network;
import packet.tun_default_policy;
import test.lease_support;
namespace {
    namespace a = ::platform::netlink_abi;
    namespace n = ::platform::netlink;
    namespace r = ::platform::routing::reverse_path_detail;
    namespace p = ::packet;
    namespace t=test::lease;
    bool enabled=false,used=false;
    std::string_view effect;
    unsigned target=0,open_read=0,open_write=0,reads=0,writes=0;
    std::array<bool,1024> scalar_fd{};
    auto reject(std::string_view phase,unsigned ordinal) noexcept -> bool {
        if(!enabled || used || phase!=effect || ordinal!=target)return false;
        used=true;*a::__errno_location()=std::to_underlying(std::errc::permission_denied);return true;
    }
}
extern "C" {
    decltype(a::open) __real_open;
    decltype(a::read) __real_read;
    decltype(a::write) __real_write;
    auto __wrap_open(char const* path,int flags,...) -> int {
        auto text=std::string_view(path);bool scalar=text.starts_with("/proc/sys/net/ipv4/conf/")&&text.ends_with("/rp_filter");
        if(enabled&&scalar) {
            bool writing=flags&a::O_WRONLY;
            if(reject(writing?"open-write":"open-read",writing?++open_write:++open_read))return -1;
        }
        auto fd=__real_open(path,flags);if(fd>=0&&std::size_t(fd)<scalar_fd.size())scalar_fd[fd]=scalar;return fd;
    }
    auto __wrap_read(int fd,void* buffer,std::size_t size) -> std::ptrdiff_t {
        if(enabled&&fd>=0&&std::size_t(fd)<scalar_fd.size()&&scalar_fd[fd]) {
            ++reads;if(reject("read",reads))return -1;
            if(!used&&effect=="short-read"&&reads==target){used=true;auto actual=__real_read(fd,buffer,size);return actual>1?1:actual;}
        }
        return __real_read(fd,buffer,size);
    }
    auto __wrap_write(int fd,void const* buffer,std::size_t size) -> std::ptrdiff_t {
        if(enabled&&fd>=0&&std::size_t(fd)<scalar_fd.size()&&scalar_fd[fd]) {
            ++writes;if(reject("write",writes))return -1;
            if(!used&&effect=="short-write"&&writes==target){used=true;auto actual=__real_write(fd,buffer,size);return actual>1?1:actual;}
        }
        return __real_write(fd,buffer,size);
    }
}
auto main(int argc,char**argv)->int {
    try {
        t::isolation(argc,argv);t::require(argc==5);effect=argv[3];target=t::number(argv[4]);
        n::Socket<> control;t::require(control.open().has_value());
        auto physical=p::tun_network_detail::View(control,0,t::deadline()).link("nx-phys");t::require(physical&&*physical);
        r::Entry scalar{.index=(**physical).index,.name=(**physical).name};
        auto original=r::access(scalar);t::require(original&&*original==1);
        auto options=t::options();options.route_count=0;
        auto device=p::LinuxTun::create("nx-rpf");t::require(device.has_value());
        auto lease=p::TunNetworkLease<>::create(*device,options);t::require(lease&&lease->start(t::deadline()));
        p::TunDefaultPolicy<> policy;enabled=true;
        auto started=policy.start(*lease,{},t::deadline(),t::deadline());
        auto start_reads=reads,start_writes=writes,start_open_read=open_read,start_open_write=open_write;
        auto report=policy.stop(t::deadline());enabled=false;
        t::require(used||effect=="none");
        auto remaining=r::access(scalar);t::require(remaining.has_value());
        bool restoration_fault=report.uncertain!=0;
        if(restoration_fault) {
            t::require(started.has_value()&&(*remaining==2 || *remaining==*original));
            // The reported restore failure is observable; fixture cleanup is
            // separate and only touches its explicitly owned namespace.
            if(*remaining!=*original)t::require(r::access(scalar,*original).has_value());
        } else t::require(*remaining==*original&&!report.settings_preserved&&policy.drained());
        p::TunDefaultPolicy<> recovered;t::require(recovered.start(*lease,{},t::deadline(),t::deadline()).has_value());
        auto fresh=recovered.stop(t::deadline());auto final=r::access(scalar);t::require(!fresh.uncertain&&!fresh.settings_preserved&&recovered.drained()&&final&&*final==*original);
        auto cleanup=lease->stop(t::deadline());t::require(!cleanup.total&&lease->drained());
        std::println("RPF scalar fault={} target={} startup_success={} startup open-read={} open-write={} read={} write={} total open-read={} open-write={} read={} write={} restoration_reported={} fresh owner restored original",effect,target,started.has_value(),start_open_read,start_open_write,start_reads,start_writes,open_read,open_write,reads,writes,restoration_fault);
    }catch(int code){enabled=false;return code;}
}
