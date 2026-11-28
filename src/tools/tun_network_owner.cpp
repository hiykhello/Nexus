module;
#include <cerrno>
#include <csignal>
#include <cstring>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
module cli.tun_network_owner;
import std;
import packet.tun_linux;
import packet.tun_network;
import packet.tun_network_types;
import packet.tun_default_policy;
import cli.tun_resolved;
import platform.nftables;
import platform.unique_fd;

namespace cli::tun_enabled {
    namespace {
        using Clock=std::chrono::steady_clock;
        using namespace std::chrono_literals;
        constexpr int child_socket=3;
        constexpr std::size_t kAddrChunk=1024;
        using FileDescriptor = platform::UniqueFd;

        struct RouteUpdateHeader {
            char tag='U';
            std::uint32_t exclude_count=0, include_count=0;
        };

        auto wait_events(int fd,short wanted,Clock::time_point deadline) noexcept -> short {
            pollfd item{fd,wanted,0};
            while (Clock::now()<deadline) {
                auto remaining=std::chrono::ceil<std::chrono::milliseconds>(deadline-Clock::now());
                auto ready=::poll(&item,1,static_cast<int>(std::max(0ms,remaining).count()));
                if (ready>=0) return item.revents;
                if (errno!=EINTR) return POLLERR;
            }
            return 0;
        }

        auto send_addrs(int channel,std::span<packet::TunAddress const> list) noexcept -> bool {
            for (std::size_t off=0; off<list.size(); off+=kAddrChunk) {
                auto n=std::min(kAddrChunk,list.size()-off);
                auto bytes=n*sizeof(packet::TunAddress);
                if (::send(channel,list.data()+off,bytes,MSG_NOSIGNAL)!=static_cast<ssize_t>(bytes)) return false;
            }
            return true;
        }

        auto recv_addrs(int channel,std::uint32_t count,std::vector<packet::TunAddress>& out,Clock::time_point deadline) -> bool {
            out.clear();
            if (count>packet::max_tun_excludes) return false;
            out.resize(count);
            std::size_t got=0;
            while (got<count) {
                if (!wait_events(channel,POLLIN,deadline)) return false;
                auto want=std::min(kAddrChunk,count-got);
                auto bytes=want*sizeof(packet::TunAddress);
                auto n=::recv(channel,out.data()+got,bytes,MSG_TRUNC);
                if (n!=static_cast<ssize_t>(bytes)) return false;
                got+=want;
            }
            return true;
        }

        auto send_fd(int channel,int fd) noexcept -> bool {
            char value='T';
            iovec data{&value,sizeof value};
            alignas(cmsghdr) std::array<char,CMSG_SPACE(sizeof fd)> control{};
            msghdr message{};
            message.msg_iov=&data;message.msg_iovlen=1;
            message.msg_control=control.data();message.msg_controllen=control.size();
            auto* header=CMSG_FIRSTHDR(&message);
            header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;header->cmsg_len=CMSG_LEN(sizeof fd);
            std::memcpy(CMSG_DATA(header),&fd,sizeof fd);
            return ::sendmsg(channel,&message,MSG_NOSIGNAL)==1;
        }

        auto receive_fd(int channel,int& redirect_error) noexcept -> int {
            std::array<char,sizeof(int)> value{};
            iovec data{value.data(),value.size()};
            alignas(cmsghdr) std::array<char,CMSG_SPACE(sizeof(int))> control{};
            msghdr message{};
            message.msg_iov=&data;message.msg_iovlen=1;
            message.msg_control=control.data();message.msg_controllen=control.size();
            auto size=::recvmsg(channel,&message,MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
            if (size==sizeof(int) && !CMSG_FIRSTHDR(&message) && !(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))) {
                std::memcpy(&redirect_error,value.data(),sizeof redirect_error);
                return -1;
            }
            if (size<=0) return -1;
            auto* header=CMSG_FIRSTHDR(&message);
            int fd=-1;
            if (header && header->cmsg_level==SOL_SOCKET && header->cmsg_type==SCM_RIGHTS &&
                header->cmsg_len>=CMSG_LEN(sizeof fd)) {
                std::memcpy(&fd,CMSG_DATA(header),sizeof fd);
                if (header->cmsg_len>=CMSG_LEN(2*sizeof fd)) {
                    int extra=-1;
                    std::memcpy(&extra,CMSG_DATA(header)+sizeof fd,sizeof extra);
                    if (extra>=0) (void)::close(extra);
                }
            }
            if (size!=1 || value[0]!='T' || (message.msg_flags&(MSG_CTRUNC|MSG_TRUNC)) ||
                !header || header->cmsg_len!=CMSG_LEN(sizeof fd)) {
                if (fd>=0) (void)::close(fd);
                return -1;
            }
            return fd;
        }

        auto channel_is_private(int fd) noexcept -> bool {
            int type=0; socklen_t size=sizeof type;
            sockaddr_storage address{}; socklen_t address_size=sizeof address;
            return ::getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)==0 && type==SOCK_SEQPACKET &&
                ::getpeername(fd,reinterpret_cast<sockaddr*>(&address),&address_size)==0 &&
                address.ss_family==AF_UNIX && address_size==sizeof(sa_family_t);
        }

        auto start_worker(int child_end,pid_t& pid) noexcept -> bool {
            posix_spawn_file_actions_t actions;
            if (::posix_spawn_file_actions_init(&actions)) return false;
            posix_spawnattr_t attributes;
            if (::posix_spawnattr_init(&attributes)) { (void)::posix_spawn_file_actions_destroy(&actions); return false; }
            char executable[]="/proc/self/exe";
            char action[]="--internal-tun-network-owner";
            char* argv[]{executable,action,nullptr};
            bool started=::posix_spawn_file_actions_adddup2(&actions,child_end,child_socket)==0 &&
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
                ::posix_spawn_file_actions_addclosefrom_np(&actions,child_socket+1)==0 &&
#endif
                ::posix_spawnattr_setpgroup(&attributes,0)==0 &&
                ::posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETPGROUP)==0 &&
                ::posix_spawn(&pid,executable,&actions,&attributes,argv,environ)==0;
            (void)::posix_spawnattr_destroy(&attributes);
            (void)::posix_spawn_file_actions_destroy(&actions);
            return started;
        }

        struct NftStorage {
            std::vector<platform::nftables::Prefix> excluded, included, protected_list, local_destinations;
            std::vector<platform::nftables::UidRange> inc_uids, exc_uids;
            platform::nftables::Redirect options{};
        };

        auto build_nft_redirect(StrictTunHeader const& hdr, std::span<packet::TunAddress const> excludes,
            std::span<packet::TunAddress const> includes, std::span<packet::TunAddress const> local_dests) -> NftStorage {
            NftStorage st;
            auto to_pfx=[](std::span<packet::TunAddress const> in) {
                std::vector<platform::nftables::Prefix> out;
                out.reserve(in.size());
                for (auto const& a : in) out.push_back({a.family,a.prefix,a.bytes});
                return out;
            };
            st.excluded=to_pfx(excludes);
            st.included=to_pfx(includes);
            st.protected_list=to_pfx(std::span(hdr.redirect.protected_destinations).first(hdr.redirect.protected_count));
            st.local_destinations=to_pfx(local_dests);
            for (auto const& u : std::span(hdr.redirect.include_uids).first(hdr.redirect.include_uid_count))
                st.inc_uids.push_back({u.min,u.max});
            for (auto const& u : std::span(hdr.redirect.exclude_uids).first(hdr.redirect.exclude_uid_count))
                st.exc_uids.push_back({u.min,u.max});
            auto& o=st.options;
            o.port=hdr.redirect.port; o.intercept_dns=hdr.redirect.tcp_dns; o.intercept_udp_dns=hdr.redirect.udp_dns;
            o.exclude_mptcp=hdr.redirect.exclude_mptcp; o.socket_mark=hdr.policy.mark;
            o.include_mark=hdr.policy.include_mark; o.exclude_mark=hdr.policy.exclude_mark;
            for (auto const& addr : std::span(hdr.network.addresses).first(hdr.network.address_count)) {
                o.ipv4|=addr.family==4; o.ipv6|=addr.family==6;
            }
            o.excludes=st.excluded; o.includes=st.included;
            o.protected_destinations=st.protected_list; o.local_destinations=st.local_destinations;
            o.input_mark=hdr.redirect.input_mark; o.output_mark=hdr.redirect.output_mark;
            o.reset_mark=hdr.redirect.reset_mark; o.tproxy_mark=hdr.redirect.tproxy_mark;
            o.tproxy_port=hdr.redirect.tproxy_port ? hdr.redirect.tproxy_port : hdr.redirect.port;
            o.include_uids=st.inc_uids; o.exclude_uids=st.exc_uids;
            o.include_interfaces=std::span(hdr.redirect.include_interfaces).first(hdr.redirect.include_if_count);
            o.exclude_interfaces=std::span(hdr.redirect.exclude_interfaces).first(hdr.redirect.exclude_if_count);
            o.include_macs=std::span(hdr.redirect.include_macs).first(hdr.redirect.include_mac_count);
            o.exclude_macs=std::span(hdr.redirect.exclude_macs).first(hdr.redirect.exclude_mac_count);
            return st;
        }
    }

    StrictTunOwner::~StrictTunOwner() {(void)stop();}

    auto StrictTunOwner::start(StrictTunRequest const& request) -> std::expected<packet::LinuxTun,std::string> {
        std::lock_guard lock(io_mutex_);
        if (pid_>=0) return std::unexpected("TUN network owner already started");
        if (request.excludes.size()>packet::max_tun_excludes || request.includes.size()>packet::max_tun_excludes)
            return std::unexpected("TUN route limit exceeded");
        int descriptors[2];
        if (::socketpair(AF_UNIX,SOCK_SEQPACKET | SOCK_CLOEXEC,0,descriptors))
            return std::unexpected("cannot create TUN network owner channel");
        FileDescriptor local(descriptors[0]),child(descriptors[1]);
        pid_t pid=-1;
        if (!start_worker(child.get(),pid)) return std::unexpected("cannot launch TUN network owner");
        (void)::close(child.release());
        pid_=pid;
        socket_=local.release();
        auto cleanup_fail=[&](std::string msg) -> std::expected<packet::LinuxTun,std::string> {
            if (socket_>=0) (void)::close(std::exchange(socket_,-1));
            if (pid_>=0) { int s=0; ::kill(pid_,SIGKILL); while(::waitpid(pid_,&s,0)<0 && errno==EINTR){} pid_=-1; }
            return std::unexpected(std::move(msg));
        };
        StrictTunHeader hdr{
            .name=request.name,.dns_stub=request.dns_stub,.network=request.network,.policy=request.policy,
            .exclude_count=static_cast<std::uint32_t>(request.excludes.size()),
            .include_count=static_cast<std::uint32_t>(request.includes.size()),
            .multi_queue=request.multi_queue,.vnet_hdr=request.vnet_hdr,.redirect=request.redirect
        };
        static_assert(std::is_trivially_copyable_v<StrictTunHeader>);
        if (::send(socket_,&hdr,sizeof hdr,MSG_NOSIGNAL)!=sizeof hdr ||
            !send_addrs(socket_,request.excludes) || !send_addrs(socket_,request.includes) ||
            !wait_events(socket_,POLLIN,Clock::now()+(request.dns_stub.front() ? 19s : 12s)))
            return cleanup_fail("TUN strict-route installation failed or timed out");
        int redirect_error=0;
        FileDescriptor fd(receive_fd(socket_,redirect_error));
        if (redirect_error) return cleanup_fail("TUN auto-redirect NETLINK_NETFILTER: "+
            std::error_code(redirect_error,std::generic_category()).message());
        if (fd.get()<0) return cleanup_fail("TUN strict-route installation failed");
        auto tun=packet::LinuxTun::attach(fd.get(),packet::TunFdOwnership::adopt);
        if (!tun) return cleanup_fail("cannot adopt TUN network owner's device");
        (void)fd.release();
        return std::move(*tun);
    }

    auto StrictTunOwner::update_routes(std::span<packet::TunAddress const> excludes,
        std::span<packet::TunAddress const> includes) -> std::expected<void,std::string> {
        std::lock_guard lock(io_mutex_);
        if (socket_<0 || pid_<0) return std::unexpected("TUN network owner not running");
        if (excludes.size()>packet::max_tun_excludes || includes.size()>packet::max_tun_excludes)
            return std::unexpected("TUN route limit exceeded");
        RouteUpdateHeader hdr{'U',static_cast<std::uint32_t>(excludes.size()),static_cast<std::uint32_t>(includes.size())};
        if (::send(socket_,&hdr,sizeof hdr,MSG_NOSIGNAL)!=sizeof hdr ||
            !send_addrs(socket_,excludes) || !send_addrs(socket_,includes))
            return std::unexpected("failed sending TUN route-set update");
        if (!wait_events(socket_,POLLIN,Clock::now()+5s))
            return std::unexpected("TUN route-set update timed out");
        std::uint8_t status=1;
        if (::recv(socket_,&status,sizeof status,MSG_TRUNC)!=sizeof status || status!=0)
            return std::unexpected("TUN live route-set update rejected by kernel owner");
        return {};
    }

    auto StrictTunOwner::healthy() const noexcept -> bool {
        std::unique_lock lock(io_mutex_, std::try_to_lock);
        if (!lock.owns_lock()) return true; // route update in progress
        if (socket_<0) return false;
        pollfd item{socket_,POLLIN,0};
        auto result=::poll(&item,1,0);
        return result==0 || (result<0 && errno==EINTR);
    }

    auto StrictTunOwner::stop() noexcept -> bool {
        std::lock_guard lock(io_mutex_);
        if (socket_>=0) (void)::close(std::exchange(socket_,-1));
        if (pid_<0) return true;
        int status=0; pid_t done;
        auto deadline=Clock::now()+9s;
        do {
            done=::waitpid(pid_,&status,WNOHANG);
            if (done==pid_) {
                pid_=-1;
                return WIFEXITED(status) && (WEXITSTATUS(status)==0 || WEXITSTATUS(status)==2);
            }
            if (done<0 && errno!=EINTR) {pid_=-1;return false;}
            (void)::poll(nullptr,0,10);
        } while (Clock::now()<deadline);
        (void)::kill(pid_,SIGKILL);
        while (::waitpid(pid_,&status,0)<0 && errno==EINTR) {}
        pid_=-1;
        return false;
    }

    auto run_strict_tun_owner() -> int {
        FileDescriptor channel(child_socket);
        if (!channel_is_private(channel.get()) || !wait_events(channel.get(),POLLIN,Clock::now()+2s)) return 2;
        StrictTunHeader hdr{};
        static_assert(std::is_trivially_copyable_v<StrictTunHeader>);
        if (::recv(channel.get(),&hdr,sizeof hdr,MSG_TRUNC)!=sizeof hdr ||
            hdr.name.back()!=0 || hdr.dns_stub.back()!=0 ||
            hdr.exclude_count>packet::max_tun_excludes || hdr.include_count>packet::max_tun_excludes ||
            hdr.network.route_count || !packet::tun_network_detail::validate(hdr.network)) return 2;
        if (hdr.redirect.protected_count>hdr.redirect.protected_destinations.size() ||
            hdr.redirect.include_uid_count>hdr.redirect.include_uids.size() ||
            hdr.redirect.exclude_uid_count>hdr.redirect.exclude_uids.size() ||
            hdr.redirect.include_if_count>hdr.redirect.include_interfaces.size() ||
            hdr.redirect.exclude_if_count>hdr.redirect.exclude_interfaces.size() ||
            hdr.redirect.include_mac_count>hdr.redirect.include_macs.size() ||
            hdr.redirect.exclude_mac_count>hdr.redirect.exclude_macs.size()) return 2;
        std::vector<packet::TunAddress> excludes, includes;
        auto recv_deadline=Clock::now()+4s;
        if (!recv_addrs(channel.get(),hdr.exclude_count,excludes,recv_deadline) ||
            !recv_addrs(channel.get(),hdr.include_count,includes,recv_deadline)) return 2;
        for (auto const& e : std::span(hdr.redirect.protected_destinations).first(hdr.redirect.protected_count))
            if (!packet::tun_network_detail::valid(e,true)) return 2;
        for (auto const& e : includes) if (!packet::tun_policy_detail::valid_policy_prefix(e,true)) return 2;
        auto tun=packet::LinuxTun::create(hdr.name.data(),{.vnet_hdr=hdr.vnet_hdr,.multi_queue=hdr.multi_queue});
        if (!tun) return 2;
        auto token=tun->claim_network();
        if (!token) return 2;
        std::optional<packet::TunNetworkLease<>> network;
        if (!packet::TunNetworkLease<>::emplace_into(network,std::move(*token),hdr.network)) return 2;
        if (!network->start(Clock::now()+4s)) { (void)network->stop(Clock::now()+3s); return 2; }
        packet::TunDefaultPolicy<> policy;
        auto deadline=Clock::now()+3s;
        if (!policy.start(*network,hdr.policy,deadline,deadline+2s,excludes,hdr.redirect,includes)) {
            (void)policy.stop(Clock::now()+3s); (void)network->stop(Clock::now()+3s); return 2;
        }
        bool drift=false;
        TunResolvedLease resolver;
        if (hdr.dns_stub.front()) {
            auto until=Clock::now()+3s;
            auto claimed=start_tun_resolved(*network,hdr.dns_stub.data(),until,until+2s);
            if (!claimed) {
                (void)policy.stop(Clock::now()+3s); (void)network->stop(Clock::now()+3s);
                return claimed.error()==TunResolvedError::rejected && policy.drained() && network->drained() ? 2 : 1;
            }
            resolver=std::move(*claimed);
        }
        platform::nftables::Table firewall;
        if (hdr.redirect.port) {
            auto st=build_nft_redirect(hdr,excludes,includes,policy.local_destinations());
            if (auto error=firewall.start(st.options,Clock::now()+2s)) {
                auto detail=error.value();
                (void)::send(channel.get(),&detail,sizeof detail,MSG_NOSIGNAL);
                if (resolver) (void)resolver->stop(Clock::now()+2s);
                (void)policy.stop(Clock::now()+3s); (void)network->stop(Clock::now()+3s);
                return policy.drained() && network->drained() ? 2 : 1;
            }
        }
        if (send_fd(channel.get(),tun->native_handle())) {
            for (;;) {
                auto ev=wait_events(channel.get(),POLLIN,Clock::now()+100ms);
                if (ev) {
                    RouteUpdateHeader upd{};
                    auto n=::recv(channel.get(),&upd,sizeof upd,MSG_DONTWAIT|MSG_TRUNC);
                    if (n==sizeof upd && upd.tag=='U') {
                        std::vector<packet::TunAddress> next_exc, next_inc;
                        std::uint8_t rc=1;
                        if (recv_addrs(channel.get(),upd.exclude_count,next_exc,Clock::now()+3s) &&
                            recv_addrs(channel.get(),upd.include_count,next_inc,Clock::now()+3s)) {
                            bool ok=policy.update_routes(next_exc,next_inc,Clock::now()+3s).has_value();
                            if (ok && hdr.redirect.port) {
                                auto st=build_nft_redirect(hdr,next_exc,next_inc,policy.local_destinations());
                                ok=!firewall.replace(st.options,Clock::now()+2s);
                            }
                            if (ok) { excludes=std::move(next_exc); includes=std::move(next_inc); rc=0; }
                        }
                        (void)::send(channel.get(),&rc,sizeof rc,MSG_NOSIGNAL);
                        continue;
                    }
                    break;
                }
                bool healthy=policy.check().has_value();
                if (healthy && resolver) healthy=resolver->poll(Clock::now(),Clock::now()+200ms);
                if (!healthy) {
                    drift=true;
                    (void)::shutdown(channel.get(),SHUT_WR);
                    (void)wait_events(channel.get(),POLLIN,Clock::now()+2s);
                    break;
                }
            }
        }
        auto firewall_error=firewall.stop(Clock::now()+2s);
        auto dns_clean=!resolver || resolver->stop(Clock::now()+2s);
        (void)policy.stop(Clock::now()+3s);
        (void)network->stop(Clock::now()+3s);
        if (firewall_error || !dns_clean || !policy.drained() || !network->drained()) return 1;
        return drift ? 2 : 0;
    }
}
