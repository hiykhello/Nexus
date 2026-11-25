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
        using FileDescriptor = platform::UniqueFd;

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
            int type=0;
            socklen_t size=sizeof type;
            sockaddr_storage address{};
            socklen_t address_size=sizeof address;
            return ::getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)==0 && type==SOCK_SEQPACKET &&
                ::getpeername(fd,reinterpret_cast<sockaddr*>(&address),&address_size)==0 &&
                address.ss_family==AF_UNIX && address_size==sizeof(sa_family_t);
        }

        auto start_worker(int child_end,pid_t& pid) noexcept -> bool {
            posix_spawn_file_actions_t actions;
            if (::posix_spawn_file_actions_init(&actions)) return false;
            posix_spawnattr_t attributes;
            if (::posix_spawnattr_init(&attributes)) {
                (void)::posix_spawn_file_actions_destroy(&actions);
                return false;
            }
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
    }

    StrictTunOwner::~StrictTunOwner() {(void)stop();}

    auto StrictTunOwner::start(StrictTunRequest const& request) -> std::expected<packet::LinuxTun,std::string> {
        if (pid_>=0) return std::unexpected("TUN network owner already started");
        int descriptors[2];
        if (::socketpair(AF_UNIX,SOCK_SEQPACKET | SOCK_CLOEXEC,0,descriptors))
            return std::unexpected("cannot create TUN network owner channel");
        FileDescriptor local(descriptors[0]),child(descriptors[1]);
        pid_t pid=-1;
        if (!start_worker(child.get(),pid)) return std::unexpected("cannot launch TUN network owner");
        (void)::close(child.release());
        pid_=pid;
        socket_=local.release();
        struct Rollback { StrictTunOwner& owner; bool ok=false; ~Rollback() { if (!ok) (void)owner.stop(); } } rollback{*this};
        auto amount=::send(socket_,&request,sizeof request,MSG_NOSIGNAL);
        if (amount!=sizeof request || !wait_events(socket_,POLLIN,Clock::now()+(request.dns_stub.front() ? 19s : 12s)))
            return std::unexpected("TUN strict-route installation failed or timed out");
        int redirect_error=0;
        FileDescriptor fd(receive_fd(socket_,redirect_error));
        if (redirect_error) return std::unexpected("TUN auto-redirect NETLINK_NETFILTER: "+
            std::error_code(redirect_error,std::generic_category()).message());
        if (fd.get()<0) return std::unexpected("TUN strict-route installation failed");
        auto tun=packet::LinuxTun::attach(fd.get(),packet::TunFdOwnership::adopt);
        if (!tun) return std::unexpected("cannot adopt TUN network owner's device");
        (void)fd.release();
        rollback.ok=true;
        return std::move(*tun);
    }

    auto StrictTunOwner::healthy() const noexcept -> bool {
        if (socket_<0) return false;
        pollfd item{socket_,POLLIN,0};
        auto result=::poll(&item,1,0);
        return result==0 || (result<0 && errno==EINTR);
    }

    auto StrictTunOwner::stop() noexcept -> bool {
        if (socket_>=0) (void)::close(std::exchange(socket_,-1));
        if (pid_<0) return true;
        int status=0;
        pid_t done;
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
        StrictTunRequest request{};
        static_assert(std::is_trivially_copyable_v<StrictTunRequest>);
        if (::recv(channel.get(),&request,sizeof request,MSG_TRUNC)!=sizeof request ||
            request.name.back()!=0 || request.dns_stub.back()!=0 ||
            request.exclude_count>request.excludes.size() || request.include_count>request.includes.size() ||
            std::size_t(request.exclude_count)+request.include_count>packet::max_tun_excludes ||
            (request.redirect.port && request.include_count) ||
            request.network.route_count || !packet::tun_network_detail::validate(request.network)) return 2;
        if (request.redirect.protected_count>request.redirect.protected_destinations.size() ||
            request.redirect.include_uid_count>request.redirect.include_uids.size() ||
            request.redirect.exclude_uid_count>request.redirect.exclude_uids.size() ||
            request.redirect.include_if_count>request.redirect.include_interfaces.size() ||
            request.redirect.exclude_if_count>request.redirect.exclude_interfaces.size()) return 2;
        auto protected_destinations=std::span(request.redirect.protected_destinations).first(request.redirect.protected_count);
        for (auto const& entry:protected_destinations)
            if (!packet::tun_network_detail::valid(entry,true)) return 2;
        auto includes=std::span(request.includes).first(request.include_count);
        for (auto const& entry:includes)
            if (!packet::tun_network_detail::valid(entry,true)) return 2;
        auto tun=packet::LinuxTun::create(request.name.data(),{.multi_queue=request.multi_queue});
        if (!tun) return 2;
        auto token=tun->claim_network();
        if (!token) return 2;
        std::optional<packet::TunNetworkLease<>> network;
        if (!packet::TunNetworkLease<>::emplace_into(network,std::move(*token),request.network)) return 2;
        if (!network->start(Clock::now()+4s)) { (void)network->stop(Clock::now()+3s); return 2; }
        packet::TunDefaultPolicy<> policy;
        auto deadline=Clock::now()+3s;
        auto excludes=std::span(request.excludes).first(request.exclude_count);
        if (!policy.start(*network,request.policy,deadline,deadline+2s,excludes,request.redirect,includes)) {
            (void)policy.stop(Clock::now()+3s);
            (void)network->stop(Clock::now()+3s);
            return 2;
        }
        bool drift=false;
        TunResolvedLease resolver;
        if (request.dns_stub.front()) {
            auto until=Clock::now()+3s;
            auto claimed=start_tun_resolved(*network,request.dns_stub.data(),until,until+2s);
            if (!claimed) {
                (void)policy.stop(Clock::now()+3s);
                (void)network->stop(Clock::now()+3s);
                return claimed.error()==TunResolvedError::rejected && policy.drained() && network->drained() ? 2 : 1;
            }
            resolver=std::move(*claimed);
        }
        platform::nftables::Table firewall;
        if (request.redirect.port) {
            platform::nftables::Redirect options{
                .port=request.redirect.port,.intercept_dns=request.redirect.tcp_dns,
                .exclude_mptcp=request.redirect.exclude_mptcp,.socket_mark=request.policy.mark,
                .include_mark=request.policy.include_mark,.exclude_mark=request.policy.exclude_mark
            };
            for (auto const& addr:std::span(request.network.addresses).first(request.network.address_count)) {
                options.ipv4|=addr.family==4;
                options.ipv6|=addr.family==6;
            }
            auto prefixes=[](std::span<packet::TunAddress const> input) {
                std::vector<platform::nftables::Prefix> list;
                for (auto const& addr:input) list.push_back({addr.family,addr.prefix,addr.bytes});
                return list;
            };
            auto excluded=prefixes(excludes);
            auto protected_list=prefixes(protected_destinations);
            auto local_destinations=prefixes(policy.local_destinations());
            options.excludes=excluded;
            options.protected_destinations=protected_list;
            options.local_destinations=local_destinations;
            options.input_mark=request.redirect.input_mark;
            options.output_mark=request.redirect.output_mark;
            options.reset_mark=request.redirect.reset_mark;
            std::vector<platform::nftables::UidRange> inc_uids, exc_uids;
            for (auto const& u : std::span(request.redirect.include_uids).first(request.redirect.include_uid_count))
                inc_uids.push_back({u.min, u.max});
            for (auto const& u : std::span(request.redirect.exclude_uids).first(request.redirect.exclude_uid_count))
                exc_uids.push_back({u.min, u.max});
            options.include_uids=inc_uids;
            options.exclude_uids=exc_uids;
            options.include_interfaces=std::span(request.redirect.include_interfaces).first(request.redirect.include_if_count);
            options.exclude_interfaces=std::span(request.redirect.exclude_interfaces).first(request.redirect.exclude_if_count);
            if (auto error=firewall.start(options,Clock::now()+2s)) {
                auto detail=error.value();
                (void)::send(channel.get(),&detail,sizeof detail,MSG_NOSIGNAL);
                if (resolver) (void)resolver->stop(Clock::now()+2s);
                (void)policy.stop(Clock::now()+3s);
                (void)network->stop(Clock::now()+3s);
                return policy.drained() && network->drained() ? 2 : 1;
            }
        }
        if (send_fd(channel.get(),tun->native_handle())) {
            while (!wait_events(channel.get(),POLLIN,Clock::now()+100ms)) {
                bool healthy=policy.check().has_value();
                if (healthy && resolver)
                    healthy=resolver->poll(Clock::now(),Clock::now()+200ms);
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
