module;
#include <cerrno>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/tcp_socket.hpp>

module relay;
import std;
import containers.inplace_vector;
import platform.ip_address;
import platform.unique_fd;
import rules;

namespace relay {
    namespace {
        using Fd = platform::UniqueFd;

        struct SocketAddress {
            std::array<std::uint8_t,16> bytes{};
            std::uint8_t family;
            auto operator==(SocketAddress const&) const noexcept -> bool=default;
        };

        auto normalize(SocketAddress address) noexcept -> SocketAddress {
            constexpr std::array<std::uint8_t,12> mapped{0,0,0,0,0,0,0,0,0,0,255,255};
            if (address.family!=AF_INET6 || !std::equal(mapped.begin(),mapped.end(),address.bytes.begin()))
                return address;
            SocketAddress result{{},AF_INET};
            std::copy_n(address.bytes.begin()+12,4,result.bytes.begin());
            return result;
        }

        auto loopback(io::endpoint endpoint) noexcept -> std::optional<SocketAddress> {
            if (!endpoint.port()) return {};
            auto address=endpoint.address();
            SocketAddress value{{},AF_INET};
            if (address.is_v4()) {
                auto bytes=address.to_v4().to_bytes();
                std::ranges::copy(bytes,value.bytes.begin());
            } else {
                value=normalize({address.to_v6().to_bytes(),AF_INET6});
            }
            constexpr SocketAddress v6_loopback{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},AF_INET6};
            if (value.family==AF_INET ? value.bytes[0]==127 : value==v6_loopback) return value;
            return {};
        }

        auto response_address(std::uint8_t family,__be32 const (&address)[4]) noexcept -> SocketAddress {
            SocketAddress result{{},family};
            std::memcpy(result.bytes.data(),address,family==AF_INET ? 4 : 16);
            return normalize(result);
        }

        auto read_overflow_uid() noexcept -> std::optional<std::uint32_t> {
            int raw_fd = -1;
            for (int tries = 0; tries < 16; ++tries) {
                raw_fd = ::open("/proc/sys/kernel/overflowuid", O_RDONLY | O_CLOEXEC);
                if (raw_fd >= 0 || errno != EINTR) break;
            }
            Fd file{raw_fd};
            if (file.get() < 0) return {};
            std::array<char, 16> bytes;
            ssize_t size = -1;
            for (int tries = 0; tries < 16; ++tries) {
                size = ::read(file.get(), bytes.data(), bytes.size());
                if (size >= 0 || errno != EINTR) break;
            }
            if (size <= 0 || static_cast<std::size_t>(size) == bytes.size()) return {};
            std::string_view text(bytes.data(), static_cast<std::size_t>(size));
            if (text.ends_with('\n')) text.remove_suffix(1);
            return rules::parse_source_uid(text);
        }

        auto cached_user_for_uid(uid_t uid) -> std::string {
            using Clock = std::chrono::steady_clock;
            struct Entry {
                uid_t uid = 0;
                std::string name;
                Clock::time_point expires{};
                bool valid = false;
            };
            static std::mutex mu;
            static std::array<Entry, 64> cache{};
            static std::size_t next_slot = 0;
            auto now = Clock::now();
            {
                std::lock_guard lock(mu);
                for (auto const& e : cache)
                    if (e.valid && e.uid == uid && now < e.expires) return e.name;
            }
            passwd pw{};
            passwd* pw_ptr = nullptr;
            std::array<char, 1024> pw_buf{};
            int rc = EINTR;
            for (int tries = 0; tries < 8 && rc == EINTR; ++tries)
                rc = ::getpwuid_r(uid, &pw, pw_buf.data(), pw_buf.size(), &pw_ptr);
            std::string name;
            if (rc == 0 && pw_ptr && pw.pw_name) name.assign(pw.pw_name);
            {
                std::lock_guard lock(mu);
                cache[next_slot++ % cache.size()] = Entry{uid, name, now + std::chrono::seconds(30), true};
            }
            return name;
        }
    }

    auto local_process_details(std::uint32_t inode, std::uint32_t uid,
        std::optional<std::uint32_t>& gid_out, std::string& package_out,
        containers::inplace_vector<std::string, 8>& paths_out) -> void;

    struct SocketOwner {
        std::uint32_t uid, inode;
        std::array<std::uint32_t,2> cookie;
        auto operator==(SocketOwner const&) const -> bool = default;
    };

    static auto local_socket_owner(io::endpoint peer,io::endpoint local) noexcept -> std::optional<SocketOwner> {
        auto source=loopback(peer),destination=loopback(local);
        if (!source || !destination || source->family!=destination->family) return {};
        static const auto overflow_uid=read_overflow_uid();
        if (!overflow_uid) return {};

        Fd netlink{::socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,NETLINK_SOCK_DIAG)};
        if (netlink.get()<0) return {};
        struct Request {
            nlmsghdr header;
            inet_diag_req_v2 body;
        } request{};
        request.header.nlmsg_len=sizeof(request);
        request.header.nlmsg_type=SOCK_DIAG_BY_FAMILY;
        request.header.nlmsg_flags=NLM_F_REQUEST;
        request.header.nlmsg_seq=1;
        request.body.sdiag_family=source->family;
        request.body.sdiag_protocol=IPPROTO_TCP;
        request.body.idiag_states=1U<<TCP_ESTABLISHED;
        auto& tuple=request.body.id;
        tuple.idiag_sport=platform::host_to_net16(peer.port());
        tuple.idiag_dport=platform::host_to_net16(local.port());
        tuple.idiag_cookie[0]=tuple.idiag_cookie[1]=INET_DIAG_NOCOOKIE;
        std::memcpy(tuple.idiag_src,source->bytes.data(),source->bytes.size());
        std::memcpy(tuple.idiag_dst,destination->bytes.data(),destination->bytes.size());
        sockaddr_nl kernel{.nl_family=AF_NETLINK};
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(15);
        ssize_t sent = -1;
        do {
            sent = ::sendto(netlink.get(),&request,sizeof(request),0,reinterpret_cast<sockaddr*>(&kernel),sizeof(kernel));
        } while (sent < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline);
        if (sent != static_cast<ssize_t>(sizeof(request))) return {};

        std::array<std::byte, 1024> rx{};
        sockaddr_nl sender{};
        iovec data{rx.data(), rx.size()};
        msghdr message{.msg_name=&sender,.msg_namelen=sizeof(sender),.msg_iov=&data,.msg_iovlen=1};
        ssize_t size = -1;
        for (;;) {
            size = ::recvmsg(netlink.get(), &message, 0);
            if (size >= 0) break;
            if (errno == EINTR && std::chrono::steady_clock::now() < deadline) continue;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && std::chrono::steady_clock::now() < deadline) {
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
                pollfd pfd{netlink.get(), POLLIN, 0};
                if (::poll(&pfd, 1, static_cast<int>(std::clamp<long long>(rem, 1, 15))) > 0) continue;
            }
            return {};
        }
        if (size < static_cast<ssize_t>(NLMSG_LENGTH(sizeof(inet_diag_msg))) ||
            (message.msg_flags & MSG_TRUNC) != 0 || message.msg_namelen != sizeof(sender) ||
            sender.nl_family != AF_NETLINK || sender.nl_pid || sender.nl_groups)
            return {};
        nlmsghdr nlh{};
        std::memcpy(&nlh, rx.data(), sizeof(nlh));
        if (nlh.nlmsg_seq != 1 || nlh.nlmsg_type != SOCK_DIAG_BY_FAMILY ||
            nlh.nlmsg_len < NLMSG_LENGTH(sizeof(inet_diag_msg)) ||
            nlh.nlmsg_len > static_cast<std::size_t>(size))
            return {};
        inet_diag_msg owner{};
        std::memcpy(&owner, rx.data() + NLMSG_HDRLEN, sizeof(owner));
        if ((owner.idiag_family!=AF_INET && owner.idiag_family!=AF_INET6) ||
            owner.idiag_state!=TCP_ESTABLISHED || !owner.idiag_inode || owner.idiag_uid==*overflow_uid ||
            owner.id.idiag_sport!=tuple.idiag_sport || owner.id.idiag_dport!=tuple.idiag_dport ||
            response_address(owner.idiag_family,owner.id.idiag_src)!=*source ||
            response_address(owner.idiag_family,owner.id.idiag_dst)!=*destination)
            return {};
        return SocketOwner{owner.idiag_uid,owner.idiag_inode,{owner.id.idiag_cookie[0],owner.id.idiag_cookie[1]}};
    }

    auto Session::inspect_source_owner(rules::RouteMatcher const& policy,std::optional<io::endpoint> original) -> void {
        auto const* program=ordered_tcp ? &ordered_tcp->program : nullptr;
        auto needs_process=policy.uses_process() || (program && program->uses_process());
        if (!needs_process && !policy.uses_source_uid() && !(program && program->uses_source_uid())) return;
        auto peer=accepted_peer(client);
        auto destination=original ? *original : accepted_local(client);
        auto owner=local_socket_owner(peer,destination);
        if (!owner) return;
        source_uid=owner->uid;
        if (auto user = cached_user_for_uid(owner->uid); !user.empty()) source_user = std::move(user);
        if (needs_process) {
            std::optional<std::uint32_t> gid;
            std::string pkg;
            containers::inplace_vector<std::string, 8> paths;
            local_process_details(owner->inode,owner->uid,gid,pkg,paths);
            if ((!paths.empty() || !pkg.empty()) && local_socket_owner(peer,destination)==owner) {
                if (!paths.empty()) {
                    process_path=paths.front();
                    process_paths=std::move(paths);
                }
                if (gid) source_gid=gid;
                if (!pkg.empty()) package_name=std::move(pkg);
            }
        }
    }
}
