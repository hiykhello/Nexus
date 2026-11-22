module;
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/tcp_socket.hpp>

module proxy;
import std;
import platform.ip_address;
import rules;

namespace proxy {
    namespace {
        struct Fd {
            int value;
            ~Fd() { if (value>=0) ::close(value); }
        };

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
            Fd file{::open("/proc/sys/kernel/overflowuid",O_RDONLY|O_CLOEXEC)};
            if (file.value<0) return {};
            std::array<char,16> bytes;
            auto size=::read(file.value,bytes.data(),bytes.size());
            if (size<=0 || static_cast<std::size_t>(size)==bytes.size()) return {};
            std::string_view text(bytes.data(),static_cast<std::size_t>(size));
            if (text.ends_with('\n')) text.remove_suffix(1);
            return rules::parse_source_uid(text);
        }
    }

    auto local_process_path(std::uint32_t inode, std::uint32_t uid) -> std::string;

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
        if (netlink.value<0) return {};
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
        if (::sendto(netlink.value,&request,sizeof(request),0,reinterpret_cast<sockaddr*>(&kernel),sizeof(kernel))!=sizeof(request))
            return {};

        struct Response {
            nlmsghdr header;
            inet_diag_msg body;
            std::array<std::byte,512> attributes;
        } response;
        sockaddr_nl sender{};
        iovec data{&response,sizeof(response)};
        msghdr message{.msg_name=&sender,.msg_namelen=sizeof(sender),.msg_iov=&data,.msg_iovlen=1};
        auto size=::recvmsg(netlink.value,&message,0);
        if (size<static_cast<ssize_t>(sizeof(response.header)+sizeof(response.body)) ||
            message.msg_flags&MSG_TRUNC || message.msg_namelen!=sizeof(sender) ||
            sender.nl_family!=AF_NETLINK || sender.nl_pid || sender.nl_groups || response.header.nlmsg_seq!=1 ||
            response.header.nlmsg_type!=SOCK_DIAG_BY_FAMILY ||
            response.header.nlmsg_len<sizeof(response.header)+sizeof(response.body) ||
            response.header.nlmsg_len>static_cast<std::size_t>(size))
            return {};

        auto const& owner=response.body;
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
        if (needs_process) {
            auto path=local_process_path(owner->inode,owner->uid);
            if (!path.empty() && local_socket_owner(peer,destination)==owner) process_path=std::move(path);
        }
    }
}
