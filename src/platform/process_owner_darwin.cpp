module;
#if defined(__APPLE__)
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>
#endif

module platform.process_owner;
import std;

namespace platform {
#if defined(__APPLE__)
    namespace {
        auto same_ip4(std::uint32_t be_addr, IpAddress const& ip) noexcept -> bool {
            if (ip.size == 4) return std::memcmp(&be_addr, ip.bytes.data(), 4) == 0;
            return ip.size == 0 || be_addr == 0;
        }
        auto same_ip6(in6_addr const& addr, IpAddress const& ip) noexcept -> bool {
            if (ip.size == 16) return std::memcmp(&addr, ip.bytes.data(), 16) == 0;
            in6_addr zero{};
            return std::memcmp(&addr, &zero, sizeof(zero)) == 0;
        }
        auto is_zero4(std::uint32_t be_addr) noexcept -> bool { return be_addr == 0; }
        auto is_zero6(in6_addr const& addr) noexcept -> bool {
            in6_addr zero{};
            return std::memcmp(&addr, &zero, sizeof(zero)) == 0;
        }
    }

    auto lookup_socket_owner(SocketTuple const& tuple) -> std::optional<ProcessOwner> {
        if (tuple.local_port == 0) return std::nullopt;
        int needed = ::proc_listallpids(nullptr, 0);
        if (needed <= 0) return std::nullopt;
        std::vector<pid_t> pids(static_cast<std::size_t>(needed) + 64);
        int count = ::proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
        if (count <= 0) return std::nullopt;
        pids.resize(static_cast<std::size_t>(count));

        std::optional<ProcessOwner> wildcard;
        for (pid_t pid : pids) {
            if (pid <= 0) continue;
            int fd_bytes = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
            if (fd_bytes <= 0) continue;
            std::vector<struct proc_fdinfo> fds(static_cast<std::size_t>(fd_bytes) / sizeof(struct proc_fdinfo) + 8);
            int actual = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(struct proc_fdinfo)));
            if (actual <= 0) continue;
            fds.resize(static_cast<std::size_t>(actual) / sizeof(struct proc_fdinfo));

            for (auto const& fd : fds) {
                if (fd.proc_fdtype != PROX_FDTYPE_SOCKET) continue;
                struct socket_fdinfo si{};
                if (::proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si)) != sizeof(si)) continue;
                auto kind = si.psi.soi_kind;
                if (tuple.is_udp ? (kind != SOCKINFO_IN) : (kind != SOCKINFO_TCP && kind != SOCKINFO_IN)) continue;
                int proto = si.psi.soi_protocol;
                if (tuple.is_udp ? (proto != IPPROTO_UDP) : (proto != IPPROTO_TCP)) continue;
                auto const& ins = (kind == SOCKINFO_TCP) ? si.psi.soi_proto.pri_tcp.tcpsi_ini
                                                         : si.psi.soi_proto.pri_in;
                std::uint16_t lport = ntohs(static_cast<std::uint16_t>(ins.insi_lport));
                std::uint16_t rport = ntohs(static_cast<std::uint16_t>(ins.insi_fport));
                if (lport != tuple.local_port) continue;

                bool v6 = (ins.insi_vflag & INI_IPV6) != 0;
                bool loc_exact = v6 ? same_ip6(ins.insi_laddr.ina_6, tuple.local_ip)
                                    : same_ip4(ins.insi_laddr.ina_46.i46a_addr4.s_addr, tuple.local_ip);
                bool loc_zero = v6 ? is_zero6(ins.insi_laddr.ina_6)
                                   : is_zero4(ins.insi_laddr.ina_46.i46a_addr4.s_addr);
                bool rem_match = (rport == tuple.remote_port) &&
                    (rport == 0 || (v6 ? same_ip6(ins.insi_faddr.ina_6, tuple.remote_ip)
                                       : same_ip4(ins.insi_faddr.ina_46.i46a_addr4.s_addr, tuple.remote_ip)));
                if (!(loc_exact && rem_match) && !((loc_exact || loc_zero) && rport == 0)) continue;

                ProcessOwner owner{.pid = static_cast<std::uint32_t>(pid)};
                struct proc_bsdinfo bsd{};
                if (::proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) == sizeof(bsd))
                    owner.uid = static_cast<std::uint32_t>(bsd.pbi_uid);
                char path_buf[PROC_PIDPATHINFO_MAXSIZE]{};
                if (::proc_pidpath(pid, path_buf, sizeof(path_buf)) > 0) owner.executable = path_buf;
                if (loc_exact && rem_match) return owner;
                if (!wildcard) wildcard = std::move(owner);
            }
        }
        return wildcard;
    }
#else
    auto lookup_socket_owner(SocketTuple const&) -> std::optional<ProcessOwner> { return std::nullopt; }
#endif
}
