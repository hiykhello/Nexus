module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

module platform.process_owner;
import std;
import platform.platform_defaults;

namespace platform {
    namespace {
        auto parse_hex_word(std::string_view hex, std::uint32_t& out) noexcept -> bool {
            if (hex.size() != 8) return false;
            auto [p, ec] = std::from_chars(hex.data(), hex.data() + hex.size(), out, 16);
            return ec == std::errc{} && p == hex.data() + hex.size();
        }

        auto parse_endpoint(std::string_view token, bool ipv6, IpAddress& ip, std::uint16_t& port) noexcept -> bool {
            auto colon = token.find(':');
            if (colon == token.npos) return false;
            auto addr_hex = token.substr(0, colon);
            auto port_hex = token.substr(colon + 1);
            if (port_hex.size() != 4) return false;
            unsigned pval = 0;
            auto [pp, pec] = std::from_chars(port_hex.data(), port_hex.data() + port_hex.size(), pval, 16);
            if (pec != std::errc{} || pp != port_hex.data() + port_hex.size()) return false;
            port = static_cast<std::uint16_t>(pval);
            ip = {};
            if (!ipv6) {
                std::uint32_t w = 0;
                if (!parse_hex_word(addr_hex, w)) return false;
                std::memcpy(ip.bytes.data(), &w, 4);
                ip.size = 4;
                return true;
            }
            if (addr_hex.size() != 32) return false;
            for (std::size_t i = 0; i < 4; ++i) {
                std::uint32_t w = 0;
                if (!parse_hex_word(addr_hex.substr(i * 8, 8), w)) return false;
                std::memcpy(ip.bytes.data() + i * 4, &w, 4);
            }
            ip.size = 16;
            return true;
        }

        auto is_zero_ip(IpAddress const& ip) noexcept -> bool {
            return std::ranges::all_of(ip.view(), [](std::uint8_t b) { return b == 0; });
        }

        auto same_ip(IpAddress const& a, IpAddress const& b) noexcept -> bool {
            return a.size == b.size && std::ranges::equal(a.view(), b.view());
        }

        auto find_proc_inode(char const* path, bool ipv6, SocketTuple const& tuple) -> std::optional<std::uint64_t> {
            std::ifstream in(path);
            if (!in) return std::nullopt;
            std::string line;
            if (!std::getline(in, line)) return std::nullopt; // skip header
            std::optional<std::uint64_t> wildcard_match;
            while (std::getline(in, line)) {
                std::string_view sv(line);
                std::array<std::string_view, 12> cols{};
                std::size_t ncol = 0, pos = 0;
                while (ncol < cols.size()) {
                    while (pos < sv.size() && (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == '\n')) ++pos;
                    if (pos >= sv.size()) break;
                    auto end = pos;
                    while (end < sv.size() && sv[end] != ' ' && sv[end] != '\t' && sv[end] != '\n') ++end;
                    cols[ncol++] = sv.substr(pos, end - pos);
                    pos = end;
                }
                if (ncol < 10) continue;
                IpAddress loc{}, rem{};
                std::uint16_t lport = 0, rport = 0;
                if (!parse_endpoint(cols[1], ipv6, loc, lport) || !parse_endpoint(cols[2], ipv6, rem, rport)) continue;
                if (lport != tuple.local_port) continue;
                std::uint64_t inode = 0;
                auto [ip, iec] = std::from_chars(cols[9].data(), cols[9].data() + cols[9].size(), inode);
                if (iec != std::errc{} || ip != cols[9].data() + cols[9].size() || inode == 0) continue;
                bool exact_loc = same_ip(loc, tuple.local_ip);
                bool any_loc = is_zero_ip(loc) || is_zero_ip(tuple.local_ip);
                if (exact_loc && rport == tuple.remote_port && (rport == 0 || same_ip(rem, tuple.remote_ip)))
                    return inode;
                if ((exact_loc || any_loc) && rport == 0 && !wildcard_match)
                    wildcard_match = inode;
            }
            return wildcard_match;
        }

        auto read_all_eintr(int fd, char* dst, std::size_t cap) noexcept -> ssize_t {
            for (int tries = 0; tries < 16; ++tries) {
                ssize_t n = ::read(fd, dst, cap);
                if (n >= 0 || errno != EINTR) return n;
            }
            return -1;
        }

        auto open_eintr(char const* path, int flags) noexcept -> int {
            for (int tries = 0; tries < 16; ++tries) {
                int fd = ::open(path, flags);
                if (fd >= 0 || errno != EINTR) return fd;
            }
            return -1;
        }

        auto readlinkat_eintr(int dirfd, char const* name, char* buf, std::size_t cap) noexcept -> ssize_t {
            for (int tries = 0; tries < 16; ++tries) {
                ssize_t n = ::readlinkat(dirfd, name, buf, cap);
                if (n >= 0 || errno != EINTR) return n;
            }
            return -1;
        }

        auto readlink_eintr(char const* path, char* buf, std::size_t cap) noexcept -> ssize_t {
            for (int tries = 0; tries < 16; ++tries) {
                ssize_t n = ::readlink(path, buf, cap);
                if (n >= 0 || errno != EINTR) return n;
            }
            return -1;
        }

        auto lookup_passwd_cached(uid_t uid, std::optional<std::uint32_t>* gid_out = nullptr) -> std::string {
            using Clock = std::chrono::steady_clock;
            struct Entry {
                uid_t uid = 0;
                std::optional<std::uint32_t> gid{};
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
                for (auto const& e : cache) {
                    if (e.valid && e.uid == uid && now < e.expires) {
                        if (gid_out && e.gid) *gid_out = *e.gid;
                        return e.name;
                    }
                }
            }
            passwd pw{};
            passwd* pw_ptr = nullptr;
            std::array<char, 1024> pw_buf{};
            int rc = EINTR;
            for (int tries = 0; tries < 8 && rc == EINTR; ++tries)
                rc = ::getpwuid_r(uid, &pw, pw_buf.data(), pw_buf.size(), &pw_ptr);
            std::optional<std::uint32_t> gid{};
            std::string name;
            if (rc == 0 && pw_ptr) {
                gid = static_cast<std::uint32_t>(pw.pw_gid);
                if (pw.pw_name) name.assign(pw.pw_name);
            }
            if (gid_out && gid) *gid_out = *gid;
            {
                std::lock_guard lock(mu);
                auto slot = next_slot++ % cache.size();
                cache[slot] = Entry{uid, gid, name, now + std::chrono::seconds(30), true};
            }
            return name;
        }

        auto owner_from_inode(std::uint64_t inode) -> std::optional<ProcessOwner> {
            std::string target = std::format("socket:[{}]", inode);
            DIR* proc_dir = ::opendir("/proc");
            if (!proc_dir) return std::nullopt;
            auto close_dir = [](DIR* d) { ::closedir(d); };
            std::unique_ptr<DIR, decltype(close_dir)> proc_guard(proc_dir, close_dir);

            std::optional<ProcessOwner> out;
            containers::inplace_vector<std::string, 8> real_paths;
            std::size_t scanned_pids = 0;
            while (auto const* ent = ::readdir(proc_dir)) {
                std::string_view pid_sv(ent->d_name);
                if (pid_sv.empty() || !std::ranges::all_of(pid_sv, [](unsigned char c) { return c >= '0' && c <= '9'; }))
                    continue;
                if (++scanned_pids > 8192) break;
                std::uint32_t pid = 0;
                auto [pp, pec] = std::from_chars(pid_sv.data(), pid_sv.data() + pid_sv.size(), pid);
                if (pec != std::errc{} || pp != pid_sv.data() + pid_sv.size()) continue;

                std::string fd_dir_path = std::format("/proc/{}/fd", pid);
                DIR* fd_dir = ::opendir(fd_dir_path.c_str());
                if (!fd_dir) continue;
                std::unique_ptr<DIR, decltype(close_dir)> fd_guard(fd_dir, close_dir);

                bool found = false;
                std::size_t scanned_fds = 0;
                char link_buf[128];
                while (auto const* fde = ::readdir(fd_dir)) {
                    if (fde->d_name[0] == '.') continue;
                    if (++scanned_fds > 4096) break;
                    ssize_t n = readlinkat_eintr(::dirfd(fd_dir), fde->d_name, link_buf, sizeof(link_buf));
                    if (n > 0 && std::string_view(link_buf, static_cast<std::size_t>(n)) == target) {
                        found = true;
                        break;
                    }
                }
                if (!found) continue;

                std::string proc_path = std::format("/proc/{}", pid);
                char exe_buf[4096];
                std::string exe_link = proc_path + "/exe";
                ssize_t exe_n = readlink_eintr(exe_link.c_str(), exe_buf, sizeof(exe_buf));
                std::string_view exe_sv = exe_n > 0 ? std::string_view(exe_buf, static_cast<std::size_t>(exe_n)) : std::string_view{};
                bool const zygote = !exe_sv.empty() && platform::is_android_zygote_noise(exe_sv);

                std::string pkg;
                std::array<char, 256> cmd_buf{};
                std::string cmd_path = proc_path + "/cmdline";
                if (int cmd_fd = open_eintr(cmd_path.c_str(), O_RDONLY | O_CLOEXEC); cmd_fd >= 0) {
                    ssize_t n = read_all_eintr(cmd_fd, cmd_buf.data(), cmd_buf.size() - 1);
                    ::close(cmd_fd);
                    if (n > 0) {
                        std::string_view raw(cmd_buf.data(), static_cast<std::size_t>(n));
                        auto nul = raw.find('\0');
                        auto arg0 = nul == std::string_view::npos ? raw : raw.substr(0, nul);
                        if (auto colon = arg0.find(':'); colon != std::string_view::npos) arg0 = arg0.substr(0, colon);
                        if (!arg0.empty() && arg0.find('/') == std::string_view::npos && arg0.contains('.') &&
                            std::ranges::all_of(arg0, [](unsigned char c) {
                                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                       (c >= '0' && c <= '9') || c == '.' || c == '_';
                            }))
                            pkg.assign(arg0);
                    }
                }

                if (!out) {
                    out.emplace(ProcessOwner{.pid = pid});
                    struct stat st{};
                    if (::lstat(proc_path.c_str(), &st) == 0) {
                        out->uid = static_cast<std::uint32_t>(st.st_uid);
                        out->gid = static_cast<std::uint32_t>(st.st_gid);
                        out->user = lookup_passwd_cached(st.st_uid);
                    }
                } else if (!zygote && real_paths.empty()) {
                    out->pid = pid;
                }
                if (out->package_name.empty() && !pkg.empty()) out->package_name = std::move(pkg);
                if (!exe_sv.empty() && !zygote &&
                    !std::ranges::contains(real_paths, exe_sv) &&
                    real_paths.size() < real_paths.capacity()) {
                    real_paths.push_back(std::string(exe_sv));
                }
                if (real_paths.size() == real_paths.capacity() && !out->package_name.empty()) break;
            }
            if (!out) return std::nullopt;
            if (!real_paths.empty()) {
                out->executable = real_paths.front();
                out->executables = std::move(real_paths);
            }
            return out;
        }
    }

    struct NetlinkMatch {
        std::uint32_t uid = 0;
        std::uint64_t inode = 0;
    };

    auto host_to_be16(std::uint16_t v) noexcept -> __be16 {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return static_cast<__be16>((v >> 8) | (v << 8));
#else
        return static_cast<__be16>(v);
#endif
    }

    auto read_overflow_uid() noexcept -> std::uint32_t {
        static std::uint32_t const cached = []() noexcept -> std::uint32_t {
            int fd = open_eintr("/proc/sys/kernel/overflowuid", O_RDONLY | O_CLOEXEC);
            if (fd < 0) return 65534u;
            std::array<char, 16> buf{};
            ssize_t n = read_all_eintr(fd, buf.data(), buf.size());
            ::close(fd);
            if (n <= 0) return 65534u;
            std::string_view sv(buf.data(), static_cast<std::size_t>(n));
            if (sv.ends_with('\n')) sv.remove_suffix(1);
            std::uint32_t out = 65534u;
            (void)std::from_chars(sv.data(), sv.data() + sv.size(), out);
            return out;
        }();
        return cached;
    }

    auto copy_diag_ip(IpAddress const& ip, std::uint8_t family, void* dst) noexcept -> bool {
        if (family == AF_INET) {
            if (ip.size != 4) return false;
            std::memcpy(dst, ip.bytes.data(), 4);
            return true;
        }
        if (ip.size == 16) {
            std::memcpy(dst, ip.bytes.data(), 16);
            return true;
        }
        if (ip.size == 4) {
            auto* out = static_cast<std::uint8_t*>(dst);
            std::fill_n(out, 10, std::uint8_t{0});
            out[10] = 0xff; out[11] = 0xff;
            std::memcpy(out + 12, ip.bytes.data(), 4);
            return true;
        }
        return false;
    }

    auto query_sock_diag(int nl_fd, std::uint8_t family, std::uint8_t proto, bool dump,
                         SocketTuple const& tuple, std::uint32_t overflow_uid) noexcept -> std::optional<NetlinkMatch> {
        struct Request {
            nlmsghdr header;
            inet_diag_req_v2 body;
        } req{};
        req.header.nlmsg_len = sizeof(req);
        req.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        req.header.nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0));
        req.header.nlmsg_seq = dump ? 2u : 1u;
        req.body.sdiag_family = family;
        req.body.sdiag_protocol = proto;
        req.body.idiag_states = proto == IPPROTO_UDP
            ? ((1u << TCP_ESTABLISHED) | (1u << TCP_CLOSE))
            : ((1u << TCP_ESTABLISHED) | (1u << TCP_SYN_RECV) | (1u << TCP_FIN_WAIT1) | (1u << TCP_FIN_WAIT2) | (1u << TCP_CLOSE));
        auto sport_be = host_to_be16(tuple.local_port);
        auto dport_be = host_to_be16(tuple.remote_port);
        req.body.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
        req.body.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
        if (!dump) {
            if (!copy_diag_ip(tuple.local_ip, family, req.body.id.idiag_src) ||
                !copy_diag_ip(tuple.remote_ip, family, req.body.id.idiag_dst))
                return std::nullopt;
            req.body.id.idiag_sport = sport_be;
            req.body.id.idiag_dport = dport_be;
        }
        sockaddr_nl kernel{.nl_family = AF_NETLINK};
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(25);
        ssize_t sent = -1;
        do {
            sent = ::sendto(nl_fd, &req, sizeof(req), 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel));
        } while (sent < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline);
        if (sent != static_cast<ssize_t>(sizeof(req)))
            return std::nullopt;

        std::array<std::byte, 8192> rx{};
        std::optional<NetlinkMatch> wildcard;
        for (;;) {
            if (std::chrono::steady_clock::now() >= deadline) break;
            sockaddr_nl sender{};
            iovec iov{rx.data(), rx.size()};
            msghdr hdr{.msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &iov, .msg_iovlen = 1};
            ssize_t len = -1;
            do {
                len = ::recvmsg(nl_fd, &hdr, 0);
            } while (len < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline);
            if (len <= 0 || (hdr.msg_flags & MSG_TRUNC) != 0 || hdr.msg_namelen != sizeof(sender) ||
                sender.nl_family != AF_NETLINK || sender.nl_pid != 0 || sender.nl_groups != 0)
                break;
            std::size_t off = 0;
            auto const total = static_cast<std::size_t>(len);
            while (total - off >= sizeof(nlmsghdr)) {
                nlmsghdr nlh{};
                std::memcpy(&nlh, rx.data() + off, sizeof(nlh));
                if (nlh.nlmsg_len < sizeof(nlmsghdr) || nlh.nlmsg_len > total - off) break;
                if (nlh.nlmsg_seq == req.header.nlmsg_seq) {
                    if (nlh.nlmsg_type == NLMSG_DONE || nlh.nlmsg_type == NLMSG_ERROR) return wildcard;
                    if (nlh.nlmsg_type == SOCK_DIAG_BY_FAMILY && nlh.nlmsg_len >= NLMSG_LENGTH(sizeof(inet_diag_msg))) {
                        inet_diag_msg msg{};
                        std::memcpy(&msg, rx.data() + off + NLMSG_HDRLEN, sizeof(msg));
                        if (msg.idiag_inode != 0 && msg.idiag_uid != overflow_uid && msg.id.idiag_sport == sport_be) {
                            if (!dump) return NetlinkMatch{msg.idiag_uid, msg.idiag_inode};
                            auto raw_len = family == AF_INET ? std::size_t{4} : std::size_t{16};
                            auto loc = normalize_socket_ip(std::span<std::uint8_t const>(
                                reinterpret_cast<std::uint8_t const*>(msg.id.idiag_src), raw_len));
                            auto rem = normalize_socket_ip(std::span<std::uint8_t const>(
                                reinterpret_cast<std::uint8_t const*>(msg.id.idiag_dst), raw_len));
                            if (loc && rem) {
                                bool exact_loc = same_ip(*loc, tuple.local_ip);
                                bool any_loc = is_zero_ip(*loc) || is_zero_ip(tuple.local_ip);
                                if (exact_loc && msg.id.idiag_dport == dport_be &&
                                    (tuple.remote_port == 0 || same_ip(*rem, tuple.remote_ip)))
                                    return NetlinkMatch{msg.idiag_uid, msg.idiag_inode};
                                if ((exact_loc || any_loc) && msg.id.idiag_dport == 0 && !wildcard)
                                    wildcard = NetlinkMatch{msg.idiag_uid, msg.idiag_inode};
                            }
                        }
                    }
                }
                std::size_t step = NLMSG_ALIGN(nlh.nlmsg_len);
                if (step < sizeof(nlmsghdr) || step > total - off) break;
                off += step;
            }
            if (!dump) break;
        }
        return wildcard;
    }

    auto find_netlink_socket(SocketTuple const& tuple) noexcept -> std::optional<NetlinkMatch> {
        int fd = ::socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        if (fd < 0) return std::nullopt;
        timeval tv{0, 10000};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        std::uint32_t overflow_uid = read_overflow_uid();
        std::uint8_t proto = tuple.is_udp ? IPPROTO_UDP : IPPROTO_TCP;
        std::optional<NetlinkMatch> hit;
        if (tuple.local_ip.size == 16) hit = query_sock_diag(fd, AF_INET6, proto, false, tuple, overflow_uid);
        if (!hit && tuple.local_ip.size == 4) {
            hit = query_sock_diag(fd, AF_INET, proto, false, tuple, overflow_uid);
            if (!hit) hit = query_sock_diag(fd, AF_INET6, proto, false, tuple, overflow_uid);
        }
        if (!hit && tuple.is_udp) {
            if (tuple.local_ip.size == 16) hit = query_sock_diag(fd, AF_INET6, proto, true, tuple, overflow_uid);
            if (!hit) hit = query_sock_diag(fd, AF_INET, proto, true, tuple, overflow_uid);
        }
        ::close(fd);
        return hit;
    }

    auto fill_user_from_uid(std::uint32_t uid) -> ProcessOwner {
        ProcessOwner out{.pid = 0, .uid = uid};
        out.user = lookup_passwd_cached(uid, &out.gid);
        return out;
    }

    auto lookup_socket_owner(SocketTuple const& tuple) -> std::optional<ProcessOwner> {
        if (tuple.local_port == 0) return std::nullopt;
        if (auto diag = find_netlink_socket(tuple)) {
            if (!tuple.need_process) return fill_user_from_uid(diag->uid);
            return owner_from_inode(diag->inode);
        }
        std::optional<std::uint64_t> inode;
        if (tuple.is_udp) {
            if (tuple.local_ip.size == 16) inode = find_proc_inode("/proc/net/udp6", true, tuple);
            if (!inode) inode = find_proc_inode("/proc/net/udp", false, tuple);
        } else {
            if (tuple.local_ip.size == 16) inode = find_proc_inode("/proc/net/tcp6", true, tuple);
            if (!inode) inode = find_proc_inode("/proc/net/tcp", false, tuple);
        }
        if (!inode) return std::nullopt;
        return owner_from_inode(*inode);
    }
}
