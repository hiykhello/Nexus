module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

module platform.process_owner;
import std;

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

        auto owner_from_inode(std::uint64_t inode) -> std::optional<ProcessOwner> {
            std::string target = std::format("socket:[{}]", inode);
            DIR* proc_dir = ::opendir("/proc");
            if (!proc_dir) return std::nullopt;
            auto close_dir = [](DIR* d) { ::closedir(d); };
            std::unique_ptr<DIR, decltype(close_dir)> proc_guard(proc_dir, close_dir);

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
                    ssize_t n = ::readlinkat(::dirfd(fd_dir), fde->d_name, link_buf, sizeof(link_buf));
                    if (n > 0 && std::string_view(link_buf, static_cast<std::size_t>(n)) == target) {
                        found = true;
                        break;
                    }
                }
                if (!found) continue;

                ProcessOwner out{.pid = pid};
                struct stat st{};
                std::string proc_path = std::format("/proc/{}", pid);
                if (::lstat(proc_path.c_str(), &st) == 0) out.uid = static_cast<std::uint32_t>(st.st_uid);
                char exe_buf[4096];
                std::string exe_link = proc_path + "/exe";
                ssize_t exe_n = ::readlink(exe_link.c_str(), exe_buf, sizeof(exe_buf));
                if (exe_n > 0) out.executable.assign(exe_buf, static_cast<std::size_t>(exe_n));
                return out;
            }
            return std::nullopt;
        }
    }

    auto lookup_socket_owner(SocketTuple const& tuple) -> std::optional<ProcessOwner> {
        if (tuple.local_port == 0) return std::nullopt;
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
