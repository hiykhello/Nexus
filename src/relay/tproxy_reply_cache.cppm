// Private TPROXY UDP transparent socket & bounded reply-socket cache.
module;
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

module relay:tproxy_reply_cache;
import std;
import config.listen_types;
import containers.cache_index;
import net.udp_socket;
import platform.socket_options;
import relay.listener_options;
import :types;

namespace relay::tproxy_detail {
    struct Address {
        sockaddr_storage value{};
        socklen_t size{};
        explicit Address(net::UdpEndpoint const& endpoint) noexcept {
            if (endpoint.family == 4) {
                sockaddr_in address{};
                address.sin_family = AF_INET;
                address.sin_port = htons(endpoint.port);
                std::memcpy(&address.sin_addr, endpoint.address.data(), 4);
                std::memcpy(&value, &address, sizeof(address));
                size = sizeof(address);
            } else {
                sockaddr_in6 address{};
                address.sin6_family = AF_INET6;
                address.sin6_port = htons(endpoint.port);
                std::memcpy(&address.sin6_addr, endpoint.address.data(), 16);
                std::memcpy(&value, &address, sizeof(address));
                size = sizeof(address);
            }
        }
        [[nodiscard]] auto get() const noexcept -> sockaddr const* {
            return reinterpret_cast<sockaddr const*>(&value);
        }
    };

    struct Socket {
        int fd = -1;
        Socket() = default;
        Socket(Socket const&) = delete;
        auto operator=(Socket const&) -> Socket& = delete;
        Socket(Socket&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
        auto operator=(Socket&& other) noexcept -> Socket& {
            if (this != &other) { close(); fd = std::exchange(other.fd, -1); }
            return *this;
        }
        ~Socket() { close(); }
        auto close() noexcept -> void { if (fd >= 0) ::close(std::exchange(fd, -1)); }

        auto bind(net::UdpEndpoint const& local, bool receive, bool reuse, std::optional<std::uint32_t> mark = {},
            config::ListenOptions const* listen = nullptr)
            -> std::error_code {
            bool ipv6 = local.family == 6;
            auto error = [] { return std::error_code(errno, std::generic_category()); };
            if (listen && !listen->netns.empty()) {
                auto opened = platform::open_physical_socket(ipv6, true, false, listen->netns);
                if (!opened) return opened.error();
                fd = *opened;
            } else {
                fd = ::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                if (fd < 0) return error();
            }
            int one = 1;
            auto set = [&](int level, int name, auto value) {
                return ::setsockopt(fd, level, name, &value, sizeof(value)) == 0;
            };
            auto level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
            if (receive && listen && listen->configured()) {
                if (auto ec = apply_udp_listen_options(fd, *listen, ipv6)) { close(); return ec; }
            }
            if (!set(level, ipv6 ? IPV6_TRANSPARENT : IP_TRANSPARENT, one) ||
                (ipv6 && !set(IPPROTO_IPV6, IPV6_V6ONLY, one)) ||
                (receive && (!set(level, ipv6 ? IPV6_RECVORIGDSTADDR : IP_RECVORIGDSTADDR, one) ||
                             !set(level, ipv6 ? IPV6_RECVPKTINFO : IP_PKTINFO, one) ||
                             !set(level, ipv6 ? IPV6_RECVTCLASS : IP_RECVTOS, one))) ||
                (receive && reuse && !set(SOL_SOCKET, SO_REUSEPORT, one)) ||
                (!receive && !set(SOL_SOCKET, SO_REUSEADDR, one)) ||
                (mark && !(receive && listen && listen->routing_mark) && !set(SOL_SOCKET, SO_MARK, *mark))) {
                auto ec = error();
                close();
                return ec;
            }
            Address address(local);
            if (::bind(fd, address.get(), address.size) < 0) {
                auto ec = error();
                close();
                return ec;
            }
            return {};
        }

        auto send_errno(net::UdpEndpoint const& endpoint, std::span<std::uint8_t const> bytes) const noexcept -> int {
            Address address(endpoint);
            auto n = ::sendto(fd, bytes.data(), bytes.size(), MSG_DONTWAIT, address.get(), address.size);
            if (n == static_cast<ssize_t>(bytes.size())) return 0;
            return n < 0 ? errno : EMSGSIZE;
        }
    };

    inline auto current_netns_inode() noexcept -> std::uint64_t {
        struct stat st{};
        return ::stat("/proc/self/ns/net", &st) == 0 ? static_cast<std::uint64_t>(st.st_ino) : 0;
    }

    // Bounded cache of IP_TRANSPARENT UDP reply sockets keyed by (family, source addr, port, mark, netns).
    // Avoids per-flow socket()/setsockopt()/bind()/close() churn across concurrent/short-lived UDP flows.
    class TproxyReplySocketCache {
    public:
        enum class SendResult : std::uint8_t { sent, dropped, failed };
        static constexpr std::size_t max_entries = 64;
        static constexpr auto idle_ttl = std::chrono::seconds(60);

    private:
        struct Key {
            std::uint8_t family = 0;
            std::array<std::uint8_t, 16> address{};
            std::uint16_t port = 0;
            bool has_mark = false;
            std::uint32_t mark = 0;
            std::uint64_t netns = 0;
            auto operator==(Key const&) const noexcept -> bool = default;
        };
        struct Entry {
            Key key;
            Socket socket;
            Clock::time_point last_used{};
        };

        containers::IntrusiveLruTable<Entry> entries_;
        std::uint64_t netns_ = 0;
        Clock::time_point last_reap_{};

        static auto make_key(net::UdpEndpoint const& source, std::optional<std::uint32_t> mark,
            std::uint64_t netns) noexcept -> Key {
            Key k{};
            k.family = source.family;
            auto len = source.family == 4 ? std::size_t{4} : std::size_t{16};
            std::copy_n(source.address.begin(), len, k.address.begin());
            k.port = source.port;
            k.has_mark = mark.has_value();
            k.mark = mark.value_or(0);
            k.netns = netns;
            return k;
        }

        static auto hash_key(Key const& k) noexcept -> std::size_t {
            std::uint64_t h = 14695981039346656037ull, a0 = 0, a1 = 0;
            auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
            mix((static_cast<std::uint64_t>(k.family) << 24) | (static_cast<std::uint64_t>(k.has_mark) << 16) | k.port);
            std::memcpy(&a0, k.address.data(), 8); mix(a0);
            if (k.family == 6) { std::memcpy(&a1, k.address.data() + 8, 8); mix(a1); }
            mix(k.mark);
            mix(k.netns);
            return static_cast<std::size_t>(h ^ (h >> 32));
        }

        auto find_idx(Key const& key, std::size_t hash) const noexcept -> std::optional<std::uint32_t> {
            return entries_.find(hash, [&](Entry const& e) noexcept { return e.key == key; });
        }

        auto evict_expired(Clock::time_point now) noexcept -> void {
            while (auto tail = entries_.lru()) {
                if (now - entries_.at(*tail).last_used < idle_ttl) break;
                entries_.erase(*tail);
            }
        }

        auto evict_one(Clock::time_point now) noexcept -> void {
            evict_expired(now);
            if (entries_.size() < max_entries) return;
            if (auto tail = entries_.lru()) entries_.erase(*tail);
        }

    public:
        TproxyReplySocketCache() : entries_(max_entries), netns_(current_netns_inode()) {}

        auto clear() noexcept -> void { entries_.clear(); }

        auto refresh_netns() noexcept -> void {
            auto ns = current_netns_inode();
            if (ns != netns_) {
                entries_.clear();
                netns_ = ns;
            }
        }

        auto reap_idle(Clock::time_point now) noexcept -> void {
            if (now - last_reap_ < std::chrono::seconds(1)) return;
            last_reap_ = now;
            evict_expired(now);
        }

        auto ensure_bound(net::UdpEndpoint const& source, std::optional<std::uint32_t> mark) -> std::error_code {
            auto now = Clock::now();
            auto key = make_key(source, mark, netns_);
            auto h = hash_key(key);
            if (auto hit = find_idx(key, h)) {
                entries_.at(*hit).last_used = now;
                entries_.promote(*hit);
                return {};
            }
            Socket sock;
            if (auto ec = sock.bind(source, false, false, mark)) return ec;
            if (entries_.size() >= max_entries) evict_one(now);
            entries_.insert_front(h, Entry{key, std::move(sock), now});
            return {};
        }

        auto send(net::UdpEndpoint const& source, std::optional<std::uint32_t> mark,
            net::UdpEndpoint const& client, std::span<std::uint8_t const> bytes) -> SendResult {
            auto now = Clock::now();
            auto key = make_key(source, mark, netns_);
            auto h = hash_key(key);
            if (auto hit = find_idx(key, h)) {
                auto& entry = entries_.at(*hit);
                int err = entry.socket.send_errno(client, bytes);
                if (err == 0) {
                    entry.last_used = now;
                    entries_.promote(*hit);
                    return SendResult::sent;
                }
                if (err == EMSGSIZE) {
                    entry.last_used = now;
                    entries_.promote(*hit);
                    return SendResult::dropped;
                }
                if (err != ENOBUFS && err != EINVAL && err != EADDRNOTAVAIL && err != EBADF &&
                    err != ENETUNREACH && err != EHOSTUNREACH) {
                    return SendResult::failed;
                }
                entries_.erase(*hit);
            }
            if (ensure_bound(source, mark)) return SendResult::failed;
            auto bound = find_idx(key, h);
            if (!bound) return SendResult::failed;
            auto& entry = entries_.at(*bound);
            int err = entry.socket.send_errno(client, bytes);
            if (err == 0) {
                entry.last_used = now;
                entries_.promote(*bound);
                return SendResult::sent;
            }
            if (err == EMSGSIZE) {
                entry.last_used = now;
                entries_.promote(*bound);
                return SendResult::dropped;
            }
            return SendResult::failed;
        }
    };
}
