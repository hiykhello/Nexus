module;
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

export module tls.outbound_fragment;
import std;
import crypto;
import capy;
import corosio;

export namespace tls {
    struct OutboundFragmentOptions {
        bool enabled = false;
        bool record_fragment = false;
        std::uint16_t min_bytes = 10;
        std::uint16_t max_bytes = 100;
        std::uint32_t fallback_delay_ms = 500;
        [[nodiscard]] constexpr auto active() const noexcept -> bool { return enabled || record_fragment; }
        auto operator==(OutboundFragmentOptions const&) const -> bool = default;
    };

    struct ClientHelloSniRange {
        std::size_t ext_offset = 0;
        std::size_t ext_end = 0;
        std::size_t host_offset = 0;
        std::size_t host_len = 0;
    };

    namespace detail {
        inline auto read_u16_be(std::span<std::uint8_t const> s, std::size_t pos) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{s[pos]} << 8) | s[pos + 1]);
        }

        inline auto splitmix64(std::uint64_t& state) noexcept -> std::uint64_t {
            std::uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
            return z ^ (z >> 31);
        }

        inline auto random_seed() noexcept -> std::uint64_t {
            std::array<std::uint8_t, 8> raw{};
            std::uint64_t seed = 0;
            if (crypto::random_bytes(raw)) {
                for (auto b : raw) seed = (seed << 8) | b;
                if (seed != 0) return seed;
            }
            seed = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            return seed ? seed : 0x5eed1234abcd5678ULL;
        }

        inline auto choose_sni_cut(std::span<std::uint8_t const> wire, ClientHelloSniRange const& sni,
                                   std::uint64_t& prng) noexcept -> std::size_t {
            // Prefer cutting strictly inside the longest DNS label (len >= 2) of the SNI hostname.
            auto host = wire.subspan(sni.host_offset, sni.host_len);
            std::size_t best_start = 0, best_len = 0;
            std::size_t cur = 0;
            for (std::size_t i = 0; i <= host.size(); ++i) {
                if (i == host.size() || host[i] == '.') {
                    auto len = i - cur;
                    if (len > best_len) { best_start = cur; best_len = len; }
                    cur = i + 1;
                }
            }
            if (best_len >= 2) {
                auto inner_off = 1 + static_cast<std::size_t>(splitmix64(prng) % (best_len - 1));
                return sni.host_offset + best_start + inner_off;
            }
            if (sni.host_len >= 2) {
                auto inner_off = 1 + static_cast<std::size_t>(splitmix64(prng) % (sni.host_len - 1));
                return sni.host_offset + inner_off;
            }
            return sni.host_offset;
        }

        template<class Socket>
        auto enable_tcp_nodelay(Socket& socket) noexcept -> void {
            if constexpr (requires(Socket& s) { s.native_handle(); }) {
                auto fd = socket.native_handle();
#if defined(_WIN32)
                if (fd != INVALID_SOCKET) {
                    BOOL one = TRUE;
                    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char const*>(&one), sizeof(one));
                }
#else
                if (fd >= 0) {
                    int one = 1;
                    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                }
#endif
            }
        }

        template<class Socket>
        auto tcp_acked_all(Socket& socket) noexcept -> bool {
#if defined(__linux__)
            if constexpr (requires(Socket& s) { s.native_handle(); }) {
                auto fd = socket.native_handle();
                if (fd >= 0) {
                    struct tcp_info info{};
                    socklen_t len = sizeof(info);
                    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0 && len >= sizeof(info))
                        return info.tcpi_unacked == 0;
                }
            }
#else
            (void)socket;
#endif
            return false;
        }

        template<class Socket>
        auto write_all_chunk(Socket& socket, std::span<std::uint8_t const> chunk)
            -> capy::task<std::error_code> {
            std::size_t off = 0;
            while (off < chunk.size()) {
                auto [ec, n] = co_await socket.write_some(
                    capy::const_buffer(chunk.data() + off, chunk.size() - off));
                if (ec || n == 0 || n > chunk.size() - off)
                    co_return ec ? ec : std::make_error_code(std::errc::broken_pipe);
                off += n;
            }
            co_return std::error_code{};
        }

        template<class Socket>
        auto stagger_after_chunk(Socket& socket, std::chrono::milliseconds budget,
                                 std::chrono::steady_clock::time_point deadline) -> capy::task<void> {
            if (budget.count() <= 0) co_return;
            if constexpr (requires(Socket& s) { s.context(); }) {
                auto now = std::chrono::steady_clock::now();
                auto stop_at = std::min(deadline, now + budget);
                if (stop_at <= now) co_return;
                corosio::steady_timer timer(socket.context());
                while (now < stop_at) {
                    if (tcp_acked_all(socket)) co_return;
                    auto step = std::min(stop_at, now + std::chrono::milliseconds(2));
                    timer.expires_at(step);
                    auto [ec] = co_await timer.wait();
                    if (ec) co_return;
                    now = std::chrono::steady_clock::now();
                }
            } else {
                (void)socket; (void)deadline;
            }
            co_return;
        }
    }

    [[nodiscard]] inline auto is_client_hello_record(std::span<std::uint8_t const> wire) noexcept -> bool {
        if (wire.size() < 10) return false;
        if (wire[0] != 0x16 || wire[1] != 0x03 || wire[2] > 0x04) return false;
        auto rec_len = std::size_t{detail::read_u16_be(wire, 3)};
        if (rec_len < 4 || rec_len != wire.size() - 5) return false;
        return wire[5] == 0x01;
    }

    [[nodiscard]] inline auto locate_client_hello_sni(std::span<std::uint8_t const> wire) noexcept
        -> std::optional<ClientHelloSniRange> {
        if (!is_client_hello_record(wire)) return std::nullopt;
        // 5-byte record header + 4-byte handshake header + 2-byte version + 32-byte random = 43.
        if (wire.size() < 44) return std::nullopt;
        auto hs_len = (std::size_t{wire[6]} << 16) | (std::size_t{wire[7]} << 8) | wire[8];
        if (hs_len > wire.size() - 9) return std::nullopt;
        auto end = 9 + hs_len;
        std::size_t pos = 43;
        if (pos >= end) return std::nullopt;
        auto sid_len = std::size_t{wire[pos++]};
        if (sid_len > end - pos) return std::nullopt;
        pos += sid_len;
        if (end - pos < 2) return std::nullopt;
        auto cs_len = std::size_t{detail::read_u16_be(wire, pos)}; pos += 2;
        if (cs_len > end - pos) return std::nullopt;
        pos += cs_len;
        if (pos >= end) return std::nullopt;
        auto comp_len = std::size_t{wire[pos++]};
        if (comp_len > end - pos) return std::nullopt;
        pos += comp_len;
        if (end - pos < 2) return std::nullopt;
        auto ext_total = std::size_t{detail::read_u16_be(wire, pos)}; pos += 2;
        if (ext_total > end - pos) return std::nullopt;
        auto ext_limit = pos + ext_total;
        while (pos + 4 <= ext_limit) {
            auto ext_start = pos;
            auto type = detail::read_u16_be(wire, pos);
            auto len = std::size_t{detail::read_u16_be(wire, pos + 2)};
            pos += 4;
            if (len > ext_limit - pos) return std::nullopt;
            if (type == 0x0000) {
                // server_name: [u16 list_len][u8 name_type(0)][u16 host_len][hostname]
                if (len < 5) return std::nullopt;
                auto list_len = std::size_t{detail::read_u16_be(wire, pos)};
                if (list_len + 2 != len || wire[pos + 2] != 0) return std::nullopt;
                auto host_len = std::size_t{detail::read_u16_be(wire, pos + 3)};
                if (host_len == 0 || host_len + 5 > len) return std::nullopt;
                return ClientHelloSniRange{ext_start, pos + len, pos + 5, host_len};
            }
            pos += len;
        }
        return std::nullopt;
    }

    [[nodiscard]] inline auto plan_client_hello_splits(std::span<std::uint8_t const> wire,
                                                       OutboundFragmentOptions const& opts,
                                                       std::uint64_t seed) -> std::vector<std::size_t> {
        if (wire.size() <= 1 || !is_client_hello_record(wire))
            return wire.empty() ? std::vector<std::size_t>{} : std::vector<std::size_t>{wire.size()};
        std::size_t lo = std::clamp<std::size_t>(opts.min_bytes, 1, 16384);
        std::size_t hi = std::clamp<std::size_t>(std::max<std::size_t>(opts.min_bytes, opts.max_bytes), lo, 16384);
        std::uint64_t prng = seed ? seed : 0x5eed1234abcd5678ULL;
        auto next_step = [&]() -> std::size_t {
            if (lo == hi) return lo;
            return lo + static_cast<std::size_t>(detail::splitmix64(prng) % (hi - lo + 1));
        };
        std::optional<std::size_t> mandatory_cut;
        if (auto sni = locate_client_hello_sni(wire); sni && sni->host_len >= 2) {
            auto cut = detail::choose_sni_cut(wire, *sni, prng);
            if (cut > 0 && cut < wire.size()) mandatory_cut = cut;
        }
        std::vector<std::size_t> chunks;
        chunks.reserve(wire.size() / std::max<std::size_t>(lo, 1) + 4);
        std::size_t pos = 0;
        while (pos < wire.size()) {
            std::size_t remaining = wire.size() - pos;
            std::size_t take = std::min(remaining, next_step());
            if (mandatory_cut && pos < *mandatory_cut && pos + take > *mandatory_cut) {
                take = *mandatory_cut - pos;
            }
            if (take == 0) take = 1;
            chunks.push_back(take);
            pos += take;
        }
        return chunks;
    }

    [[nodiscard]] inline auto fragment_client_hello_records(std::span<std::uint8_t const> wire,
                                                            OutboundFragmentOptions const& opts,
                                                            std::uint64_t seed) -> crypto::Bytes {
        if (!is_client_hello_record(wire))
            return crypto::Bytes(wire.begin(), wire.end());
        auto payload = wire.subspan(5);
        if (payload.size() <= 1)
            return crypto::Bytes(wire.begin(), wire.end());
        std::size_t lo = std::clamp<std::size_t>(opts.min_bytes, 1, 16384);
        std::size_t hi = std::clamp<std::size_t>(std::max<std::size_t>(opts.min_bytes, opts.max_bytes), lo, 16384);
        std::uint64_t prng = seed ? seed : 0x5eed1234abcd5678ULL;
        auto next_step = [&]() -> std::size_t {
            if (lo == hi) return lo;
            return lo + static_cast<std::size_t>(detail::splitmix64(prng) % (hi - lo + 1));
        };
        std::optional<std::size_t> mandatory_cut;
        if (auto sni = locate_client_hello_sni(wire); sni && sni->host_len >= 2) {
            auto cut = detail::choose_sni_cut(wire, *sni, prng);
            if (cut > 5 && cut < wire.size()) mandatory_cut = cut - 5;
        }
        crypto::Bytes out;
        out.reserve(wire.size() + (payload.size() / std::max<std::size_t>(lo, 1) + 2) * 5);
        std::size_t pos = 0;
        while (pos < payload.size()) {
            std::size_t remaining = payload.size() - pos;
            std::size_t take = std::min(remaining, next_step());
            if (mandatory_cut && pos < *mandatory_cut && pos + take > *mandatory_cut)
                take = *mandatory_cut - pos;
            if (take == 0) take = 1;
            out.push_back(0x16);
            out.push_back(wire[1]);
            out.push_back(wire[2]);
            out.push_back(static_cast<std::uint8_t>(take >> 8));
            out.push_back(static_cast<std::uint8_t>(take & 0xff));
            out.insert(out.end(), payload.begin() + static_cast<std::ptrdiff_t>(pos),
                       payload.begin() + static_cast<std::ptrdiff_t>(pos + take));
            pos += take;
        }
        return out;
    }

    template<class Socket>
    auto write_fragmented_client_hello(Socket& socket, std::span<std::uint8_t const> wire,
                                       OutboundFragmentOptions const& opts,
                                       std::chrono::steady_clock::time_point deadline)
        -> capy::task<std::error_code> {
        if (!opts.active() || !is_client_hello_record(wire))
            co_return co_await detail::write_all_chunk(socket, wire);
        auto seed = detail::random_seed();
        detail::enable_tcp_nodelay(socket);
        auto total_cap = std::chrono::milliseconds(opts.fallback_delay_ms);
        auto start_time = std::chrono::steady_clock::now();
        auto delay_limit = std::min(deadline, start_time + total_cap);

        if (opts.record_fragment) {
            auto fragmented = fragment_client_hello_records(wire, opts, seed);
            if (!opts.enabled)
                co_return co_await detail::write_all_chunk(socket, fragmented);
            // Send record-by-record with bounded stagger.
            std::vector<std::size_t> rec_sizes;
            for (std::size_t off = 0; off + 5 <= fragmented.size();) {
                auto len = std::size_t{detail::read_u16_be(fragmented, off + 3)};
                if (5 + len > fragmented.size() - off) break;
                rec_sizes.push_back(5 + len);
                off += 5 + len;
            }
            if (rec_sizes.size() <= 1)
                co_return co_await detail::write_all_chunk(socket, fragmented);
            auto per_gap = opts.fallback_delay_ms > 0
                ? std::chrono::milliseconds(std::clamp<std::uint32_t>(
                    opts.fallback_delay_ms / static_cast<std::uint32_t>(rec_sizes.size() - 1), 1, 25))
                : std::chrono::milliseconds(0);
            std::size_t off = 0;
            for (std::size_t i = 0; i < rec_sizes.size(); ++i) {
                auto ec = co_await detail::write_all_chunk(
                    socket, std::span<std::uint8_t const>(fragmented).subspan(off, rec_sizes[i]));
                if (ec) co_return ec;
                off += rec_sizes[i];
                if (i + 1 < rec_sizes.size() && per_gap.count() > 0)
                    co_await detail::stagger_after_chunk(socket, per_gap, delay_limit);
            }
            co_return std::error_code{};
        }

        auto chunks = plan_client_hello_splits(wire, opts, seed);
        if (chunks.size() <= 1)
            co_return co_await detail::write_all_chunk(socket, wire);
        auto per_gap = opts.fallback_delay_ms > 0
            ? std::chrono::milliseconds(std::clamp<std::uint32_t>(
                opts.fallback_delay_ms / static_cast<std::uint32_t>(chunks.size() - 1), 1, 25))
            : std::chrono::milliseconds(0);
        std::size_t off = 0;
        for (std::size_t i = 0; i < chunks.size(); ++i) {
            auto ec = co_await detail::write_all_chunk(socket, wire.subspan(off, chunks[i]));
            if (ec) co_return ec;
            off += chunks[i];
            if (i + 1 < chunks.size() && per_gap.count() > 0)
                co_await detail::stagger_after_chunk(socket, per_gap, delay_limit);
        }
        co_return std::error_code{};
    }
}
