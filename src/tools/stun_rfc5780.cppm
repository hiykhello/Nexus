// RFC 5780 STUN NAT Mapping & Filtering Behavior codec, classifier & live probe.
module;
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

export module cli.stun_rfc5780;
import std;
import crypto;
import encoding.json;
import platform.ip_address;
import platform.unique_fd;
import sniff.stun;

export namespace cli::stun {
    struct Endpoint {
        bool ipv6 = false;
        std::array<std::uint8_t, 16> addr{};
        std::uint16_t port = 0;

        [[nodiscard]] auto operator==(Endpoint const& o) const noexcept -> bool {
            if (ipv6 != o.ipv6 || port != o.port) return false;
            auto len = ipv6 ? std::size_t{16} : std::size_t{4};
            return std::ranges::equal(std::span(addr).first(len), std::span(o.addr).first(len));
        }
        [[nodiscard]] auto same_ip(Endpoint const& o) const noexcept -> bool {
            if (ipv6 != o.ipv6) return false;
            auto len = ipv6 ? std::size_t{16} : std::size_t{4};
            return std::ranges::equal(std::span(addr).first(len), std::span(o.addr).first(len));
        }
        [[nodiscard]] auto format() const -> std::string {
            if (ipv6) return std::format("[{}]:{}", platform::format_ipv6(addr), port);
            std::array<std::uint8_t, 4> v4{};
            std::copy_n(addr.begin(), 4, v4.begin());
            return std::format("{}:{}", platform::format_ipv4(v4), port);
        }
    };

    enum class NatMapping : std::uint8_t {
        unknown, direct, endpoint_independent, address_dependent, address_and_port_dependent
    };
    enum class NatFiltering : std::uint8_t {
        unknown, endpoint_independent, address_dependent, address_and_port_dependent
    };

    inline auto mapping_name(NatMapping m) noexcept -> std::string_view {
        switch (m) {
        case NatMapping::direct: return "Direct";
        case NatMapping::endpoint_independent: return "Endpoint-Independent";
        case NatMapping::address_dependent: return "Address-Dependent";
        case NatMapping::address_and_port_dependent: return "Address-and-Port-Dependent";
        case NatMapping::unknown: return "Unknown";
        }
        return "Unknown";
    }

    inline auto filtering_name(NatFiltering f) noexcept -> std::string_view {
        switch (f) {
        case NatFiltering::endpoint_independent: return "Endpoint-Independent";
        case NatFiltering::address_dependent: return "Address-Dependent";
        case NatFiltering::address_and_port_dependent: return "Address-and-Port-Dependent";
        case NatFiltering::unknown: return "Unknown";
        }
        return "Unknown";
    }

    struct BindingResponse {
        std::optional<Endpoint> mapped;
        std::optional<Endpoint> other;
        std::optional<Endpoint> origin;
    };

    struct NatBehaviorReport {
        std::string server;
        std::optional<Endpoint> mapped_address;
        std::optional<Endpoint> other_address;
        NatMapping mapping = NatMapping::unknown;
        NatFiltering filtering = NatFiltering::unknown;
        double rtt_ms = 0.0;
        bool other_address_supported = false;
    };

    inline auto build_binding_request(std::span<std::uint8_t const, 12> tx_id,
        bool change_ip = false, bool change_port = false) -> std::vector<std::uint8_t> {
        bool has_change = change_ip || change_port;
        std::uint16_t attr_len = has_change ? 8u : 0u;
        std::vector<std::uint8_t> out(20u + attr_len, 0);
        out[0] = 0x00; out[1] = 0x01; // Binding Request
        out[2] = static_cast<std::uint8_t>(attr_len >> 8);
        out[3] = static_cast<std::uint8_t>(attr_len & 0xffu);
        out[4] = 0x21; out[5] = 0x12; out[6] = 0xa4; out[7] = 0x42; // RFC 5389 Magic Cookie
        std::ranges::copy(tx_id, out.begin() + 8);
        if (has_change) {
            out[20] = 0x00; out[21] = 0x03; // CHANGE-REQUEST (RFC 5780 §7.2)
            out[22] = 0x00; out[23] = 0x04;
            out[27] = static_cast<std::uint8_t>((change_ip ? 0x04u : 0u) | (change_port ? 0x02u : 0u));
        }
        return out;
    }

    inline auto parse_addr_attr(std::span<std::uint8_t const> pkt, std::size_t off,
        std::uint16_t len, bool xored) noexcept -> std::optional<Endpoint> {
        if (len < 8 || off + len > pkt.size()) return std::nullopt;
        std::uint8_t fam = pkt[off + 1];
        std::uint16_t port = (std::uint16_t(pkt[off + 2]) << 8) | pkt[off + 3];
        if (xored) port ^= 0x2112u;
        Endpoint ep{};
        ep.port = port;
        if (fam == 0x01 && len >= 8) {
            ep.ipv6 = false;
            std::copy_n(pkt.begin() + static_cast<std::ptrdiff_t>(off + 4), 4, ep.addr.begin());
            if (xored) {
                ep.addr[0] ^= 0x21; ep.addr[1] ^= 0x12; ep.addr[2] ^= 0xa4; ep.addr[3] ^= 0x42;
            }
            return ep;
        }
        if (fam == 0x02 && len >= 20) {
            ep.ipv6 = true;
            std::copy_n(pkt.begin() + static_cast<std::ptrdiff_t>(off + 4), 16, ep.addr.begin());
            if (xored) {
                for (std::size_t i = 0; i < 16; ++i) ep.addr[i] ^= pkt[4 + i];
            }
            return ep;
        }
        return std::nullopt;
    }

    inline auto parse_binding_response(std::span<std::uint8_t const> pkt,
        std::span<std::uint8_t const, 12> expected_tx_id) noexcept -> std::optional<BindingResponse> {
        if (pkt.size() < 20 || !sniff::stun_datagram(pkt)) return std::nullopt;
        std::uint16_t msg_type = (std::uint16_t(pkt[0]) << 8) | pkt[1];
        if (msg_type != 0x0101u) return std::nullopt;
        if (!std::ranges::equal(pkt.subspan(8, 12), expected_tx_id)) return std::nullopt;
        std::uint16_t msg_len = (std::uint16_t(pkt[2]) << 8) | pkt[3];
        if (20u + msg_len > pkt.size()) return std::nullopt;
        auto end = std::size_t{20} + msg_len;
        BindingResponse res{};
        std::optional<Endpoint> fallback_mapped;
        std::optional<Endpoint> fallback_other;
        std::size_t off = 20;
        while (off + 4 <= end) {
            std::uint16_t type = (std::uint16_t(pkt[off]) << 8) | pkt[off + 1];
            std::uint16_t len = (std::uint16_t(pkt[off + 2]) << 8) | pkt[off + 3];
            off += 4;
            if (off + len > end) break;
            if (type == 0x0020u) res.mapped = parse_addr_attr(pkt, off, len, true);
            else if (type == 0x0001u && !fallback_mapped) fallback_mapped = parse_addr_attr(pkt, off, len, false);
            else if (type == 0x802cu) res.other = parse_addr_attr(pkt, off, len, false);
            else if (type == 0x0005u && !fallback_other) fallback_other = parse_addr_attr(pkt, off, len, false);
            else if (type == 0x802bu || type == 0x0004u) {
                if (!res.origin) res.origin = parse_addr_attr(pkt, off, len, false);
            }
            off += (std::size_t{len} + 3u) & ~std::size_t{3};
        }
        if (!res.mapped) res.mapped = fallback_mapped;
        if (!res.other) res.other = fallback_other;
        if (!res.mapped) return std::nullopt;
        return res;
    }

    inline auto classify_nat_mapping(std::optional<Endpoint> const& local,
        Endpoint const& test1_mapped,
        std::optional<Endpoint> const& test2_mapped,
        std::optional<Endpoint> const& test3_mapped) noexcept -> NatMapping {
        if (local && *local == test1_mapped) return NatMapping::direct;
        if (!test2_mapped) return NatMapping::unknown;
        if (test1_mapped == *test2_mapped) return NatMapping::endpoint_independent;
        if (!test3_mapped) return NatMapping::unknown;
        if (*test2_mapped == *test3_mapped) return NatMapping::address_dependent;
        return NatMapping::address_and_port_dependent;
    }

    inline auto classify_nat_filtering(bool change_ip_port_replied, bool change_port_replied) noexcept -> NatFiltering {
        if (change_ip_port_replied) return NatFiltering::endpoint_independent;
        if (change_port_replied) return NatFiltering::address_dependent;
        return NatFiltering::address_and_port_dependent;
    }

    inline auto format_report_json(NatBehaviorReport const& r) -> std::string {
        std::string out = std::format("{{\"server\":{},\"rtt_ms\":{:.2f},\"other_address_supported\":{}",
            encoding::json_quote(r.server), r.rtt_ms, r.other_address_supported ? "true" : "false");
        if (r.mapped_address) out += std::format(",\"mapped_address\":{}", encoding::json_quote(r.mapped_address->format()));
        if (r.other_address) out += std::format(",\"other_address\":{}", encoding::json_quote(r.other_address->format()));
        out += std::format(",\"mapping\":{},\"filtering\":{}}}\n",
            encoding::json_quote(mapping_name(r.mapping)), encoding::json_quote(filtering_name(r.filtering)));
        return out;
    }

    inline auto format_report_text(NatBehaviorReport const& r) -> std::string {
        std::string out = std::format("Server: {}\nMapped Address: {}\nRTT: {:.2f} ms\n",
            r.server, r.mapped_address ? r.mapped_address->format() : "none", r.rtt_ms);
        if (r.other_address) out += std::format("Other Address: {}\n", r.other_address->format());
        out += std::format("NAT Mapping: {}\nNAT Filtering: {}\n",
            mapping_name(r.mapping), filtering_name(r.filtering));
        return out;
    }

    namespace detail {
        inline auto to_sockaddr(Endpoint const& ep, sockaddr_storage& ss, socklen_t& slen) noexcept -> bool {
            std::memset(&ss, 0, sizeof(ss));
            if (!ep.ipv6) {
                auto& s4 = *reinterpret_cast<sockaddr_in*>(&ss);
                s4.sin_family = AF_INET;
                s4.sin_port = htons(ep.port);
                std::memcpy(&s4.sin_addr, ep.addr.data(), 4);
                slen = sizeof(sockaddr_in);
                return true;
            }
            auto& s6 = *reinterpret_cast<sockaddr_in6*>(&ss);
            s6.sin6_family = AF_INET6;
            s6.sin6_port = htons(ep.port);
            std::memcpy(&s6.sin6_addr, ep.addr.data(), 16);
            slen = sizeof(sockaddr_in6);
            return true;
        }

        inline auto from_sockaddr(sockaddr const* sa) noexcept -> std::optional<Endpoint> {
            if (!sa) return std::nullopt;
            Endpoint ep{};
            if (sa->sa_family == AF_INET) {
                auto const& s4 = *reinterpret_cast<sockaddr_in const*>(sa);
                ep.ipv6 = false;
                ep.port = ntohs(s4.sin_port);
                std::memcpy(ep.addr.data(), &s4.sin_addr, 4);
                return ep;
            }
            if (sa->sa_family == AF_INET6) {
                auto const& s6 = *reinterpret_cast<sockaddr_in6 const*>(sa);
                ep.ipv6 = true;
                ep.port = ntohs(s6.sin6_port);
                std::memcpy(ep.addr.data(), &s6.sin6_addr, 16);
                return ep;
            }
            return std::nullopt;
        }

        inline auto exchange_once(auto fd, Endpoint const& dest, std::uint32_t timeout_ms,
            bool change_ip, bool change_port, double* rtt_ms = nullptr) -> std::optional<BindingResponse> {
            std::array<std::uint8_t, 12> tx{};
            if (!crypto::random_bytes(tx)) return std::nullopt;
            auto req = build_binding_request(tx, change_ip, change_port);
            sockaddr_storage ss{};
            socklen_t slen = 0;
            to_sockaddr(dest, ss, slen);
            auto const per_try = std::max<std::uint32_t>(250u, timeout_ms / 2u);
            for (int attempt = 0; attempt < 2; ++attempt) {
                auto t0 = std::chrono::steady_clock::now();
                if (::sendto(fd, reinterpret_cast<char const*>(req.data()), static_cast<int>(req.size()), 0,
                        reinterpret_cast<sockaddr const*>(&ss), slen) < 0)
                    return std::nullopt;
                auto deadline = t0 + std::chrono::milliseconds(per_try);
                while (std::chrono::steady_clock::now() < deadline) {
                    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
                    if (rem <= 0) break;
#ifdef _WIN32
                    fd_set rfds;
                    FD_ZERO(&rfds);
                    FD_SET(fd, &rfds);
                    timeval tv{static_cast<long>(rem / 1000), static_cast<long>((rem % 1000) * 1000)};
                    if (::select(0, &rfds, nullptr, nullptr, &tv) <= 0) break;
#else
                    pollfd pfd{fd, POLLIN, 0};
                    if (::poll(&pfd, 1, static_cast<int>(rem)) <= 0) break;
#endif
                    std::array<std::uint8_t, 1024> rx{};
                    auto n = ::recvfrom(fd, reinterpret_cast<char*>(rx.data()), static_cast<int>(rx.size()), 0, nullptr, nullptr);
                    if (n < 20) continue;
                    if (auto parsed = parse_binding_response(std::span(rx).first(static_cast<std::size_t>(n)), tx)) {
                        if (rtt_ms) *rtt_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
                        return parsed;
                    }
                }
            }
            return std::nullopt;
        }
    }

    inline auto probe_nat_behavior(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms = 3000)
        -> std::expected<NatBehaviorReport, std::string> {
#ifdef _WIN32
        static bool wsa_ok = []() noexcept { WSADATA d{}; return ::WSAStartup(MAKEWORD(2, 2), &d) == 0; }();
        (void)wsa_ok;
#endif
        addrinfo hints{};
        hints.ai_socktype = SOCK_DGRAM;
        std::string host_s(host), port_s = std::to_string(port);
        addrinfo* res = nullptr;
        if (::getaddrinfo(host_s.c_str(), port_s.c_str(), &hints, &res) != 0 || !res)
            return std::unexpected("STUN server resolution failed");
        struct FreeAi { addrinfo* p; ~FreeAi() { if (p) ::freeaddrinfo(p); } } ai_guard{res};

        for (auto* ai = res; ai != nullptr; ai = ai->ai_next) {
            auto primary = detail::from_sockaddr(ai->ai_addr);
            if (!primary) continue;
#ifdef _WIN32
            SOCKET raw = ::socket(ai->ai_family, SOCK_DGRAM, ai->ai_protocol);
            if (raw == INVALID_SOCKET) continue;
            struct CloseSock { SOCKET s; ~CloseSock() { ::closesocket(s); } } sg{raw};
            auto fd = raw;
#else
            platform::UniqueFd sg(::socket(ai->ai_family, SOCK_DGRAM, ai->ai_protocol));
            if (!sg.valid()) continue;
            auto fd = sg.get();
#endif
            double rtt = 0.0;
            auto t1 = detail::exchange_once(fd, *primary, timeout_ms, false, false, &rtt);
            if (!t1 || !t1->mapped) continue;

            NatBehaviorReport report{};
            report.server = std::format("{}:{}", host, port);
            report.mapped_address = t1->mapped;
            report.other_address = t1->other;
            report.rtt_ms = rtt;

            sockaddr_storage lss{};
            socklen_t lslen = sizeof(lss);
            std::optional<Endpoint> local_ep;
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&lss), &lslen) == 0)
                local_ep = detail::from_sockaddr(reinterpret_cast<sockaddr const*>(&lss));

            if (!t1->other || t1->other->ipv6 != primary->ipv6 || t1->other->same_ip(*primary) || t1->other->port == 0) {
                report.other_address_supported = false;
                report.mapping = (local_ep && *local_ep == *t1->mapped) ? NatMapping::direct : NatMapping::unknown;
                report.filtering = NatFiltering::unknown;
                return report;
            }
            report.other_address_supported = true;

            // Mapping Test II: alternate IP, primary port
            Endpoint alt_ip_pri_port = *t1->other;
            alt_ip_pri_port.port = primary->port;
            auto m2 = detail::exchange_once(fd, alt_ip_pri_port, timeout_ms, false, false);
            std::optional<Endpoint> m2_mapped = m2 ? m2->mapped : std::nullopt;
            std::optional<Endpoint> m3_mapped;
            if (m2_mapped && !(*m2_mapped == *t1->mapped)) {
                // Mapping Test III: alternate IP, alternate port
                auto m3 = detail::exchange_once(fd, *t1->other, timeout_ms, false, false);
                if (m3) m3_mapped = m3->mapped;
            }
            report.mapping = classify_nat_mapping(local_ep, *t1->mapped, m2_mapped, m3_mapped);

            // Filtering Test II: CHANGE-REQUEST (change IP + change port)
            auto f2 = detail::exchange_once(fd, *primary, timeout_ms, true, true);
            bool f3_ok = false;
            if (!f2) {
                // Filtering Test III: CHANGE-REQUEST (change port only)
                auto f3 = detail::exchange_once(fd, *primary, timeout_ms, false, true);
                f3_ok = f3.has_value();
            }
            report.filtering = classify_nat_filtering(f2.has_value(), f3_ok);
            return report;
        }
        return std::unexpected("STUN RFC 5780 probe failed or timed out");
    }
}
