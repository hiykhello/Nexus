module;
#if defined(__APPLE__)
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

module packet.tun_network_darwin;
import std;

namespace packet {
    auto plan_darwin_tun_network(TunRoutePlanInput const& input, std::string_view ifname)
        -> std::expected<TunRoutePlan, std::string> {
        if (!ifname.empty()) {
            if (ifname.size() > 15 || !ifname.starts_with("utun") || ifname.size() == 4)
                return std::unexpected("Darwin TUN requires utun<N> interface name or empty");
            auto digits = ifname.substr(4);
            unsigned unit = 0;
            auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), unit);
            if (ec != std::errc{} || end != digits.data() + digits.size())
                return std::unexpected("Darwin TUN requires numeric utun<N> suffix");
        }
        return plan_cross_platform_tun_routes(input);
    }

#if defined(__APPLE__)
    namespace {
        // Darwin XNU bsd/net/rtsock.c uses 32-bit sockaddr alignment (ROUNDUP32).
        constexpr auto roundup_sa(std::size_t len) noexcept -> std::size_t {
            constexpr std::size_t align = sizeof(std::uint32_t);
            return len > 0 ? (1u + ((len - 1u) | (align - 1u))) : align;
        }

        struct GatewayAddr {
            sockaddr_storage ss{};
            std::size_t len = 0;
            int flags = 0;
            bool valid = false;
        };

        struct RouteRecord {
            TunCidr dst;
            GatewayAddr gw;
        };

        auto mask_from_prefix(std::uint8_t prefix, sockaddr_in& out) noexcept -> void {
            std::memset(&out, 0, sizeof(out));
            out.sin_len = sizeof(out);
            out.sin_family = AF_INET;
            std::uint32_t m = prefix == 0 ? 0u : (0xffffffffu << (32u - prefix));
            out.sin_addr.s_addr = htonl(m);
        }

        auto mask_from_prefix6(std::uint8_t prefix, sockaddr_in6& out) noexcept -> void {
            std::memset(&out, 0, sizeof(out));
            out.sin6_len = sizeof(out);
            out.sin6_family = AF_INET6;
            for (unsigned i = 0; i < prefix; ++i)
                out.sin6_addr.s6_addr[i / 8] |= static_cast<std::uint8_t>(0x80u >> (i % 8));
        }

        auto make_iface_gateway(unsigned int ifindex) noexcept -> GatewayAddr {
            GatewayAddr out{};
            sockaddr_dl sdl{};
            sdl.sdl_len = sizeof(sockaddr_dl);
            sdl.sdl_family = AF_LINK;
            sdl.sdl_index = static_cast<u_short>(ifindex);
            std::memcpy(&out.ss, &sdl, sizeof(sdl));
            out.len = sizeof(sdl);
            out.flags = 0;
            out.valid = true;
            return out;
        }

        auto append_sa(std::span<std::uint8_t> buf, std::size_t& off, void const* sa, std::size_t len) noexcept -> bool {
            std::size_t step = roundup_sa(len);
            if (len > step || step > buf.size() - off) return false;
            std::memcpy(buf.data() + off, sa, len);
            if (step > len) std::memset(buf.data() + off + len, 0, step - len);
            off += step;
            return true;
        }

        auto route_msg(int rtm_fd, int cmd, TunCidr const& dst, GatewayAddr const& gw, int seq) noexcept -> std::error_code {
            std::array<std::uint8_t, 512> buf{};
            rt_msghdr hdr{};
            hdr.rtm_type = static_cast<u_char>(cmd);
            hdr.rtm_version = RTM_VERSION;
            hdr.rtm_flags = RTF_UP | RTF_STATIC | gw.flags;
            hdr.rtm_seq = seq;
            hdr.rtm_pid = ::getpid();
            hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
            std::size_t off = sizeof(rt_msghdr);
            if (dst.family == 4) {
                sockaddr_in d{}, m{};
                d.sin_len = sizeof(d); d.sin_family = AF_INET;
                std::memcpy(&d.sin_addr, dst.address.data(), 4);
                mask_from_prefix(dst.prefix, m);
                if (!append_sa(buf, off, &d, sizeof(d)) || !append_sa(buf, off, &gw.ss, gw.len) ||
                    !append_sa(buf, off, &m, sizeof(m)))
                    return std::make_error_code(std::errc::message_size);
            } else {
                sockaddr_in6 d{}, m{};
                d.sin6_len = sizeof(d); d.sin6_family = AF_INET6;
                std::memcpy(&d.sin6_addr, dst.address.data(), 16);
                mask_from_prefix6(dst.prefix, m);
                if (!append_sa(buf, off, &d, sizeof(d)) || !append_sa(buf, off, &gw.ss, gw.len) ||
                    !append_sa(buf, off, &m, sizeof(m)))
                    return std::make_error_code(std::errc::message_size);
            }
            hdr.rtm_msglen = static_cast<u_short>(off);
            std::memcpy(buf.data(), &hdr, sizeof(hdr));
            if (::write(rtm_fd, buf.data(), off) < 0) {
                if (cmd == RTM_DELETE && errno == ESRCH) return {};
                return {errno, std::generic_category()};
            }
            return {};
        }

        auto query_default_gateway(int rtm_fd, std::uint8_t family, unsigned int tun_ifindex, int seq) noexcept -> GatewayAddr {
            std::array<std::uint8_t, 512> req{};
            rt_msghdr hdr{};
            pid_t const pid = ::getpid();
            hdr.rtm_type = RTM_GET;
            hdr.rtm_version = RTM_VERSION;
            hdr.rtm_flags = RTF_UP;
            hdr.rtm_seq = seq;
            hdr.rtm_pid = pid;
            hdr.rtm_addrs = RTA_DST | RTA_NETMASK;
            std::size_t off = sizeof(rt_msghdr);
            if (family == 4) {
                sockaddr_in z{};
                z.sin_len = sizeof(z); z.sin_family = AF_INET;
                if (!append_sa(req, off, &z, sizeof(z)) || !append_sa(req, off, &z, sizeof(z))) return {};
            } else {
                sockaddr_in6 z{};
                z.sin6_len = sizeof(z); z.sin6_family = AF_INET6;
                if (!append_sa(req, off, &z, sizeof(z)) || !append_sa(req, off, &z, sizeof(z))) return {};
            }
            hdr.rtm_msglen = static_cast<u_short>(off);
            std::memcpy(req.data(), &hdr, sizeof(hdr));
            timeval tv{.tv_sec = 1, .tv_usec = 0};
            (void)::setsockopt(rtm_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (::write(rtm_fd, req.data(), off) < 0) return {};
            std::array<std::uint8_t, 2048> rep{};
            for (int tries = 0; tries < 16; ++tries) {
                ssize_t n = ::read(rtm_fd, rep.data(), rep.size());
                if (n < static_cast<ssize_t>(sizeof(rt_msghdr))) break;
                rt_msghdr rh{};
                std::memcpy(&rh, rep.data(), sizeof(rh));
                if (rh.rtm_type != RTM_GET || rh.rtm_pid != pid || rh.rtm_seq != seq) continue;
                if (rh.rtm_errno != 0 || rh.rtm_index == tun_ifindex) return {};
                std::size_t pos = sizeof(rt_msghdr);
                std::size_t end = std::min<std::size_t>(static_cast<std::size_t>(n), rh.rtm_msglen);
                for (int bit = 1; bit <= RTA_NETMASK && pos < end; bit <<= 1) {
                    if (!(rh.rtm_addrs & bit)) continue;
                    sockaddr sa{};
                    if (end - pos < sizeof(sa.sa_len) + sizeof(sa.sa_family)) break;
                    std::memcpy(&sa, rep.data() + pos, std::min<std::size_t>(sizeof(sa), end - pos));
                    std::size_t salen = sa.sa_len;
                    std::size_t step = roundup_sa(salen);
                    if (bit == RTA_GATEWAY && salen > 0 && salen <= sizeof(sockaddr_storage) && pos + salen <= end) {
                        GatewayAddr gw{};
                        std::memcpy(&gw.ss, rep.data() + pos, salen);
                        gw.len = salen;
                        gw.flags = (rh.rtm_flags & RTF_GATEWAY) ? RTF_GATEWAY : 0;
                        gw.valid = true;
                        return gw;
                    }
                    if (step > end - pos) break;
                    pos += step;
                }
                return {};
            }
            return {};
        }
    }

    struct DarwinTunNetwork::Impl {
        std::string ifname;
        unsigned int ifindex = 0;
        std::vector<TunCidr> installed_v4;
        std::vector<TunCidr> installed_v6;
        std::vector<RouteRecord> installed_routes;
        bool active = false;
    };

    DarwinTunNetwork::DarwinTunNetwork() : impl_(std::make_unique<Impl>()) {}
    DarwinTunNetwork::~DarwinTunNetwork() { stop(); }
    DarwinTunNetwork::DarwinTunNetwork(DarwinTunNetwork&&) noexcept = default;
    auto DarwinTunNetwork::operator=(DarwinTunNetwork&&) noexcept -> DarwinTunNetwork& = default;

    auto DarwinTunNetwork::start(std::string_view ifname, TunRoutePlan const& plan)
        -> std::expected<void, std::error_code> {
        stop();
        if (ifname.empty() || ifname.size() >= IFNAMSIZ)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (!impl_) impl_ = std::make_unique<Impl>();
        impl_->ifname = std::string(ifname);
        impl_->ifindex = ::if_nametoindex(impl_->ifname.c_str());
        if (!impl_->ifindex) return std::unexpected(std::make_error_code(std::errc::no_such_device));

        int rtm = -1;
        if (!plan.routes.empty()) {
            rtm = ::socket(PF_ROUTE, SOCK_RAW, 0);
            if (rtm < 0) return std::unexpected(std::error_code{errno, std::generic_category()});
        }
        struct FdGuard { int fd; ~FdGuard() { if (fd >= 0) ::close(fd); } } gr{rtm};
        int seq = 1;
        std::optional<GatewayAddr> gw4, gw6;
        auto resolve_exclude = [&](TunCidr const& exc) -> std::expected<GatewayAddr, std::error_code> {
            auto& cached = exc.family == 4 ? gw4 : gw6;
            if (!cached) cached = query_default_gateway(rtm, exc.family, impl_->ifindex, seq++);
            if (!cached->valid) return std::unexpected(std::make_error_code(std::errc::network_unreachable));
            return *cached;
        };
        auto configure_interface = [&]() -> std::error_code {
            int s4 = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (s4 < 0) return {errno, std::generic_category()};
            FdGuard g4{s4};

            ifreq mtu_req{};
            std::strncpy(mtu_req.ifr_name, impl_->ifname.c_str(), IFNAMSIZ - 1);
            mtu_req.ifr_mtu = static_cast<int>(plan.mtu);
            if (::ioctl(s4, SIOCSIFMTU, &mtu_req) < 0) return {errno, std::generic_category()};

            bool has_v6_addr = false;
            for (auto const& addr : plan.addresses) {
                if (addr.family == 6) { has_v6_addr = true; continue; }
                if (addr.family == 4) {
                    ifaliasreq a4{};
                    std::strncpy(a4.ifra_name, impl_->ifname.c_str(), IFNAMSIZ - 1);
                    auto* sin = reinterpret_cast<sockaddr_in*>(&a4.ifra_addr);
                    sin->sin_len = sizeof(sockaddr_in); sin->sin_family = AF_INET;
                    std::memcpy(&sin->sin_addr, addr.address.data(), 4);
                    auto* dst = reinterpret_cast<sockaddr_in*>(&a4.ifra_dstaddr);
                    *dst = *sin;
                    mask_from_prefix(addr.prefix, *reinterpret_cast<sockaddr_in*>(&a4.ifra_mask));
                    if (::ioctl(s4, SIOCAIFADDR, &a4) < 0) {
                        if (errno != EEXIST) return {errno, std::generic_category()};
                    } else {
                        impl_->installed_v4.push_back(addr);
                    }
                }
            }
            if (has_v6_addr) {
                int s6 = ::socket(AF_INET6, SOCK_DGRAM, 0);
                if (s6 < 0) return {errno, std::generic_category()};
                FdGuard g6{s6};
                for (auto const& addr : plan.addresses) {
                    if (addr.family != 6) continue;
                    in6_aliasreq a6{};
                    std::strncpy(a6.ifra_name, impl_->ifname.c_str(), IFNAMSIZ - 1);
                    a6.ifra_addr.sin6_len = sizeof(sockaddr_in6); a6.ifra_addr.sin6_family = AF_INET6;
                    std::memcpy(&a6.ifra_addr.sin6_addr, addr.address.data(), 16);
                    mask_from_prefix6(addr.prefix, a6.ifra_prefixmask);
                    a6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
                    a6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
                    if (::ioctl(s6, SIOCAIFADDR_IN6, &a6) < 0) {
                        if (errno != EEXIST) return {errno, std::generic_category()};
                    } else {
                        impl_->installed_v6.push_back(addr);
                    }
                }
            }
            ifreq flags_req{};
            std::strncpy(flags_req.ifr_name, impl_->ifname.c_str(), IFNAMSIZ - 1);
            if (::ioctl(s4, SIOCGIFFLAGS, &flags_req) == 0) {
                flags_req.ifr_flags |= IFF_UP | IFF_RUNNING;
                (void)::ioctl(s4, SIOCSIFFLAGS, &flags_req);
            }
            return {};
        };
        auto install_exclude = [&](TunCidr const& exc, GatewayAddr const& gw) -> std::error_code {
            auto err = route_msg(rtm, RTM_ADD, exc, gw, seq++);
            if (!err) impl_->installed_routes.push_back({exc, gw});
            else if (err != std::errc::file_exists) return err;
            return {};
        };
        auto tun_gw = make_iface_gateway(impl_->ifindex);
        auto install_capture = [&](TunCidr const& rt) -> std::error_code {
            auto err = route_msg(rtm, RTM_ADD, rt, tun_gw, seq++);
            if (!err) impl_->installed_routes.push_back({rt, tun_gw});
            else if (err != std::errc::file_exists) return err;
            return {};
        };
        auto applied = apply_tun_route_plan(
            plan, resolve_exclude, configure_interface, install_exclude, install_capture, [&]() noexcept { stop(); });
        if (!applied) return std::unexpected(applied.error());
        impl_->active = true;
        return {};
    }

    auto DarwinTunNetwork::stop() noexcept -> void {
        if (!impl_) return;
        if (!impl_->installed_routes.empty()) {
            if (int rtm = ::socket(PF_ROUTE, SOCK_RAW, 0); rtm >= 0) {
                int seq = 100;
                for (auto it = impl_->installed_routes.rbegin(); it != impl_->installed_routes.rend(); ++it)
                    (void)route_msg(rtm, RTM_DELETE, it->dst, it->gw, seq++);
                ::close(rtm);
            }
            impl_->installed_routes.clear();
        }
        if (!impl_->installed_v6.empty()) {
            if (int s6 = ::socket(AF_INET6, SOCK_DGRAM, 0); s6 >= 0) {
                for (auto const& addr : impl_->installed_v6) {
                    in6_ifreq a6{};
                    std::strncpy(a6.ifr_name, impl_->ifname.c_str(), IFNAMSIZ - 1);
                    a6.ifr_addr.sin6_len = sizeof(sockaddr_in6); a6.ifr_addr.sin6_family = AF_INET6;
                    std::memcpy(&a6.ifr_addr.sin6_addr, addr.address.data(), 16);
                    (void)::ioctl(s6, SIOCDIFADDR_IN6, &a6);
                }
                ::close(s6);
            }
            impl_->installed_v6.clear();
        }
        if (!impl_->installed_v4.empty()) {
            if (int s4 = ::socket(AF_INET, SOCK_DGRAM, 0); s4 >= 0) {
                for (auto const& addr : impl_->installed_v4) {
                    ifreq a4{};
                    std::strncpy(a4.ifr_name, impl_->ifname.c_str(), IFNAMSIZ - 1);
                    auto* sin = reinterpret_cast<sockaddr_in*>(&a4.ifr_addr);
                    sin->sin_len = sizeof(sockaddr_in); sin->sin_family = AF_INET;
                    std::memcpy(&sin->sin_addr, addr.address.data(), 4);
                    (void)::ioctl(s4, SIOCDIFADDR, &a4);
                }
                ::close(s4);
            }
            impl_->installed_v4.clear();
        }
        impl_->active = false;
    }

    auto DarwinTunNetwork::active() const noexcept -> bool {
        return impl_ && impl_->active;
    }
#else
    struct DarwinTunNetwork::Impl { bool active = false; };
    DarwinTunNetwork::DarwinTunNetwork() : impl_(std::make_unique<Impl>()) {}
    DarwinTunNetwork::~DarwinTunNetwork() = default;
    DarwinTunNetwork::DarwinTunNetwork(DarwinTunNetwork&&) noexcept = default;
    auto DarwinTunNetwork::operator=(DarwinTunNetwork&&) noexcept -> DarwinTunNetwork& = default;
    auto DarwinTunNetwork::start(std::string_view, TunRoutePlan const&)
        -> std::expected<void, std::error_code> {
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    }
    auto DarwinTunNetwork::stop() noexcept -> void { if (impl_) impl_->active = false; }
    auto DarwinTunNetwork::active() const noexcept -> bool { return impl_ && impl_->active; }
#endif
}
