module;
#if defined(__APPLE__)
#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>
#endif

module platform.network_state;
import std;

namespace platform::network {
#if defined(__APPLE__)
    namespace {
        auto netmask_prefix(sockaddr const* mask, int family,
            std::size_t avail_bytes = std::numeric_limits<std::size_t>::max()) noexcept -> std::uint8_t {
            if (!mask || avail_bytes < 2) return family == AF_INET ? 32 : 128;
            std::size_t const bounded = std::min<std::size_t>(mask->sa_len, avail_bytes);
            if (bounded == 0) return 0;
            if (mask->sa_family != 0 && mask->sa_family != family) return family == AF_INET ? 32 : 128;
            std::size_t const addr_off = family == AF_INET
                ? offsetof(sockaddr_in, sin_addr) : offsetof(sockaddr_in6, sin6_addr);
            std::size_t const max_len = family == AF_INET ? 4u : 16u;
            if (bounded <= addr_off) return 0;
            std::size_t const len = std::min<std::size_t>(max_len, bounded - addr_off);
            auto const* bytes = reinterpret_cast<std::uint8_t const*>(mask) + addr_off;
            std::uint8_t prefix = 0;
            for (std::size_t i = 0; i < len; ++i) {
                if (bytes[i] == 0xff) { prefix += 8; continue; }
                for (int b = 7; b >= 0 && (bytes[i] & (1u << b)); --b) ++prefix;
                break;
            }
            return prefix;
        }

        auto darwin_is_wifi(std::string_view ifname) noexcept -> bool {
            if (ifname.empty() || ifname.size() >= IFNAMSIZ) return false;
            int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return false;
            struct ifmediareq ifmr{};
            std::memcpy(ifmr.ifm_name, ifname.data(), ifname.size());
            bool wifi = (::ioctl(fd, SIOCGIFMEDIA, &ifmr) == 0) &&
                (IFM_TYPE(ifmr.ifm_active) == IFM_IEEE80211 || IFM_TYPE(ifmr.ifm_current) == IFM_IEEE80211);
            ::close(fd);
            return wifi;
        }

        auto darwin_default_ifindex(int family) noexcept -> std::uint32_t {
            try {
                int mib[6] = {CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP, 0};
                std::size_t needed = 0;
                if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) != 0 || needed == 0 || needed > 4 * 1024 * 1024)
                    return 0;
                std::vector<std::byte> buf(needed);
                if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) != 0) return 0;
                auto step_sa = [](sockaddr const* sa) noexcept -> std::size_t {
                    std::size_t len = sa->sa_len;
                    return len == 0 ? sizeof(std::uint32_t) : (1u + ((len - 1u) | (sizeof(std::uint32_t) - 1u)));
                };
                std::size_t off = 0;
                while (off + sizeof(rt_msghdr) <= needed) {
                    auto const* rtm = reinterpret_cast<rt_msghdr const*>(buf.data() + off);
                    if (rtm->rtm_msglen < sizeof(rt_msghdr) || off + rtm->rtm_msglen > needed) break;
                    std::size_t const msg_end = off + rtm->rtm_msglen;
                    if ((rtm->rtm_flags & (RTF_UP | RTF_GATEWAY)) == (RTF_UP | RTF_GATEWAY) &&
                        rtm->rtm_index > 0 && (rtm->rtm_addrs & RTA_DST)) {
                        std::size_t aoff = off + sizeof(rt_msghdr);
                        if (aoff + 2 <= msg_end) {
                            auto const* dst = reinterpret_cast<sockaddr const*>(buf.data() + aoff);
                            std::size_t const dst_avail = msg_end - aoff;
                            std::size_t const dst_step = step_sa(dst);
                            bool zero_dst = false;
                            if (dst->sa_len <= dst_avail && dst_step <= dst_avail) {
                                if (family == AF_INET && dst->sa_family == AF_INET &&
                                    dst->sa_len >= sizeof(sockaddr_in) && sizeof(sockaddr_in) <= dst_avail)
                                    zero_dst = reinterpret_cast<sockaddr_in const*>(dst)->sin_addr.s_addr == 0;
                                else if (family == AF_INET6 && dst->sa_family == AF_INET6 &&
                                    dst->sa_len >= sizeof(sockaddr_in6) && sizeof(sockaddr_in6) <= dst_avail)
                                    zero_dst = IN6_IS_ADDR_UNSPECIFIED(&reinterpret_cast<sockaddr_in6 const*>(dst)->sin6_addr);
                            }
                            if (zero_dst) {
                                bool zero_mask = !(rtm->rtm_addrs & RTA_NETMASK);
                                if (!zero_mask) {
                                    aoff += dst_step;
                                    bool ok = true;
                                    if (rtm->rtm_addrs & RTA_GATEWAY) {
                                        if (aoff + 2 > msg_end) ok = false;
                                        else {
                                            auto const* gw = reinterpret_cast<sockaddr const*>(buf.data() + aoff);
                                            std::size_t const gw_step = step_sa(gw);
                                            if (gw->sa_len > msg_end - aoff || gw_step > msg_end - aoff) ok = false;
                                            else aoff += gw_step;
                                        }
                                    }
                                    if (ok && aoff + 2 <= msg_end) {
                                        auto const* mask = reinterpret_cast<sockaddr const*>(buf.data() + aoff);
                                        std::size_t const mask_avail = msg_end - aoff;
                                        zero_mask = mask->sa_len == 0 ||
                                            (mask->sa_len <= mask_avail && netmask_prefix(mask, family, mask_avail) == 0);
                                    }
                                }
                                if (zero_mask) return static_cast<std::uint32_t>(rtm->rtm_index);
                            }
                        }
                    }
                    off += rtm->rtm_msglen;
                }
                return 0;
            } catch (...) {
                return 0;
            }
        }

        auto parse_bssid_text(std::string_view text) noexcept -> std::optional<MacAddress> {
            MacAddress mac{};
            std::size_t idx = 0, pos = 0;
            while (idx < 6 && pos < text.size()) {
                auto colon = text.find(':', pos);
                auto part = colon == text.npos ? text.substr(pos) : text.substr(pos, colon - pos);
                if (part.empty() || part.size() > 2) return {};
                unsigned v = 0;
                auto [end, ec] = std::from_chars(part.data(), part.data() + part.size(), v, 16);
                if (ec != std::errc{} || end != part.data() + part.size() || v > 0xff) return {};
                mac[idx++] = static_cast<std::uint8_t>(v);
                if (colon == text.npos) break;
                pos = colon + 1;
            }
            if (idx != 6) return {};
            bool any_nz = false, any_nff = false;
            for (auto b : mac) { any_nz |= (b != 0); any_nff |= (b != 0xff); }
            return (any_nz && any_nff) ? std::optional(mac) : std::nullopt;
        }

        auto darwin_read_wifi_sc(std::string_view ifname, std::optional<std::string>& ssid,
            std::optional<MacAddress>& bssid) noexcept -> void {
            using CFTypeRef = void const*;
            using CFStringRef = void const*;
            using CFDictionaryRef = void const*;
            using SCDynamicStoreRef = void const*;
            using CreateStoreFn = SCDynamicStoreRef(*)(void const*, CFStringRef, void const*, void const*);
            using CopyValueFn = CFTypeRef(*)(SCDynamicStoreRef, CFStringRef);
            using StrCreateFn = CFStringRef(*)(void const*, char const*, std::uint32_t);
            using StrGetFn = unsigned char(*)(CFStringRef, char*, long, std::uint32_t);
            using DictGetFn = CFTypeRef(*)(CFDictionaryRef, void const*);
            using GetTypeIdFn = unsigned long(*)(CFTypeRef);
            using StaticTypeIdFn = unsigned long(*)();
            using ReleaseFn = void(*)(CFTypeRef);
            static void* sc_lib = ::dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_LAZY | RTLD_LOCAL);
            static void* cf_lib = ::dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY | RTLD_LOCAL);
            if (!sc_lib || !cf_lib) return;
            auto create_store = reinterpret_cast<CreateStoreFn>(::dlsym(sc_lib, "SCDynamicStoreCreate"));
            auto copy_val = reinterpret_cast<CopyValueFn>(::dlsym(sc_lib, "SCDynamicStoreCopyValue"));
            auto str_create = reinterpret_cast<StrCreateFn>(::dlsym(cf_lib, "CFStringCreateWithCString"));
            auto str_get = reinterpret_cast<StrGetFn>(::dlsym(cf_lib, "CFStringGetCString"));
            auto dict_get = reinterpret_cast<DictGetFn>(::dlsym(cf_lib, "CFDictionaryGetValue"));
            auto get_tid = reinterpret_cast<GetTypeIdFn>(::dlsym(cf_lib, "CFGetTypeID"));
            auto dict_tid = reinterpret_cast<StaticTypeIdFn>(::dlsym(cf_lib, "CFDictionaryGetTypeID"));
            auto str_tid = reinterpret_cast<StaticTypeIdFn>(::dlsym(cf_lib, "CFStringGetTypeID"));
            auto release = reinterpret_cast<ReleaseFn>(::dlsym(cf_lib, "CFRelease"));
            if (!create_store || !copy_val || !str_create || !str_get || !dict_get || !get_tid || !dict_tid || !str_tid || !release)
                return;
            constexpr std::uint32_t kCFStringEncodingUTF8 = 0x08000100u;
            CFStringRef name_cf = str_create(nullptr, "nexus-netstate", kCFStringEncodingUTF8);
            if (!name_cf) return;
            SCDynamicStoreRef store = create_store(nullptr, name_cf, nullptr, nullptr);
            release(name_cf);
            if (!store) return;
            struct CfGuard { ReleaseFn fn; CFTypeRef ref; ~CfGuard() { if (ref) fn(ref); } };
            CfGuard store_guard{release, store};
            try {
                std::string key = "State:/Network/Interface/" + std::string(ifname) + "/AirPort";
                CFStringRef key_cf = str_create(nullptr, key.c_str(), kCFStringEncodingUTF8);
                CFTypeRef val = key_cf ? copy_val(store, key_cf) : nullptr;
                if (key_cf) release(key_cf);
                CfGuard val_guard{release, val};
                if (val && get_tid(val) == dict_tid()) {
                    auto read_str = [&](char const* k) -> std::string {
                        CFStringRef kcf = str_create(nullptr, k, kCFStringEncodingUTF8);
                        if (!kcf) return {};
                        CFTypeRef v = dict_get(val, kcf);
                        release(kcf);
                        if (!v || get_tid(v) != str_tid()) return {};
                        char buf[128]{};
                        return str_get(v, buf, sizeof(buf), kCFStringEncodingUTF8) ? std::string(buf) : std::string{};
                    };
                    if (auto s = read_str("SSID_STR"); !s.empty() && s.size() <= 32) ssid = std::move(s);
                    if (auto b = read_str("BSSID"); !b.empty()) bssid = parse_bssid_text(b);
                }
            } catch (...) {}
        }

        auto find_or_add_link(std::vector<Link>& links, std::uint32_t index, std::string_view name,
            unsigned int flags) -> void {
            for (auto& existing : links) {
                if (existing.index == index) {
                    existing.flags |= ((flags & IFF_UP) ? constants::iff_up : 0u) |
                                      ((flags & IFF_RUNNING) ? constants::iff_lower_up : 0u);
                    return;
                }
            }
            Link link{};
            link.index = index;
            link.name = std::string(name);
            link.flags = ((flags & IFF_UP) ? constants::iff_up : 0u) |
                         ((flags & IFF_RUNNING) ? constants::iff_lower_up : 0u);
            if (link.name.starts_with("pdp_ip")) link.kind = "wwan";
            else if (darwin_is_wifi(link.name)) link.kind = "wlan";
            links.push_back(std::move(link));
        }
    }

    struct Monitor::Impl {
        bool active = false;
    };

    Monitor::Monitor(bool include_neighbors)
        : impl_(std::make_unique<Impl>()), include_neighbors_(include_neighbors) {}
    Monitor::~Monitor() = default;

    auto Monitor::started() const noexcept -> bool { return impl_ && impl_->active; }

    auto Monitor::start(Clock::time_point deadline) -> std::expected<void, MonitorFailure> {
        if (!impl_) return fail_monitor(MonitorError::closed);
        if (impl_->active) return fail_monitor(MonitorError::configuration);
        impl_->active = true;
        auto loaded = refresh(deadline);
        if (!loaded) impl_->active = false;
        return loaded;
    }

    auto Monitor::poll(Clock::time_point deadline) -> std::expected<bool, MonitorFailure> {
        if (!impl_ || !impl_->active) return fail_monitor(MonitorError::closed);
        if (get()) return false;
        auto loaded = refresh(deadline);
        if (!loaded) return std::unexpected(loaded.error());
        return true;
    }

    auto Monitor::refresh(Clock::time_point deadline) -> std::expected<void, MonitorFailure> {
        if (!impl_ || !impl_->active) return fail_monitor(MonitorError::closed);
        if (Clock::now() >= deadline) return fail_monitor(MonitorError::timeout);
        if (generation_ == std::numeric_limits<std::uint64_t>::max())
            return fail_monitor(MonitorError::sequence_exhausted);
        invalidate();

        struct ifaddrs* list = nullptr;
        if (::getifaddrs(&list) != 0) {
            return fail_monitor(MonitorError::system, {errno, std::generic_category()});
        }
        auto candidate = std::make_shared<Snapshot>();
        std::vector<std::pair<std::uint32_t, std::uint8_t>> routed;
        for (auto* cur = list; cur; cur = cur->ifa_next) {
            if (!cur->ifa_name || !cur->ifa_addr) continue;
            unsigned int idx = ::if_nametoindex(cur->ifa_name);
            if (idx == 0) continue;
            find_or_add_link(candidate->links, idx, cur->ifa_name, cur->ifa_flags);
            int fam = cur->ifa_addr->sa_family;
            if (fam != AF_INET && fam != AF_INET6) continue;
            Address addr{};
            addr.index = idx;
            addr.family = (fam == AF_INET) ? constants::af_inet : constants::af_inet6;
            addr.prefix = netmask_prefix(cur->ifa_netmask, fam);
            if (fam == AF_INET) {
                auto const* s4 = reinterpret_cast<sockaddr_in const*>(cur->ifa_addr);
                std::memcpy(addr.local.data(), &s4->sin_addr, 4);
                addr.scope = constants::rt_scope_universe;
            } else {
                auto const* s6 = reinterpret_cast<sockaddr_in6 const*>(cur->ifa_addr);
                std::memcpy(addr.local.data(), &s6->sin6_addr, 16);
                addr.scope = IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr) ? 253 : constants::rt_scope_universe;
            }
            candidate->addresses.push_back(addr);
            if (!(cur->ifa_flags & IFF_LOOPBACK) && (cur->ifa_flags & IFF_UP) &&
                (cur->ifa_flags & IFF_RUNNING) && addr.scope == constants::rt_scope_universe) {
                routed.emplace_back(idx, addr.family);
            }
        }
        ::freeifaddrs(list);
        for (auto [idx, fam] : routed) {
            Route route{};
            route.family = fam;
            route.index = idx;
            route.table = constants::rt_table_main;
            route.type = constants::rtn_unicast;
            route.scope = constants::rt_scope_universe;
            candidate->routes.push_back(route);
        }
        std::ranges::sort(candidate->links, {}, &Link::index);
        std::uint32_t def_idx = darwin_default_ifindex(AF_INET);
        if (!def_idx) def_idx = darwin_default_ifindex(AF_INET6);
        if (!def_idx && !routed.empty()) def_idx = routed.front().first;
        if (def_idx) {
            candidate->default_interface_index = def_idx;
            if (auto const* link = candidate->find_link(def_idx)) {
                auto kind = infer_network_type(*link);
                candidate->default_network_type = kind;
                candidate->network_is_expensive = kind == NetworkType::cellular;
                candidate->network_is_constrained = false;
                if (kind == NetworkType::wifi)
                    darwin_read_wifi_sc(link->name, candidate->wifi_ssid, candidate->wifi_bssid);
            }
        }
        candidate->generation = ++generation_;
        candidate->observed = Clock::now();
        live_.store(std::move(candidate), std::memory_order_release);
        return {};
    }

    auto Monitor::stop() noexcept -> void {
        invalidate();
        if (impl_) impl_->active = false;
    }
#else
    struct Monitor::Impl {};
    Monitor::Monitor(bool include_neighbors) : impl_(std::make_unique<Impl>()), include_neighbors_(include_neighbors) {}
    Monitor::~Monitor() = default;
    auto Monitor::started() const noexcept -> bool { return false; }
    auto Monitor::start(Clock::time_point) -> std::expected<void, MonitorFailure> { return fail_monitor(MonitorError::unsupported); }
    auto Monitor::poll(Clock::time_point) -> std::expected<bool, MonitorFailure> { return fail_monitor(MonitorError::unsupported); }
    auto Monitor::refresh(Clock::time_point) -> std::expected<void, MonitorFailure> { return fail_monitor(MonitorError::unsupported); }
    auto Monitor::stop() noexcept -> void { invalidate(); }
#endif
}
