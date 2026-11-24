module;
#if defined(__APPLE__)
#include <arpa/inet.h>
#include <cerrno>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

module platform.network_state;
import std;

namespace platform::network {
#if defined(__APPLE__)
    namespace {
        auto netmask_prefix(sockaddr const* mask, int family) noexcept -> std::uint8_t {
            if (!mask || mask->sa_family != family) return family == AF_INET ? 32 : 128;
            auto const* bytes = family == AF_INET
                ? reinterpret_cast<std::uint8_t const*>(&reinterpret_cast<sockaddr_in const*>(mask)->sin_addr)
                : reinterpret_cast<std::uint8_t const*>(&reinterpret_cast<sockaddr_in6 const*>(mask)->sin6_addr);
            std::size_t len = family == AF_INET ? 4 : 16;
            std::uint8_t prefix = 0;
            for (std::size_t i = 0; i < len; ++i) {
                if (bytes[i] == 0xff) { prefix += 8; continue; }
                for (int b = 7; b >= 0 && (bytes[i] & (1u << b)); --b) ++prefix;
                break;
            }
            return prefix;
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
