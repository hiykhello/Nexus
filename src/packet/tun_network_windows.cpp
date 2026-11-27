module;
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#endif

module packet.tun_network_windows;
import std;

namespace packet {
    auto plan_windows_tun_network(TunRoutePlanInput const& input)
        -> std::expected<TunRoutePlan, std::string> {
        return plan_cross_platform_tun_routes(input);
    }

#if defined(_WIN32)
    namespace {
        using InitUnicastFn = decltype(&::InitializeUnicastIpAddressEntry);
        using CreateUnicastFn = decltype(&::CreateUnicastIpAddressEntry);
        using DeleteUnicastFn = decltype(&::DeleteUnicastIpAddressEntry);
        using InitForwardFn = decltype(&::InitializeIpForwardEntry);
        using CreateForwardFn = decltype(&::CreateIpForwardEntry2);
        using DeleteForwardFn = decltype(&::DeleteIpForwardEntry2);
        using GetBestRoute2Fn = decltype(&::GetBestRoute2);
        using InitIpIfaceFn = decltype(&::InitializeIpInterfaceEntry);
        using GetIpIfaceFn = decltype(&::GetIpInterfaceEntry);
        using SetIpIfaceFn = decltype(&::SetIpInterfaceEntry);

        static_assert(std::is_invocable_v<InitIpIfaceFn, PMIB_IPINTERFACE_ROW>,
            "InitializeIpInterfaceEntry must take a single PMIB_IPINTERFACE_ROW argument");
        static_assert(!std::is_invocable_v<InitIpIfaceFn, ADDRESS_FAMILY, PMIB_IPINTERFACE_ROW>,
            "InitializeIpInterfaceEntry does not take an ADDRESS_FAMILY parameter");

        struct ResolvedExclude {
            NET_LUID luid{};
            SOCKADDR_INET next_hop{};
        };

        auto to_sockaddr_inet(TunCidr const& cidr, SOCKADDR_INET& dst) noexcept -> void {
            std::memset(&dst, 0, sizeof(dst));
            if (cidr.family == 4) {
                dst.si_family = AF_INET;
                std::memcpy(&dst.Ipv4.sin_addr, cidr.address.data(), 4);
            } else {
                dst.si_family = AF_INET6;
                std::memcpy(&dst.Ipv6.sin6_addr, cidr.address.data(), 16);
            }
        }
    }

    struct WindowsTunNetwork::Impl {
        HMODULE iphlp = nullptr;
        std::vector<MIB_UNICASTIPADDRESS_ROW> addresses;
        std::vector<MIB_IPFORWARD_ROW2> routes;
        DeleteUnicastFn del_unicast = nullptr;
        DeleteForwardFn del_forward = nullptr;
        bool active = false;

        ~Impl() { shutdown(); }
        auto shutdown() noexcept -> void {
            if (del_forward)
                for (auto it = routes.rbegin(); it != routes.rend(); ++it) (void)del_forward(&*it);
            if (del_unicast)
                for (auto it = addresses.rbegin(); it != addresses.rend(); ++it) (void)del_unicast(&*it);
            routes.clear();
            addresses.clear();
            if (iphlp) { ::FreeLibrary(iphlp); iphlp = nullptr; }
            active = false;
        }
    };

    WindowsTunNetwork::WindowsTunNetwork() : impl_(std::make_unique<Impl>()) {}
    WindowsTunNetwork::~WindowsTunNetwork() { stop(); }
    WindowsTunNetwork::WindowsTunNetwork(WindowsTunNetwork&&) noexcept = default;
    auto WindowsTunNetwork::operator=(WindowsTunNetwork&&) noexcept -> WindowsTunNetwork& = default;

    auto WindowsTunNetwork::start(std::uint64_t adapter_luid, TunRoutePlan const& plan)
        -> std::expected<void, std::error_code> {
        stop();
        if (!adapter_luid) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        HMODULE iphlp = ::LoadLibraryExW(L"iphlpapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!iphlp) return std::unexpected(std::error_code{static_cast<int>(::GetLastError()), std::system_category()});
        if (!impl_) impl_ = std::make_unique<Impl>();
        impl_->iphlp = iphlp;

        auto init_u = reinterpret_cast<InitUnicastFn>(::GetProcAddress(iphlp, "InitializeUnicastIpAddressEntry"));
        auto add_u = reinterpret_cast<CreateUnicastFn>(::GetProcAddress(iphlp, "CreateUnicastIpAddressEntry"));
        impl_->del_unicast = reinterpret_cast<DeleteUnicastFn>(::GetProcAddress(iphlp, "DeleteUnicastIpAddressEntry"));
        auto init_f = reinterpret_cast<InitForwardFn>(::GetProcAddress(iphlp, "InitializeIpForwardEntry"));
        auto add_f = reinterpret_cast<CreateForwardFn>(::GetProcAddress(iphlp, "CreateIpForwardEntry2"));
        impl_->del_forward = reinterpret_cast<DeleteForwardFn>(::GetProcAddress(iphlp, "DeleteIpForwardEntry2"));
        auto get_best = reinterpret_cast<GetBestRoute2Fn>(::GetProcAddress(iphlp, "GetBestRoute2"));
        auto init_if = reinterpret_cast<InitIpIfaceFn>(::GetProcAddress(iphlp, "InitializeIpInterfaceEntry"));
        auto get_if = reinterpret_cast<GetIpIfaceFn>(::GetProcAddress(iphlp, "GetIpInterfaceEntry"));
        auto set_if = reinterpret_cast<SetIpIfaceFn>(::GetProcAddress(iphlp, "SetIpInterfaceEntry"));
        if (!init_u || !add_u || !impl_->del_unicast || !init_f || !add_f || !impl_->del_forward) {
            stop();
            return std::unexpected(std::make_error_code(std::errc::function_not_supported));
        }

        auto resolve_exclude = [&](TunCidr const& exc) -> std::expected<ResolvedExclude, std::error_code> {
            if (!get_best) return std::unexpected(std::make_error_code(std::errc::function_not_supported));
            SOCKADDR_INET dst{}, best_src{};
            to_sockaddr_inet(exc, dst);
            MIB_IPFORWARD_ROW2 best{};
            init_f(&best);
            auto st = get_best(nullptr, 0, nullptr, &dst, 0, &best, &best_src);
            if (st != NO_ERROR) return std::unexpected(std::error_code{static_cast<int>(st), std::system_category()});
            if (best.InterfaceLuid.Value == 0 || best.InterfaceLuid.Value == adapter_luid)
                return std::unexpected(std::make_error_code(std::errc::network_unreachable));
            return ResolvedExclude{best.InterfaceLuid, best.NextHop};
        };
        auto configure_interface = [&]() -> std::error_code {
            if (init_if && get_if && set_if) {
                for (ADDRESS_FAMILY fam : {AF_INET, AF_INET6}) {
                    MIB_IPINTERFACE_ROW ifrow{};
                    init_if(&ifrow);
                    ifrow.Family = fam;
                    ifrow.InterfaceLuid.Value = adapter_luid;
                    if (get_if(&ifrow) == NO_ERROR) {
                        ifrow.NlMtu = plan.mtu;
                        ifrow.UseAutomaticMetric = FALSE;
                        ifrow.Metric = 0;
                        if (fam == AF_INET) ifrow.SitePrefixLength = 0;
                        (void)set_if(&ifrow);
                    }
                }
            }
            for (auto const& addr : plan.addresses) {
                MIB_UNICASTIPADDRESS_ROW row{};
                init_u(&row);
                row.InterfaceLuid.Value = adapter_luid;
                row.OnLinkPrefixLength = addr.prefix;
                row.DadState = IpDadStatePreferred;
                to_sockaddr_inet(addr, row.Address);
                auto st = add_u(&row);
                if (st == NO_ERROR) impl_->addresses.push_back(row);
                else if (st != ERROR_OBJECT_ALREADY_EXISTS)
                    return {static_cast<int>(st), std::system_category()};
            }
            return {};
        };
        auto install_exclude = [&](TunCidr const& exc, ResolvedExclude const& gw) -> std::error_code {
            MIB_IPFORWARD_ROW2 row{};
            init_f(&row);
            row.InterfaceLuid = gw.luid;
            row.NextHop = gw.next_hop;
            to_sockaddr_inet(exc, row.DestinationPrefix.Prefix);
            row.DestinationPrefix.PrefixLength = exc.prefix;
            row.Metric = 0;
            auto st = add_f(&row);
            if (st == NO_ERROR) impl_->routes.push_back(row);
            else if (st != ERROR_OBJECT_ALREADY_EXISTS)
                return {static_cast<int>(st), std::system_category()};
            return {};
        };
        auto install_capture = [&](TunCidr const& rt) -> std::error_code {
            MIB_IPFORWARD_ROW2 row{};
            init_f(&row);
            row.InterfaceLuid.Value = adapter_luid;
            to_sockaddr_inet(rt, row.DestinationPrefix.Prefix);
            row.DestinationPrefix.PrefixLength = rt.prefix;
            row.Metric = 0;
            auto st = add_f(&row);
            if (st == NO_ERROR) impl_->routes.push_back(row);
            else if (st != ERROR_OBJECT_ALREADY_EXISTS)
                return {static_cast<int>(st), std::system_category()};
            return {};
        };
        auto applied = apply_tun_route_plan(
            plan, resolve_exclude, configure_interface, install_exclude, install_capture, [&]() noexcept { stop(); });
        if (!applied) return std::unexpected(applied.error());
        impl_->active = true;
        return {};
    }

    auto WindowsTunNetwork::stop() noexcept -> void {
        if (impl_) impl_->shutdown();
    }

    auto WindowsTunNetwork::active() const noexcept -> bool {
        return impl_ && impl_->active;
    }
#else
    struct WindowsTunNetwork::Impl { bool active = false; };
    WindowsTunNetwork::WindowsTunNetwork() : impl_(std::make_unique<Impl>()) {}
    WindowsTunNetwork::~WindowsTunNetwork() = default;
    WindowsTunNetwork::WindowsTunNetwork(WindowsTunNetwork&&) noexcept = default;
    auto WindowsTunNetwork::operator=(WindowsTunNetwork&&) noexcept -> WindowsTunNetwork& = default;
    auto WindowsTunNetwork::start(std::uint64_t, TunRoutePlan const&)
        -> std::expected<void, std::error_code> {
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    }
    auto WindowsTunNetwork::stop() noexcept -> void { if (impl_) impl_->active = false; }
    auto WindowsTunNetwork::active() const noexcept -> bool { return impl_ && impl_->active; }
#endif
}
