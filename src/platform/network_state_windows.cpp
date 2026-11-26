module;
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <wlanapi.h>
#if defined(_MSC_VER)
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#endif

module platform.network_state;
import std;

namespace platform::network {
#if defined(_WIN32)
    namespace {
        auto wide_to_utf8(wchar_t const* wide) -> std::string {
            if (!wide || !*wide) return {};
            int len = ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 1) return {};
            std::string out(static_cast<std::size_t>(len - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), len - 1, nullptr, nullptr);
            return out;
        }

        auto format_guid_braced(GUID const& g) -> std::string {
            return std::format("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
                g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        }

        auto windows_read_wifi(std::string_view adapter_guid, std::optional<std::string>& ssid,
            std::optional<MacAddress>& bssid) noexcept -> void {
            HMODULE dll = ::LoadLibraryExW(L"wlanapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!dll) return;
            struct DllGuard { HMODULE m; ~DllGuard() { if (m) ::FreeLibrary(m); } } dll_guard{dll};
            using OpenFn = DWORD(WINAPI*)(DWORD, PVOID, PDWORD, PHANDLE);
            using CloseFn = DWORD(WINAPI*)(HANDLE, PVOID);
            using EnumFn = DWORD(WINAPI*)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*);
            using QueryFn = DWORD(WINAPI*)(HANDLE, GUID const*, WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID*, PWLAN_OPCODE_VALUE_TYPE);
            using FreeFn = VOID(WINAPI*)(PVOID);
            auto open_fn = reinterpret_cast<OpenFn>(::GetProcAddress(dll, "WlanOpenHandle"));
            auto close_fn = reinterpret_cast<CloseFn>(::GetProcAddress(dll, "WlanCloseHandle"));
            auto enum_fn = reinterpret_cast<EnumFn>(::GetProcAddress(dll, "WlanEnumInterfaces"));
            auto query_fn = reinterpret_cast<QueryFn>(::GetProcAddress(dll, "WlanQueryInterface"));
            auto free_fn = reinterpret_cast<FreeFn>(::GetProcAddress(dll, "WlanFreeMemory"));
            if (!open_fn || !close_fn || !enum_fn || !query_fn || !free_fn) return;
            DWORD version = 0;
            HANDLE client = nullptr;
            if (open_fn(2, nullptr, &version, &client) != ERROR_SUCCESS || !client) return;
            PWLAN_INTERFACE_INFO_LIST list = nullptr;
            if (enum_fn(client, nullptr, &list) == ERROR_SUCCESS && list) {
                auto equal_ci = [](std::string_view a, std::string_view b) noexcept {
                    if (a.size() != b.size()) return false;
                    for (std::size_t i = 0; i < a.size(); ++i)
                        if (std::toupper(static_cast<unsigned char>(a[i])) != std::toupper(static_cast<unsigned char>(b[i]))) return false;
                    return true;
                };
                GUID const* picked = nullptr;
                for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
                    auto const& item = list->InterfaceInfo[i];
                    if (item.isState != wlan_interface_state_connected) continue;
                    if (!adapter_guid.empty()) {
                        try {
                            if (equal_ci(format_guid_braced(item.InterfaceGuid), adapter_guid)) {
                                picked = &item.InterfaceGuid;
                                break;
                            }
                        } catch (...) {}
                    }
                    if (!picked) picked = &item.InterfaceGuid;
                }
                if (picked) {
                    DWORD size = 0;
                    PVOID data = nullptr;
                    if (query_fn(client, picked, wlan_intf_opcode_current_connection, nullptr, &size, &data, nullptr) == ERROR_SUCCESS &&
                        data && size >= sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
                        auto const* attrs = reinterpret_cast<WLAN_CONNECTION_ATTRIBUTES const*>(data);
                        auto const& assoc = attrs->wlanAssociationAttributes;
                        if (assoc.dot11Ssid.uSSIDLength > 0 && assoc.dot11Ssid.uSSIDLength <= 32) {
                            try {
                                ssid = std::string(reinterpret_cast<char const*>(assoc.dot11Ssid.ucSSID), assoc.dot11Ssid.uSSIDLength);
                            } catch (...) {}
                        }
                        MacAddress mac{};
                        std::memcpy(mac.data(), assoc.dot11Bssid, 6);
                        bool any_nz = false, any_nff = false;
                        for (auto b : mac) { any_nz |= (b != 0); any_nff |= (b != 0xff); }
                        if (any_nz && any_nff) bssid = mac;
                    }
                    if (data) free_fn(data);
                }
                free_fn(list);
            }
            close_fn(client, nullptr);
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

        ULONG buf_len = 32768;
        std::vector<std::byte> buf(buf_len);
        ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        ULONG rc = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &buf_len);
        if (rc == ERROR_BUFFER_OVERFLOW && buf_len > 0) {
            buf.resize(buf_len);
            rc = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &buf_len);
        }
        if (rc != NO_ERROR) {
            return fail_monitor(MonitorError::system, {static_cast<int>(rc), std::system_category()});
        }

        auto candidate = std::make_shared<Snapshot>();
        std::vector<std::pair<std::uint32_t, std::string>> adapter_guids;
        for (auto const* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES const*>(buf.data()); aa; aa = aa->Next) {
            std::uint32_t idx = aa->IfIndex ? aa->IfIndex : aa->Ipv6IfIndex;
            if (!idx) continue;
            Link link{};
            link.index = idx;
            link.name = wide_to_utf8(aa->FriendlyName);
            if (link.name.empty() && aa->AdapterName) link.name = aa->AdapterName;
            if (aa->AdapterName) adapter_guids.emplace_back(idx, aa->AdapterName);
            if (aa->IfType == IF_TYPE_IEEE80211) link.kind = "wlan";
            else if (aa->IfType == IF_TYPE_WWANPP || aa->IfType == IF_TYPE_WWANPP2) link.kind = "wwan";
            else if (aa->IfType == IF_TYPE_ETHERNET_CSMACD || aa->IfType == IF_TYPE_GIGABITETHERNET) link.kind = "eth";
            if (aa->OperStatus == IfOperStatusUp)
                link.flags = constants::iff_up | constants::iff_lower_up;
            candidate->links.push_back(std::move(link));

            for (auto const* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
                if (!ua->Address.lpSockaddr) continue;
                int fam = ua->Address.lpSockaddr->sa_family;
                if (fam != AF_INET && fam != AF_INET6) continue;
                Address addr{};
                addr.index = idx;
                addr.family = (fam == AF_INET) ? constants::af_inet : constants::af_inet6;
                addr.prefix = ua->OnLinkPrefixLength;
                addr.scope = constants::rt_scope_universe;
                if (ua->DadState == IpDadStateTentative) addr.flags |= constants::ifa_f_tentative;
                else if (ua->DadState == IpDadStateDuplicate) addr.flags |= constants::ifa_f_dadfailed;
                if (fam == AF_INET) {
                    auto const* s4 = reinterpret_cast<sockaddr_in const*>(ua->Address.lpSockaddr);
                    std::memcpy(addr.local.data(), &s4->sin_addr, 4);
                } else {
                    auto const* s6 = reinterpret_cast<sockaddr_in6 const*>(ua->Address.lpSockaddr);
                    std::memcpy(addr.local.data(), &s6->sin6_addr, 16);
                    if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) addr.scope = 253;
                }
                candidate->addresses.push_back(addr);
            }
        }

        PMIB_IPFORWARD_TABLE2 fwd = nullptr;
        if (::GetIpForwardTable2(AF_UNSPEC, &fwd) == NO_ERROR && fwd) {
            for (ULONG i = 0; i < fwd->NumEntries; ++i) {
                auto const& row = fwd->Table[i];
                if (row.DestinationPrefix.PrefixLength != 0) continue;
                auto fam = row.DestinationPrefix.Prefix.si_family;
                if (fam != AF_INET && fam != AF_INET6) continue;
                Route route{};
                route.family = (fam == AF_INET) ? constants::af_inet : constants::af_inet6;
                route.index = row.InterfaceIndex;
                route.priority = row.Metric;
                route.table = constants::rt_table_main;
                route.type = constants::rtn_unicast;
                route.scope = constants::rt_scope_universe;
                candidate->routes.push_back(route);
            }
            ::FreeMibTable(fwd);
        }

        std::ranges::sort(candidate->links, {}, &Link::index);
        candidate->links.erase(std::ranges::unique(candidate->links, {}, &Link::index).begin(), candidate->links.end());
        Route const* best_route = nullptr;
        for (auto const& route : candidate->routes) {
            if (!route.default_route() || !route.index) continue;
            auto const* link = candidate->find_link(route.index);
            if (!link || !link->up()) continue;
            if (!best_route || route.priority < best_route->priority) best_route = &route;
        }
        if (best_route) {
            candidate->default_interface_index = best_route->index;
            if (auto const* link = candidate->find_link(best_route->index)) {
                auto kind = infer_network_type(*link);
                candidate->default_network_type = kind;
                candidate->network_is_expensive = kind == NetworkType::cellular;
                candidate->network_is_constrained = false;
                if (kind == NetworkType::wifi) {
                    std::string_view guid{};
                    for (auto const& [idx, g] : adapter_guids) if (idx == link->index) { guid = g; break; }
                    windows_read_wifi(guid, candidate->wifi_ssid, candidate->wifi_bssid);
                }
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
