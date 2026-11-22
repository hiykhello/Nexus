module;
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#endif

module platform.process_owner;
import std;

namespace platform {
#if defined(_WIN32)
    namespace {
        auto pid_executable(std::uint32_t pid) -> std::string {
            HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) return {};
            std::wstring wbuf(1024, L'\0');
            DWORD wlen = static_cast<DWORD>(wbuf.size());
            bool ok = ::QueryFullProcessImageNameW(h, 0, wbuf.data(), &wlen) != 0;
            ::CloseHandle(h);
            if (!ok || wlen == 0) return {};
            int u8len = ::WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), static_cast<int>(wlen), nullptr, 0, nullptr, nullptr);
            if (u8len <= 0) return {};
            std::string out(static_cast<std::size_t>(u8len), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), static_cast<int>(wlen), out.data(), u8len, nullptr, nullptr);
            return out;
        }
        auto port_host(DWORD net_port) noexcept -> std::uint16_t {
            return ntohs(static_cast<std::uint16_t>(net_port & 0xffffu));
        }
        auto same_bytes(void const* a, std::span<std::uint8_t const> b) noexcept -> bool {
            return std::memcmp(a, b.data(), b.size()) == 0;
        }
        auto zero_bytes(void const* a, std::size_t len) noexcept -> bool {
            auto const* p = static_cast<std::uint8_t const*>(a);
            return std::all_of(p, p + len, [](std::uint8_t x) { return x == 0; });
        }
    }

    auto lookup_socket_owner(SocketTuple const& tuple) -> std::optional<ProcessOwner> {
        if (tuple.local_port == 0) return std::nullopt;
        ULONG af = (tuple.local_ip.size == 16) ? AF_INET6 : AF_INET;
        DWORD size = 0;
        std::optional<std::uint32_t> best_pid;
        if (!tuple.is_udp) {
            (void)::GetExtendedTcpTable(nullptr, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size == 0) return std::nullopt;
            std::vector<std::byte> buf(size);
            if (::GetExtendedTcpTable(buf.data(), &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
                return std::nullopt;
            if (af == AF_INET) {
                auto const* tbl = reinterpret_cast<MIB_TCPTABLE_OWNER_PID const*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    auto const& r = tbl->table[i];
                    if (port_host(r.dwLocalPort) != tuple.local_port) continue;
                    bool loc_ok = tuple.local_ip.size == 4 && same_bytes(&r.dwLocalAddr, tuple.local_ip.view());
                    if (loc_ok && port_host(r.dwRemotePort) == tuple.remote_port) { best_pid = r.dwOwningPid; break; }
                    if ((loc_ok || r.dwLocalAddr == 0) && r.dwRemotePort == 0 && !best_pid) best_pid = r.dwOwningPid;
                }
            } else {
                auto const* tbl = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID const*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    auto const& r = tbl->table[i];
                    if (port_host(r.dwLocalPort) != tuple.local_port) continue;
                    bool loc_ok = tuple.local_ip.size == 16 && same_bytes(r.ucLocalAddr, tuple.local_ip.view());
                    if (loc_ok && port_host(r.dwRemotePort) == tuple.remote_port) { best_pid = r.dwOwningPid; break; }
                    if ((loc_ok || zero_bytes(r.ucLocalAddr, 16)) && r.dwRemotePort == 0 && !best_pid) best_pid = r.dwOwningPid;
                }
            }
        } else {
            (void)::GetExtendedUdpTable(nullptr, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
            if (size == 0) return std::nullopt;
            std::vector<std::byte> buf(size);
            if (::GetExtendedUdpTable(buf.data(), &size, FALSE, af, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
                return std::nullopt;
            if (af == AF_INET) {
                auto const* tbl = reinterpret_cast<MIB_UDPTABLE_OWNER_PID const*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    auto const& r = tbl->table[i];
                    if (port_host(r.dwLocalPort) != tuple.local_port) continue;
                    if (r.dwLocalAddr == 0 || (tuple.local_ip.size == 4 && same_bytes(&r.dwLocalAddr, tuple.local_ip.view()))) {
                        best_pid = r.dwOwningPid; break;
                    }
                }
            } else {
                auto const* tbl = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID const*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    auto const& r = tbl->table[i];
                    if (port_host(r.dwLocalPort) != tuple.local_port) continue;
                    if (zero_bytes(r.ucLocalAddr, 16) || (tuple.local_ip.size == 16 && same_bytes(r.ucLocalAddr, tuple.local_ip.view()))) {
                        best_pid = r.dwOwningPid; break;
                    }
                }
            }
        }
        if (!best_pid || *best_pid == 0) return std::nullopt;
        return ProcessOwner{.pid = *best_pid, .uid = 0, .executable = pid_executable(*best_pid)};
    }
#else
    auto lookup_socket_owner(SocketTuple const&) -> std::optional<ProcessOwner> { return std::nullopt; }
#endif
}
