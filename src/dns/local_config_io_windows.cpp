module;
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#endif

module dns.local_config;
import std;
import platform.platform_defaults;

namespace dns::detail {
#ifdef _WIN32
    namespace {
        auto win32_wide_to_utf8(wchar_t const* wide) -> std::string {
            if (!wide || !*wide) return {};
            int len = ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 1) return {};
            std::string out(static_cast<std::size_t>(len - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), len - 1, nullptr, nullptr);
            return out;
        }

        auto win32_utf8_to_wide(std::string_view utf8) -> std::wstring {
            if (utf8.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            if (len <= 0) return {};
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), len);
            return out;
        }

        auto win32_read_file_bytes(std::wstring const& wpath, std::size_t max_bytes)
            -> std::expected<std::string, LocalConfigError> {
            HANDLE h = ::CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return std::unexpected(LocalConfigError::io_error);
            struct Guard { HANDLE handle; ~Guard() { ::CloseHandle(handle); } } guard{h};
            LARGE_INTEGER sz{};
            if (!::GetFileSizeEx(h, &sz) || sz.QuadPart < 0) return std::unexpected(LocalConfigError::io_error);
            if (static_cast<std::uint64_t>(sz.QuadPart) > max_bytes) return std::unexpected(LocalConfigError::too_large);
            std::string data;
            data.reserve(static_cast<std::size_t>(sz.QuadPart));
            std::array<char, 4096> buf{};
            for (;;) {
                DWORD got = 0;
                if (!::ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr))
                    return std::unexpected(LocalConfigError::io_error);
                if (got == 0) break;
                if (got > max_bytes - data.size()) return std::unexpected(LocalConfigError::too_large);
                data.append(buf.data(), got);
            }
            return data;
        }

        auto win32_enumerate_resolv_conf(std::size_t max_bytes)
            -> std::expected<std::string, LocalConfigError> {
            ULONG size = 16384;
            std::vector<std::uint8_t> storage;
            ULONG status = ERROR_BUFFER_OVERFLOW;
            for (int attempt = 0; attempt < 4 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
                storage.resize(size);
                status = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                    nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data()), &size);
            }
            if (status != NO_ERROR) return std::unexpected(LocalConfigError::io_error);
            std::string text;
            std::vector<std::string> servers;
            std::vector<std::string> search;
            for (auto const* aa = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data()); aa; aa = aa->Next) {
                if (aa->OperStatus != IfOperStatusUp) continue;
                for (auto const* dns_addr = aa->FirstDnsServerAddress; dns_addr && servers.size() < 3; dns_addr = dns_addr->Next) {
                    if (!dns_addr->Address.lpSockaddr) continue;
                    std::array<char, INET6_ADDRSTRLEN + 1> ip_buf{};
                    auto const family = dns_addr->Address.lpSockaddr->sa_family;
                    if (family == AF_INET) {
                        auto const* sa4 = reinterpret_cast<sockaddr_in const*>(dns_addr->Address.lpSockaddr);
                        if (::inet_ntop(AF_INET, &sa4->sin_addr, ip_buf.data(), static_cast<DWORD>(ip_buf.size()))) {
                            std::string ip(ip_buf.data());
                            if (!std::ranges::contains(servers, ip)) servers.push_back(std::move(ip));
                        }
                    } else if (family == AF_INET6) {
                        auto const* sa6 = reinterpret_cast<sockaddr_in6 const*>(dns_addr->Address.lpSockaddr);
                        static_assert(sizeof(sa6->sin6_addr) == 16);
                        auto const* raw6 = reinterpret_cast<std::uint8_t const*>(&sa6->sin6_addr);
                        if (platform::is_windows_site_local_fake_dns(std::span<std::uint8_t const, 16>(raw6, 16))) continue;
                        if (::inet_ntop(AF_INET6, &sa6->sin6_addr, ip_buf.data(), static_cast<DWORD>(ip_buf.size()))) {
                            std::string_view sv(ip_buf.data());
                            if (!sv.contains('%')) {
                                std::string ip(sv);
                                if (!std::ranges::contains(servers, ip)) servers.push_back(std::move(ip));
                            }
                        }
                    }
                }
                if (auto suffix = win32_wide_to_utf8(aa->DnsSuffix); !suffix.empty() && search.size() < 6) {
                    if (std::ranges::find(search, suffix) == search.end()) search.push_back(std::move(suffix));
                }
            }
            if (servers.empty()) return std::unexpected(LocalConfigError::io_error);
            for (auto const& s : servers) { text += "nameserver "; text += s; text.push_back('\n'); }
            if (!search.empty()) {
                text += "search";
                for (auto const& s : search) { text.push_back(' '); text += s; }
                text.push_back('\n');
            }
            if (text.size() > max_bytes) return std::unexpected(LocalConfigError::too_large);
            return text;
        }
    }

    auto read_local_config_file(std::string_view path, std::size_t max_bytes)
        -> std::expected<std::string, LocalConfigError> {
        if (path == "/etc/resolv.conf") return win32_enumerate_resolv_conf(max_bytes);
        if (path == "/etc/hosts") {
            std::array<wchar_t, MAX_PATH + 1> sysdir{};
            UINT n = ::GetWindowsDirectoryW(sysdir.data(), static_cast<UINT>(sysdir.size()));
            if (n > 0 && n < sysdir.size()) {
                std::wstring wpath(sysdir.data(), n);
                wpath += L"\\System32\\drivers\\etc\\hosts";
                return win32_read_file_bytes(wpath, max_bytes);
            }
            return std::unexpected(LocalConfigError::io_error);
        }
        auto wpath = win32_utf8_to_wide(path);
        if (wpath.empty()) return std::unexpected(LocalConfigError::io_error);
        return win32_read_file_bytes(wpath, max_bytes);
    }
#else
    auto read_local_config_file(std::string_view, std::size_t) -> std::expected<std::string, LocalConfigError> {
        return std::unexpected(LocalConfigError::io_error);
    }
#endif
}
