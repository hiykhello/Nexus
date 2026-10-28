module;
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

module nexus.http.connect;
import std;

namespace nexus::http {
    namespace {
        struct Authority {
            HostKind kind = HostKind::domain;
            std::string host;
            std::array<std::uint8_t, 16> address{};
            std::optional<std::uint16_t> port;
        };
        auto lower(char c) -> char { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; }
        auto equal_ci(std::string_view a, std::string_view b) -> bool {
            return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
                [](char x, char y) { return lower(x) == lower(y); });
        }
        auto token(char c) -> bool {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
        }
        auto domain(std::string_view value) -> bool {
            if (value.empty() || value.size() > 253) return false;
            std::size_t start = 0;
            for (std::size_t i = 0; i <= value.size(); ++i) {
                if (i == value.size() || value[i] == '.') {
                    if (i == start || i - start > 63 || value[start] == '-' || value[i - 1] == '-') return false;
                    start = i + 1;
                } else if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= 'A' && value[i] <= 'Z') ||
                             (value[i] >= '0' && value[i] <= '9') || value[i] == '-')) return false;
            }
            return true;
        }
        auto authority(std::string_view text, bool port_required) -> std::optional<Authority> {
            Authority result;
            std::string_view host, port;
            if (text.empty()) return {};
            if (text.front() == '[') {
                auto end = text.find(']');
                if (end == std::string_view::npos || end == 1) return {};
                host = text.substr(1, end - 1);
                auto rest = text.substr(end + 1);
                if (!rest.empty()) { if (rest.front() != ':') return {}; port = rest.substr(1); }
                else if (port_required) return {};
                if (host.size() >= INET6_ADDRSTRLEN) return {};
                result.host = host;
                if (::inet_pton(AF_INET6, result.host.c_str(), result.address.data()) != 1) return {};
                result.kind = HostKind::ipv6;
            } else {
                auto split = text.find(':');
                host = text.substr(0, split);
                if (split != std::string_view::npos) port = text.substr(split + 1);
                else if (port_required) return {};
                if (!domain(host)) return {};
                result.host = host;
                if (::inet_pton(AF_INET, result.host.c_str(), result.address.data()) == 1) result.kind = HostKind::ipv4;
                else if (std::all_of(host.begin(), host.end(), [](char c) { return (c >= '0' && c <= '9') || c == '.'; }))
                    return {}; // Prevent alternate numeric-address interpretations by the system resolver.
            }
            if (text.back() == ':') return {};
            if (!port.empty()) {
                unsigned value = 0;
                auto [end, ec] = std::from_chars(port.data(), port.data() + port.size(), value);
                if (ec != std::errc{} || end != port.data() + port.size() || value == 0 || value > 65535) return {};
                result.port = static_cast<std::uint16_t>(value);
            }
            return result;
        }
        auto same_host(Authority const& a, Authority const& b) -> bool {
            if (a.kind != b.kind) return false;
            if (a.kind == HostKind::domain) return equal_ci(a.host, b.host);
            return a.address == b.address;
        }
        auto trim(std::string_view value) -> std::string_view {
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
            return value;
        }
    }

    auto parse_connect(std::string_view input) -> ConnectRequest {
        auto end = input.find("\r\n\r\n");
        if (end == std::string_view::npos)
            return {input.size() >= max_connect_header_bytes ? ConnectStatus::too_large : ConnectStatus::incomplete};
        auto consumed = end + 4;
        if (consumed > max_connect_header_bytes) return {ConnectStatus::too_large};
        auto line_end = input.find("\r\n");
        if (line_end == std::string_view::npos || line_end > 8192) return {ConnectStatus::malformed};
        auto line = input.substr(0, line_end);
        auto first = line.find(' '), second = first == line.npos ? line.npos : line.find(' ', first + 1);
        if (first == line.npos || second == line.npos || first == 0 || second == first + 1 ||
            line.find(' ', second + 1) != line.npos || line.substr(second + 1) != "HTTP/1.1" ||
            !std::all_of(line.begin(), line.begin() + first, token)) return {ConnectStatus::malformed};
        if (line.substr(0, first) != "CONNECT") return {ConnectStatus::unsupported};
        auto target = authority(line.substr(first + 1, second - first - 1), true);
        if (!target) return {ConnectStatus::malformed};
        bool host_seen = false;
        std::size_t fields = 0, pos = line_end + 2;
        while (pos < end + 2) {
            auto next = input.find("\r\n", pos);
            if (next == input.npos || next > end || next - pos > 8192 || ++fields > max_connect_fields)
                return {ConnectStatus::malformed};
            auto field = input.substr(pos, next - pos);
            auto colon = field.find(':');
            if (colon == field.npos || colon == 0 || !std::all_of(field.begin(), field.begin() + colon, token))
                return {ConnectStatus::malformed};
            auto name = field.substr(0, colon);
            auto value = trim(field.substr(colon + 1));
            for (unsigned char c : value) if ((c < 32 && c != '\t') || c == 127) return {ConnectStatus::malformed};
            if (equal_ci(name, "host")) {
                if (host_seen) return {ConnectStatus::malformed};
                auto host = authority(value, false);
                if (!host || !same_host(*target, *host) || (host->port && host->port != target->port))
                    return {ConnectStatus::malformed};
                host_seen = true;
            } else if (equal_ci(name, "content-length") || equal_ci(name, "transfer-encoding") ||
                       equal_ci(name, "proxy-authorization") || equal_ci(name, "upgrade") || equal_ci(name, "expect")) {
                return {ConnectStatus::unsupported};
            }
            pos = next + 2;
        }
        if (!host_seen) return {ConnectStatus::malformed};
        return {ConnectStatus::accepted, consumed, target->kind, std::move(target->host), target->address, *target->port};
    }
}
