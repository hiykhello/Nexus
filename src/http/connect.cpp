module http.connect;
import std;
import platform.ip_address;
import http.header;

namespace http {
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
        auto is_numeric_or_hex_label(std::string_view label) noexcept -> bool {
            if (label.empty()) return false;
            if (std::ranges::all_of(label, [](char c) { return c >= '0' && c <= '9'; })) return true;
            if (label.size() > 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X'))
                return std::ranges::all_of(label.substr(2), [](char c) {
                    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                });
            return false;
        }
        auto is_alternate_numeric_ipv4(std::string_view host) noexcept -> bool {
            std::size_t labels = 0;
            bool all_num = true;
            std::string_view last;
            for (std::size_t start = 0; start <= host.size();) {
                auto dot = host.find('.', start);
                auto label = dot == host.npos ? host.substr(start) : host.substr(start, dot - start);
                ++labels;
                last = label;
                if (!is_numeric_or_hex_label(label)) all_num = false;
                if (dot == host.npos) break;
                start = dot + 1;
            }
            return (labels >= 1 && labels <= 4 && all_num) || is_numeric_or_hex_label(last);
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
                if (host.size() > 45) return {};
                auto parsed = platform::parse_ip_address(host);
                if (!parsed || parsed->size != 16) return {};
                result.host = host;
                result.address = parsed->bytes;
                result.kind = HostKind::ipv6;
            } else {
                auto split = text.find(':');
                host = text.substr(0, split);
                if (split != std::string_view::npos) port = text.substr(split + 1);
                else if (port_required) return {};
                if (!domain(host)) return {};
                result.host = host;
                if (auto parsed = platform::parse_ip_address(host); parsed && parsed->size == 4) {
                    result.address = parsed->bytes;
                    result.kind = HostKind::ipv4;
                }
                else if (is_alternate_numeric_ipv4(host))
                    return {}; // Prevent alternate numeric/hex-address interpretations by the system resolver.
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
    }

    auto parse_destination_authority(std::string_view input) -> ConnectRequest {
        auto parsed=authority(input,true);if(!parsed || !parsed->port)return {ConnectStatus::malformed};
        return {ConnectStatus::accepted,0,parsed->kind,std::move(parsed->host),parsed->address,*parsed->port};
    }

    auto parse_connect(std::string_view input) -> ConnectRequest {
        auto header = inspect_header(input);
        if (header.status == HeaderStatus::incomplete) return {ConnectStatus::incomplete};
        if (header.status == HeaderStatus::too_large) return {ConnectStatus::too_large};
        if (header.status == HeaderStatus::malformed) return {ConnectStatus::malformed};
        auto line = header.first;
        auto first = line.find(' '), second = first == line.npos ? line.npos : line.find(' ', first + 1);
        if (first == line.npos || second == line.npos || first == 0 || second == first + 1 ||
            line.find(' ', second + 1) != line.npos || line.substr(second + 1) != "HTTP/1.1" ||
            !std::all_of(line.begin(), line.begin() + first, header_token)) return {ConnectStatus::malformed};
        if (line.substr(0, first) != "CONNECT") return {ConnectStatus::unsupported};
        auto target = authority(line.substr(first + 1, second - first - 1), true);
        if (!target) return {ConnectStatus::malformed};
        bool host_seen = false;
        HeaderFieldCursor fields(header.field_lines);
        while (true) {
            auto field = fields.next();
            if (field.status == HeaderFieldStatus::end) break;
            if (field.status == HeaderFieldStatus::malformed) return {ConnectStatus::malformed};
            auto [name, value] = field.field;
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
        }
        if (!host_seen) return {ConnectStatus::malformed};
        return {ConnectStatus::accepted, header.consumed, target->kind, std::move(target->host), target->address, *target->port};
    }

    auto ConnectDecoder::feed(std::string_view input) -> ConnectStep {
        if (state_==State::complete) return {ConnectEvent::accepted};
        if (state_==State::failed) return {ConnectEvent::rejected};
        if (state_==State::truncated) return {ConnectEvent::truncated};
        if (boundary_.inspect(input)==HeaderBoundaryStatus::incomplete) return {ConnectEvent::need_more};
        request_=parse_connect(input);
        if (request_.status!=ConnectStatus::accepted) {
            state_=State::failed;
            return {ConnectEvent::rejected};
        }
        state_=State::complete;
        return {ConnectEvent::accepted,request_.consumed};
    }

    auto ConnectDecoder::finish() noexcept -> ConnectStep {
        if (state_==State::complete) return {ConnectEvent::accepted};
        if (state_==State::failed) return {ConnectEvent::rejected};
        state_=State::truncated;
        return {ConnectEvent::truncated};
    }
}
