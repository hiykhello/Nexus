module nexus.http.connect;
import std;

namespace nexus::http {
    namespace {
        auto lower(char c) -> char { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; }
        auto lower_copy(std::string_view s) -> std::string {
            std::string result(s);
            std::ranges::transform(result, result.begin(), lower);
            return result;
        }
        auto token(char c) -> bool {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
        }
        auto trim(std::string_view s) -> std::string_view {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
            return s;
        }
        struct Field { std::string name; std::string_view value; };
        struct Header {
            ConnectStatus status = ConnectStatus::incomplete;
            std::string_view first;
            std::size_t consumed = 0;
            std::vector<Field> fields;
            std::vector<std::string> connection;
        };
        auto parse_header(std::string_view input) -> Header {
            Header result;
            auto end = input.find("\r\n\r\n");
            if (end == input.npos) {
                if (input.size() >= max_connect_header_bytes) result.status = ConnectStatus::too_large;
                return result;
            }
            result.consumed = end + 4;
            if (result.consumed > max_connect_header_bytes) { result.status = ConnectStatus::too_large; return result; }
            auto first_end = input.find("\r\n");
            if (first_end > 8192) { result.status = ConnectStatus::malformed; return result; }
            result.first = input.substr(0, first_end);
            auto pos = first_end + 2;
            while (pos < end + 2) {
                auto next = input.find("\r\n", pos);
                if (next == input.npos || next > end || next - pos > 8192 || result.fields.size() >= max_connect_fields) {
                    result.status = ConnectStatus::malformed; return result;
                }
                auto line = input.substr(pos, next - pos);
                auto colon = line.find(':');
                if (colon == line.npos || colon == 0 || !std::all_of(line.begin(), line.begin() + colon, token)) {
                    result.status = ConnectStatus::malformed; return result;
                }
                auto value = trim(line.substr(colon + 1));
                for (unsigned char c : value) if ((c < 32 && c != '\t') || c == 127) {
                    result.status = ConnectStatus::malformed; return result;
                }
                auto name = lower_copy(line.substr(0, colon));
                if (name == "connection") {
                    auto rest = value;
                    do {
                        auto comma = rest.find(',');
                        auto option = trim(rest.substr(0, comma));
                        if (option.empty() || !std::all_of(option.begin(), option.end(), token)) {
                            result.status = ConnectStatus::malformed; return result;
                        }
                        result.connection.push_back(lower_copy(option));
                        if (comma == rest.npos) break;
                        rest.remove_prefix(comma + 1);
                    } while (true);
                }
                result.fields.push_back({std::move(name), value});
                pos = next + 2;
            }
            result.status = ConnectStatus::accepted;
            return result;
        }
        auto hop(Header const& h, std::string_view name) -> bool {
            return name == "connection" || name == "proxy-connection" || name == "keep-alive" ||
                   name == "te" || name == "trailer" || name == "upgrade" || name == "proxy-authenticate" ||
                   name == "proxy-authorization" || std::ranges::find(h.connection, name) != h.connection.end();
        }
        auto critical(Header const& h) -> bool {
            return std::ranges::find(h.connection, std::string_view("host")) != h.connection.end() ||
                   std::ranges::find(h.connection, std::string_view("content-length")) != h.connection.end() ||
                   std::ranges::find(h.connection, std::string_view("transfer-encoding")) != h.connection.end();
        }
        auto append_fields(std::string& out, Header const& h, bool request, bool close = true) -> void {
            for (auto const& field : h.fields) {
                if (hop(h, field.name) || (request && field.name == "host")) continue;
                out += field.name;
                out += ": ";
                out += field.value;
                out += "\r\n";
            }
            if (close) out += "Connection: close\r\n";
            out += "\r\n";
        }
        auto parse_target_authority(std::string_view authority) -> ConnectRequest {
            auto port_present = authority.starts_with('[') ?
                authority.find(']') != authority.npos && authority.find(']') + 1 < authority.size() :
                authority.find(':') != authority.npos;
            auto target = std::string(authority);
            if (!port_present) target += ":80";
            return parse_connect("CONNECT " + target + " HTTP/1.1\r\nHost: " + std::string(authority) + "\r\n\r\n");
        }
        auto target_path(std::string_view path) -> bool {
            for (std::size_t i = 0; i < path.size(); ++i) {
                unsigned char c = static_cast<unsigned char>(path[i]);
                if (c <= 32 || c >= 127 || c == '#' || c == '\\') return false;
                if (c == '%') {
                    if (i + 2 >= path.size() || !std::isxdigit(static_cast<unsigned char>(path[i + 1])) ||
                        !std::isxdigit(static_cast<unsigned char>(path[i + 2]))) return false;
                    i += 2;
                }
            }
            return true;
        }
    }

    auto parse_forward_request(std::string_view input) -> ForwardRequest {
        ForwardRequest result;
        auto header = parse_header(input);
        result.status = header.status;
        if (header.status != ConnectStatus::accepted) return result;
        result.status = ConnectStatus::malformed;
        auto first = header.first.find(' '), second = first == header.first.npos ? first : header.first.find(' ', first + 1);
        if (first == header.first.npos || second == header.first.npos || header.first.substr(second + 1) != "HTTP/1.1") return result;
        auto method = header.first.substr(0, first);
        if (method.empty() || !std::all_of(method.begin(), method.end(), token) || method == "CONNECT") return result;
        auto uri = header.first.substr(first + 1, second - first - 1);
        if (!uri.starts_with("http://")) return result;
        uri.remove_prefix(7);
        auto split = uri.find_first_of("/?#");
        auto authority = uri.substr(0, split);
        auto path = split == uri.npos ? std::string_view{} : uri.substr(split);
        if (!target_path(path) || critical(header) ||
            std::ranges::find(header.connection, std::string_view("expect")) != header.connection.end()) return result;
        auto target = parse_target_authority(authority);
        if (target.status != ConnectStatus::accepted) return result;
        bool host = false, content_length = false, transfer = false, expect_seen = false, invalid_expect = false;
        for (auto const& field : header.fields) {
            if (field.name == "host") {
                if (host || parse_target_authority(field.value).status != ConnectStatus::accepted) return result;
                host = true;
            } else if (field.name == "content-length") {
                if (content_length || field.value.empty()) return result;
                auto [end, ec] = std::from_chars(field.value.data(), field.value.data() + field.value.size(), result.body_length);
                if (ec != std::errc{} || end != field.value.data() + field.value.size()) return result;
                content_length = true;
            } else if (field.name == "transfer-encoding") {
                if (transfer || lower_copy(field.value) != "chunked") return result;
                transfer = true;
            } else if (field.name == "expect") {
                if (expect_seen || lower_copy(field.value) != "100-continue") invalid_expect = true;
                expect_seen = true;
            } else if (field.name == "upgrade" || field.name == "proxy-authorization") {
                result.status = ConnectStatus::unsupported; return result;
            }
        }
        if (!host || (content_length && transfer)) return result;
        if (invalid_expect) { result.status = ConnectStatus::expectation_failed; return result; }
        result.consumed = header.consumed;
        result.chunked = transfer;
        result.head = method == "HEAD";
        result.wire = std::string(method) + " " + (path.empty() || path.front() == '?' ? "/" : "") + std::string(path) + " HTTP/1.1\r\nHost: " + std::string(authority) + "\r\n";
        append_fields(result.wire, header, true);
        result.destination = std::move(target);
        result.status = ConnectStatus::accepted;
        return result;
    }

    auto parse_forward_response(std::string_view input, bool head) -> ForwardResponse {
        ForwardResponse result;
        auto header = parse_header(input);
        result.status = header.status;
        if (header.status != ConnectStatus::accepted) return result;
        result.status = ConnectStatus::malformed;
        auto line = header.first;
        if (line.size() < 12 || (!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 ")) ||
            line[8] != ' ' || line[9] < '1' || line[9] > '5' || line[10] < '0' || line[10] > '9' ||
            line[11] < '0' || line[11] > '9' || (line.size() > 12 && line[12] != ' ') || critical(header)) return result;
        for (unsigned char c : line) if (c < 32 || c == 127) return result;
        bool has_length = false, has_transfer = false;
        std::uint64_t length = 0;
        for (auto const& field : header.fields) {
            if (field.name == "upgrade") return result;
            if (field.name == "transfer-encoding") {
                if (has_transfer || lower_copy(field.value) != "chunked" || line.starts_with("HTTP/1.0 ")) return result;
                has_transfer = true;
            }
            if (field.name == "content-length") {
                if (has_length || field.value.empty()) return result;
                auto [end, ec] = std::from_chars(field.value.data(), field.value.data() + field.value.size(), length);
                if (ec != std::errc{} || end != field.value.data() + field.value.size()) return result;
                has_length = true;
            }
        }
        auto code = (line[9] - '0') * 100 + (line[10] - '0') * 10 + line[11] - '0';
        result.informational = code < 200;
        if ((result.informational && (code == 101 || line.starts_with("HTTP/1.0 ") || has_length || has_transfer)) ||
            (has_transfer && has_length) ||
            ((code == 204 || code == 304) && has_transfer) ||
            (code == 204 && has_length && length != 0) ||
            (code == 205 && (has_transfer || (has_length && length != 0)))) return result;
        result.chunked = has_transfer && !head && code != 304;
        result.body_length = result.informational || head || code == 204 || code == 205 || code == 304 ? std::optional<std::uint64_t>(0) :
                             has_length ? std::optional<std::uint64_t>(length) : std::nullopt;
        result.consumed = header.consumed;
        result.wire = std::string(line) + "\r\n";
        append_fields(result.wire, header, false, !result.informational);
        result.status = ConnectStatus::accepted;
        return result;
    }
}
