import std;
import http.connect;

namespace h = http;

int main() {
    std::string request = "CONNECT Example.COM:443 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    auto length = request.size();
    request += "\x16\x03\x01";
    for (std::size_t n = 0; n < length; ++n) {
        if (h::parse_connect(std::string_view(request).substr(0, n)).status != h::ConnectStatus::incomplete) {
            std::cerr << "partial request rejected at " << n << '\n'; return 1;
        }
    }
    auto parsed = h::parse_connect(request);
    if (parsed.status != h::ConnectStatus::accepted || parsed.consumed != length || parsed.host != "Example.COM" ||
        parsed.port != 443 || parsed.kind != h::HostKind::domain) return 1;
    for (auto const& [text, kind] : std::vector<std::pair<std::string, h::HostKind>>{
        {"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n", h::HostKind::ipv4},
        {"CONNECT [::1]:443 HTTP/1.1\r\nHost: [0:0:0:0:0:0:0:1]:443\r\n\r\n", h::HostKind::ipv6}}) {
        auto result = h::parse_connect(text);
        if (result.status != h::ConnectStatus::accepted || result.kind != kind) return 1;
    }
    using enum h::ConnectStatus;
    std::vector<std::pair<std::string, h::ConnectStatus>> cases{
        {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", unsupported},
        {"CONNECT example.com:443 HTTP/1.0\r\nHost: example.com\r\n\r\n", malformed},
        {"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n", malformed},
        {"CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\n\r\n", malformed},
        {"CONNECT example.com:65536 HTTP/1.1\r\nHost: example.com\r\n\r\n", malformed},
        {"CONNECT [::1:443 HTTP/1.1\r\nHost: [::1]\r\n\r\n", malformed},
        {"CONNECT 127.1:80 HTTP/1.1\r\nHost: 127.1\r\n\r\n", malformed},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: other.com\r\n\r\n", malformed},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:80\r\n\r\n", malformed},
        {"CONNECT example.com:443 HTTP/1.1\r\n\r\n", malformed},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n", malformed},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n", unsupported},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n", unsupported},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic x\r\n\r\n", unsupported},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n folded\r\n\r\n", malformed},
        {"CONNECT example.com:443 HTTP/1.1\r\nHost : example.com\r\n\r\n", malformed},
        {std::string(h::max_connect_header_bytes, 'x'), too_large},
    };
    for (auto const& [text, expected] : cases) {
        auto actual = h::parse_connect(text).status;
        if (actual != expected) { std::cerr << "unexpected result for " << text.substr(0, 50) << '\n'; return 1; }
    }
    auto many = std::string("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n");
    for (int i = 0; i < 100; ++i) many += "X: x\r\n";
    many += "\r\n";
    if (h::parse_connect(many).status != malformed) return 1;
    std::cout << "HTTP CONNECT request parsing and boundaries passed\n";
}
