import std;
import corosio;

namespace io = ::corosio;

auto main() -> int {
    auto [v4_error, v4] = io::make_endpoint("127.0.0.1:8080");
    if (v4_error || !v4.is_v4() || v4.port() != 8080) return 1;

    auto [v6_error, v6] = io::make_endpoint("[::1]:443");
    if (v6_error || !v6.is_v6() || v6.port() != 443) return 2;

    auto [no_port_error, no_port] = io::make_endpoint("192.0.2.1");
    if (no_port_error || !no_port.is_v4() || no_port.port() != 0) return 3;

    if (io::detect_endpoint_format("192.0.2.1:80") != io::endpoint_format::ipv4_with_port ||
        io::detect_endpoint_format("[::1]") != io::endpoint_format::ipv6_bracketed)
        return 4;

    auto [bad_error, bad] = io::make_endpoint("[::1");
    if (!bad_error || bad.port() != 0) return 5;

    auto [local_error, local] = io::make_local_endpoint("/tmp/nexus-corosio-endpoint.sock");
    if (local_error || local.empty() || local.path() != "/tmp/nexus-corosio-endpoint.sock") return 6;

    auto [long_error, unused] = io::make_local_endpoint(std::string(io::local_endpoint::max_path_length + 1, 'x'));
    if (!long_error || !unused.empty()) return 7;

    std::println("Corosio endpoint factories and module exports passed");
}
