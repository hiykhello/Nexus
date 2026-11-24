export module test.lease_support;
import std;
import platform.netlink_abi;
import platform.netlink_socket;
import packet.tun_network_types;

export namespace test::lease {
    namespace abi = ::platform::netlink_abi;
    namespace nl = ::platform::netlink;
    inline auto require(bool condition, std::source_location source = std::source_location::current()) -> void {
        if (!condition) {
            std::println("TUN lease test failed at {}:{}", source.file_name(), source.line());
            throw 1;
        }
    }
    inline auto namespace_id(char const *path) -> std::uint64_t {
        std::array<char, 128> text{};
        auto count = abi::readlink(path, text.data(), text.size());
        if (count <= 0 || count >= static_cast<std::ptrdiff_t>(text.size())) return 0;
        auto view = std::string_view(text.data(), count);
        auto start = view.find('[');
        if (start == view.npos || !view.ends_with(']')) return 0;
        std::uint64_t value = 0;
        auto parsed = std::from_chars(view.data() + start + 1, view.data() + view.size() - 1, value);
        return parsed.ec == std::errc{} && parsed.ptr == view.data() + view.size() - 1 ? value : 0;
    }
    inline auto number(std::string_view text) -> std::uint64_t {
        std::uint64_t value = 0;
        auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
        require(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size());
        return value;
    }
    inline auto isolation(int argc, char **argv) -> void {
        require(argc >= 3);
        auto net = number(argv[1]), user = number(argv[2]);
        auto current_net = namespace_id("/proc/self/ns/net"), current_user = namespace_id("/proc/self/ns/user");
        require(net && user && current_net && current_user && net != current_net && user != current_user);
    }
    inline auto options() -> ::packet::TunNetworkOptions {
        ::packet::TunNetworkOptions result;
        result.mtu = 1420;
        result.address_count = result.route_count = 2;
        result.addresses[0] = {4, {10, 42, 0, 1}, 24};
        result.addresses[1] = {6, {0xfd, 0x42}, 64};
        result.addresses[1].bytes[15] = 1;
        result.routes[0] = {4, {10, 42, 0, 2}, 32};
        result.routes[1] = {6, {0xfd, 0x42}, 128};
        result.routes[1].bytes[15] = 2;
        return result;
    }
    inline auto deadline() -> nl::Clock::time_point { return nl::Clock::now() + std::chrono::seconds(4); }
} // namespace test::lease
