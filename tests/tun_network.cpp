import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network;
import packet.tun_network_records;
namespace n = ::platform::netlink;
namespace a = ::platform::netlink_abi;
namespace p = ::packet;
namespace {
    auto check(bool condition, std::source_location source = std::source_location::current()) -> void {
        if (!condition) {
            std::println("TUN lease failure line {}", source.line());
            throw 1;
        }
    }
    auto inode(char const *path) -> std::uint64_t {
        std::array<char, 128> text{};
        auto count = a::readlink(path, text.data(), text.size());
        if (count <= 0 || count >= static_cast<std::ptrdiff_t>(text.size())) return 0;
        auto view = std::string_view(text.data(), count);
        auto start = view.find('[');
        if (start == view.npos || !view.ends_with(']')) return 0;
        std::uint64_t value = 0;
        auto parsed = std::from_chars(view.data() + start + 1, view.data() + view.size() - 1, value);
        return parsed.ec == std::errc{} && parsed.ptr == view.data() + view.size() - 1 ? value : 0;
    }
    auto isolation(int argc, char **argv) -> void {
        check(argc == 3);
        std::uint64_t net = 0, user = 0;
        auto first = std::string_view(argv[1]), second = std::string_view(argv[2]);
        check(std::from_chars(first.data(), first.data() + first.size(), net).ec == std::errc{} &&
              std::from_chars(second.data(), second.data() + second.size(), user).ec == std::errc{});
        check(net && user && inode("/proc/self/ns/net") != net && inode("/proc/self/ns/user") != user);
    }
    auto options() -> p::TunNetworkOptions {
        p::TunNetworkOptions result;
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
} // namespace
auto main(int argc, char **argv) -> int {
    try {
        isolation(argc, argv);
        auto tun = p::LinuxTun::create("nx-lease");
        check(tun.has_value());
        auto lease = p::TunNetworkLease<>::create(*tun, options());
        check(lease.has_value());
        auto started = lease->start(n::Clock::now() + std::chrono::seconds(3));
        if (!started) {
            auto error = started.error();
            std::println("start error code={} stage={} system={} nl={} device={} cleanup={} removed={}", int(error.code), int(error.stage), error.system.message(),
                         error.netlink ? int(error.netlink->code) : -1, error.device ? int(error.device->index()) : -1, lease->cleanup().total, lease->cleanup().device_removed);
        }
        check(started.has_value());
        auto state = lease->status();
        check(state.started && !state.stopped && state.addresses == 2 && state.routes == 2 && state.ifindex > 0);
        auto stopped = lease->stop(n::Clock::now() + std::chrono::seconds(3));
        if (stopped.total)
            for (std::size_t i = 0; i < stopped.recorded; ++i)
                std::println("cleanup error {} stage={} system={}", int(stopped.issues[i].code), int(stopped.issues[i].stage), stopped.issues[i].system.message());
        check(!stopped.total && lease->drained() && tun->native_handle() == -1);
        std::println("real TUN netlink lease configured MTU, dual-family NOPREFIXROUTE/NODAD addresses and explicit split routes; ACK/readback and stop removed device; sizeof "
                     "lease={} tun={}",
                     sizeof(*lease), sizeof(*tun));
    } catch (int value) { return value; }
}
