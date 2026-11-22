import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_linux;
namespace n = ::platform::netlink;
namespace a = ::platform::netlink_abi;
namespace p = ::packet;
namespace {
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
    auto isolated(int argc, char **argv) -> bool {
        if (argc != 3) return false;
        std::uint64_t net = 0, user = 0;
        auto first = std::string_view(argv[1]), second = std::string_view(argv[2]);
        auto pn = std::from_chars(first.data(), first.data() + first.size(), net), pu = std::from_chars(second.data(), second.data() + second.size(), user);
        return pn.ec == std::errc{} && pu.ec == std::errc{} && net && user && inode("/proc/self/ns/net") != net && inode("/proc/self/ns/user") != user;
    }
} // namespace
auto main(int argc, char **argv) -> int {
    if (!isolated(argc, argv)) {
        std::println("requires independently identified disposable user/network namespaces");
        return 1;
    }
    auto tun = p::LinuxTun::create("nx-lease-probe");
    if (!tun) return 2;
    auto token = tun->claim_network();
    if (!token || tun->claim_network() || !token->inspect()) return 3;
    n::Socket socket;
    if (!socket.open()) return 4;
    unsigned links = 0, own = 0;
    auto result = socket.dump(a::RTM_GETLINK, a::AF_UNSPEC, n::Clock::now() + std::chrono::seconds(2), [&](n::Message message) -> std::expected<void, n::Failure> {
        if (message.header.nlmsg_type != a::RTM_NEWLINK) return n::fail(n::Error::protocol);
        auto link = n::native<a::ifinfomsg>(message.payload);
        if (!link) return n::fail(n::Error::protocol);
        ++links;
        return n::attributes(message.payload.subspan(sizeof(*link)), [&](n::Attribute attribute) -> std::expected<void, n::Failure> {
            if (attribute.type == a::IFLA_IFNAME && n::text(attribute, 15) == tun->name()) ++own;
            return {};
        });
    });
    if (!result) {
        std::println("dump error {} system {}", static_cast<int>(result.error().code), result.error().system.message());
        return 5;
    }
    if (links != 2 || own != 1) return 6;
    (void)token->close_device();
    if (tun->native_handle() != -1 || token->inspect()) return 7;
    std::println("native netlink private port id={} verified real kernel multipart link dump and sealed once-only TUN namespace token; links={}", socket.port_id(), links);
}
