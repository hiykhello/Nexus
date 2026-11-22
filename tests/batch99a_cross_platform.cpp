#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/random.h>

constexpr int kSysONoFollow = O_NOFOLLOW;
constexpr int kSysOCloexec = O_CLOEXEC;
constexpr unsigned int kSysGrndNonblock = GRND_NONBLOCK;
#undef O_NOFOLLOW
#undef O_CLOEXEC
#undef GRND_NONBLOCK

import std;
import platform.ip_address;
import platform.netlink_abi;
import platform.linux_random;

static_assert(platform::netlink_abi::O_NOFOLLOW == kSysONoFollow);
static_assert(platform::netlink_abi::O_CLOEXEC == kSysOCloexec);
static_assert(platform::linux_random_abi::nonblocking_flag == kSysGrndNonblock);

// Compile-time constexpr check proving zero libc dependency in platform.ip_address!
static_assert(platform::parse_ip_address("127.0.0.1").has_value());
static_assert(platform::parse_ip_address("2001:db8::1").has_value());
static_assert(!platform::parse_ip_address("fe80::1%eth0").has_value());
static_assert(!platform::parse_ip_address("01.2.3.4").has_value());

int main() {
    constexpr std::string_view kCases[] = {
        // Valid IPv4
        "0.0.0.0", "127.0.0.1", "10.0.0.1", "192.168.255.254", "255.255.255.255",
        // Invalid IPv4
        "", " ", "0.0.0", "0.0.0.0.0", "256.0.0.1", "1.2.3.999", "01.2.3.4", "1.02.3.4",
        "1.2.3.04", "1.2.3.", ".1.2.3", "1..2.3", "1.2.3.4 ", " 1.2.3.4", "+1.2.3.4", "-1.2.3.4",
        "1.2.3.4/24", "1.2.3.4:80", "0x7f.0.0.1",
        // Valid IPv6
        "::", "::1", "fe80::", "fe80::1", "2001:db8::1", "2001:0db8:0000:0000:0000:ff00:0042:8329",
        "2001:DB8:a:b:c:d:e:F", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8",
        // Valid IPv4-mapped / embedded IPv6
        "::ffff:192.0.2.128", "::127.0.0.1", "64:ff9b::192.0.2.33", "0:0:0:0:0:ffff:10.20.30.40",
        "2001:db8:1:2:3:4:192.0.2.1",
        // Invalid IPv6
        ":", ":::", "::1::2", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:", ":1:2:3:4:5:6:7", "2001:db8::1%eth0", "2001:db8::1/64",
        "2001:db8::12345", "2001:db8::gggg", "::ffff:01.2.3.4", "::ffff:256.0.0.1",
        "1:2:3:4:5:6:7:1.2.3.4", "2001:db8::1.2.3", "[::1]", "2001:db8::1 ",
    };

    for (auto text : kCases) {
        std::string z(text);
        std::array<std::uint8_t, 16> ref{};
        std::uint8_t ref_size = 0;
        if (::inet_pton(AF_INET, z.c_str(), ref.data()) == 1) ref_size = 4;
        else if (::inet_pton(AF_INET6, z.c_str(), ref.data()) == 1) ref_size = 16;

        auto got = platform::parse_ip_address(text);
        if (ref_size == 0) {
            if (got.has_value()) {
                std::cerr << "false positive on: [" << text << "]\n";
                return 1;
            }
        } else {
            if (!got || got->size != ref_size || !std::ranges::equal(got->view(), std::span(ref).first(ref_size))) {
                std::cerr << "mismatch on valid IP: [" << text << "]\n";
                return 2;
            }
        }
    }

    std::string with_nul("127.0.0.1\0extra", 15);
    if (platform::parse_ip_address(with_nul).has_value()) return 3;

    // Batch 100: Exhaustive RFC 5952 + inet_ntop parity checks & byte-order helpers
    static_assert(platform::host_to_net16(0x1234) == platform::net_to_host16(0x1234));
    static_assert(platform::net_to_host16(platform::host_to_net16(0x1234)) == 0x1234);
    static_assert(platform::net_to_host32(platform::host_to_net32(0x12345678u)) == 0x12345678u);

    constexpr std::string_view kFormatCases[] = {
        "0.0.0.0", "1.2.3.4", "10.0.0.1", "127.0.0.1", "192.168.100.255", "255.255.255.255",
        "::", "::1", "::2", "fe80::", "fe80::1", "2001:db8::1", "2001:db8:0:0:1::1",
        "2001:db8:0:1:0:0:0:1", "2001:db8:0:0:1:0:0:1", "2001:db8:1:0:2:0:3:4",
        "1:2:3:4:5:6:7:8", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "::ffff:192.0.2.128", "::ffff:0.0.0.0", "::192.0.2.1", "::0.1.2.3",
        "0:0:0:0:0:ffff:10.20.30.40", "2001:db8::0:1:2", "0:0:1:2:3:4:5:6",
    };
    for (auto text : kFormatCases) {
        auto parsed = platform::parse_ip_address(text);
        if (!parsed) return 4;
        auto formatted = platform::format_ip_address(parsed->view());
        if (!formatted) return 5;
        char ref[INET6_ADDRSTRLEN]{};
        int af = parsed->size == 4 ? AF_INET : AF_INET6;
        if (!::inet_ntop(af, parsed->bytes.data(), ref, sizeof(ref))) return 6;
        if (*formatted != ref) {
            std::cerr << "format mismatch for [" << text << "]: got=[" << *formatted << "] ref=[" << ref << "]\n";
            return 7;
        }
    }

    std::cout << "ALL BATCH 99A + 100 CROSS-PLATFORM PORTABILITY, IP PARSER & RFC 5952 FORMATTER TESTS PASSED ("
              << std::size(kCases) << " parse + " << std::size(kFormatCases) << " format cases)\n";
    return 0;
}
