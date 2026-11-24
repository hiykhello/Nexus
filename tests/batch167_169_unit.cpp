#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import platform.linux_random;
import platform.stream_peer;
import platform.network_state;
import platform.network_selection;
import platform.process_owner;
import platform.socket_options;
import packet;
import packet.tun_pump;

namespace {
    int failures = 0;
    auto expect(bool cond, std::string_view label) -> void {
        if (!cond) { ++failures; std::cerr << "FAIL: " << label << '\n'; }
    }

    enum class MockTunErr { fatal };
    using MockTunFailure = std::variant<MockTunErr, std::error_code>;
    struct MockTun {
        std::deque<std::expected<std::optional<std::vector<std::uint8_t>>, MockTunFailure>> reads;
        std::deque<std::expected<void, MockTunFailure>> write_results;
        std::vector<std::vector<std::uint8_t>> written;

        auto read_packet(std::span<std::uint8_t> out)
            -> std::expected<std::optional<std::size_t>, MockTunFailure> {
            if (reads.empty()) return std::optional<std::size_t>{};
            auto next = std::move(reads.front());
            reads.pop_front();
            if (!next) return std::unexpected(next.error());
            if (!*next) return std::optional<std::size_t>{};
            auto n = (**next).size();
            if (n <= out.size()) std::ranges::copy(**next, out.begin());
            return std::optional<std::size_t>{n};
        }

        auto write_packet(std::span<std::uint8_t const> pkt)
            -> std::expected<void, MockTunFailure> {
            if (!write_results.empty()) {
                auto next = std::move(write_results.front());
                write_results.pop_front();
                if (!next) return next;
            }
            written.emplace_back(pkt.begin(), pkt.end());
            return {};
        }
    };

    auto test_secure_random() -> void {
        expect(static_cast<bool>(platform::secure_random({})), "empty secure_random succeeds");
        std::array<std::byte, 32> a{}, b{};
        std::array<std::byte, 64> big{};
        expect(static_cast<bool>(platform::secure_random(a)), "32B secure_random succeeds");
        expect(static_cast<bool>(platform::secure_random(b)), "32B second secure_random succeeds");
        expect(static_cast<bool>(platform::secure_random(big)), "64B secure_random succeeds");
        auto nonzero = [](auto const& span) {
            return std::ranges::any_of(span, [](std::byte v) { return v != std::byte{0}; });
        };
        expect(nonzero(a) && nonzero(b) && nonzero(big), "secure_random produces non-zero entropy");
        expect(a != b, "consecutive secure_random outputs differ");
    }

    auto test_stream_peer() -> void {
        expect(!platform::stream_peer_closed(-1), "negative fd is not reported closed");
        int fds[2]{-1, -1};
        expect(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair for stream_peer");
        if (fds[0] >= 0 && fds[1] >= 0) {
            expect(!platform::stream_peer_closed(fds[0]), "open peer reports false");
            ::close(fds[1]);
            fds[1] = -1;
            expect(platform::stream_peer_closed(fds[0]), "closed peer reports true");
            ::close(fds[0]);
        }
    }

    auto test_network_state_and_selection() -> void {
        using namespace platform::network;
        Monitor mon{false};
        expect(!mon.started(), "monitor initially stopped");
        auto started = mon.start(Clock::now() + std::chrono::seconds(2));
        expect(started.has_value() && mon.started(), "monitor start succeeds on host");
        auto snap = mon.get();
        expect(snap && snap->generation >= 1 && !snap->links.empty(), "monitor snapshot populated");
        auto polled = mon.poll(Clock::now() + std::chrono::milliseconds(50));
        expect(polled.has_value() && !*polled, "clean poll returns false");
        mon.stop();
        expect(!mon.started(), "monitor stops cleanly");

        Snapshot synthetic{};
        synthetic.links = {
            {.index = 10, .flags = constants::iff_up | constants::iff_lower_up, .name = "eth0"},
            {.index = 20, .flags = constants::iff_up | constants::iff_lower_up, .name = "wlan0"},
        };
        Address a1{.index = 10, .family = constants::af_inet, .prefix = 24, .scope = constants::rt_scope_universe};
        Address a2{.index = 20, .family = constants::af_inet, .prefix = 24, .scope = constants::rt_scope_universe};
        synthetic.addresses = {a1, a2};
        Route r1{.table = constants::rt_table_main, .priority = 50, .index = 10, .family = constants::af_inet, .type = constants::rtn_unicast};
        Route r2{.table = constants::rt_table_main, .priority = 200, .index = 20, .family = constants::af_inet, .type = constants::rtn_unicast};
        synthetic.routes = {r1, r2};
        Policy pol{};
        pol.preferred = Type::wifi;
        pol.strategy = Strategy::fallback;
        pol.interfaces = {{"eth0", Type::ethernet}, {"wlan0", Type::wifi}};
        auto sel = select_interfaces(synthetic, pol, false);
        expect(sel.indices.size() == 2 && sel.indices[0] == 20 && sel.indices[1] == 10, "wifi preferred before wired fallback");
    }

    auto test_process_owner_helpers() -> void {
        constexpr std::array<std::uint8_t, 4> lo4{127, 0, 0, 1};
        constexpr std::array<std::uint8_t, 4> pub4{8, 8, 8, 8};
        constexpr std::array<std::uint8_t, 16> lo6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        constexpr std::array<std::uint8_t, 16> mapped4{0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,9};

        auto t4 = platform::make_loopback_socket_tuple(false, lo4, 41234, lo4, 1080);
        expect(t4 && t4->local_ip.size == 4 && t4->local_port == 41234 && t4->remote_port == 1080, "v4 loopback tuple");
        auto tm = platform::make_loopback_socket_tuple(false, mapped4, 41235, lo4, 1080);
        expect(tm && tm->local_ip.size == 4 && tm->local_ip.bytes[3] == 9, "mapped v4 normalized to IPv4 tuple");
        auto t6 = platform::make_loopback_socket_tuple(true, lo6, 51234, lo6, 1081);
        expect(t6 && t6->is_udp && t6->local_ip.size == 16 && t6->remote_ip.size == 16, "v6 loopback tuple");
        expect(!platform::make_loopback_socket_tuple(false, pub4, 1000, lo4, 1080), "public IP rejected");
        expect(!platform::make_loopback_socket_tuple(false, lo4, 0, lo4, 1080), "zero port rejected");
        expect(!platform::make_loopback_socket_tuple(false, lo6, 1000, lo4, 1080), "mixed family rejected");

        int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        int cli = ::socket(AF_INET, SOCK_STREAM, 0);
        if (srv >= 0 && cli >= 0) {
            sockaddr_in sa{.sin_family = AF_INET, .sin_port = 0};
            sa.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
            socklen_t slen = sizeof(sa);
            if (::bind(srv, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0 &&
                ::listen(srv, 1) == 0 &&
                ::getsockname(srv, reinterpret_cast<sockaddr*>(&sa), &slen) == 0 &&
                ::connect(cli, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0) {
                sockaddr_in ca{};
                socklen_t clen = sizeof(ca);
                if (::getsockname(cli, reinterpret_cast<sockaddr*>(&ca), &clen) == 0) {
                    auto tuple = platform::make_loopback_socket_tuple(
                        false, lo4, ::ntohs(ca.sin_port), lo4, ::ntohs(sa.sin_port));
                    if (tuple) {
                        if (auto owner = platform::lookup_socket_owner(*tuple)) {
                            expect(owner->uid == static_cast<std::uint32_t>(::getuid()), "live lookup returns own uid");
                        }
                    }
                }
            }
        }
        if (cli >= 0) ::close(cli);
        if (srv >= 0) ::close(srv);
    }

    auto test_tun_pump() -> void {
        using Pump = packet::TunDevicePump<MockTun>;
        MockTun tun{};
        packet::MemoryLink link({.packet_bytes = 128, .queue_packets = 1, .queue_bytes = 256});
        expect(!Pump::create(tun, link, 64), "mtu below 68 rejected");
        auto created = Pump::create(tun, link, 128);
        expect(created.has_value(), "valid pump created");
        if (!created) return;
        auto& pump = *created;

        tun.reads.push_back(std::vector<std::uint8_t>{0x45, 0x00, 0x00, 0x14});
        auto step1 = pump.step();
        expect(step1.input && step1.input_delivered && !step1.input_backpressured && !step1.input_error, "inbound delivered");
        auto got_in = link.receive_packet(packet::Side::second);
        expect(got_in && *got_in && (*got_in)->bytes.size() == 4, "MemoryLink second side received packet");

        tun.write_results.push_back(std::unexpected(MockTunFailure{std::make_error_code(std::errc::resource_unavailable_try_again)}));
        expect(static_cast<bool>(link.send(packet::Side::second, std::array<std::uint8_t, 5>{0x60, 1, 2, 3, 4})), "send to link");
        auto step2 = pump.step();
        expect(step2.output_backpressured && !step2.output_delivered && pump.pending(), "write would-block preserves output");
        auto step3 = pump.step();
        expect(step3.output_delivered && !pump.pending() && tun.written.size() == 1 && tun.written[0].size() == 5, "retried write delivers");

        tun.reads.push_back(std::optional<std::vector<std::uint8_t>>{});
        auto step4 = pump.step();
        expect(!step4.input && !step4.input_error && !step4.output_delivered, "empty read poll is no-op");

        tun.reads.push_back(std::vector<std::uint8_t>(200, 0x45));
        auto step5 = pump.step();
        expect(step5.input_error.has_value() && !pump.pending(), "oversize inbound packet rejected");

        expect(static_cast<bool>(link.send(packet::Side::second, std::array<std::uint8_t, 4>{1, 2, 3, 4})), "queue outbound discard setup");
        expect(static_cast<bool>(link.send(packet::Side::first, std::array<std::uint8_t, 4>{5, 6, 7, 8})), "queue full inbound setup");
        tun.reads.push_back(std::vector<std::uint8_t>{0x45, 1, 2, 3});
        auto step6 = pump.step([](void*, packet::QueuedPacket const&) noexcept { return false; });
        expect(step6.output_discarded && step6.input_backpressured && pump.pending(), "validator discards & full queue backpressures");
        (void)link.receive_packet(packet::Side::second);
        auto step7 = pump.step();
        expect(step7.input_delivered && !pump.pending(), "queued inbound delivers once link drains");

        expect(static_cast<bool>(link.send(packet::Side::second, std::array<std::uint8_t, 4>{9, 8, 7, 6})), "send error test packet");
        tun.write_results.push_back(std::unexpected(MockTunFailure{MockTunErr::fatal}));
        auto step8 = pump.step();
        expect(step8.output_error.has_value() && !pump.pending(), "fatal write error clears output");
    }
}

auto main() -> int {
    test_secure_random();
    test_stream_peer();
    test_network_state_and_selection();
    test_process_owner_helpers();
    test_tun_pump();
    if (failures) {
        std::cerr << "batch167-169-unit failed (" << failures << " checks)\n";
        return 1;
    }
    std::cout << "batch167-169 unit tests (entropy / stream_peer / network_state / process_owner / tun_pump) passed\n";
    return 0;
}
