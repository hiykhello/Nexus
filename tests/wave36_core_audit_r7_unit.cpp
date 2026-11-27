#include <cstdlib>
#include <fcntl.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

import std;
import cli.control;
import packet.tun_network_plan;
import packet.tun_network_darwin;
import packet.tun_network_windows;
import platform.os_fs;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL [wave36-r7-unit]: " << msg << '\n';
            std::exit(1);
        }
    }

    auto cidr(std::string_view text) -> packet::TunCidr {
        auto parsed = packet::parse_tun_cidr(text);
        require(parsed.has_value(), "parse_tun_cidr");
        return *parsed;
    }

    auto test_tun_cidr_coverage_and_required_excludes() -> void {
        using namespace packet;
        require(tun_cidr_covers(TunCidr{4, {0}, 1}, cidr("10.0.0.0/8")), "0.0.0.0/1 covers 10.0.0.0/8");
        require(tun_cidr_covers(TunCidr{4, {128}, 1}, cidr("192.168.0.0/16")), "128.0.0.0/1 covers 192.168.0.0/16");
        require(!tun_cidr_covers(TunCidr{4, {0}, 1}, cidr("192.168.0.0/16")), "0.0.0.0/1 does not cover 192.168.0.0/16");
        require(!tun_cidr_covers(TunCidr{4, {0}, 1}, cidr("fc00::/7")), "v4 does not cover v6");
        require(tun_cidr_covers(TunCidr{6, {0x80}, 1}, cidr("fc00::/7")), "8000::/1 covers fc00::/7");
        require(tun_cidr_covers(TunCidr{6, {0x80}, 1}, cidr("fe80::/10")), "8000::/1 covers fe80::/10");
        require(tun_cidr_covers(cidr("198.18.0.0/15"), cidr("198.18.1.0/24")), "198.18.0.0/15 covers 198.18.1.0/24");
        require(!tun_cidr_covers(cidr("198.18.1.0/24"), cidr("198.18.0.0/15")), "narrow does not cover broad");

        TunRoutePlanInput full_in{
            .inet4 = cidr("172.19.0.1/30"),
            .inet6 = cidr("fdfe:dcba:9876::1/126"),
            .mtu = 1500,
            .auto_route = true,
            .route_exclude_private = true,
        };
        auto full_plan = plan_cross_platform_tun_routes(full_in);
        require(full_plan.has_value(), "dual-stack plan");
        auto req_full = required_tun_excludes(*full_plan);
        require(req_full.size() == 7, "all 7 private excludes required under split default routes");

        TunRoutePlanInput narrow_in{
            .inet4 = cidr("172.19.0.1/30"),
            .mtu = 1500,
            .auto_route = true,
            .includes = {cidr("198.18.0.0/15")},
            .excludes = {cidr("10.0.0.0/8"), cidr("198.18.1.0/24")},
        };
        auto narrow_plan = plan_cross_platform_tun_routes(narrow_in);
        require(narrow_plan.has_value(), "narrow plan");
        auto req_narrow = required_tun_excludes(*narrow_plan);
        require(req_narrow.size() == 1 && req_narrow[0] == cidr("198.18.1.0/24"),
            "only excludes covered by capture routes are required");

        TunRoutePlanInput no_auto_in{
            .inet4 = cidr("172.19.0.1/30"),
            .mtu = 1500,
            .auto_route = false,
            .route_exclude_private = true,
        };
        auto no_auto_plan = plan_cross_platform_tun_routes(no_auto_in);
        require(no_auto_plan.has_value() && required_tun_excludes(*no_auto_plan).empty(),
            "no capture routes means no required exclude routes");
    }

    auto test_tun_apply_rollback_and_ordering() -> void {
        using namespace packet;
        TunRoutePlanInput dual_in{
            .inet4 = cidr("172.19.0.1/30"),
            .inet6 = cidr("fdfe:dcba:9876::1/126"),
            .mtu = 1500,
            .auto_route = true,
            .route_exclude_private = true,
        };
        auto plan = plan_darwin_tun_network(dual_in, "utun9");
        require(plan.has_value(), "darwin dual-stack plan");

        // 1. Darwin case: IPv4 default GW ok, IPv6 default GW missing -> abort & rollback before capture routes.
        {
            bool configured = false, rolled_back = false;
            std::size_t exc_added = 0, cap_added = 0;
            auto res = apply_tun_route_plan(
                *plan,
                [](TunCidr const& exc) -> std::expected<int, std::error_code> {
                    if (exc.family == 6) return std::unexpected(std::make_error_code(std::errc::network_unreachable));
                    return 4;
                },
                [&]() -> std::error_code { configured = true; return {}; },
                [&](TunCidr const&, int) -> std::error_code { ++exc_added; return {}; },
                [&](TunCidr const&) -> std::error_code { ++cap_added; return {}; },
                [&]() noexcept { rolled_back = true; });
            require(!res && res.error() == std::errc::network_unreachable, "missing v6 gw fails");
            require(!configured && exc_added == 0 && cap_added == 0 && rolled_back,
                "missing v6 gw aborts before interface/capture mutation and rolls back");
        }

        // 2. Windows case: GetBestRoute2 returns TUN adapter LUID -> abort & rollback before capture routes.
        {
            auto wplan = plan_windows_tun_network(dual_in);
            require(wplan.has_value(), "windows dual-stack plan");
            constexpr std::uint64_t kTunLuid = 42, kNicLuid = 7;
            bool rolled_back = false;
            std::size_t resolve_calls = 0, cap_added = 0;
            auto res = apply_tun_route_plan(
                *wplan,
                [&](TunCidr const&) -> std::expected<std::uint64_t, std::error_code> {
                    ++resolve_calls;
                    std::uint64_t best = (resolve_calls == 3) ? kTunLuid : kNicLuid;
                    if (best == 0 || best == kTunLuid)
                        return std::unexpected(std::make_error_code(std::errc::network_unreachable));
                    return best;
                },
                []() -> std::error_code { return {}; },
                [](TunCidr const&, std::uint64_t) -> std::error_code { return {}; },
                [&](TunCidr const&) -> std::error_code { ++cap_added; return {}; },
                [&]() noexcept { rolled_back = true; });
            require(!res && res.error() == std::errc::network_unreachable && cap_added == 0 && rolled_back,
                "windows route pointing into TUN aborts with rollback");
        }

        // 3. Mid-install exclude failure -> rolls back installed excludes & addresses, zero capture routes installed.
        {
            std::vector<std::string> log;
            std::size_t exc_n = 0, cap_n = 0;
            auto res = apply_tun_route_plan(
                *plan,
                [](TunCidr const&) -> std::expected<int, std::error_code> { return 1; },
                [&]() -> std::error_code { log.emplace_back("cfg"); return {}; },
                [&](TunCidr const&, int) -> std::error_code {
                    ++exc_n;
                    if (exc_n == 2) return std::make_error_code(std::errc::permission_denied);
                    log.emplace_back("exc");
                    return {};
                },
                [&](TunCidr const&) -> std::error_code { ++cap_n; return {}; },
                [&]() noexcept { log.emplace_back("rollback"); });
            require(!res && res.error() == std::errc::permission_denied, "exclude install failure propagated");
            require(cap_n == 0 && log.size() == 3 && log[0] == "cfg" && log[1] == "exc" && log[2] == "rollback",
                "exclude failure rolls back without installing any capture route");
        }

        // 4. Mid-install capture failure -> rolls back capture route #1 + all excludes + addresses.
        {
            bool rolled_back = false;
            std::size_t exc_n = 0, cap_n = 0;
            auto res = apply_tun_route_plan(
                *plan,
                [](TunCidr const&) -> std::expected<int, std::error_code> { return 1; },
                []() -> std::error_code { return {}; },
                [&](TunCidr const&, int) -> std::error_code { ++exc_n; return {}; },
                [&](TunCidr const&) -> std::error_code {
                    ++cap_n;
                    if (cap_n == 2) return std::make_error_code(std::errc::io_error);
                    return {};
                },
                [&]() noexcept { rolled_back = true; });
            require(!res && res.error() == std::errc::io_error && exc_n == 7 && cap_n == 2 && rolled_back,
                "capture install failure rolls back all excludes & prior capture routes");
        }

        // 5. Happy path: strict phase ordering resolve -> configure -> excludes -> captures.
        {
            std::vector<int> phases;
            auto res = apply_tun_route_plan(
                *plan,
                [&](TunCidr const&) -> std::expected<int, std::error_code> { phases.push_back(1); return 1; },
                [&]() -> std::error_code { phases.push_back(2); return {}; },
                [&](TunCidr const&, int) -> std::error_code { phases.push_back(3); return {}; },
                [&](TunCidr const&) -> std::error_code { phases.push_back(4); return {}; },
                []() noexcept { require(false, "happy path must not rollback"); });
            require(res.has_value(), "happy path succeeds");
            require(std::ranges::is_sorted(phases) && phases.front() == 1 && phases.back() == 4,
                "phases execute strictly in order 1 -> 2 -> 3 -> 4");
            require(std::ranges::count(phases, 1) == 7 && std::ranges::count(phases, 2) == 1 &&
                    std::ranges::count(phases, 3) == 7 && std::ranges::count(phases, 4) == 4,
                "exact phase counts match plan");
        }
    }

    auto test_windows_flush_classification() -> void {
        using platform::classify_windows_flush_result;
        require(classify_windows_flush_result(true, false, 0), "file flush success");
        require(classify_windows_flush_result(true, true, 0), "dir flush success");
        require(classify_windows_flush_result(false, true, 5), "dir ERROR_ACCESS_DENIED accepted");
        require(classify_windows_flush_result(false, true, 1), "dir ERROR_INVALID_FUNCTION accepted");
        require(!classify_windows_flush_result(false, false, 5), "regular file ERROR_ACCESS_DENIED must fail");
        require(!classify_windows_flush_result(false, false, 1), "regular file ERROR_INVALID_FUNCTION must fail");
        require(!classify_windows_flush_result(false, true, 1117), "dir ERROR_IO_DEVICE must fail");
        require(!classify_windows_flush_result(false, true, 29), "dir ERROR_WRITE_FAULT must fail");
        require(!classify_windows_flush_result(false, true, 6), "dir ERROR_INVALID_HANDLE must fail");
        require(!classify_windows_flush_result(false, false, 1117), "regular file ERROR_IO_DEVICE must fail");

        require(platform::sync_native_handle(static_cast<std::uintptr_t>(-1)) < 0, "invalid handle sync fails");
#if !defined(_WIN32)
        auto tmp = std::filesystem::temp_directory_path() /
            ("nexus-r7-sync-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(tmp);
        int dfd = ::open(tmp.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        require(dfd >= 0 && platform::sync_native_handle(static_cast<std::uintptr_t>(dfd)) == 0, "posix dir sync ok");
        ::close(dfd);
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
#endif
    }

    struct MockPipeOps {
        struct SlotScript {
            cli::AsyncPipeIoStatus next_connect = cli::AsyncPipeIoStatus::pending;
            cli::AsyncPipeIoResult connect_poll{cli::AsyncPipeIoStatus::pending, 0};
            std::string next_read_payload;
            cli::AsyncPipeIoStatus next_read_status = cli::AsyncPipeIoStatus::pending;
            cli::AsyncPipeIoResult read_poll{cli::AsyncPipeIoStatus::pending, 0};
            std::string read_poll_payload;
            std::size_t write_chunk_limit = 65536;
            bool write_async = false;
            cli::AsyncPipeIoResult write_poll{cli::AsyncPipeIoStatus::pending, 0};
            cli::AsyncPipeIoStatus next_drain = cli::AsyncPipeIoStatus::broken;
            cli::AsyncPipeIoResult drain_poll{cli::AsyncPipeIoStatus::pending, 0};
            int cancel_pending_ticks = 0;

            bool ready = false;
            bool cancelled = false;
            std::size_t cancel_calls = 0;
            std::size_t disconnect_calls = 0;
            std::size_t connect_calls = 0;
            std::string written;
            std::span<char> active_read_buf{};
            std::size_t active_write_len = 0;
            enum class Op { none, connect, read, write, drain } active_op = Op::none;
        };

        std::vector<SlotScript> slots;
        explicit MockPipeOps(std::size_t n) : slots(n) {}

        auto start_connect(std::size_t idx) -> cli::AsyncPipeIoStatus {
            auto& s = slots[idx];
            ++s.connect_calls;
            s.cancelled = false;
            s.active_op = SlotScript::Op::connect;
            return s.next_connect;
        }
        auto start_read(std::size_t idx, std::span<char> buf) -> cli::AsyncPipeIoResult {
            auto& s = slots[idx];
            s.active_op = SlotScript::Op::read;
            s.active_read_buf = buf;
            if (s.next_read_status == cli::AsyncPipeIoStatus::completed) {
                auto n = std::min(buf.size(), s.next_read_payload.size());
                std::memcpy(buf.data(), s.next_read_payload.data(), n);
                return {cli::AsyncPipeIoStatus::completed, n};
            }
            return {s.next_read_status, 0};
        }
        auto start_write(std::size_t idx, std::span<char const> buf) -> cli::AsyncPipeIoResult {
            auto& s = slots[idx];
            s.active_op = SlotScript::Op::write;
            auto n = std::min(buf.size(), s.write_chunk_limit);
            s.written.append(buf.data(), n);
            s.active_write_len = n;
            if (s.write_async) return {cli::AsyncPipeIoStatus::pending, 0};
            return {cli::AsyncPipeIoStatus::completed, n};
        }
        auto start_drain(std::size_t idx, char&) -> cli::AsyncPipeIoResult {
            auto& s = slots[idx];
            s.active_op = SlotScript::Op::drain;
            return {s.next_drain, 0};
        }
        auto poll_io(std::size_t idx) -> cli::AsyncPipeIoResult {
            auto& s = slots[idx];
            if (s.cancelled) {
                if (s.cancel_pending_ticks > 0) {
                    --s.cancel_pending_ticks;
                    return {cli::AsyncPipeIoStatus::pending, 0};
                }
                return {cli::AsyncPipeIoStatus::failed, 0};
            }
            switch (s.active_op) {
            case SlotScript::Op::connect:
                return std::exchange(s.connect_poll, {cli::AsyncPipeIoStatus::pending, 0});
            case SlotScript::Op::read:
                if (s.read_poll.status == cli::AsyncPipeIoStatus::completed) {
                    auto n = std::min(s.active_read_buf.size(), s.read_poll_payload.size());
                    std::memcpy(s.active_read_buf.data(), s.read_poll_payload.data(), n);
                    return {cli::AsyncPipeIoStatus::completed, n};
                }
                return s.read_poll;
            case SlotScript::Op::write:
                return s.write_poll;
            case SlotScript::Op::drain:
                return s.drain_poll;
            default:
                return {cli::AsyncPipeIoStatus::failed, 0};
            }
        }
        [[nodiscard]] auto has_ready_io(std::size_t idx) const noexcept -> bool { return slots[idx].ready; }
        auto cancel_io(std::size_t idx) noexcept -> void {
            slots[idx].cancelled = true;
            ++slots[idx].cancel_calls;
        }
        auto disconnect(std::size_t idx) noexcept -> void {
            ++slots[idx].disconnect_calls;
            slots[idx].active_op = SlotScript::Op::none;
        }
    };

    auto test_async_pipe_state_machine() -> void {
        using Clock = cli::AsyncPipeEngine::Clock;
        auto handler_fn = [](cli::ControlRole, std::span<std::string_view const> args)
            -> std::expected<std::string, std::string> {
            if (!args.empty() && args[0] == "status") return std::string("running");
            return std::unexpected("unknown");
        };
        cli::ControlHandler handler{handler_fn};
        auto t0 = Clock::now();

        // 1. Stalled drain on slot 0 NEVER blocks slot 1, times out at deadline, honors slow CancelIoEx.
        {
            MockPipeOps ops(2);
            cli::AsyncPipeEngine eng(2, std::chrono::milliseconds(2000));
            require(eng.init(ops), "init 2 slots");
            require(!eng.next_poll_delay(ops).has_value(), "idle slots have no tight poll delay");

            // Slot 0 connects & reads & writes, then enters pending draining (stalled client never reads!).
            ops.slots[0].connect_poll = {cli::AsyncPipeIoStatus::completed, 0};
            ops.slots[0].next_read_status = cli::AsyncPipeIoStatus::completed;
            ops.slots[0].next_read_payload = "NEXUS/1 status";
            ops.slots[0].next_drain = cli::AsyncPipeIoStatus::pending;
            ops.slots[0].drain_poll = {cli::AsyncPipeIoStatus::pending, 0};
            ops.slots[0].cancel_pending_ticks = 2;
            ops.slots[0].ready = true;
            require(eng.next_poll_delay(ops) == std::chrono::milliseconds(0), "ready io asks 0ms poll");

            eng.poll(ops, t0, handler);
            ops.slots[0].ready = false;
            require(eng.slot_phase(0) == cli::AsyncPipePhase::draining && eng.slot_pending(0),
                "slot 0 parked non-blockingly in draining");
            require(ops.slots[0].written == "NEXUS/1 OK\nrunning\n", "slot 0 reply written");
            require(eng.next_poll_delay(ops) == std::chrono::milliseconds(5), "active draining asks 5ms poll");

            // While slot 0 is stalled in draining, slot 1 serves a healthy client end-to-end in 1 tick!
            ops.slots[1].connect_poll = {cli::AsyncPipeIoStatus::completed, 0};
            ops.slots[1].next_read_status = cli::AsyncPipeIoStatus::completed;
            ops.slots[1].next_read_payload = "NEXUS/1 status";
            ops.slots[1].next_drain = cli::AsyncPipeIoStatus::broken;
            ops.slots[1].next_connect = cli::AsyncPipeIoStatus::pending;
            eng.poll(ops, t0 + std::chrono::milliseconds(500), handler);
            require(ops.slots[1].written == "NEXUS/1 OK\nrunning\n" && ops.slots[1].disconnect_calls == 1 &&
                    eng.slot_phase(1) == cli::AsyncPipePhase::accepting,
                "slot 1 serves healthy client while slot 0 stalls");
            require(eng.slot_phase(0) == cli::AsyncPipePhase::draining && ops.slots[0].cancel_calls == 0,
                "slot 0 not cancelled before deadline");

            // Past deadline: slot 0 fires CancelIoEx and stays safely in cancelling while kernel completes!
            eng.poll(ops, t0 + std::chrono::milliseconds(2001), handler);
            require(ops.slots[0].cancel_calls == 1 && eng.slot_phase(0) == cli::AsyncPipePhase::cancelling &&
                    eng.slot_pending(0) && ops.slots[0].disconnect_calls == 0,
                "slot 0 waits non-blockingly in cancelling while cancel is pending");
            eng.poll(ops, t0 + std::chrono::milliseconds(2006), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::cancelling && ops.slots[0].disconnect_calls == 0,
                "slot 0 still cancelling on tick 2");
            eng.poll(ops, t0 + std::chrono::milliseconds(2011), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::accepting && ops.slots[0].disconnect_calls == 1 &&
                    ops.slots[0].connect_calls == 2,
                "slot 0 disconnects & rearms accepting once cancel finishes");
            auto diag = eng.diagnostics();
            require(diag.authorized == 2 && diag.expired == 1 && diag.reply_failed == 0,
                "diagnostics reflect 2 requests + 1 drain timeout");
        }

        // 2. Partial async write + stalled read timeout + stalled write timeout + oversized request.
        {
            MockPipeOps ops(1);
            cli::AsyncPipeEngine eng(1, std::chrono::milliseconds(1000));
            require(eng.init(ops), "init 1 slot");

            // Partial async write (8 bytes at a time) + delayed client drain close.
            ops.slots[0].connect_poll = {cli::AsyncPipeIoStatus::completed, 0};
            ops.slots[0].next_read_status = cli::AsyncPipeIoStatus::pending;
            ops.slots[0].read_poll = {cli::AsyncPipeIoStatus::pending, 0};
            eng.poll(ops, t0, handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::reading, "async read pending");

            ops.slots[0].read_poll = {cli::AsyncPipeIoStatus::completed, 14};
            ops.slots[0].read_poll_payload = "NEXUS/1 status";
            ops.slots[0].write_chunk_limit = 8;
            ops.slots[0].write_async = true;
            ops.slots[0].write_poll = {cli::AsyncPipeIoStatus::pending, 0};
            eng.poll(ops, t0 + std::chrono::milliseconds(10), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::writing && eng.slot_pending(0), "partial async write");

            // Complete chunk 1 (8B), chunk 2 (8B), chunk 3 (3B) across polls, then drain.
            ops.slots[0].write_poll = {cli::AsyncPipeIoStatus::completed, 8};
            ops.slots[0].write_async = false;
            ops.slots[0].next_drain = cli::AsyncPipeIoStatus::broken;
            eng.poll(ops, t0 + std::chrono::milliseconds(20), handler);
            require(ops.slots[0].written == "NEXUS/1 OK\nrunning\n" &&
                    eng.slot_phase(0) == cli::AsyncPipePhase::accepting,
                "multi-chunk async write finishes and rearms");

            // Stalled read past deadline -> expired + rearm.
            ops.slots[0].connect_poll = {cli::AsyncPipeIoStatus::completed, 0};
            ops.slots[0].next_read_status = cli::AsyncPipeIoStatus::pending;
            ops.slots[0].read_poll = {cli::AsyncPipeIoStatus::pending, 0};
            eng.poll(ops, t0 + std::chrono::milliseconds(100), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::reading, "stalled read");
            eng.poll(ops, t0 + std::chrono::milliseconds(1200), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::accepting && eng.diagnostics().expired == 1,
                "stalled read cancelled & rearmed");

            // Oversized request (ERROR_MORE_DATA) -> request-too-large error reply.
            ops.slots[0].written.clear();
            ops.slots[0].connect_poll = {cli::AsyncPipeIoStatus::completed, 0};
            ops.slots[0].next_read_status = cli::AsyncPipeIoStatus::more_data;
            ops.slots[0].write_chunk_limit = 65536;
            ops.slots[0].write_async = false;
            eng.poll(ops, t0 + std::chrono::milliseconds(1300), handler);
            require(ops.slots[0].written == "NEXUS/1 ERROR\nrequest-too-large\n", "oversized reply");

            // Stalled write past deadline -> expired + reply_failed + rearm.
            ops.slots[0].written.clear();
            ops.slots[0].connect_poll = {cli::AsyncPipeIoStatus::completed, 0};
            ops.slots[0].next_read_status = cli::AsyncPipeIoStatus::completed;
            ops.slots[0].next_read_payload = "NEXUS/1 status";
            ops.slots[0].write_async = true;
            ops.slots[0].write_poll = {cli::AsyncPipeIoStatus::pending, 0};
            eng.poll(ops, t0 + std::chrono::milliseconds(1400), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::writing, "stalled write");
            eng.poll(ops, t0 + std::chrono::milliseconds(2500), handler);
            require(eng.slot_phase(0) == cli::AsyncPipePhase::accepting &&
                    eng.diagnostics().expired == 2 && eng.diagnostics().reply_failed == 1,
                "stalled write cancelled, counted, and rearmed");
        }

        // 3. Unique random control instance_id (preserves R6 P2-5).
        auto id1 = cli::generate_control_instance_id(4242);
        auto id2 = cli::generate_control_instance_id(4242);
        require(id1.size() == 32 && id2.size() == 32 && id1 != id2, "control instance_id unique per restart");
    }
}

auto main() -> int {
    test_tun_cidr_coverage_and_required_excludes();
    test_tun_apply_rollback_and_ordering();
    test_windows_flush_classification();
    test_async_pipe_state_machine();
    std::cout << "Wave 36 Round 7 Track A unit tests (R7 P1-1..P1-4) passed\n";
    return 0;
}
