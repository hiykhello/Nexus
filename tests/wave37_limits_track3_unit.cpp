#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>

import std;
import capy;
import corosio;
import containers.lru_slab;
import net.datagram_frame;
import net.lazy_readers;
import net.stream_datagrams;
import net.udp_direct;
import platform.socket_options;
import rules;

namespace {
    using namespace std::chrono_literals;
    int g_failures = 0;

    auto check(bool ok, std::string_view label) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << label << "\n";
            ++g_failures;
        }
    }

    auto make_v4_peer(std::uint16_t port, std::uint8_t d = 1) noexcept -> net::UdpEndpoint {
        net::UdpEndpoint ep{};
        ep.family = 4;
        ep.address[0] = 127; ep.address[1] = 0; ep.address[2] = 0; ep.address[3] = d;
        ep.port = port;
        return ep;
    }

    // 1. containers::LruSlab scale (4096), pointer stability across growth, exact O(1) LRU eviction, freelist reuse.
    auto test_lru_slab_scale_and_invariants() -> void {
        struct Payload {
            int id = 0;
            int touches = 0;
        };
        containers::LruSlab<std::uint64_t, Payload> slab(4096);
        check(slab.empty() && slab.chunk_count() == 0 && slab.allocated_slots() == 0, "LruSlab zero idle alloc");

        std::uint32_t first_idx = 0;
        Payload* first_ptr = nullptr;
        for (std::uint64_t i = 0; i < 4096; ++i) {
            auto idx = slab.emplace(i, Payload{static_cast<int>(i), 0});
            check(idx.has_value(), "LruSlab insert up to 4096");
            if (i == 0 && idx) {
                first_idx = *idx;
                first_ptr = &slab.slot_value(*idx);
            }
        }
        check(slab.size() == 4096 && slab.allocated_slots() == 4096 && slab.chunk_count() == 128,
              "LruSlab grew lazily to 4096 (128x32 chunks)");
        check(&slab.slot_value(first_idx) == first_ptr && first_ptr->id == 0,
              "LruSlab pointer stability across 0->4096 chunk growth");

        // Touch key 0 -> key 1 becomes exact LRU tail.
        auto* hit0 = slab.find_and_touch(0ull);
        check(hit0 == first_ptr && hit0 != nullptr, "LruSlab find_and_touch O(1) hit");
        auto lru_idx = slab.lru_index();
        check(lru_idx && slab.slot_key(*lru_idx) == 1ull, "LruSlab tail is key 1 after touching key 0");

        // Insert 512 more keys beyond soft cap: exact LRU evicted each time, allocated_slots stays 4096 (freelist reuse!).
        std::vector<std::uint64_t> evicted_keys;
        for (std::uint64_t i = 4096; i < 4096 + 512; ++i) {
            auto [idx, inserted] = slab.emplace_or_evict(i,
                [&](std::uint32_t, std::uint64_t const& k, Payload&) { evicted_keys.push_back(k); },
                Payload{static_cast<int>(i), 0});
            check(inserted && slab.slot_value(idx).id == static_cast<int>(i), "LruSlab emplace_or_evict inserted");
        }
        check(slab.size() == 4096 && slab.allocated_slots() == 4096 && slab.chunk_count() == 128,
              "LruSlab zero steady-state heap growth on 512 evictions (freelist reuse)");
        check(evicted_keys.size() == 512 && evicted_keys.front() == 1ull && evicted_keys.back() == 512ull,
              "LruSlab evicted exact LRU keys 1..512 in order");
        check(slab.find(0ull) == first_ptr, "LruSlab touched key 0 survived all 512 evictions");
        check(slab.find(1ull) == nullptr && slab.find(512ull) == nullptr && slab.find(513ull) != nullptr,
              "LruSlab post-eviction membership exact");

        // In-place rekey_lru preserves exact Value address while migrating hash key to MRU head.
        auto tail_before = *slab.lru_index();
        auto* tail_addr = &slab.slot_value(tail_before);
        std::uint64_t rekeyed_from = 0;
        auto rk = slab.rekey_lru(99999ull, [&](std::uint32_t, std::uint64_t const& k, Payload&) { rekeyed_from = k; });
        check(rk && *rk == tail_before && &slab.slot_value(*rk) == tail_addr,
              "LruSlab rekey_lru preserves exact Value address in-place");
        check(rekeyed_from == 513ull && slab.find(513ull) == nullptr && slab.find(99999ull) == tail_addr &&
              slab.mru_index() == rk, "LruSlab rekey_lru updates hash & promotes to MRU");

        // Safe erasure during for_each.
        std::size_t erased = 0;
        slab.for_each([&](std::uint32_t idx, std::uint64_t const& k, Payload&) {
            if ((k & 1ull) == 0) { slab.erase(idx); ++erased; }
        });
        check(erased > 1000 && slab.size() + erased == 4096, "LruSlab safe erase during for_each");
    }

    // 2. RoutedDatagramSlots (>512 outbounds), FixedDatagramSlots (>512 peers), LazyReaders<0> (>512 readers).
    auto test_datagram_slots_and_lazy_readers_scale() -> void {
        struct DummySlot { int tag = 0; bool canceled = false; };

        // 2a. RoutedDatagramSlots: 600 distinct outbounds (including indices > 512, way past old 64/128 cap).
        net::RoutedDatagramSlots<DummySlot> routed(600);
        for (std::uint64_t ob = 0; ob < 600; ++ob) {
            auto key = (ob << 1) | (ob & 1u);
            auto sel = routed.select_or_evict(key, [](DummySlot& s) { s.canceled = true; });
            check(sel && !sel->evicted, "RoutedDatagramSlots inserts 600 without premature eviction");
            if (sel) routed.slot(sel->index).tag = static_cast<int>(ob);
        }
        check(routed.size() == 600, "RoutedDatagramSlots holds 600 active outbounds");
        // Touch outbound 0 so outbound 1 becomes LRU.
        auto hit0 = routed.select_or_evict(0ull, [](DummySlot&) {});
        check(hit0 && !hit0->evicted && routed.slot(hit0->index).tag == 0, "RoutedDatagramSlots O(1) hit touches LRU");
        int evicted_tag = -1;
        auto over = routed.select_or_evict((10000ull << 1), [&](DummySlot& v) { evicted_tag = v.tag; v.canceled = true; });
        check(over && over->evicted && evicted_tag == 1, "RoutedDatagramSlots evicts exact LRU outbound 1 at cap");

        // 2b. FixedDatagramSlots: default soft cap 512 (up from 16), 600 distinct UDP peers.
        net::FixedDatagramSlots<DummySlot, net::UdpEndpoint> fixed;
        check(fixed.soft_cap() == 512, "FixedDatagramSlots default soft_cap is 512");
        DummySlot* ptr0 = nullptr;
        for (std::uint16_t p = 1; p <= 512; ++p) {
            auto sel = fixed.select_or_evict(0, make_v4_peer(p), [](DummySlot&) {});
            check(sel && !sel->evicted, "FixedDatagramSlots accepts 512 distinct peers without drop");
            if (sel) {
                fixed.slot(sel->index).tag = p;
                if (p == 1) ptr0 = &fixed.slot(sel->index);
            }
        }
        check(fixed.size() == 512 && ptr0 == &fixed.slot(0), "FixedDatagramSlots 512 active + pointer-stable");
        // Touch peer 1 -> peer 2 becomes LRU; insert peers 513..600 -> evicts peers 2..89 in exact LRU order!
        auto touch1 = fixed.select_or_evict(0, make_v4_peer(1), [](DummySlot&) {});
        check(touch1 && !touch1->evicted, "FixedDatagramSlots touch peer 1");
        std::vector<int> fixed_evicted;
        for (std::uint16_t p = 513; p <= 600; ++p) {
            auto sel = fixed.select_or_evict(0, make_v4_peer(p), [&](DummySlot& v) { fixed_evicted.push_back(v.tag); });
            check(sel && sel->evicted, "FixedDatagramSlots evicts LRU beyond 512");
            if (sel) {
                fixed.slot(sel->index).tag = p;
                check(fixed.peer(sel->index).port == p, "FixedDatagramSlots peer() reflects rebound destination");
            }
        }
        check(fixed_evicted.size() == 88 && fixed_evicted.front() == 2 && fixed_evicted.back() == 89,
              "FixedDatagramSlots evicted exact LRU peers 2..89");
        auto check1 = fixed.select_or_evict(0, make_v4_peer(1), [](DummySlot&) {});
        check(check1 && !check1->evicted && fixed.slot(check1->index).tag == 1, "FixedDatagramSlots touched peer 1 survived");

        // 2c. LazyReaders<0> handling 4096 concurrent readers in flat O(1)-stack loop (normal drain + error cancel).
        {
            constexpr std::size_t kScale = 4096;
            auto ctx = corosio::make_io_context(false);
            net::LazyReaders<0> readers(4608);
            capy::async_event release;
            std::atomic<int> entered{0}, exited{0};
            for (std::size_t i = 0; i < kScale; ++i) {
                if (!readers.request(i) || !readers.request(i)) {
                    check(false, "LazyReaders<0> request 0..4095 & dedup");
                    break;
                }
            }
            check(!readers.request(4608), "LazyReaders<0> rejects out-of-bounds index");
            bool done = false, had_err = false;
            capy::run_async(ctx.get_executor(),
                [&](capy::results<> v) { done = true; had_err = bool(std::get<0>(v)); },
                [&](std::exception_ptr) { done = true; had_err = true; })(
                readers.run([&](std::size_t) -> capy::task<capy::results<>> {
                    struct G { std::atomic<int>& e; ~G() { ++e; } } g{exited};
                    ++entered;
                    (void)co_await release.wait();
                    co_return capy::results<>{};
                }));
            ctx.run_for(2s);
            ctx.restart();
            check(entered.load() == static_cast<int>(kScale) && !done, "LazyReaders<0> launched all 4096 readers");
            readers.stop();
            ctx.run_for(20ms);
            ctx.restart();
            check(!done && exited.load() == 0, "LazyReaders<0> stop() does not cancel running readers");
            release.set();
            ctx.run_for(2s);
            check(done && !had_err && exited.load() == static_cast<int>(kScale),
                  "LazyReaders<0> flat O(1)-stack drained all 4096 readers cleanly");
        }
        {
            constexpr std::size_t kScale = 4096;
            auto ctx = corosio::make_io_context(false);
            net::LazyReaders<0> readers(4608);
            capy::async_event never_set;
            std::atomic<int> entered{0}, exited{0};
            for (std::size_t i = 0; i < kScale - 1; ++i) (void)readers.request(i);
            bool done = false, had_err = false;
            capy::run_async(ctx.get_executor(),
                [&](capy::results<> v) { done = true; had_err = bool(std::get<0>(v)); },
                [&](std::exception_ptr) { done = true; had_err = true; })(
                readers.run([&](std::size_t idx) -> capy::task<capy::results<>> {
                    struct G { std::atomic<int>& e; ~G() { ++e; } } g{exited};
                    ++entered;
                    if (idx == kScale - 1) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                    co_return co_await never_set.wait();
                }));
            ctx.run_for(2s);
            ctx.restart();
            check(entered.load() == static_cast<int>(kScale - 1) && !done, "LazyReaders<0> 4095 readers parked");
            check(readers.request(kScale - 1), "LazyReaders<0> request failing reader #4095");
            ctx.run_for(2s);
            check(done && had_err && exited.load() == static_cast<int>(kScale),
                  "LazyReaders<0> error propagates & cancels/drains all 4096 readers in flat O(1) stack");
        }
    }

    // 3. Live net::stream_datagrams::Server scale test:
    //    (a) 600 distinct fixed-peer destinations (512 cap + exact LRU eviction keeping session alive!)
    //    (b) 600 distinct non-fixed tunnel outbounds (way beyond old outbound < 64 / 128 cap!)
    struct MockTunnelState {
        std::atomic<int> connects{0}, sends{0}, cancels{0};
        std::atomic<int> reads_before_connect{0}, reads_after_connect{0};
        capy::async_event* connect_gate = nullptr;
        std::uint16_t gated_port = 0;
        std::vector<std::uint16_t> connected_ports;
        std::vector<std::uint16_t> canceled_ports;
    };

    enum class MockConnectResult { connected = 0 };
    struct MockTunnelProxy {
        struct Impl {
            MockTunnelState* st = nullptr;
            std::uint16_t port = 0;
            capy::async_event wait_ev;
            bool connected = false;
            bool canceled = false;
            auto packet_transport() const noexcept -> net::PacketTransport {
                return {net::PacketTransportKind::framed, net::DatagramFraming{net::AddressWire::uot, false, false}, false};
            }
            auto connect_packets(net::ProxyAddress const& dst, std::chrono::steady_clock::time_point)
                -> capy::task<MockConnectResult> {
                port = dst.port;
                if (st->connect_gate && st->gated_port == port) (void)co_await st->connect_gate->wait();
                connected = true;
                ++st->connects;
                st->connected_ports.push_back(port);
                co_return MockConnectResult::connected;
            }
            auto send(std::span<std::uint8_t const>) -> capy::task<bool> {
                ++st->sends;
                co_return !canceled;
            }
            auto read(std::span<std::uint8_t>) -> capy::task<std::expected<std::size_t, std::string>> {
                if (!connected) ++st->reads_before_connect;
                else ++st->reads_after_connect;
                if (!canceled) (void)co_await wait_ev.wait();
                co_return std::unexpected(std::string("canceled"));
            }
            auto cancel() noexcept -> void {
                if (!canceled) {
                    canceled = true;
                    ++st->cancels;
                    st->canceled_ports.push_back(port);
                }
                wait_ev.set();
            }
        };
        std::shared_ptr<Impl> impl;
        explicit operator bool() const noexcept { return static_cast<bool>(impl); }
        auto operator->() const noexcept -> Impl* { return impl.get(); }
    };

    struct MockFactory {
        MockTunnelState* state = nullptr;
        bool packet_dual_family = true;
        bool packet_fixed_peer = false;
        std::uint32_t timeout_ms = 5000;
        template<class S, class C>
        auto operator()(S&, C&) const -> MockTunnelProxy {
            auto impl = std::make_shared<MockTunnelProxy::Impl>();
            impl->st = state;
            return MockTunnelProxy{std::move(impl)};
        }
    };

    struct MockSession {
        bool closed = false;
        std::stop_source stop;
        MockTunnelProxy tunnel;
        std::vector<MockFactory> const* tunnel_factories = nullptr;
        struct DirectOpts { platform::SocketBinding binding{}; };
        DirectOpts const* direct_tcp_options = nullptr;
        std::optional<std::string_view> auth_user;
        std::optional<std::string_view> source_interface;
        void* dns_operation = nullptr;
        void (*cancel_dns)(void*) noexcept = nullptr;
        auto close() noexcept -> void { closed = true; stop.request_stop(); }
        auto record_datagram_route(bool, net::UdpSelection const&) noexcept -> void {}
        auto count_traffic(bool, std::size_t) noexcept -> void {}
        std::chrono::steady_clock::time_point touched{};
    };

    struct MockIncoming {
        static constexpr bool native_packets = true;
        auto send_packet(net::ProxyAddress const&, std::span<std::uint8_t const>)
            -> capy::task<net::stream_datagrams::ReplySendStatus> {
            co_return net::stream_datagrams::ReplySendStatus::sent;
        }
    };

    struct MockResolver {
        auto operator()(std::string, std::uint16_t, std::chrono::steady_clock::time_point)
            -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
            co_return std::nullopt;
        }
    };

    auto test_stream_datagrams_live_scale_and_eviction() -> void {
        auto ctx = corosio::make_io_context(false);
        auto policy = rules::RouteMatcher::compile({}, 2, 602);
        check(policy.has_value(), "stream_datagrams mock RouteMatcher compiled");
        if (!policy) return;

        // 3a. Fixed-peer outbound: 512 cap -> 512 distinct peers succeed, touch #1, send #513..#520 ->
        //     exact LRU peers #2..#9 evicted & canceled cleanly, session stays OPEN!
        {
            MockTunnelState ts;
            std::vector<MockFactory> factories{{&ts, true, true, 5000}};
            MockSession session;
            session.tunnel_factories = &factories;
            MockIncoming incoming;
            net::stream_datagrams::Server<MockSession, MockIncoming, MockResolver> srv(
                session, ctx, incoming, *policy, MockResolver{}, net::DatagramFraming{});
            check(srv.routed.soft_cap() == 4096 && srv.fixed.soft_cap() == 512,
                  "stream_datagrams default caps are 4096 routed / 512 fixed");

            bool driver_done = false;
            auto driver = [&]() -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 4> payload{1, 2, 3, 4};
                auto dl = std::chrono::steady_clock::now() + 10s;
                for (std::uint16_t p = 1; p <= 512; ++p) {
                    bool ok = co_await net::stream_datagrams::forward(srv, 0, make_v4_peer(p), payload, dl);
                    if (!ok) { check(false, "stream_datagrams fixed 1..512 forward"); break; }
                }
                // Touch peer #1 so peer #2 is LRU.
                bool hit1 = co_await net::stream_datagrams::forward(srv, 0, make_v4_peer(1), payload, dl);
                check(hit1, "stream_datagrams touch peer #1");
                // Send 8 more distinct peers beyond 512 -> evicts exact LRU peers 2..9 without closing session!
                for (std::uint16_t p = 513; p <= 520; ++p) {
                    bool ok = co_await net::stream_datagrams::forward(srv, 0, make_v4_peer(p), payload, dl);
                    check(ok && !session.closed, "stream_datagrams fixed eviction >512 keeps session alive");
                }
                session.close();
                srv.cancel();
                co_return capy::results<>{};
            };
            capy::run_async(ctx.get_executor(), [&](auto&&) { driver_done = true; }, [&](std::exception_ptr) { driver_done = true; })(
                capy::when_all(driver(), srv.readers.run([&](std::size_t idx) {
                    return net::stream_datagrams::tunnel_download(srv, idx);
                })));
            ctx.run_for(5s);
            ctx.restart();
            check(driver_done, "stream_datagrams fixed scale driver completed");
            check(srv.fixed.size() == 512 && ts.connects.load() == 520 && ts.sends.load() == 521,
                  "stream_datagrams 520 distinct fixed peers connected & 521 packets sent");
            check(ts.canceled_ports.size() >= 8 && ts.canceled_ports[0] == 2 && ts.canceled_ports[7] == 9,
                  "stream_datagrams evicted exact LRU peers 2..9 first (peer #1 preserved)");
        }

        // 3b. Non-fixed outbounds: 600 distinct outbounds (indices 0..599, far past old outbound<64 / 128 cap!).
        {
            MockTunnelState ts;
            std::vector<MockFactory> factories(600, MockFactory{&ts, true, false, 5000});
            MockSession session;
            session.tunnel_factories = &factories;
            MockIncoming incoming;
            net::stream_datagrams::Server<MockSession, MockIncoming, MockResolver> srv(
                session, ctx, incoming, *policy, MockResolver{}, net::DatagramFraming{});

            bool driver_done = false;
            auto driver = [&]() -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 4> payload{5, 6, 7, 8};
                auto dl = std::chrono::steady_clock::now() + 10s;
                for (std::size_t ob = 0; ob < 600; ++ob) {
                    bool ok = co_await net::stream_datagrams::forward(srv, ob, make_v4_peer(8000), payload, dl);
                    if (!ok) { check(false, "stream_datagrams routed 0..599 forward"); break; }
                }
                session.close();
                srv.cancel();
                co_return capy::results<>{};
            };
            capy::run_async(ctx.get_executor(), [&](auto&&) { driver_done = true; }, [&](std::exception_ptr) { driver_done = true; })(
                capy::when_all(driver(), srv.readers.run([&](std::size_t idx) {
                    return net::stream_datagrams::tunnel_download(srv, idx);
                })));
            ctx.run_for(5s);
            ctx.restart();
            check(driver_done && srv.routed.size() == 600 && ts.connects.load() == 600 && ts.sends.load() == 600,
                  "stream_datagrams routed 600 distinct outbounds (>128 old cap) with 0 drops");
        }

        // 3c. Slow-connect eviction safety: reader woken on LRU eviction must NEVER read unconnected replacement tunnel.
        {
            capy::async_event connect_gate;
            MockTunnelState ts;
            ts.connect_gate = &connect_gate;
            ts.gated_port = 3;
            std::vector<MockFactory> factories{{&ts, true, true, 5000}};
            MockSession session;
            session.tunnel_factories = &factories;
            MockIncoming incoming;
            net::stream_datagrams::Server<MockSession, MockIncoming, MockResolver> srv(
                session, ctx, incoming, *policy, MockResolver{}, net::DatagramFraming{});
            srv.fixed.set_soft_cap(2);

            bool driver_done = false;
            auto driver = [&]() -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 4> payload{9, 8, 7, 6};
                auto dl = std::chrono::steady_clock::now() + 10s;
                check(co_await net::stream_datagrams::forward(srv, 0, make_v4_peer(1), payload, dl), "3c peer 1");
                check(co_await net::stream_datagrams::forward(srv, 0, make_v4_peer(2), payload, dl), "3c peer 2");
                auto releaser = [&]() -> capy::task<capy::results<>> {
                    (void)co_await corosio::delay(30ms);
                    check(ts.reads_before_connect.load() == 0, "3c no read on unconnected replacement during connect");
                    connect_gate.set();
                    co_return capy::results<>{};
                };
                auto evictor = [&]() -> capy::task<capy::results<>> {
                    check(co_await net::stream_datagrams::forward(srv, 0, make_v4_peer(3), payload, dl), "3c peer 3 evicts 1");
                    co_return capy::results<>{};
                };
                (void)co_await capy::when_all(evictor(), releaser());
                (void)co_await corosio::delay(20ms);
                check(ts.reads_before_connect.load() == 0 && ts.reads_after_connect.load() >= 3,
                      "3c reader resumed cleanly after replacement finished connecting");
                session.close();
                srv.cancel();
                co_return capy::results<>{};
            };
            capy::run_async(ctx.get_executor(), [&](auto&&) { driver_done = true; }, [&](std::exception_ptr) { driver_done = true; })(
                capy::when_all(driver(), srv.readers.run([&](std::size_t idx) {
                    return net::stream_datagrams::tunnel_download(srv, idx);
                })));
            ctx.run_for(5s);
            check(driver_done && ts.connects.load() == 3 && ts.sends.load() == 3,
                  "3c slow-connect eviction driver completed");
        }
    }
}

auto main() -> int {
    try {
        test_lru_slab_scale_and_invariants();
        test_datagram_slots_and_lazy_readers_scale();
        test_stream_datagrams_live_scale_and_eviction();
    } catch (std::exception const& ex) {
        std::cerr << "EXCEPTION: " << ex.what() << "\n";
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << "wave37_limits_track3_unit: FAIL (" << g_failures << " failures)\n";
        return 1;
    }
    std::cout << "wave37_limits_track3_unit: PASS\n";
    return 0;
}
