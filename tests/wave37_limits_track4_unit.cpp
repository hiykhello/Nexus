import std;
import corosio;
import dns.cache;
import dns.cache_snapshot;
import dns.corosio_query;
import dns.message;
import dns.quic_query_runtime;
import platform.network_state;
import state;
import state.fakeip_disk;
import state.maintenance;
import tailscale.multi_worker;

using namespace std::chrono_literals;

namespace {
    int failures = 0;

    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) {
            ++failures;
            std::cerr << "FAIL: " << msg << '\n';
        }
    }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view prefix) {
            auto stamp = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            path = std::filesystem::temp_directory_path() / std::format("{}-{}", prefix, stamp);
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
            std::filesystem::create_directories(path, ec);
            std::filesystem::permissions(path, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    };

    auto make_ipv4_answer(std::string_view host, std::uint32_t idx, std::uint32_t ttl = 60) -> dns::AddressAnswer {
        dns::Address addr{};
        addr.size = 4;
        addr.bytes[0] = 10;
        addr.bytes[1] = static_cast<std::uint8_t>((idx >> 16) & 0xffu);
        addr.bytes[2] = static_cast<std::uint8_t>((idx >> 8) & 0xffu);
        addr.bytes[3] = static_cast<std::uint8_t>(idx & 0xffu);
        return dns::AddressAnswer{std::string(host), {}, {addr}, ttl};
    }

    auto make_udp_ipv4_packet(std::array<std::uint8_t, 4> src_ip, std::uint16_t sport,
                              std::array<std::uint8_t, 4> dst_ip, std::uint16_t dport,
                              std::uint16_t payload_tag) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> pkt(32, 0);
        pkt[0] = 0x45;
        pkt[3] = 32;
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        std::ranges::copy(src_ip, pkt.begin() + 12);
        std::ranges::copy(dst_ip, pkt.begin() + 16);
        pkt[20] = static_cast<std::uint8_t>(sport >> 8);
        pkt[21] = static_cast<std::uint8_t>(sport & 0xffu);
        pkt[22] = static_cast<std::uint8_t>(dport >> 8);
        pkt[23] = static_cast<std::uint8_t>(dport & 0xffu);
        pkt[24] = 0;
        pkt[25] = 12;
        pkt[28] = static_cast<std::uint8_t>(payload_tag >> 8);
        pkt[29] = static_cast<std::uint8_t>(payload_tag & 0xffu);
        return pkt;
    }

    auto test_dns_pending_and_snapshot_scale() -> void {
        // 1. AddressCache default pending soft limit > 4096 (default 32768) + 5000 concurrent pending queries.
        dns::AddressCache cache(1024, 5000);
        check(cache.max_pending() == dns::AddressCache::default_max_pending && cache.max_pending() >= 32768,
            "AddressCache default max_pending >= 32768");
        constexpr std::size_t pending_burst = 5000;
        std::vector<dns::CacheToken> tokens;
        tokens.reserve(pending_burst);
        for (std::size_t i = 0; i < pending_burst; ++i) {
            auto t = cache.begin_query({1, std::format("h{}.burst.test", i), 1});
            check(t.has_value(), "AddressCache allows > 4096 concurrent pending queries");
            if (!t) break;
            tokens.push_back(*t);
        }
        check(tokens.size() == pending_burst, "all 5000 pending tokens acquired without query_limit");
        for (std::size_t i = 0; i < 600 && i < tokens.size(); ++i) {
            auto host = std::format("h{}.burst.test", i);
            check(cache.publish({1, host, 1}, make_ipv4_answer(host, static_cast<std::uint32_t>(i)), 1000, tokens[i]).has_value(),
                "publish from 5000-pending burst");
        }
        for (std::size_t i = 600; i < tokens.size(); ++i)
            check(cache.cancel_query(tokens[i]).has_value(), "cancel remaining pending tokens");
        check(cache.size() == 600, "AddressCache stores 600 published entries cleanly");

        // Configurable custom pending cap > 4096 enforces exact boundary.
        dns::AddressCache custom_pending(32, 0, false, 0, 5000);
        check(custom_pending.max_pending() == 5000, "custom max_pending reflected");
        std::vector<dns::CacheToken> ctoks;
        ctoks.reserve(5000);
        for (std::size_t i = 0; i < 5000; ++i) ctoks.push_back(*custom_pending.begin_query({1, std::format("c{}.test", i), 1}));
        auto denied = custom_pending.begin_query({1, "overflow.test", 1});
        check(!denied && denied.error() == dns::CacheError::query_limit, "custom pending cap enforced at 5001");
        check(custom_pending.cancel_query(ctoks.back()).has_value() &&
              custom_pending.begin_query({1, "overflow.test", 1}).has_value(), "pending cap recovers after cancel");

        // 2. Ordered snapshot AddressCache > 256 & > 512 entries + > 4096 pending.
        dns::AddressCache snap_cache(1024, 5000, true, 2);
        check(snap_cache.capacity() == 1024 && snap_cache.max_pending() == 32768,
            "snapshot AddressCache supports capacity > 256 and pending > 4096");
        auto reader = snap_cache.reader(0);
        std::vector<dns::CacheToken> stoks;
        stoks.reserve(pending_burst);
        for (std::size_t i = 0; i < pending_burst; ++i) {
            auto t = snap_cache.begin_query({1, std::format("s{}.snap.test", i), 1});
            check(t.has_value(), "snapshot cache allows > 4096 pending queries");
            if (!t) break;
            stoks.push_back(*t);
        }
        constexpr std::size_t snap_entries = 700;
        for (std::size_t i = 0; i < snap_entries && i < stoks.size(); ++i) {
            auto host = std::format("s{}.snap.test", i);
            check(snap_cache.publish({1, host, 1}, make_ipv4_answer(host, static_cast<std::uint32_t>(i)), 2000, stoks[i]).has_value(),
                "publish snapshot entry past 256/512 cap");
        }
        for (std::size_t i = snap_entries; i < stoks.size(); ++i)
            check(snap_cache.cancel_query(stoks[i]).has_value(), "cancel remaining snapshot pending");
        check(snap_cache.size() == snap_entries, "ordered snapshot holds all 700 entries without 256 truncation");
        for (std::size_t i = 0; i < snap_entries; ++i) {
            auto hit = snap_cache.lookup({1, std::format("s{}.snap.test", i), 1}, 2500, reader);
            check(hit && *hit && (**hit).addresses.size() == 1 &&
                  (**hit).addresses[0].bytes[2] == static_cast<std::uint8_t>((i >> 8) & 0xffu) &&
                  (**hit).addresses[0].bytes[3] == static_cast<std::uint8_t>(i & 0xffu),
                "ordered snapshot lookup round-trip across 700 entries");
        }

        // 3. Hashed BasicSnapshotState<false> > 512 entries + tombstone compaction.
        dns::detail::BasicSnapshotState<false> hashed(1024, 5000, 2);
        auto hreader = hashed.reader(0);
        for (std::size_t i = 0; i < snap_entries; ++i) {
            auto host = std::format("u{}.hash.test", i);
            auto tok = hashed.begin_query({1, host, 1});
            check(tok && hashed.publish({1, host, 1}, make_ipv4_answer(host, static_cast<std::uint32_t>(i)), 3000, *tok).has_value(),
                "hashed snapshot publish past 512");
        }
        check(hashed.size() == snap_entries, "hashed snapshot holds all 700 entries");
        for (std::size_t i = 0; i < 300; ++i) {
            auto host = std::format("u{}.hash.test", i);
            auto tok = hashed.begin_query({1, host, 1});
            check(tok && hashed.invalidate({1, host, 1}, 3100, *tok).has_value(), "hashed snapshot invalidate triggers compaction");
        }
        for (std::size_t i = 0; i < 300; ++i) {
            auto miss = hashed.lookup({1, std::format("u{}.hash.test", i), 1}, 3100, hreader);
            check(miss && !*miss, "invalidated hashed entry removed");
        }
        for (std::size_t i = 300; i < snap_entries; ++i) {
            auto hit = hashed.lookup({1, std::format("u{}.hash.test", i), 1}, 3100, hreader);
            check(hit && *hit && (**hit).addresses[0].bytes[3] == static_cast<std::uint8_t>(i & 0xffu),
                "surviving hashed entries intact after compaction");
        }

        // Small-capacity hashed snapshot (cap=32, slot_count=64 -> compaction threshold 16, not 128).
        dns::detail::BasicSnapshotState<false> small_hash(32, 5000, 2);
        auto sreader = small_hash.reader(0);
        for (std::size_t i = 0; i < 32; ++i) {
            auto host = std::format("sm{}.hash.test", i);
            auto tok = small_hash.begin_query({1, host, 1});
            check(tok && small_hash.publish({1, host, 1}, make_ipv4_answer(host, static_cast<std::uint32_t>(i)), 4000, *tok).has_value(),
                "small hashed snapshot publish");
        }
        for (std::size_t i = 0; i < 16; ++i) {
            auto host = std::format("sm{}.hash.test", i);
            auto tok = small_hash.begin_query({1, host, 1});
            check(tok && small_hash.invalidate({1, host, 1}, 4100, *tok).has_value(), "small hashed snapshot invalidate");
        }
        check(small_hash.tombstones() == 0 && small_hash.size() == 16,
            "small hashed snapshot (cap=32) compacts tombstones at slot_count/4 instead of waiting for 128");
        for (std::size_t i = 16; i < 32; ++i) {
            auto hit = small_hash.lookup({1, std::format("sm{}.hash.test", i), 1}, 4100, sreader);
            check(hit && *hit && (**hit).addresses[0].bytes[3] == static_cast<std::uint8_t>(i),
                "small hashed snapshot survivors intact after compaction");
        }
        std::cout << "  [PASS] DNS pending (>4096) & ordered/hashed snapshot (>512 + small compaction) scale tests\n";
    }

    struct FakeDoqPolicy {
        struct Profile { int id = 0; };
        struct TicketCache {};
        static auto make_ticket_cache() noexcept -> TicketCache { return {}; }
    };

    struct FakeDoqConn {
        std::shared_ptr<FakeDoqPolicy::Profile const> profile;
        corosio::endpoint peer;
        std::optional<dns::doq_detail::InterfaceAttempt> path;
        bool is_done = false, is_idle = true, is_ready = true, stopped = false;

        FakeDoqConn(corosio::io_context&, std::shared_ptr<FakeDoqPolicy::Profile const> p, corosio::endpoint ep,
                    FakeDoqPolicy::TicketCache, std::optional<dns::doq_detail::InterfaceAttempt> iface)
            : profile(std::move(p)), peer(ep), path(iface) {}
        auto start(corosio::io_context&, std::shared_ptr<FakeDoqConn>, dns::doq_detail::Clock::time_point, bool) -> bool { return true; }
        auto done() const noexcept -> bool { return is_done; }
        auto idle() const noexcept -> bool { return !stopped && !is_done && is_idle; }
        auto accepts(FakeDoqPolicy::Profile const& p, corosio::endpoint ep) const noexcept -> bool {
            return !stopped && !is_done && &p == profile.get() && ep == peer;
        }
        auto matches(std::optional<dns::doq_detail::InterfaceAttempt> p) const noexcept -> bool {
            return p ? path && path->index == p->index : !path;
        }
        auto ready_on(std::span<std::uint32_t const> ifaces) const noexcept -> bool {
            return path && is_ready && std::ranges::contains(ifaces, path->index);
        }
        auto stop() noexcept -> void { stopped = true; is_done = true; }
    };

    auto test_doq_pool_scale_and_lru() -> void {
        corosio::io_context io;
        using TestPool = dns::doq_detail::Pool<FakeDoqPolicy, FakeDoqConn>;
        auto& pool = io.use_service<TestPool>();
        check(pool.max_connections() == 256, "DoQ pool default soft cap raised to 256");

        auto prof = std::make_shared<FakeDoqPolicy::Profile const>(FakeDoqPolicy::Profile{1});
        auto deadline = dns::doq_detail::Clock::now() + 5s;
        std::vector<std::shared_ptr<FakeDoqConn>> conns;
        for (std::uint16_t i = 0; i < 40; ++i) {
            corosio::endpoint ep(corosio::ipv4_address::loopback(), static_cast<std::uint16_t>(10000 + i));
            auto c = pool.acquire(io, prof, ep, deadline, false);
            check(c.has_value(), "DoQ pool allows > 16 concurrent pooled endpoints");
            if (c) conns.push_back(*c);
        }
        check(pool.size() == 40 && conns.size() == 40, "DoQ pool holds 40 active connections");
        // O(1) reuse hits the exact same connection.
        auto reused = pool.acquire(io, prof, corosio::endpoint(corosio::ipv4_address::loopback(), 10000), deadline, false);
        check(reused && *reused == conns[0], "DoQ pool O(1) key reuse returns same connection");

        // Test soft cap + idle LRU eviction + busy budget_exhausted on a fresh pool.
        corosio::io_context io2;
        auto& pool2 = io2.use_service<TestPool>();
        pool2.set_max_connections(24);
        std::vector<std::shared_ptr<FakeDoqConn>> c2;
        for (std::uint16_t i = 0; i < 24; ++i) {
            corosio::endpoint ep(corosio::ipv4_address::loopback(), static_cast<std::uint16_t>(12000 + i));
            auto c = pool2.acquire(io2, prof, ep, deadline, false, dns::doq_detail::InterfaceAttempt{7u, deadline});
            check(c.has_value(), "fill 24 DoQ pool slots");
            if (c) c2.push_back(*c);
        }
        // Mark oldest (#0) busy, promote #1 to MRU via acquire -> #2 becomes oldest idle victim!
        c2[0]->is_idle = false;
        auto promoted = pool2.acquire(io2, prof, corosio::endpoint(corosio::ipv4_address::loopback(), 12001), deadline, false,
            dns::doq_detail::InterfaceAttempt{7u, deadline});
        check(promoted && *promoted == c2[1], "touch #1 promotes it to MRU");
        auto extra = pool2.acquire(io2, prof, corosio::endpoint(corosio::ipv4_address::loopback(), 13000), deadline, false,
            dns::doq_detail::InterfaceAttempt{7u, deadline});
        check(extra.has_value() && pool2.size() == 24 && c2[2]->stopped && !c2[0]->stopped && !c2[1]->stopped,
            "DoQ pool evicts oldest idle connection (#2) via LRU while keeping busy (#0) and MRU (#1)");

        // O(1) find_ready hits interface-indexed connection.
        std::array<std::uint32_t, 1> ifaces{7u};
        auto ready = pool2.find_ready(*prof, corosio::endpoint(corosio::ipv4_address::loopback(), 12001), ifaces);
        check(ready == c2[1], "DoQ pool find_ready resolves via O(1) key lookup");

        // When all 24 connections are busy, acquiring a 25th fails cleanly with budget_exhausted.
        for (auto& c : c2) c->is_idle = false;
        if (extra) (*extra)->is_idle = false;
        auto full = pool2.acquire(io2, prof, corosio::endpoint(corosio::ipv4_address::loopback(), 13001), deadline, false);
        check(!full && full.error() == dns::doq_detail::Error::budget_exhausted,
            "DoQ pool returns budget_exhausted when all slots are actively busy");
        std::cout << "  [PASS] DoQ/DoH3 pool (>16 default 256, O(1) lookup, idle LRU eviction)\n";
    }

    auto test_neighbor_table_scale() -> void {
        platform::network::Monitor mon(true);
        check(mon.neighbor_limit() == platform::network::default_neighbor_limit && mon.neighbor_limit() == 65536,
            "network Monitor default neighbor_limit raised to 65536");
        mon.set_neighbor_limit(8192);
        check(mon.neighbor_limit() == 8192, "network Monitor neighbor_limit configurable");

        platform::network::Snapshot snap{};
        bool overflow = false;
        constexpr std::size_t count = 8192;
        for (std::size_t i = 0; i < count; ++i) {
            platform::network::Neighbor n{};
            n.family = platform::network::constants::af_inet;
            n.index = 2;
            n.address[0] = 10;
            n.address[1] = 20;
            n.address[2] = static_cast<std::uint8_t>((i >> 8) & 0xffu);
            n.address[3] = static_cast<std::uint8_t>(i & 0xffu);
            n.mac = {0x02, 0x00, 0x00, 0x01, static_cast<std::uint8_t>((i >> 8) & 0xffu), static_cast<std::uint8_t>(i & 0xffu)};
            check(platform::network::append_neighbor(snap, n, overflow, mon.neighbor_limit()),
                "append_neighbor accepts > 4096 entries up to configured limit");
        }
        check(!overflow && snap.neighbors.size() == count, "8192 neighbors retained without 4096 truncation");
        std::ranges::sort(snap.neighbors, {}, [](auto const& v) { return std::tie(v.family, v.address); });
        std::array<std::uint8_t, 4> last_ip{10, 20, 31, 255};
        auto mac = snap.neighbor_mac(last_ip, 2);
        check(mac && (*mac)[4] == 31 && (*mac)[5] == 255, "Snapshot::neighbor_mac resolves 8192nd entry");

        // Overflow guard at custom limit still protects cleanly.
        platform::network::Neighbor extra{};
        extra.family = platform::network::constants::af_inet;
        extra.index = 2;
        extra.address[0] = 10; extra.address[1] = 21;
        extra.mac = {0x02, 0, 0, 0, 0, 1};
        check(!platform::network::append_neighbor(snap, extra, overflow, mon.neighbor_limit()) &&
              overflow && snap.neighbors.empty(), "overflow guard triggers cleanly past configured neighbor_limit");
        std::cout << "  [PASS] System neighbor table (>4096, default 65536, configurable limit)\n";
    }

    auto test_fakeip_wal_scaling_and_recovery(TempDir const& tmp) -> void {
        check(state::fakeip_wal_threshold(65534) == 2u * 1024 * 1024, "FakeIP /16 pool WAL threshold = 2 MiB");
        check(state::fakeip_wal_threshold(131072) == 4u * 1024 * 1024, "FakeIP /15 pool WAL threshold = 4 MiB");
        check(state::fakeip_wal_threshold(262144) == 8u * 1024 * 1024, "FakeIP /14 pool WAL threshold = 8 MiB");
        check(state::fakeip_wal_threshold(1048576) == 32u * 1024 * 1024, "FakeIP /12 pool WAL threshold = 32 MiB");
        check(state::fakeip_wal_threshold(4194304) == 64u * 1024 * 1024, "FakeIP /10 pool WAL threshold clamped to 64 MiB");
        check(state::fakeip_wal_threshold(65534, 128u * 1024) == 128u * 1024, "FakeIP explicit WAL override honored");

        // 1. Large /14 FakeIP pool (262,144 addresses > old 65,536 cap) scales WAL threshold to 8 MiB & recovers cleanly.
        auto dir_large = tmp.path / "fakeip-large";
        std::filesystem::create_directories(dir_large);
        std::filesystem::permissions(dir_large, std::filesystem::perms::owner_all);
        state::FakeIpScope large_scope{0xC6100000u, 0xC613FFFFu, 0xC6100001u, 0xC613FFFEu};
        {
            auto opened = state::FakeIpStore::open(dir_large, large_scope, state::CrashMode::range_reserve);
            check(opened.has_value(), "open large /14 FakeIP store");
            if (opened) {
                auto& store = **opened;
                check(store.wal_limit() == 8u * 1024 * 1024, "large /14 FakeIP store WAL threshold auto-scales to 8 MiB");
                for (unsigned i = 0; i < 300; ++i) {
                    auto deadline = std::chrono::steady_clock::now() + 3s;
                    for (;;) {
                        auto r = store.assign(std::format("large-{}.example.test", i), 1);
                        if (r) break;
                        check(r.error().stage == state::Stage::capacity && std::chrono::steady_clock::now() < deadline, "assign retry");
                        std::this_thread::sleep_for(1ms);
                    }
                }
                check(store.flush().has_value() && store.stop().has_value(), "flush & stop large FakeIP store");
            }
        }
        {
            auto reopened = state::FakeIpStore::open(dir_large, large_scope, state::CrashMode::range_reserve);
            check(reopened.has_value(), "reopen large /14 FakeIP store");
            if (reopened) {
                unsigned recovered = 0;
                check((*reopened)->visit_recovered([&](auto const&) { ++recovered; return true; }) && recovered == 300,
                    "all 300 large-pool FakeIP mappings recovered from WAL");
            }
        }

        // 2. Explicit small WAL override (64 KiB) triggers compaction & recovery cleanly.
        auto dir_ov = tmp.path / "fakeip-override";
        std::filesystem::create_directories(dir_ov);
        std::filesystem::permissions(dir_ov, std::filesystem::perms::owner_all);
        state::FakeIpScope ov_scope{0xC6120000u, 0xC612FFFFu, 0xC6120001u, 0xC612FFFEu};
        {
            auto opened = state::FakeIpStore::open(dir_ov, ov_scope, state::CrashMode::range_reserve, 64u * 1024);
            check(opened && (*opened)->wal_limit() == 64u * 1024, "open FakeIP store with explicit 64 KiB WAL override");
            if (opened) {
                auto& store = **opened;
                for (unsigned i = 0; i < 400; ++i) {
                    auto dom = std::format("{}.{}.{}.wal.test", i, std::string(50, 'a'), std::string(50, 'b'));
                    auto deadline = std::chrono::steady_clock::now() + 3s;
                    for (;;) {
                        auto r = store.assign(dom, 1);
                        if (r) break;
                        check(r.error().stage == state::Stage::capacity && std::chrono::steady_clock::now() < deadline, "override assign retry");
                        std::this_thread::sleep_for(1ms);
                    }
                }
                check(store.flush().has_value() && store.stop().has_value(), "flush & stop override FakeIP store");
            }
        }
        check(std::filesystem::exists(dir_ov / "fakeip/fakeip.ckpt"), "override threshold triggered checkpoint compaction");
        check(std::filesystem::file_size(dir_ov / "fakeip/fakeip.wal") < 64u * 1024, "WAL truncated below 64 KiB override");
        {
            auto reopened = state::FakeIpStore::open(dir_ov, ov_scope, state::CrashMode::range_reserve, 64u * 1024);
            unsigned recovered = 0;
            check(reopened && (*reopened)->visit_recovered([&](auto const&) { ++recovered; return true; }) && recovered == 400,
                "all 400 compacted + WAL FakeIP rows recovered");
        }
        auto inv_ov = state::inspect_fakeip(dir_ov / "fakeip", true);
        check(inv_ov.health == "ok" && inv_ov.entries == 400, "inspect_fakeip reports ok on compacted override store");

        // 3. > 65536-row /14 compacted checkpoint (> old 65536*267+4 = 17.5 MiB payload ceiling) inspected cleanly as ok!
        auto dir_big = tmp.path / "fakeip-big-ckpt";
        std::filesystem::create_directories(dir_big);
        std::filesystem::permissions(dir_big, std::filesystem::perms::owner_all);
        {
            auto lock = state::InstanceLock::open_child(dir_big, "fakeip");
            check(lock.has_value(), "open big-ckpt fakeip lock");
            if (lock) {
                auto meta = state::fakeip_meta(*lock, large_scope);
                auto wal = state::open_dir_append(lock->directory(), "fakeip.wal", state::Stage::open);
                check(meta && wal, "init big-ckpt meta & wal");
                if (meta && wal) {
                    constexpr std::size_t big_count = 85000;
                    std::string pad(63, 'a');
                    std::vector<state::FakeIpRow> rows;
                    rows.reserve(big_count);
                    for (std::size_t i = 0; i < big_count; ++i)
                        rows.push_back({static_cast<std::uint32_t>(large_scope.alloc_first + i), 1,
                            std::format("r{}.{}.{}.{}.test", i, pad, pad, pad)});
                    auto compacted = state::compact_fakeip(*lock, *meta, wal->get(), rows, 262144);
                    check(compacted.has_value(), "compact 85000-row (>17.5 MiB) FakeIP checkpoint");
                }
            }
        }
        auto ckpt_sz = std::filesystem::file_size(dir_big / "fakeip/fakeip.ckpt");
        auto inv_big = state::inspect_fakeip(dir_big / "fakeip", true);
        check(ckpt_sz > 65536u * 267u + 4u && inv_big.health == "ok" && inv_big.entries == 85000,
            "inspect_fakeip accepts > 17.5 MiB (85000-row) /14 checkpoint as ok (not damaged)");
        std::cout << "  [PASS] FakeIP WAL auto-scaling (/14 8 MiB), explicit compaction override & >65k checkpoint inspect\n";
    }

    auto test_tailscale_multi_worker_ring_scale() -> void {
        tailscale::MultiWorkerMeshHub hub(4);
        check(hub.outbound_cap() == 2048 && hub.worker_rx_cap() == 1024 && hub.max_tracked_flows() == 65536,
            "MultiWorkerMeshHub raised default queue & flow caps (2048 / 1024 / 65536)");
        hub.update_network(tailscale::MultiWorkerMeshHub::Network{std::array<std::uint8_t, 4>{100, 64, 0, 1}, std::nullopt, 1});
        auto rev = hub.network()->revision;

        // > 256 outbound packets (1000) accepted and drained in FIFO order.
        for (std::uint16_t i = 0; i < 1000; ++i) {
            auto pkt = make_udp_ipv4_packet({100, 64, 0, 1}, static_cast<std::uint16_t>(10000 + (i % 500)),
                                            {100, 64, 0, 2}, static_cast<std::uint16_t>(20000 + i), i);
            check(hub.send_from_worker(0, rev, pkt), "MultiWorkerMeshHub outbound accepts > 256 packets");
        }
        for (std::uint16_t i = 0; i < 1000; ++i) {
            auto pkt = hub.pop_outbound();
            check(pkt && pkt->size() == 32 && ((std::uint16_t((*pkt)[28]) << 8) | (*pkt)[29]) == i,
                "MultiWorkerMeshHub outbound FIFO order preserved across 1000 packets");
        }
        check(!hub.pop_outbound().has_value(), "outbound ring empty after drain");

        // > 128 worker RX packets (500) accepted and drained in FIFO order.
        for (std::uint16_t i = 0; i < 500; ++i) {
            auto reply = make_udp_ipv4_packet({100, 64, 0, 2}, static_cast<std::uint16_t>(20000 + i),
                                              {100, 64, 0, 1}, static_cast<std::uint16_t>(10000 + (i % 500)), i);
            check(hub.dispatch_inbound(reply), "MultiWorkerMeshHub worker RX accepts > 128 packets");
        }
        for (std::uint16_t i = 0; i < 500; ++i) {
            auto pkt = hub.receive_for_worker(0, rev);
            check(pkt && pkt->size() == 32 && ((std::uint16_t((*pkt)[28]) << 8) | (*pkt)[29]) == i,
                "MultiWorkerMeshHub worker RX FIFO order preserved across 500 packets");
        }

        // Configurable queue caps enforce exact backpressure and power-of-two ring wrap-around.
        tailscale::MultiWorkerMeshHub custom(2, {}, {.outbound_cap = 300, .worker_rx_cap = 200, .max_flows = 1024});
        check(custom.outbound_cap() == 300 && custom.worker_rx_cap() == 200 && custom.max_tracked_flows() == 1024,
            "MultiWorkerMeshHub custom Options applied");
        custom.update_network(tailscale::MultiWorkerMeshHub::Network{std::array<std::uint8_t, 4>{100, 64, 0, 1}, std::nullopt, 1});
        auto crev = custom.network()->revision;
        auto sample_tx = make_udp_ipv4_packet({100, 64, 0, 1}, 10001, {100, 64, 0, 2}, 443, 1);
        for (int i = 0; i < 300; ++i) check(custom.send_from_worker(0, crev, sample_tx), "custom outbound fill to 300");
        check(!custom.send_from_worker(0, crev, sample_tx), "custom outbound backpressure at 301");
        check(custom.pop_outbound().has_value() && custom.send_from_worker(0, crev, sample_tx), "outbound ring wrap-around after pop");

        auto sample_rx = make_udp_ipv4_packet({100, 64, 0, 2}, 443, {100, 64, 0, 1}, 10001, 2);
        for (int i = 0; i < 200; ++i) check(custom.dispatch_inbound(sample_rx), "custom RX fill to 200");
        check(!custom.dispatch_inbound(sample_rx), "custom RX backpressure at 201");
        check(custom.receive_for_worker(0, crev).has_value() && custom.dispatch_inbound(sample_rx), "RX ring wrap-around after pop");
        std::cout << "  [PASS] Tailscale MultiWorkerMeshHub power-of-two ring queues (>256/>128 + backpressure)\n";
    }
}

int main() {
    TempDir tmp("nexus-wave37-t4");
    test_dns_pending_and_snapshot_scale();
    test_doq_pool_scale_and_lru();
    test_neighbor_table_scale();
    test_fakeip_wal_scaling_and_recovery(tmp);
    test_tailscale_multi_worker_ring_scale();
    if (!failures) std::cout << "WAVE 37 TRACK 4 HARD-LIMITS SCALE UNIT TESTS PASSED\n";
    return failures ? 1 : 0;
}
