import std;
import containers.cache_index;
import dns.cache;
import dns.message;
import dns.message_cache;
import dns.response_cache;
import nexus.thirdparty.corosio;

namespace {
    auto make_answer(std::uint8_t octet, std::uint32_t ttl = 60) -> dns::AddressAnswer {
        dns::Address addr{};
        addr.size = 4;
        addr.bytes[0] = 10;
        addr.bytes[1] = 0;
        addr.bytes[2] = 0;
        addr.bytes[3] = octet;
        return dns::AddressAnswer{"host.test", {"host.test"}, {addr}, ttl};
    }

    auto make_dns_wire(std::uint16_t id, std::string_view name, std::uint8_t octet, std::uint32_t ttl = 60) -> dns::Bytes {
        dns::QueryMessage q{};
        q.id = id;
        q.flags = 0x0100;
        q.question = {std::string(name), 1, 1};
        auto qwire = dns::encode_query(q);
        if (!qwire) std::abort();
        auto wire = *qwire;
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[6] = 0x00;
        wire[7] = 0x01; // ANCOUNT = 1
        // Answer: pointer to offset 12 (0xc00c), TYPE A, CLASS IN, TTL, RDLENGTH 4, IPv4
        wire.push_back(0xc0); wire.push_back(0x0c);
        wire.push_back(0x00); wire.push_back(0x01);
        wire.push_back(0x00); wire.push_back(0x01);
        wire.push_back(static_cast<std::uint8_t>(ttl >> 24));
        wire.push_back(static_cast<std::uint8_t>(ttl >> 16));
        wire.push_back(static_cast<std::uint8_t>(ttl >> 8));
        wire.push_back(static_cast<std::uint8_t>(ttl));
        wire.push_back(0x00); wire.push_back(0x04);
        wire.push_back(10); wire.push_back(1); wire.push_back(2); wire.push_back(octet);
        return wire;
    }

    auto test_clock_scan_resistance() -> int {
        // Hot entry survives scan flood under CLOCK (second-chance) eviction.
        dns::AddressCache cache(64, 0, true);
        std::uint64_t now = 1000;
        for (int i = 0; i < 64; ++i) {
            dns::CacheKey k{1, "cold" + std::to_string(i) + ".test", 1};
            auto tok = cache.begin_query(k);
            if (!tok || !cache.publish(k, make_answer(static_cast<std::uint8_t>(i & 255), 300), now, *tok)) return 10;
        }
        // Mark cold0..cold7 as hot via shared-lock reads.
        for (int i = 0; i < 8; ++i) {
            auto hit = cache.lookup({1, "cold" + std::to_string(i) + ".test", 1}, now);
            if (!hit || !*hit) return 11;
        }
        // Insert 32 scan entries; unreferenced cold entries should be evicted before hot cold0..cold7.
        for (int i = 0; i < 32; ++i) {
            dns::CacheKey k{1, "scan" + std::to_string(i) + ".test", 1};
            auto tok = cache.begin_query(k);
            if (!tok || !cache.publish(k, make_answer(static_cast<std::uint8_t>(i), 300), now, *tok)) return 12;
        }
        if (cache.size() != 64) return 13;
        for (int i = 0; i < 8; ++i) {
            auto hit = cache.lookup({1, "cold" + std::to_string(i) + ".test", 1}, now);
            if (!hit || !*hit) return 14;
        }
        return 0;
    }

    auto test_large_4096_address_cache() -> int {
        dns::AddressCache cache(4096, 0, true);
        std::uint64_t now = 1000;
        for (int i = 0; i < 4096; ++i) {
            dns::CacheKey k{1, "n" + std::to_string(i) + ".scale.test", 1};
            auto tok = cache.begin_query(k);
            if (!tok || !cache.publish(k, make_answer(static_cast<std::uint8_t>(i & 255), 120), now, *tok)) return 20;
        }
        if (cache.size() != 4096) return 21;
        auto t0 = std::chrono::steady_clock::now();
        for (int round = 0; round < 10; ++round) {
            for (int i = 0; i < 4096; ++i) {
                auto hit = cache.lookup({1, "n" + std::to_string(i) + ".scale.test", 1}, now);
                if (!hit || !*hit) return 22;
            }
        }
        auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t0).count();
        std::println("AddressCache 4096x10 O(1) CLOCK lookups: {} us ({:.2f} ns/lookup)",
            elapsed_us, (elapsed_us * 1000.0) / 40960.0);
        return 0;
    }

    auto test_intrusive_lru_response_and_message_cache() -> int {
        dns::ResponseCache rc(4);
        std::uint64_t now = 1000;
        for (int i = 0; i < 4; ++i) {
            std::string name = "r" + std::to_string(i) + ".lru.test";
            auto wire = make_dns_wire(static_cast<std::uint16_t>(100 + i), name, static_cast<std::uint8_t>(i + 1), 120);
            auto parsed = dns::parse_response(wire, static_cast<std::uint16_t>(100 + i), {name, 1, 1});
            if (!parsed) return 30;
            auto tok = rc.begin({1, name, 1});
            if (!tok || !rc.publish({1, name, 1}, *parsed, now, *tok)) return 31;
        }
        // Touch r0 so it becomes MRU; r1 is now LRU!
        auto hit0 = rc.lookup({1, "r0.lru.test", 1}, now, 200);
        if (!hit0 || !*hit0) return 32;
        // Insert r4 -> must evict r1 (LRU), NOT r0 (promoted to MRU)!
        auto wire4 = make_dns_wire(104, "r4.lru.test", 5, 120);
        auto parsed4 = dns::parse_response(wire4, 104, {"r4.lru.test", 1, 1});
        if (!parsed4) return 33;
        auto tok4 = rc.begin({1, "r4.lru.test", 1});
        if (!tok4 || !rc.publish({1, "r4.lru.test", 1}, *parsed4, now, *tok4)) return 34;

        auto after0 = rc.lookup({1, "r0.lru.test", 1}, now, 201);
        auto after1 = rc.lookup({1, "r1.lru.test", 1}, now, 202);
        auto after4 = rc.lookup({1, "r4.lru.test", 1}, now, 203);
        if (!after0 || !*after0) return 35;
        if (!after1 || *after1) return 36;
        if (!after4 || !*after4) return 37;

        // MessageCache intrusive LRU test with capacity=3
        dns::MessageCache mc(std::chrono::seconds(0), 3);
        dns::MessageCache::View view(0, {nex::corosio::ipv4_address::loopback(), 53}, false, {});
        auto tp = std::chrono::steady_clock::now();
        for (int i = 0; i < 3; ++i) {
            std::string name = "m" + std::to_string(i) + ".lru.test";
            dns::QueryMessage q{static_cast<std::uint16_t>(300 + i), 0x0100, {name, 1, 1}, {}};
            auto wire = make_dns_wire(q.id, name, static_cast<std::uint8_t>(i + 1), 120);
            auto parsed = dns::parse_owned_response(std::move(wire), q.id, q.question);
            if (!parsed) return 40;
            auto ticket = mc.begin(view, q);
            if (!ticket) return 41;
            mc.publish(*ticket, q, std::move(*parsed), tp);
        }
        // Promote m0 to MRU
        dns::QueryMessage q0{400, 0x0100, {"m0.lru.test", 1, 1}, {}};
        if (!mc.lookup(view, q0, tp)) return 42;
        // Insert m3 -> must evict m1 (LRU), keeping m0, m2, m3
        dns::QueryMessage q3{403, 0x0100, {"m3.lru.test", 1, 1}, {}};
        auto wire3 = make_dns_wire(q3.id, "m3.lru.test", 4, 120);
        auto parsed3 = dns::parse_owned_response(std::move(wire3), q3.id, q3.question);
        if (!parsed3) return 43;
        auto t3 = mc.begin(view, q3);
        if (!t3) return 44;
        mc.publish(*t3, q3, std::move(*parsed3), tp);

        dns::QueryMessage q1{401, 0x0100, {"m1.lru.test", 1, 1}, {}};
        if (!mc.lookup(view, q0, tp)) return 45;
        if (mc.lookup(view, q1, tp)) return 46;
        if (!mc.lookup(view, q3, tp)) return 47;
        if (mc.size() != 3) return 48;
        std::println("ResponseCache & MessageCache intrusive uint32_t LRU passed");
        return 0;
    }
}

auto main() -> int {
    if (auto rc = test_clock_scan_resistance(); rc != 0) return rc;
    if (auto rc = test_large_4096_address_cache(); rc != 0) return rc;
    if (auto rc = test_intrusive_lru_response_and_message_cache(); rc != 0) return rc;
    std::println("ALL BATCH 96E CACHE EVICTION TESTS PASSED");
    return 0;
}
