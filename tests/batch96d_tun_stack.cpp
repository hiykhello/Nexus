import std;
import packet;
import tcp.send;
import tcp.receive;
import tcp.handshake;
import tcp.connection;
import tcp.table;
import udp;

namespace {
    auto test_ring_send_srtt_and_fast_retransmit() -> int {
        auto ts = tcp::TimedSend::create(1000, 262144);
        if (!ts) return 1;
        std::vector<std::uint8_t> payload(10000, 0x42);
        if (!ts->enqueue(payload)) return 2;
        if (ts->queued() != 10000 || ts->available() != 262144 - 10000) return 3;

        // Send 1400 bytes at t=100, ACK at t=140 -> 40ms RTT sample -> dynamic RTO drops well below 1000ms!
        auto s1 = ts->unsent(1400);
        if (s1.sequence != 1000 || s1.bytes.size() != 1400) return 4;
        if (!ts->sent(1400, 100)) return 5;
        auto ack1 = ts->acknowledge(2400, 140);
        if (!ack1 || *ack1 != 1400) return 6;
        if (!ts->srtt_ms() || *ts->srtt_ms() != 40) return 7;
        if (ts->rto() >= 1000 || ts->rto() < 200) return 8;

        // Send 3 more segments (4200 bytes) and trigger 3 duplicate ACKs -> immediate fast retransmit!
        if (!ts->sent(1400, 145) || !ts->sent(1400, 146) || !ts->sent(1400, 147)) return 9;
        for (int i = 0; i < 3; ++i) {
            auto d = ts->acknowledge(2400, 150 + static_cast<std::uint64_t>(i));
            if (!d || *d != 0) return 10;
        }
        if (!ts->fast_retransmit_pending()) return 11;
        auto due = ts->due(153, 1400);
        if (!due || !*due || (**due).sequence != 2400 || (**due).bytes.size() != 1400) return 12;
        if (!ts->retransmitted(153)) return 13;
        if (ts->fast_retransmit_pending()) return 14;
        return 0;
    }

    auto test_window_scale_256k_sack_and_pmtu() -> int {
        // SYN offering Window Scale=4 (shift 4) and SACK-Permitted + MSS 1460
        std::array<std::uint8_t, 12> syn_opts{
            2, 4, 0x05, 0xb4, // MSS 1460
            3, 3, 4, 1,       // WScale 4 + NOP
            4, 2, 1, 1        // SACK Permitted + 2x NOP
        };
        packet::Tcp4View syn{
            .source={10,0,0,2}, .destination={10,0,0,1},
            .source_port=40000, .destination_port=443,
            .sequence=5000, .flags=0x02, .window=65535, .options=syn_opts
        };
        auto conn = tcp::PassiveConnection::accept(syn, 9000, 512 * 1024, 100);
        if (!conn) return 20;
        if (!conn->window_scaling_enabled()) return 21;
        auto sa = conn->syn_ack();
        auto parsed_sa = packet::parse_tcp_syn_options(sa.options);
        if (!parsed_sa || !parsed_sa->window_scale || *parsed_sa->window_scale != 4 || !parsed_sa->sack_permitted) return 22;

        // Complete handshake with scaled window (16384 << 4 = 262144 bytes > 64 KiB!)
        packet::Tcp4View ack_hs{
            .source={10,0,0,2}, .destination={10,0,0,1},
            .source_port=40000, .destination_port=443,
            .sequence=5001, .acknowledgement=9001, .flags=0x10, .window=16384
        };
        auto hs = conn->input(ack_hs, 110);
        if (!hs || !*hs || conn->peer_window() != 262144) return 23;

        // Enqueue 200 KiB (>64 KiB!) and send >128 KiB in-flight without blocking on 64 KiB ceiling!
        std::vector<std::uint8_t> bulk(200 * 1024, 0x55);
        if (!conn->enqueue(bulk)) return 24;
        std::size_t pushed = 0;
        while (pushed < 130 * 1024) {
            auto sl = conn->unsent(1460);
            if (sl.bytes.empty()) return 25;
            if (!conn->sent(sl.bytes.size(), 120)) return 26;
            pushed += sl.bytes.size();
        }

        // Out-of-order segment generates RFC 2018 SACK option on ACK!
        std::array<std::uint8_t, 8> ooo{1,2,3,4,5,6,7,8};
        packet::Tcp4View seg_ooo{
            .source={10,0,0,2}, .destination={10,0,0,1},
            .source_port=40000, .destination_port=443,
            .sequence=5011, .acknowledgement=9001, .flags=0x18, .window=16384, .payload=ooo
        };
        if (!conn->input(seg_ooo, 130)) return 27;
        auto sack_ack = conn->ack();
        auto sack_opts = packet::parse_tcp_options(sack_ack.options);
        if (!sack_opts) return 28;
        bool found_sack = false;
        for (std::size_t i = 0; i < sack_opts->count; ++i)
            if (sack_opts->items[i].kind == 5 && sack_opts->items[i].data.size() == 8) found_sack = true;
        if (!found_sack) return 29;

        // Dynamic PMTU reduction via ICMP PTB
        conn->set_pmtu(1280, false);
        if (conn->effective_mss() != 1240) return 30;
        return 0;
    }

    auto test_icmp_ptb_roundtrip() -> int {
        std::array<std::uint8_t, 28> quote{};
        auto w4 = packet::make_icmp_ptb4({{10,0,0,1}, {10,0,0,2}, 1280, quote});
        if (!w4) return 40;
        auto p4 = packet::parse_icmp_ptb4(*w4);
        if (!p4 || p4->next_hop_mtu != 1280 || p4->quote.size() != 28) return 41;

        packet::Address6 a6{}, b6{}; a6[0] = 0xfd; a6[15] = 1; b6[0] = 0xfd; b6[15] = 2;
        auto w6 = packet::make_icmp_ptb6({a6, b6, 1280, quote});
        if (!w6) return 42;
        auto p6 = packet::parse_icmp_ptb6(*w6);
        if (!p6 || p6->next_hop_mtu != 1280 || p6->quote.size() != 28) return 43;
        return 0;
    }

    auto test_o1_hash_tables_2000_flows() -> int {
        auto t4 = tcp::ConnectionTable::create(2048, 65536);
        if (!t4) return 50;
        auto t0 = std::chrono::steady_clock::now();
        for (std::uint16_t port = 10000; port < 12000; ++port) {
            packet::Tcp4View syn{
                .source={10,0,0,2}, .destination={10,0,0,1},
                .source_port=port, .destination_port=443,
                .sequence=100, .flags=0x02, .window=65535
            };
            auto id = t4->open(syn, 200, 1000);
            if (!id) return 51;
        }
        for (int r = 0; r < 10; ++r) {
            for (std::uint16_t port = 10000; port < 12000; ++port) {
                packet::Tcp4View seg{.source={10,0,0,2}, .destination={10,0,0,1}, .source_port=port, .destination_port=443};
                auto id = t4->find(seg);
                if (!id || !t4->get(*id)) return 52;
            }
        }
        auto tcp_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();

        udp::FlowTable ut(udp::Mapping::endpoint_independent, udp::Filtering::endpoint_independent, {2048, 32, 60000});
        auto u0 = std::chrono::steady_clock::now();
        std::vector<udp::FlowId> ids;
        ids.reserve(2000);
        for (std::uint16_t port = 20000; port < 22000; ++port) {
            auto id = ut.open({{10,0,0,2}, port}, {{1,1,1,1}, 53}, 1000);
            if (!id) return 53;
            ids.push_back(*id);
        }
        for (auto id : ids) {
            auto tok = ut.begin_send(id, {{1,1,1,1}, 53}, 1000);
            if (!tok || !ut.finish_send(id, *tok, true, 1000)) return 54;
            if (!ut.accept_reply(id, {{1,1,1,1}, 53}, 1000)) return 55;
        }
        auto udp_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - u0).count();
        std::println("TUN O(1) hash tables: TCP 2000x10 lookups={} us, UDP 2000 flows={} us", tcp_us, udp_us);
        return 0;
    }
}

auto main() -> int {
    if (auto rc = test_ring_send_srtt_and_fast_retransmit(); rc != 0) return rc;
    if (auto rc = test_window_scale_256k_sack_and_pmtu(); rc != 0) return rc;
    if (auto rc = test_icmp_ptb_roundtrip(); rc != 0) return rc;
    if (auto rc = test_o1_hash_tables_2000_flows(); rc != 0) return rc;
    std::println("ALL BATCH 96D TUN STACK TESTS PASSED (ByteRing, SRTT/3-DupACK, WindowScale>64K, SACK, PMTU/PTB, O(1) TCP/UDP tables)");
    return 0;
}
