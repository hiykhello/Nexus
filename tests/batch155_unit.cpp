#include <cassert>

import std;
import crypto;
import tailscale.derp;
import tailscale.derp_messages;
import tailscale.derp_server;
import tailscale.box;
import control_api.ssmapi;
import memory.watchdog;

namespace {
    auto make_client_info(crypto::X25519Private const& cli, tailscale::derp::Key const& srv_pub)
        -> std::vector<std::uint8_t> {
        auto cli_pub = *cli.public_key();
        auto shared = *tailscale::box::SharedKey::derive(cli, srv_pub);
        tailscale::derp::Nonce nonce{};
        assert(crypto::random_bytes(nonce).has_value());
        std::string_view info = "{\"version\":2}";
        std::vector<std::uint8_t> sealed(info.size() + tailscale::box::tag_size);
        auto n = *shared.seal_to(sealed, nonce,
            std::span(reinterpret_cast<std::uint8_t const*>(info.data()), info.size()));
        sealed.resize(n);
        return *tailscale::derp::encode_client_info(cli_pub, nonce, sealed);
    }
}

int main() {
    // 1. Standalone DERP relay
    auto srv = tailscale::derp::DerpRelayServer::generate(16);
    assert(srv.has_value());
    auto alice = *crypto::X25519Private::generate();
    auto bob = *crypto::X25519Private::generate();
    auto alice_pub = *alice.public_key();
    auto bob_pub = *bob.public_key();

    assert(srv->accept_connection(1).has_value());
    assert(srv->accept_connection(2).has_value());

    {
        tailscale::derp::Decoder d1, d2;
        auto ci1 = make_client_info(alice, srv->public_key());
        auto ci2 = make_client_info(bob, srv->public_key());
        assert(d1.feed(ci1).ready && d2.feed(ci2).ready);
        auto r1 = srv->handle_frame(1, *d1.frame(), 100);
        auto r2 = srv->handle_frame(2, *d2.frame(), 101);
        assert(r1 && r1->size() == 1 && r2 && r2->size() == 1);
        assert(srv->has_peer(alice_pub) && srv->has_peer(bob_pub) && srv->stats().connected_peers == 2);
    }

    std::vector<std::uint8_t> payload{0xde, 0xad, 0xbe, 0xef};
    auto send_wire = *tailscale::derp::encode_packet(tailscale::derp::Type::send_packet, bob_pub, payload);
    {
        tailscale::derp::Decoder d;
        assert(d.feed(send_wire).ready);
        auto fwd = srv->handle_frame(1, *d.frame(), 200);
        assert(fwd && fwd->size() == 1 && (*fwd)[0].connection_id == 2);
        tailscale::derp::Decoder d_out;
        assert(d_out.feed((*fwd)[0].frame).ready);
        auto recv = *tailscale::derp::parse_packet(*d_out.frame(), tailscale::derp::Type::recv_packet);
        assert(recv.peer == alice_pub && std::ranges::equal(recv.bytes, payload));
    }

    std::array<std::uint8_t, 8> ping_tok{1, 2, 3, 4, 5, 6, 7, 8};
    auto ping_wire = *tailscale::derp::encode_ping(tailscale::derp::Type::ping, ping_tok);
    {
        tailscale::derp::Decoder d;
        assert(d.feed(ping_wire).ready);
        auto pr = srv->handle_frame(1, *d.frame(), 210);
        assert(pr && pr->size() == 1 && srv->stats().pings_replied == 1);
    }
    auto gone = srv->disconnect(2);
    assert(gone.size() == 1 && !srv->has_peer(bob_pub) && srv->stats().connected_peers == 1);

    // 2. ssmapi multi-user CRUD, quota & HTTP routing
    control_api::ssmapi::UserStore users;
    auto c1 = control_api::ssmapi::handle_http_request(users, "POST", "/v1/ssmapi/users",
        R"({"username":"alice","uPSK":"kAAAA","enabled":true,"byteQuota":1000})");
    assert(c1.status == 201);
    assert(users.within_quota("alice"));
    assert(users.record_traffic("alice", 600, 450, 5, 6));
    assert(!users.within_quota("alice"));
    assert(control_api::ssmapi::handle_http_request(users, "GET", "/v1/ssmapi/stats", {}).json.contains("\"userCount\":1"));
    assert(control_api::ssmapi::handle_http_request(users, "DELETE", "/v1/ssmapi/users/alice", {}).status == 204);
    assert(!users.get_user("alice").has_value());

    // 3. Low-memory watchdog
    std::vector<memory::PressureLevel> events;
    memory::MemoryWatchdog wd(memory::WatchdogPolicy::ios_ne_50mib());
    assert(wd.evaluate(20ull * 1024 * 1024, 1000, [&](auto lvl) { events.push_back(lvl); }) == memory::PressureLevel::normal);
    assert(events.empty());
    assert(wd.evaluate(38ull * 1024 * 1024, 2000, [&](auto lvl) { events.push_back(lvl); }) == memory::PressureLevel::soft);
    assert(wd.evaluate(39ull * 1024 * 1024, 2500, [&](auto lvl) { events.push_back(lvl); }) == memory::PressureLevel::soft);
    assert(events.size() == 1); // cooldown prevents spam
    assert(wd.evaluate(49ull * 1024 * 1024, 2600, [&](auto lvl) { events.push_back(lvl); }) == memory::PressureLevel::emergency);
    assert(!wd.should_admit_new_session() && events.size() == 2 && wd.stats().emergency_sheds == 1);
    assert(memory::sample_process_rss_bytes() > 0);

    std::println("batch155 unit tests (derp-server / ssmapi / memory watchdog) passed");
    return 0;
}
