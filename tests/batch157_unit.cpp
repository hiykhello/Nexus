#include <cassert>

import std;
import crypto;
import packet;
import openvpn.types;
import openvpn.wire;
import openvpn.session;
import openconnect.types;
import openconnect.auth;
import openconnect.cstp;
import relay.reverse_tunnel;
import packet.bridge;

int main() {
    // 1. OpenVPN control packet wire + HKDF + AEAD DataChannel + replay + reconnect
    {
        openvpn::ControlPacket reset_req{
            .opcode = openvpn::Opcode::control_hard_reset_client_v2,
            .key_id = 1,
            .session_id = 0x1122334455667788ull,
            .acks = {1, 2},
            .remote_session_id = 0x8877665544332211ull,
            .packet_id = 7,
            .payload = {0xaa, 0xbb, 0xcc},
        };
        auto wire = *openvpn::encode_control_packet(reset_req);
        auto decoded = *openvpn::decode_control_packet(wire);
        assert(decoded.opcode == reset_req.opcode && decoded.key_id == 1 && decoded.session_id == reset_req.session_id);
        assert(decoded.acks == reset_req.acks && decoded.remote_session_id == reset_req.remote_session_id);
        assert(decoded.packet_id == 7 && decoded.payload == reset_req.payload);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 16> crand{}, srand{};
        secret[0] = 0x42; crand[0] = 0x11; srand[0] = 0x22;
        auto km_cli = *openvpn::derive_data_keys(secret, crand, srand, false);
        auto km_srv = *openvpn::derive_data_keys(secret, crand, srand, true);

        openvpn::DataChannel cli, srv;
        assert(cli.init(openvpn::Cipher::aes_256_gcm, km_cli, 0x001234u, 2).has_value());
        assert(srv.init(openvpn::Cipher::aes_256_gcm, km_srv, 0x001234u, 2).has_value());

        std::vector<std::uint8_t> msg{0x45, 0x00, 0x00, 0x1c, 1, 2, 3, 4};
        auto pkt = *cli.seal_data_v2(msg);
        auto plain = *srv.open_data_v2(pkt);
        assert(plain == msg);
        assert(!srv.open_data_v2(pkt).has_value()); // anti-replay rejects duplicate packet_id

        auto tampered = *cli.seal_data_v2(msg);
        tampered.back() ^= 0xff;
        assert(!srv.open_data_v2(tampered).has_value()); // auth tag mismatch

        openvpn::DataChannel cc_cli, cc_srv;
        assert(cc_cli.init(openvpn::Cipher::chacha20_poly1305, km_cli, 77, 0).has_value());
        assert(cc_srv.init(openvpn::Cipher::chacha20_poly1305, km_srv, 77, 0).has_value());
        assert(*cc_srv.open_data_v2(*cc_cli.seal_data_v2(msg)) == msg);

        openvpn::SessionStateMachine fsm({.remote_host = "vpn.example.com", .remote_port = 1194}, 0x101);
        assert(fsm.begin_connect().has_value());
        assert(fsm.state() == openvpn::SessionState::hard_reset_sent);
        assert(fsm.on_control_packet({.opcode = openvpn::Opcode::control_hard_reset_server_v2, .session_id = 0x202, .packet_id = 0}).has_value());
        assert(fsm.state() == openvpn::SessionState::tls_handshake && fsm.remote_session_id() == 0x202);
        fsm.mark_established();
        auto recon = fsm.trigger_reconnect(0x303);
        assert(fsm.state() == openvpn::SessionState::reconnecting && fsm.generation() == 2 && recon.session_id == 0x303);
    }

    // 2. OpenConnect XML auth + CSTP framing + DPD/reconnect
    {
        auto xml = openconnect::build_config_auth_xml({.username = "alice", .password = "s&p<1>", .group = "eng"});
        assert(xml.contains("s&amp;p&lt;1&gt;"));
        auto auth = *openconnect::parse_config_auth_response(
            "<config-auth><auth id=\"success\"/><session-token>tok-abc</session-token><banner>Welcome</banner></config-auth>");
        assert(auth.authenticated && auth.cookie == "tok-abc" && auth.banner == "Welcome");

        auto req_hdr = openconnect::build_cstp_connect_headers("gw.example.com", auth.cookie, 1380);
        assert(req_hdr.contains("Cookie: webvpn=tok-abc"));
        auto conn = *openconnect::parse_cstp_connect_headers(
            "HTTP/1.1 200 OK\r\nX-CSTP-Address: 10.99.0.5\r\nX-CSTP-MTU: 1360\r\nX-DTLS-Session-ID: deadbeef\r\n\r\n");
        assert(conn.ipv4_address == "10.99.0.5" && conn.mtu == 1360 && !conn.dtls_session_id.empty());

        auto disabled_timers = *openconnect::parse_cstp_connect_headers(
            "HTTP/1.1 200 OK\r\nX-CSTP-DPD: disabled\r\nX-CSTP-Keepalive: DISABLED\r\n"
            "X-DTLS-DPD: Disabled\r\nX-DTLS-Keepalive: disabled\r\n\r\n");
        assert(disabled_timers.dpd_s == 0 && disabled_timers.keepalive_s == 0 &&
               disabled_timers.dtls_dpd_s == 0 && disabled_timers.dtls_keepalive_s == 0);

        std::vector<std::uint8_t> pl{10, 20, 30, 40};
        auto frame_bytes = *openconnect::encode_cstp_frame(openconnect::CstpType::data, pl);
        assert(!openconnect::decode_cstp_frame(std::span(frame_bytes).first(4)).has_value());
        auto [decoded, consumed] = *openconnect::decode_cstp_frame(frame_bytes);
        assert(consumed == frame_bytes.size() && decoded.type == openconnect::CstpType::data && decoded.payload == pl);

        openconnect::Session oc;
        oc.on_connected(true);
        assert(oc.state() == openconnect::Session::State::connected && oc.dtls_active());
        auto dpd = oc.handle_frame({.type = openconnect::CstpType::dpd_req, .payload = {1, 2}});
        assert(dpd && dpd->type == openconnect::CstpType::dpd_resp && dpd->payload == std::vector<std::uint8_t>({1, 2}));
        (void)oc.handle_frame({.type = openconnect::CstpType::disconnect});
        assert(oc.state() == openconnect::Session::State::reconnecting && !oc.dtls_active());
    }

    // 3. Reverse tunnel multiplexing + half-close + heartbeat + reconnect
    {
        relay::reverse_tunnel::TunnelSession hub("edge-secret-token", 8);
        auto bad_ack = hub.handle_register("wrong", 1000);
        assert(bad_ack.payload.size() == 1 && bad_ack.payload[0] == 0 && !hub.registered());
        auto ok_ack = hub.handle_register("edge-secret-token", 1000);
        auto ack_wire = *relay::reverse_tunnel::encode_frame(ok_ack);
        auto [ack_dec, nbytes] = *relay::reverse_tunnel::decode_frame(ack_wire);
        assert(nbytes == ack_wire.size() && ack_dec.payload[0] == 1 && hub.registered());

        assert(hub.open_stream(1).has_value() && hub.active_streams() == 1);
        assert(hub.on_data(1, 512).has_value());
        assert(hub.close_local(1).has_value() && hub.active_streams() == 1);
        assert(*hub.on_remote_half_close(1) == true && hub.active_streams() == 0);
        assert(!hub.heartbeat_expired(5000, std::chrono::milliseconds{10000}));
        assert(hub.heartbeat_expired(15000, std::chrono::milliseconds{10000}));
        hub.reset_all_for_reconnect();
        assert(!hub.registered() && hub.active_streams() == 0);
    }

    // 4. L3 physical bridge: IPv4 TTL/checksum, IPv6 hop-limit, loop/MTU/link-local drops
    {
        packet::bridge::Layer3Bridge bridge({.tun_interface = "nexus-tun0", .physical_interface = "eth0", .mtu = 1400});
        std::array<std::uint8_t, 12> udp_pl{1, 2, 3, 4};
        auto udp4 = *packet::make_udp4({10, 0, 0, 2}, {93, 184, 216, 34}, 5000, 443, udp_pl, 1400);
        auto initial_ttl = udp4[8];
        auto fwd4 = *bridge.forward(packet::bridge::Direction::tun_to_phys, "nexus-tun0", udp4);
        assert(fwd4[8] == initial_ttl - 1);
        assert(packet::parse_udp4(fwd4).has_value());

        auto loop_err = bridge.forward(packet::bridge::Direction::tun_to_phys, "eth0", udp4);
        assert(!loop_err && loop_err.error() == packet::bridge::ForwardError::loop_detected);

        auto ttl1 = udp4;
        ttl1[8] = 1;
        assert(bridge.forward(packet::bridge::Direction::tun_to_phys, "nexus-tun0", ttl1).error()
               == packet::bridge::ForwardError::ttl_expired);

        auto link_local_v4 = *packet::make_udp4({169, 254, 1, 2}, {8, 8, 8, 8}, 1000, 53, udp_pl, 1400);
        assert(bridge.forward(packet::bridge::Direction::tun_to_phys, "nexus-tun0", link_local_v4).error()
               == packet::bridge::ForwardError::link_local_blocked);

        std::vector<std::uint8_t> pkt6(48, 0);
        pkt6[0] = 0x60; pkt6[7] = 64; pkt6[8] = 0x20; pkt6[24] = 0x26;
        auto fwd6 = *bridge.forward(packet::bridge::Direction::phys_to_tun, "eth0", pkt6);
        assert(fwd6[7] == 63);
        assert(bridge.stats().forwarded_v4 == 1 && bridge.stats().forwarded_v6 == 1);
    }

    std::println("batch157 unit tests (openvpn / openconnect / reverse-tunnel / bridge) passed");
    return 0;
}
