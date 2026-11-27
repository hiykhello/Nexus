#include <arpa/inet.h>
#include <boost/capy/ex/run_async.hpp>
#include <cstdlib>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import capy;
import corosio;
import config;
import crypto;
import packet;
import relay;
import rules;
import tls.profiles;
import tls.server_handshake_io;
import tls.application_io;
import tls.corosio_server_handshake;
import tls.corosio_application;
import tls.byte_stream;
import openvpn.types;
import openvpn.wire;
import openvpn.control;
import openvpn.session;
import openconnect.types;
import openconnect.auth;
import openconnect.cstp;
import openconnect.dtls;

namespace {
    namespace io = ::corosio;
    namespace fs = std::filesystem;
    using namespace std::chrono_literals;

    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }

    struct Fd {
        int fd = -1;
        explicit Fd(int v = -1) : fd(v) {}
        Fd(Fd const&) = delete; auto operator=(Fd const&) -> Fd& = delete;
        ~Fd() { if (fd >= 0) ::close(fd); }
    };

    auto write_secret_file(fs::path const& p, std::string_view text) -> void {
        std::ofstream(p, std::ios::binary | std::ios::trunc).write(text.data(), static_cast<std::streamsize>(text.size()));
        fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    }

    auto xfer_fd(int fd, std::uint8_t* p, std::size_t n, bool tx) -> bool {
        while (n) {
            auto r = tx ? ::send(fd, p, n, MSG_NOSIGNAL) : ::recv(fd, p, n, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) return false;
            p += r; n -= static_cast<std::size_t>(r);
        }
        return true;
    }

    auto socks5_echo_test(std::uint16_t proxy_port, std::string_view tag) -> bool {
        Fd fd(::socket(AF_INET, SOCK_STREAM, 0)); timeval tv{4, 0};
        sockaddr_in addr{.sin_family = AF_INET, .sin_port = htons(proxy_port), .sin_addr = {htonl(INADDR_LOOPBACK)}};
        if (fd.fd < 0) return false;
        (void)::setsockopt(fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)::setsockopt(fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (::connect(fd.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
        std::array<std::uint8_t, 3> greet{5, 1, 0}; std::array<std::uint8_t, 2> g_rep{};
        std::array<std::uint8_t, 10> req{5, 1, 0, 1, 93, 184, 216, 34, 0x1f, 0x90}, rep{};
        std::string payload = "nexus-vpn-e2e:" + std::string(tag), echoed(payload.size(), '\0');
        return xfer_fd(fd.fd, greet.data(), greet.size(), true) && xfer_fd(fd.fd, g_rep.data(), g_rep.size(), false) &&
               g_rep == std::array<std::uint8_t, 2>{5, 0} && xfer_fd(fd.fd, req.data(), req.size(), true) &&
               xfer_fd(fd.fd, rep.data(), rep.size(), false) && rep[0] == 5 && rep[1] == 0 &&
               xfer_fd(fd.fd, reinterpret_cast<std::uint8_t*>(payload.data()), payload.size(), true) &&
               xfer_fd(fd.fd, reinterpret_cast<std::uint8_t*>(echoed.data()), echoed.size(), false) && echoed == payload;
    }

    struct MockL3Peer {
        std::uint32_t srv_seq = 0x10000001u, cli_ack = 0;
        template<class SendFn>
        auto on_ip(std::span<std::uint8_t const> pkt, SendFn&& send_fn) -> void {
            auto t = packet::parse_tcp4(pkt); if (!t || (t->flags & 0x04)) return;
            auto emit = [&](std::uint32_t s, std::uint32_t a, std::uint16_t f, std::span<std::uint8_t const> o, std::span<std::uint8_t const> p) {
                if (auto r = packet::make_tcp4({t->destination, t->source, t->destination_port, t->source_port, s, a, f, 65535, 0, o, p}, 1400)) send_fn(*r);
            };
            if (t->flags & 0x02) { cli_ack = t->sequence + 1; srv_seq = 0x10000001u; std::array<std::uint8_t, 4> mss{2, 4, 5, 0x50}; emit(0x10000000u, cli_ack, 0x12, mss, {}); }
            else if (t->flags & 0x01) emit(srv_seq++, t->sequence + static_cast<std::uint32_t>(t->payload.size()) + 1, 0x11, {}, {});
            else if (!t->payload.empty()) { cli_ack = t->sequence + static_cast<std::uint32_t>(t->payload.size()); emit(srv_seq, cli_ack, 0x18, {}, t->payload); srv_seq += static_cast<std::uint32_t>(t->payload.size()); }
        }
    };

    auto now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    auto test_protocol_units(fs::path const& tmp) -> void {
        std::vector<std::uint8_t> raw{1, 2, 3, 4, 5}; auto tf = *openvpn::encode_tcp_frame(raw);
        require(!openvpn::decode_tcp_frame(std::span(tf).first(tf.size() - 1))->has_value(), "partial ovpn tcp");
        auto td = *openvpn::decode_tcp_frame(tf); require(td && td->first == raw && td->second == tf.size(), "ovpn tcp frame");
        openvpn::KeyMethod2Client kmc{.options = "V4,cipher AES-256-GCM", .username = "alice", .password = "secret", .peer_info = "IV_VER=2.6.0\n"};
        std::ranges::fill(kmc.pre_master, 0x11); std::ranges::fill(kmc.random1, 0x22); std::ranges::fill(kmc.random2, 0x33);
        auto kmc_dec = *openvpn::decode_key_method2_client(*openvpn::encode_key_method2_client(kmc));
        require(kmc_dec.pre_master == kmc.pre_master && kmc_dec.username == "alice" && kmc_dec.password == "secret", "km2 client");
        openvpn::KeyMethod2Server kms{.options = "V4,cipher AES-256-GCM"};
        std::ranges::fill(kms.random1, 0x44); std::ranges::fill(kms.random2, 0x55);
        auto kms_dec = *openvpn::decode_key_method2_server(*openvpn::encode_key_method2_server(kms));
        require(kms_dec.random1 == kms.random1 && kms_dec.options == kms.options, "km2 server");
        auto ckm = *openvpn::derive_key_method2_keys(kmc.pre_master, kmc.random1, kms.random1, kmc.random2, kms.random2, 0x111, 0x222, false);
        auto skm = *openvpn::derive_key_method2_keys(kmc.pre_master, kmc.random1, kms.random1, kmc.random2, kms.random2, 0x111, 0x222, true);
        require(ckm.tx_key == skm.rx_key && ckm.rx_key == skm.tx_key && ckm.tx_iv == skm.rx_iv, "km2 PRF symmetry");
        openvpn::DataChannel cdc, sdc;
        require(cdc.init(openvpn::Cipher::aes_256_gcm, ckm, 7, 0).has_value() && sdc.init(openvpn::Cipher::aes_256_gcm, skm, 7, 0).has_value(), "dc init");
        auto wire = *cdc.seal_data_v2(std::array<std::uint8_t, 4>{9, 8, 7, 6});
        require(*sdc.open_data_v2(wire) == std::vector<std::uint8_t>{9, 8, 7, 6} && !sdc.open_data_v2(wire).has_value(), "tag-first DataChannel + replay");
        auto pr = *openvpn::parse_push_reply("PUSH_REPLY,route 0.0.0.0 0.0.0.0,ifconfig 10.8.0.42 10.8.0.1,peer-id 9,cipher CHACHA20-POLY1305,tun-mtu 1380,ping 15,ping-restart 90");
        require(pr.local_v4 == std::array<std::uint8_t, 4>{10, 8, 0, 42} && pr.peer_id == 9 &&
                pr.cipher == openvpn::Cipher::chacha20_poly1305 && pr.mtu == 1380 && pr.ping_s == 15 && pr.ping_restart_s == 90, "push reply");
        openvpn::ControlChannel cc(0xaaa, false), sc(0xbbb, true);
        require(sc.on_packet(cc.begin_client_reset(10), 10).has_value() && sc.handshake_started() &&
                cc.on_packet(sc.make_server_reset(10), 10).has_value() && cc.handshake_started(), "ctrl reset");
        auto pkts = cc.enqueue_tls_bytes(std::vector<std::uint8_t>(2300, 0x5A), 20);
        require(pkts.size() == 3 && sc.on_packet(pkts[2], 25)->empty() && sc.on_packet(pkts[0], 25)->size() == 1000 &&
                sc.on_packet(pkts[1], 25)->size() == 1300 && !cc.retransmit_due(600, 500).empty(), "ctrl frag/reorder/retransmit");
        auto sk = openvpn::parse_static_key_v1("-----BEGIN OpenVPN Static key V1-----\n" + std::string(512, 'a') + "\n-----END OpenVPN Static key V1-----\n");
        require(sk.has_value() && (*sk)[0] == 0xaa && (*sk)[255] == 0xaa, "static key V1");
        auto sk_file = tmp / "ovpn.key"; write_secret_file(sk_file, "-----BEGIN OpenVPN Static key V1-----\n" + std::string(512, 'a') + "\n-----END OpenVPN Static key V1-----\n");
        auto bad_sk = tmp / "bad.key"; write_secret_file(bad_sk, "not-a-valid-static-key\n");
        relay::Server srv;
        auto ok_sk = srv.add_openvpn({.host = "vpn.test", .port = 1194, .server_name = "vpn.test", .ca_file = (tmp / "ca.crt").string(), .static_key_file = sk_file.string(), .tls_auth_mode = config::OpenVpnTlsAuthMode::tls_crypt});
        require(ok_sk.has_value(), ok_sk ? "" : "openvpn tls-crypt static-key-file accepted: " + ok_sk.error());
        auto rej = srv.add_openvpn({.host = "vpn.test", .port = 1194, .server_name = "vpn.test", .ca_file = (tmp / "ca.crt").string(), .static_key_file = bad_sk.string(), .tls_auth_mode = config::OpenVpnTlsAuthMode::tls_auth});
        require(!rej.has_value() && rej.error().contains("static-key-file"), "malformed openvpn static-key-file rejected");
        auto step1 = *openconnect::parse_config_auth_response("<config-auth><auth id=\"main\"/><opaque>tok-xyz</opaque></config-auth>");
        require(!step1.authenticated && step1.needs_auth_reply && step1.opaque == "tok-xyz", "oc 2-step opaque");
        auto http_req = openconnect::build_http_auth_request("gw.test", {.username = "u", .password = "p", .group = "g", .opaque = step1.opaque});
        require(http_req.contains("X-Aggregate-Auth: 1") && http_req.contains("<opaque>tok-xyz</opaque>"), "oc http auth req");
        require(openconnect::build_cstp_connect_headers("gw.test", "c1", 1360, "deadbeef").contains("X-DTLS-Master-Secret: deadbeef"), "oc cstp dtls secret");
        auto cstp_res = *openconnect::parse_cstp_connect_headers(
            "HTTP/1.1 200 OK\r\nx-cstp-address: 10.99.0.7\r\nx-cstp-address-ip6: fd00::7/64\r\nx-cstp-mtu: 1350\r\n"
            "x-cstp-dpd: 25\r\nx-cstp-keepalive: 15\r\nx-cstp-dns: 1.1.1.1\r\nx-dtls-session-id: abc\r\nx-dtls-port: 4443\r\n\r\n");
        require(cstp_res.ipv4_address == "10.99.0.7" && cstp_res.ipv6_address == "fd00::7" && cstp_res.mtu == 1350 &&
                cstp_res.dpd_s == 25 && cstp_res.keepalive_s == 15 && cstp_res.dtls_port == 4443 && cstp_res.dns_servers.size() == 1, "oc cstp parse");
        auto ca_p = (tmp / "ca.crt").string(), pw_p = (tmp / "pw").string(), ck_p = (tmp / "ck").string();
        auto kdl = std::format(
            "schema-version 1\nrole \"client\"\ncertificate {{ ca-file \"{0}\"; }}\n"
            "inbounds {{ socks5 \"in\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }}; }}\n"
            "outbounds {{ direct\n"
            "    openvpn \"ov-udp\" {{ server \"vpn.test:1194\"; transport \"udp\"; cipher \"aes-256-gcm\"; tls {{ server-name \"vpn.test\"; verify #true; }}; authentication username=\"a\" password-file=\"{1}\"; }}\n"
            "    openvpn \"ov-tcp\" {{ server \"vpn.test:443\"; transport \"tcp\"; tls {{ server-name \"vpn.test\"; }}; }}\n"
            "    openconnect \"oc-pw\" {{ server \"oc.test:443\"; tls {{ server-name \"oc.test\"; }}; authentication {{ username \"a\"; password-file \"{1}\"; group \"eng\"; }}; dpd 40; keepalive 15; }}\n"
            "    openconnect \"oc-ck\" {{ server \"oc.test:8443\"; tls {{ server-name \"oc.test\"; }}; authentication cookie-file=\"{2}\"; detour \"ov-tcp\"; }}\n"
            "    selector \"grp\" {{ members \"ov-udp\" \"ov-tcp\" \"oc-pw\" \"oc-ck\"; }}\n}}\nrouting {{ default \"grp\"; }}\n", ca_p, pw_p, ck_p);
        auto cfg = config::parse_kdl(kdl);
        require(cfg.has_value(), cfg ? "" : "vpn kdl parse: " + cfg.error());
        require(cfg->openvpn_outbounds.size() == 2 && cfg->openconnect_outbounds.size() == 2 &&
                cfg->openvpn_outbounds[0].config.ca_file == ca_p && cfg->openconnect_outbounds[1].config.detour == "ov-tcp", "vpn kdl counts + inherit");
        require(!config::parse_kdl(std::format("schema-version 1\nrole \"client\"\ninbounds {{ socks5 \"s\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }}; }}\noutbounds {{ direct; openvpn \"o\" {{ server \"vpn.test:1194\"; transport \"udp\"; tcp-nodelay #true; tls {{ server-name \"vpn.test\"; ca-file \"{0}\"; }}; }}; }}\nrouting {{ default \"o\"; }}\n", ca_p)).has_value(), "reject tcp option on ovpn udp");
        require(!config::parse_kdl(std::format("schema-version 1\nrole \"client\"\ninbounds {{ socks5 \"s\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }}; }}\noutbounds {{ direct; openconnect \"o\" {{ server \"oc.test:443\"; tls {{ server-name \"oc.test\"; ca-file \"{0}\"; verify #false; }}; authentication cookie-file=\"{1}\"; }}; }}\nrouting {{ default \"o\"; }}\n", ca_p, ck_p)).has_value(), "reject unverified oc tls");
    }

    auto make_ovpn_cfg(std::uint16_t port, config::OpenVpnTransport tr, fs::path const& ca, fs::path const& pw) -> config::OpenVpnOutbound {
        return {.transport = tr, .cipher = config::OpenVpnCipher::aes_256_gcm, .host = "127.0.0.1", .port = port,
                .server_name = "localhost", .ca_file = ca.string(), .username = "alice", .password_file = pw.string(),
                .mtu = 1400, .keepalive_s = 10, .connect_timeout_ms = 4000};
    }

    auto ovpn_server_session(std::function<capy::task<bool>(std::span<std::uint8_t const>)> send_wire,
                             std::function<capy::task<std::optional<std::vector<std::uint8_t>>>()> recv_wire,
                             tls::ServerCredential const& cred, std::atomic<bool>& stop_flag) -> capy::task<> {
        openvpn::ControlChannel ctrl(0x5566778899aabbccull, true);
        auto p0 = co_await recv_wire(); if (!p0) co_return;
        auto cp0 = openvpn::decode_control_packet(*p0); if (!cp0 || !ctrl.on_packet(*cp0, now_ms())) co_return;
        auto rs = openvpn::encode_control_packet(ctrl.make_server_reset(now_ms())); if (!rs || !co_await send_wire(*rs)) co_return;
        std::vector<std::uint8_t> tls_rx;
        auto send_ctrl = [&](std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            for (auto const& c : ctrl.enqueue_tls_bytes(bytes, now_ms())) {
                auto w = openvpn::encode_control_packet(c); if (!w || !co_await send_wire(*w)) co_return false;
            }
            co_return true;
        };
        auto recv_ctrl_once = [&]() -> capy::task<bool> {
            auto p = co_await recv_wire(); if (!p) co_return false;
            auto cp = openvpn::decode_control_packet(*p); if (!cp) co_return true;
            auto c = ctrl.on_packet(*cp, now_ms()); if (!c) co_return false;
            if (auto ack = ctrl.take_ack()) { auto aw = openvpn::encode_control_packet(*ack); if (!aw || !co_await send_wire(*aw)) co_return false; }
            tls_rx.insert(tls_rx.end(), c->begin(), c->end()); co_return true;
        };
        auto hs = tls::make_server_handshake(cred, now_ms(), now_ms() + 4000); if (!hs) co_return;
        while (!hs->complete() && !stop_flag) {
            if (!hs->tick(now_ms())) co_return;
            if (!hs->pending_output().empty()) {
                auto out = hs->pending_output(); if (!co_await send_ctrl(out) || !hs->written(out.size(), now_ms())) co_return;
                continue;
            }
            while (!tls_rx.empty() && hs->pending_output().empty() && !hs->complete()) {
                auto f = hs->feed(tls_rx, now_ms()); if (!f) co_return;
                if (f->consumed == 0) break;
                tls_rx.erase(tls_rx.begin(), tls_rx.begin() + static_cast<std::ptrdiff_t>(f->consumed));
            }
            if (!hs->complete() && hs->pending_output().empty() && !co_await recv_ctrl_once()) co_return;
        }
        if (!hs->complete()) co_return;
        auto recs = hs->take_application_records(); if (!recs) co_return;
        tls::ApplicationIo app(std::move(*recs));
        auto send_app = [&](std::span<std::uint8_t const> d) -> capy::task<bool> {
            if (!app.send(d)) co_return false;
            while (!app.pending_output().empty()) {
                auto out = app.pending_output(); if (!co_await send_ctrl(out) || !app.written(out.size())) co_return false;
            }
            co_return true;
        };
        auto recv_app = [&](std::vector<std::uint8_t>& plain) -> capy::task<bool> {
            while (plain.empty() && !stop_flag) {
                while (!tls_rx.empty()) {
                    auto f = app.feed(tls_rx); if (!f) co_return false;
                    tls_rx.erase(tls_rx.begin(), tls_rx.begin() + static_cast<std::ptrdiff_t>(f->consumed));
                    if (f->event && f->event->kind == tls::ApplicationEventKind::data)
                        plain.insert(plain.end(), f->event->data.begin(), f->event->data.end());
                    if (!f->consumed) break;
                }
                if (!plain.empty()) co_return true;
                if (!co_await recv_ctrl_once()) co_return false;
            }
            co_return !plain.empty();
        };
        std::vector<std::uint8_t> km_in; std::optional<openvpn::KeyMethod2Client> kmc;
        while (!kmc && !stop_flag) {
            if (km_in.size() >= 125) if (auto d = openvpn::decode_key_method2_client(km_in)) { kmc = std::move(*d); break; }
            if (!co_await recv_app(km_in)) co_return;
        }
        if (!kmc || kmc->username != "alice" || kmc->password != "s3cr3t") co_return;

        openvpn::KeyMethod2Server kms;
        if (!crypto::random_bytes(kms.random1) || !crypto::random_bytes(kms.random2)) co_return;
        kms.options = "V4,dev-type tun,cipher AES-256-GCM";
        auto send_frag = [&](std::span<std::uint8_t const> d, std::initializer_list<std::size_t> cuts) -> capy::task<bool> {
            std::size_t off = 0;
            for (auto end : cuts) {
                auto take = std::min(end, d.size());
                if (take > off && !co_await send_app(d.subspan(off, take - off))) co_return false;
                off = take;
                if (off < d.size()) (void)co_await io::delay(5ms);
            }
            co_return off >= d.size() || co_await send_app(d.subspan(off));
        };
        if (auto kms_w = openvpn::encode_key_method2_server(kms); !kms_w || !co_await send_frag(*kms_w, {20, 68})) co_return;

        auto km = openvpn::derive_key_method2_keys(kmc->pre_master, kmc->random1, kms.random1,
            kmc->random2, kms.random2, ctrl.remote_session_id(), ctrl.local_session_id(), true);
        std::vector<std::uint8_t> push_req;
        constexpr char kPushRep[] = "PUSH_REPLY,route 0.0.0.0 0.0.0.0,ifconfig 10.8.0.99 10.8.0.1,peer-id 7,cipher AES-256-GCM,tun-mtu 1400,ping 10,ping-restart 60";
        constexpr std::string_view kWantPushReq{"PUSH_REQUEST\0", 13};
        if (!km || !co_await recv_app(push_req) ||
            std::string_view(reinterpret_cast<char const*>(push_req.data()), push_req.size()) != kWantPushReq ||
            !co_await send_frag(std::span(reinterpret_cast<std::uint8_t const*>(kPushRep), sizeof(kPushRep)), {35})) co_return;

        openvpn::DataChannel dc;
        if (!dc.init(openvpn::Cipher::aes_256_gcm, *km, 7, 0)) co_return;
        MockL3Peer l3;
        std::vector<std::vector<std::uint8_t>> replies;
        while (!stop_flag) {
            auto p = co_await recv_wire();
            if (!p) break;
            if (((*p)[0] >> 3) == static_cast<std::uint8_t>(openvpn::Opcode::data_v2)) {
                auto plain = dc.open_data_v2(*p);
                if (!plain) continue;
                replies.clear();
                l3.on_ip(*plain, [&](std::span<std::uint8_t const> rp) {
                    if (auto sealed = dc.seal_data_v2(rp)) replies.push_back(std::move(*sealed));
                });
                for (auto const& r : replies) if (!co_await send_wire(r)) co_return;
            }
        }
    }

    template<class AddFn>
    auto run_vpn_relay_check(AddFn&& add_fn, std::string_view tag, bool expect_ok = true) -> void {
        relay::Server srv;
        auto out_idx = add_fn(srv);
        require(out_idx.has_value() && srv.set_indexed_routes({}, *out_idx).has_value(), std::string(tag) + " add/route");
        auto s5 = srv.start(0, relay::Inbound::socks5, 1);
        require(s5.has_value(), std::string(tag) + " start");
        std::atomic<bool> rstop{false};
        std::jthread relay_thr([&] { while (!rstop) srv.poll(10ms); srv.stop(); });
        require(socks5_echo_test(*s5, tag) == expect_ok, std::string(tag) + " live E2E");
        rstop = true; relay_thr.join();
    }

    auto test_live_openvpn_tcp(fs::path const& ca, fs::path const& pw, tls::ServerCredential const& cred) -> void {
        io::io_context mock_ctx; io::tcp_acceptor acc{mock_ctx};
        require(!acc.open() && !acc.bind(io::endpoint(io::ipv4_address::loopback(), 0)) && !acc.listen(), "ovpn tcp listen");
        auto vpn_port = acc.local_endpoint().port();
        std::atomic<bool> stop{false};
        capy::run_async(mock_ctx.get_executor())([&]() -> capy::task<> {
            auto [ec, sock] = co_await acc.accept();
            if (ec) co_return;
            std::vector<std::uint8_t> rx;
            auto send_fn = [&](std::span<std::uint8_t const> pkt) -> capy::task<bool> {
                auto f = openvpn::encode_tcp_frame(pkt); if (!f) co_return false;
                for (std::span<std::uint8_t const> s = *f; !s.empty(); ) {
                    auto [we, n] = co_await sock.write_some(capy::const_buffer(s.data(), s.size()));
                    if (we || !n) co_return false;
                    s = s.subspan(n);
                }
                co_return true;
            };
            auto recv_fn = [&]() -> capy::task<std::optional<std::vector<std::uint8_t>>> {
                std::array<std::uint8_t, 4096> b{};
                while (!stop) {
                    auto d = openvpn::decode_tcp_frame(rx); if (!d) co_return std::nullopt;
                    if (*d) { auto out = std::move((*d)->first); rx.erase(rx.begin(), rx.begin() + static_cast<std::ptrdiff_t>((*d)->second)); co_return out; }
                    auto [re, n] = co_await sock.read_some(capy::mutable_buffer(b.data(), b.size()));
                    if (re || !n) co_return std::nullopt;
                    rx.insert(rx.end(), b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n));
                }
                co_return std::nullopt;
            };
            co_await ovpn_server_session(send_fn, recv_fn, cred, stop);
        }());
        std::jthread mock_thr([&] { mock_ctx.run_for(5s); });
        run_vpn_relay_check([&](relay::Server& s) { return s.add_openvpn(make_ovpn_cfg(vpn_port, config::OpenVpnTransport::tcp, ca, pw)); }, "ovpn-tcp");
        stop = true; mock_ctx.stop(); mock_thr.join(); acc.close();
    }

    auto test_live_openvpn_udp(fs::path const& ca, fs::path const& pw, tls::ServerCredential const& cred) -> void {
        Fd udp_fd(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
        sockaddr_in addr{.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}}; socklen_t alen = sizeof(addr);
        require(udp_fd.fd >= 0 && ::bind(udp_fd.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
                ::getsockname(udp_fd.fd, reinterpret_cast<sockaddr*>(&addr), &alen) == 0, "ovpn udp bind");
        auto vpn_port = ntohs(addr.sin_port);
        io::io_context mock_ctx; std::atomic<bool> stop{false};
        capy::run_async(mock_ctx.get_executor())([&]() -> capy::task<> {
            sockaddr_in cli{}; bool has_cli = false;
            auto send_fn = [&](std::span<std::uint8_t const> pkt) -> capy::task<bool> {
                co_return has_cli && ::sendto(udp_fd.fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&cli), sizeof(cli)) == static_cast<ssize_t>(pkt.size());
            };
            auto recv_fn = [&]() -> capy::task<std::optional<std::vector<std::uint8_t>>> {
                std::array<std::uint8_t, 4096> b{};
                while (!stop) {
                    sockaddr_in src{}; socklen_t sl = sizeof(src);
                    if (auto n = ::recvfrom(udp_fd.fd, b.data(), b.size(), 0, reinterpret_cast<sockaddr*>(&src), &sl); n > 0) {
                        cli = src; has_cli = true; co_return std::vector<std::uint8_t>(b.begin(), b.begin() + n);
                    }
                    if (auto [ec] = co_await io::delay(1ms); ec) co_return std::nullopt;
                }
                co_return std::nullopt;
            };
            co_await ovpn_server_session(send_fn, recv_fn, cred, stop);
        }());
        std::jthread mock_thr([&] { mock_ctx.run_for(5s); });
        run_vpn_relay_check([&](relay::Server& s) { return s.add_openvpn(make_ovpn_cfg(vpn_port, config::OpenVpnTransport::udp, ca, pw)); }, "ovpn-udp");
        stop = true; mock_ctx.stop(); mock_thr.join();
    }

    enum class OcMode { cstp, strict_dtls, strict_dtls_timeout };

    auto parse_dtls_secret_hdr(std::string_view req) -> std::optional<std::array<std::uint8_t, 48>> {
        auto p = req.find("X-DTLS-Master-Secret:"); if (p == req.npos) return std::nullopt;
        auto v = req.substr(p + 21);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
        if (auto e = v.find_first_of("\r\n"); e != v.npos) v = v.substr(0, e);
        if (v.size() != 96) return std::nullopt;
        std::array<std::uint8_t, 48> out{};
        for (std::size_t i = 0; i < 48; ++i) {
            unsigned b = 0; auto [end, ec] = std::from_chars(v.data() + i * 2, v.data() + i * 2 + 2, b, 16);
            if (ec != std::errc{} || end != v.data() + i * 2 + 2) return std::nullopt;
            out[i] = static_cast<std::uint8_t>(b);
        }
        return out;
    }

    auto test_live_openconnect(fs::path const& ca, fs::path const& pw, tls::ServerCredential const& cred, OcMode mode) -> void {
        io::io_context mock_ctx; io::tcp_acceptor acc{mock_ctx};
        require(!acc.open() && !acc.bind(io::endpoint(io::ipv4_address::loopback(), 0)) && !acc.listen(), "oc listen");
        auto oc_port = acc.local_endpoint().port();
        Fd udp_fd; std::uint16_t dtls_port = 0;
        if (mode != OcMode::cstp) {
            udp_fd.fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            sockaddr_in ua{.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}}; socklen_t ul = sizeof(ua);
            require(udp_fd.fd >= 0 && ::bind(udp_fd.fd, reinterpret_cast<sockaddr*>(&ua), sizeof(ua)) == 0 &&
                    ::getsockname(udp_fd.fd, reinterpret_cast<sockaddr*>(&ua), &ul) == 0, "oc dtls udp bind");
            dtls_port = ntohs(ua.sin_port);
        }
        std::atomic<bool> stop{false}; std::atomic<int> cstp_data_rx{0}, dtls_data_rx{0};
        capy::run_async(mock_ctx.get_executor())([&]() -> capy::task<> {
            for (int step = 0; step < 3 && !stop; ++step) {
                auto [ec, sock] = co_await acc.accept(); if (ec) co_return;
                auto hs = tls::make_server_handshake(cred, now_ms(), now_ms() + 4000); if (!hs) co_return;
                auto res = co_await tls::detail::server_handshake(sock, *hs); if (!res) co_return;
                tls::detail::ApplicationConnection<io::tcp_socket> app(sock, std::move(res->records), std::move(res->unread));
                tls::detail::ByteStream<io::tcp_socket> tls_stream(app);
                std::string req; std::array<std::uint8_t, 4096> b{};
                while (req.find("\r\n\r\n") == req.npos) {
                    auto r = co_await tls_stream.read(b); if (!r || *r == 0) co_return;
                    req.append(reinterpret_cast<char const*>(b.data()), *r);
                }
                if (step < 2) {
                    while (!req.contains("</config-auth>")) { auto r = co_await tls_stream.read(b); if (!r || *r == 0) break; req.append(reinterpret_cast<char const*>(b.data()), *r); }
                    std::string xml = step == 0 ? "<config-auth><auth id=\"main\"/><opaque>oc-op-99</opaque></config-auth>"
                        : (req.contains("<opaque>oc-op-99</opaque>") && req.contains("<password>s3cr3t</password>")
                            ? "<config-auth><auth id=\"success\"/><session-token>oc-tok-1</session-token></config-auth>" : "");
                    if (xml.empty()) co_return;
                    auto h = std::format("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", xml.size(), xml);
                    (void)co_await tls_stream.send(std::span(reinterpret_cast<std::uint8_t const*>(h.data()), h.size()));
                    (void)co_await tls_stream.close_output();
                } else {
                    if (!req.contains("CONNECT /CSCOSSLC/tunnel") || !req.contains("Cookie: webvpn=oc-tok-1")) co_return;
                    std::string ok_h = "HTTP/1.1 200 OK\r\nX-CSTP-Version: 1\r\nX-CSTP-Address: 10.99.0.55\r\nX-CSTP-MTU: 1380\r\nX-CSTP-DPD: 30\r\nX-CSTP-Keepalive: 20\r\n";
                    if (mode != OcMode::cstp) {
                        auto sec = parse_dtls_secret_hdr(req); if (!sec) co_return;
                        ok_h += std::format("X-DTLS-Session-ID: deadbeef01020304\r\nX-DTLS12-CipherSuite: TLS_AES_256_GCM_SHA384\r\nX-DTLS-Port: {}\r\nX-DTLS-MTU: 1380\r\n", dtls_port);
                        if (mode == OcMode::strict_dtls) {
                            capy::run_async(mock_ctx.get_executor())([fd = udp_fd.fd, sec = *sec, &stop, &dtls_data_rx]() -> capy::task<> {
                                openconnect::DtlsTransport dsrv;
                                if (!dsrv.init({openconnect::DtlsVersion::dtls1_3, openconnect::DtlsCipher::aes_256_gcm, true, {0xde,0xad,0xbe,0xef,1,2,3,4}, sec, 1380})) co_return;
                                std::array<std::uint8_t, 4096> ub{}; sockaddr_in cli{}; socklen_t cl = sizeof(cli); MockL3Peer l3;
                                bool delayed = false;
                                while (!stop) {
                                    cl = sizeof(cli);
                                    if (auto n = ::recvfrom(fd, ub.data(), ub.size(), 0, reinterpret_cast<sockaddr*>(&cli), &cl); n > 0) {
                                        auto dg = std::span(ub).first(static_cast<std::size_t>(n));
                                        if (!dsrv.established()) {
                                            if (!delayed) { delayed = true; (void)co_await io::delay(40ms); }
                                            if (auto outs = dsrv.on_handshake_datagram(dg))
                                                for (auto const& o : *outs) (void)::sendto(fd, o.data(), o.size(), 0, reinterpret_cast<sockaddr*>(&cli), cl);
                                        } else if (auto fr = dsrv.open_tunnel_frame(dg); fr && fr->type == openconnect::CstpType::data) {
                                            ++dtls_data_rx;
                                            l3.on_ip(fr->payload, [&](std::span<std::uint8_t const> rp) {
                                                if (auto s = dsrv.seal_tunnel_frame(openconnect::CstpType::data, rp))
                                                    (void)::sendto(fd, s->data(), s->size(), 0, reinterpret_cast<sockaddr*>(&cli), cl);
                                            });
                                        }
                                    } else { (void)co_await io::delay(1ms); }
                                }
                            }());
                        }
                    }
                    ok_h += "\r\n";
                    if (!co_await tls_stream.send(std::span(reinterpret_cast<std::uint8_t const*>(ok_h.data()), ok_h.size()))) co_return;
                    auto hdr_end = req.find("\r\n\r\n") + 4;
                    std::vector<std::uint8_t> rx(req.begin() + static_cast<std::ptrdiff_t>(hdr_end), req.end());
                    MockL3Peer l3; std::vector<std::vector<std::uint8_t>> replies;
                    while (!stop) {
                        for (;;) {
                            auto d = openconnect::decode_cstp_frame(rx); if (!d) { if (d.error() == "incomplete") break; co_return; }
                            auto [fr, used] = std::move(*d); rx.erase(rx.begin(), rx.begin() + static_cast<std::ptrdiff_t>(used));
                            if (fr.type == openconnect::CstpType::dpd_req) {
                                if (auto r = openconnect::encode_cstp_frame(openconnect::CstpType::dpd_resp, fr.payload))
                                    if (!co_await tls_stream.send(*r)) co_return;
                            } else if (fr.type == openconnect::CstpType::data) {
                                ++cstp_data_rx; replies.clear();
                                l3.on_ip(fr.payload, [&](std::span<std::uint8_t const> rp) {
                                    if (auto r = openconnect::encode_cstp_frame(openconnect::CstpType::data, rp)) replies.push_back(std::move(*r));
                                });
                                for (auto const& r : replies) if (!co_await tls_stream.send(r)) co_return;
                            }
                        }
                        auto r = co_await tls_stream.read(b); if (!r || *r == 0) break;
                        rx.insert(rx.end(), b.begin(), b.begin() + static_cast<std::ptrdiff_t>(*r));
                    }
                }
            }
        }());
        std::jthread mock_thr([&] { mock_ctx.run_for(5s); });
        run_vpn_relay_check([&](relay::Server& s) {
            return s.add_openconnect({.host = "127.0.0.1", .port = oc_port, .server_name = "localhost",
                .ca_file = ca.string(), .username = "alice", .group = "eng", .password_file = pw.string(),
                .dtls = (mode != OcMode::cstp), .dtls_fallback = false,
                .connect_timeout_ms = (mode == OcMode::strict_dtls_timeout ? 350u : 4000u)});
        }, mode == OcMode::cstp ? "openconnect-cstp" : mode == OcMode::strict_dtls ? "openconnect-strict-dtls" : "openconnect-strict-dtls-timeout",
        mode != OcMode::strict_dtls_timeout);
        stop = true; mock_ctx.stop(); mock_thr.join(); acc.close();
        if (mode == OcMode::cstp) require(cstp_data_rx > 0, "openconnect CSTP data frames received");
        else if (mode == OcMode::strict_dtls) require(cstp_data_rx == 0 && dtls_data_rx > 0, "P1-5 strict DTLS: zero CSTP data leak & DTLS active");
        else require(cstp_data_rx == 0, "P1-5 strict DTLS timeout: fail closed with zero CSTP data leak");
    }
}

int main(int argc, char** argv) {
    fs::path tmp = fs::canonical(fs::temp_directory_path()) / ("nexus-vpn-unit-" + std::to_string(::getpid()));
    fs::create_directories(tmp);
    struct Clean { fs::path p; ~Clean() { std::error_code ec; fs::remove_all(p, ec); } } clean{tmp};
    fs::path ca = tmp / "ca.crt", key = tmp / "srv.key", pw = tmp / "pw", ck = tmp / "ck";
    write_secret_file(pw, "s3cr3t\n"); write_secret_file(ck, "cookie-val\n");
    if (argc >= 3) { ca = argv[1]; key = argv[2]; }
    else {
        require(std::system(std::format("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout '{}' -out '{}' "
            "-days 2 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 >/dev/null 2>&1", key.string(), ca.string()).c_str()) == 0, "openssl cert");
        fs::permissions(key, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    }
    test_protocol_units(tmp);
    auto cred = tls::load_server_credential(ca.string(), key.string());
    require(cred.has_value(), cred ? "" : "load server cred: " + cred.error());
    test_live_openvpn_tcp(ca, pw, *cred); test_live_openvpn_udp(ca, pw, *cred);
    test_live_openconnect(ca, pw, *cred, OcMode::cstp);
    test_live_openconnect(ca, pw, *cred, OcMode::strict_dtls);
    test_live_openconnect(ca, pw, *cred, OcMode::strict_dtls_timeout);
    std::cout << "VPN RUNTIME UNIT AND LIVE E2E TESTS PASSED\n"; return 0; }
