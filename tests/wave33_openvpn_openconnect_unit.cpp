import std;
import config;
import crypto;
import openvpn.types;
import openvpn.wire;
import openvpn.control;
import openvpn.session;
import openvpn.tls_crypt;
import openvpn.server;
import openconnect.types;
import openconnect.auth;
import openconnect.cstp;
import openconnect.dtls;

namespace {
    auto require(bool cond, char const* msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto make_static_key_pem() -> std::string {
        std::string pem = "-----BEGIN OpenVPN Static key V1-----\n";
        for (int line = 0; line < 16; ++line) {
            for (int b = 0; b < 16; ++b) {
                auto v = static_cast<unsigned>((line * 17 + b * 13 + 7) & 0xff);
                pem += std::format("{:02x}", v);
            }
            pem += '\n';
        }
        pem += "-----END OpenVPN Static key V1-----\n";
        return pem;
    }

    auto test_openvpn_tls_auth_and_tls_crypt() -> void {
        using namespace openvpn;
        auto pem = make_static_key_pem();
        auto key = parse_static_key_v1(pem);
        require(key.has_value(), "parse_static_key_v1");

        ControlPacket orig{
            .opcode = Opcode::control_hard_reset_client_v2,
            .key_id = 0,
            .session_id = 0x1122334455667788ull,
            .packet_id = 0,
        };
        auto plain = encode_control_packet(orig);
        require(plain.has_value(), "encode_control_packet");

        // 1. tls-auth (HMAC-SHA256, key-direction 1 on client / 0 on server).
        TlsAuthCodec cli_ta, srv_ta;
        require(cli_ta.init(*key, KeyDirection::client_1, false, false), "cli tls-auth init");
        require(srv_ta.init(*key, KeyDirection::client_1, true, false), "srv tls-auth init");
        auto ta_wire = cli_ta.wrap(*plain, 1700000001u);
        require(ta_wire.has_value(), "tls-auth wrap");
        auto ta_unwrapped = srv_ta.unwrap(*ta_wire);
        require(ta_unwrapped && *ta_unwrapped == *plain, "tls-auth unwrap matches plain");
        // Replay rejected.
        require(!srv_ta.unwrap(*ta_wire).has_value(), "tls-auth replay rejected");
        // P2-3: Advancing timestamp with higher packet_id preserves replay window bitmap!
        {
            ControlReplayWindow rw;
            require(rw.check_and_record(1, 100) && rw.check_and_record(2, 100), "seed replay window");
            require(rw.check_and_record(3, 101), "timestamp bump with higher pid accepted");
            require(!rw.check_and_record(2, 101), "P2-3 duplicate pid after timestamp bump still rejected");
            require(rw.check_and_record(1, 200), "new key epoch with higher timestamp & reset pid accepted");
        }
        // Tampered packet rejected.
        auto tampered = *ta_wire;
        tampered.back() ^= 0x01;
        require(!srv_ta.unwrap(tampered).has_value(), "tls-auth tamper rejected");

        // 2. tls-auth (HMAC-SHA1, bidirectional).
        TlsAuthCodec sha1_a, sha1_b;
        require(sha1_a.init(*key, KeyDirection::bidirectional, false, true), "sha1 tls-auth init a");
        require(sha1_b.init(*key, KeyDirection::bidirectional, true, true), "sha1 tls-auth init b");
        auto sha1_wire = sha1_a.wrap(*plain, 1700000002u);
        require(sha1_wire && sha1_wire->size() == plain->size() + 20 + 8, "sha1 tag length 20");
        auto sha1_plain = sha1_b.unwrap(*sha1_wire);
        require(sha1_plain && *sha1_plain == *plain, "sha1 tls-auth unwrap");

        // 3. tls-crypt (AES-256-CTR + HMAC-SHA256) bidirectional client <-> server.
        ControlPacket ctrl_msg{
            .opcode = Opcode::control_v1,
            .key_id = 0,
            .session_id = 0xaabbccddeeff0011ull,
            .acks = {0},
            .remote_session_id = 0x1122334455667788ull,
            .packet_id = 1,
            .payload = {'S', 'E', 'C', 'R', 'E', 'T', '_', 'T', 'L', 'S', '_', 'B', 'Y', 'T', 'E', 'S'},
        };
        auto ctrl_plain = encode_control_packet(ctrl_msg);
        require(ctrl_plain.has_value(), "encode control_v1");

        TlsCryptCodec cli_tc, srv_tc;
        require(cli_tc.init(*key, false), "cli tls-crypt init");
        require(srv_tc.init(*key, true), "srv tls-crypt init");
        auto tc_wire = cli_tc.wrap(*ctrl_plain, 1700000010u);
        require(tc_wire.has_value(), "tls-crypt wrap");
        // Plaintext payload must not appear in cleartext inside wire bytes!
        std::string_view wire_sv(reinterpret_cast<char const*>(tc_wire->data()), tc_wire->size());
        require(!wire_sv.contains("SECRET_TLS_BYTES"), "tls-crypt encrypts control body");
        auto tc_plain = srv_tc.unwrap(*tc_wire);
        require(tc_plain && *tc_plain == *ctrl_plain, "tls-crypt unwrap exact match");
        require(!srv_tc.unwrap(*tc_wire).has_value(), "tls-crypt replay rejected");

        // Server -> Client direction.
        auto s2c_wire = srv_tc.wrap(*ctrl_plain, 1700000011u);
        require(s2c_wire.has_value(), "tls-crypt s2c wrap");
        auto s2c_plain = cli_tc.unwrap(*s2c_wire);
        require(s2c_plain && *s2c_plain == *ctrl_plain, "tls-crypt s2c unwrap");
        auto tc_bad = *s2c_wire;
        tc_bad[20] ^= 0x80;
        require(!cli_tc.unwrap(tc_bad).has_value(), "tls-crypt tampered tag rejected");
    }

    auto test_openvpn_push_mtls_and_server() -> void {
        using namespace openvpn;
        // 1. Extended PUSH_REPLY encode/parse round-trip.
        PushConfig push{};
        push.topology_subnet = true;
        push.local_v4 = std::array<std::uint8_t, 4>{10, 8, 0, 2};
        push.netmask_v4 = std::array<std::uint8_t, 4>{255, 255, 255, 0};
        push.gateway_v4 = std::array<std::uint8_t, 4>{10, 8, 0, 1};
        push.local_v6 = std::array<std::uint8_t, 16>{0xfd, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
        push.prefix_v6 = 64;
        push.gateway_v6 = std::array<std::uint8_t, 16>{0xfd, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        push.redirect_gateway = true;
        push.redirect_gateway_v6 = true;
        push.routes_v4.push_back({{192, 168, 10, 0}, {255, 255, 255, 0}, std::array<std::uint8_t, 4>{10, 8, 0, 1}});
        push.routes_v6.push_back({{0xfd, 0x20}, 48, std::nullopt});
        push.dns_servers = {"1.1.1.1", "8.8.8.8"};
        push.search_domains = {"corp.example"};
        push.mtu = 1420;
        push.peer_id = 42;
        push.cipher = Cipher::aes_256_gcm;
        push.ping_s = 15;
        push.ping_restart_s = 90;

        auto encoded_push = encode_push_reply(push);
        auto parsed_push = parse_push_reply(encoded_push);
        require(parsed_push.has_value(), "parse_push_reply round-trip");
        require(parsed_push->local_v4 == push.local_v4 && parsed_push->netmask_v4 == push.netmask_v4, "push IPv4");
        require(parsed_push->local_v6 == push.local_v6 && parsed_push->prefix_v6 == 64 && parsed_push->gateway_v6 == push.gateway_v6, "push IPv6");
        require(parsed_push->routes_v4.size() == 1 && parsed_push->routes_v4[0] == push.routes_v4[0], "push routes_v4");
        require(parsed_push->routes_v6.size() == 1 && parsed_push->routes_v6[0] == push.routes_v6[0], "push routes_v6");
        require(parsed_push->dns_servers == push.dns_servers && parsed_push->search_domains == push.search_domains, "push DNS/domain");
        require(parsed_push->redirect_gateway && parsed_push->redirect_gateway_v6 && parsed_push->topology_subnet, "push flags");
        require(parsed_push->mtu == 1420 && parsed_push->peer_id == 42 && parsed_push->ping_s == 15 && parsed_push->ping_restart_s == 90, "push scalars");
        require(!parse_push_reply("PUSH_REPLYbogus").has_value(), "P2-7 PUSH_REPLY delimiter");
        {
            PushConfig dirty; dirty.dns_servers = {"1.1.1.1", "8.8.8.8,redirect-gateway"}; dirty.search_domains = {"ok.local", "bad\nline"};
            auto enc_dirty = encode_push_reply(dirty);
            require(enc_dirty.contains("1.1.1.1") && !enc_dirty.contains("redirect-gateway") && !enc_dirty.contains("bad\nline"), "P2-7 strip injected push tokens");
        }

        // 2. Pure BoringSSL-libcrypto mTLS credential & signing.
        auto mtls = MtlsCredentials::generate_ephemeral_ed25519();
        require(mtls && !mtls->certificate_der().empty() && !mtls->signature_schemes().empty(), "mTLS Ed25519 credential");
        std::array<std::uint8_t, 32> th{};
        th.fill(0x5a);
        auto sig = mtls->sign_certificate_verify(mtls->signature_schemes()[0], crypto::Hash::sha256, th);
        require(sig && !sig->empty(), "mTLS CertificateVerify sign");
        auto now_s = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        require(verify_mtls_peer_chain(mtls->certificate_der(), {}, mtls->certificate_der(), now_s).has_value(),
                "mTLS self-anchor verify succeeds");
        auto other_ca = MtlsCredentials::generate_ephemeral_ed25519();
        require(!verify_mtls_peer_chain(mtls->certificate_der(), {}, other_ca->certificate_der(), now_s).has_value(),
                "mTLS wrong CA fails closed");
        {
            std::vector<std::uint8_t> trailed(mtls->certificate_der().begin(), mtls->certificate_der().end());
            trailed.push_back(0x00);
            require(!verify_mtls_peer_chain(trailed, {}, mtls->certificate_der(), now_s).has_value(), "P2-4 reject trailing DER bytes");
        }

        // 3. Full OpenVPN ServerSession <-> client handshake with tls-crypt + mTLS + P_DATA_V2!
        auto pem = make_static_key_pem();
        auto static_key = parse_static_key_v1(pem);
        {
            ServerOptions bad_mtls{}; bad_mtls.require_client_cert = true; ServerSession bad_srv;
            require(!bad_srv.init(std::move(bad_mtls), 1).has_value(), "P1-1 reject require_client_cert without CA");
        }
        ServerOptions sopts{};
        sopts.cipher = Cipher::aes_256_gcm;
        sopts.peer_id = 42;
        sopts.tls_auth_mode = TlsAuthMode::tls_crypt;
        sopts.static_key_pem = pem;
        sopts.require_client_cert = true;
        sopts.client_ca_pem.assign(reinterpret_cast<char const*>(mtls->certificate_der().data()), mtls->certificate_der().size());
        sopts.push_config = push;
        sopts.auth_callback = [&](std::string_view u, std::string_view p, std::span<std::uint8_t const> cert) {
            return u == "alice" && p == "s3cr3t" && !cert.empty();
        };

        ServerSession server;
        require(server.init(std::move(sopts), 0xfeedfacecafebeefull).has_value(), "ServerSession init");
        require(!server.verify_client_certificate({}, {}, now_s).has_value(), "P1-1 reject empty leaf cert");
        ControlChannel cli_ctrl(0x1020304050607080ull, false);
        TlsCryptCodec cli_tc;
        require(cli_tc.init(*static_key, false), "client tls-crypt init");

        // Step A: Client Hard Reset -> Server Hard Reset.
        auto reset_plain = encode_control_packet(cli_ctrl.begin_client_reset(1000));
        auto reset_wire = cli_tc.wrap(*reset_plain, 1700000100u);
        auto srv_step1 = server.on_wire_packet(*reset_wire, 1000, 1700000100u);
        require(srv_step1 && srv_step1->wire_packets.size() == 1 && server.state() == ServerState::tls_handshake,
                "server handled client hard reset");
        auto srv_reset_plain = cli_tc.unwrap(srv_step1->wire_packets[0]);
        require(srv_reset_plain.has_value(), "client unwrapped server reset");
        auto srv_reset_pkt = decode_control_packet(*srv_reset_plain);
        require(srv_reset_pkt && cli_ctrl.on_packet(*srv_reset_pkt, 1010).has_value() && cli_ctrl.handshake_started(),
                "client accepted server hard reset");

        // Step B: Verify mTLS client cert requirement & TLS establishment.
        require(!server.on_tls_established().has_value(), "server rejects TLS ready before mTLS cert verified");
        require(!server.verify_client_certificate(other_ca->certificate_der(), {}, now_s).has_value(), "P1-1 reject untrusted leaf");
        require(server.verify_client_certificate(mtls->certificate_der(), {}, now_s).has_value(), "server bind client cert");
        require(server.on_tls_established().has_value() && server.state() == ServerState::awaiting_key_method2,
                "server ready for KeyMethod2");
        {
            std::vector<std::uint8_t> huge(17000, 0x41);
            require(!server.on_tls_plaintext(huge).has_value(), "P1-2 reject >16 KiB KeyMethod2 buffer");
        }

        // Step C: KeyMethod2 exchange + PUSH_REQUEST / PUSH_REPLY.
        KeyMethod2Client km_cli{};
        require(crypto::random_bytes(km_cli.pre_master).has_value(), "rng pm");
        require(crypto::random_bytes(km_cli.random1).has_value(), "rng r1");
        require(crypto::random_bytes(km_cli.random2).has_value(), "rng r2");
        km_cli.options = "V4,dev-type tun,cipher AES-256-GCM";
        km_cli.username = "alice";
        km_cli.password = "s3cr3t";
        auto km_cli_wire = encode_key_method2_client(km_cli);
        require(km_cli_wire.has_value(), "encode km2 client");

        auto srv_km = server.on_tls_plaintext(*km_cli_wire);
        require(srv_km && !srv_km->tls_tx_plaintext.empty() && server.state() == ServerState::awaiting_push_request,
                "server processed KeyMethod2");
        auto km_srv = decode_key_method2_server(srv_km->tls_tx_plaintext);
        require(km_srv.has_value(), "client decoded KeyMethod2Server");
        auto cli_km = derive_key_method2_keys(km_cli.pre_master, km_cli.random1, km_srv->random1,
                                              km_cli.random2, km_srv->random2,
                                              cli_ctrl.local_session_id(), cli_ctrl.remote_session_id(), false);
        require(cli_km.has_value(), "client derived data keys");

        constexpr std::string_view kPushReq = "PUSH_REQUEST\0";
        auto srv_push = server.on_tls_plaintext(
            std::span(reinterpret_cast<std::uint8_t const*>(kPushReq.data()), kPushReq.size()));
        require(srv_push && server.established(), "server answered PUSH_REQUEST & established");
        std::string_view push_sv(reinterpret_cast<char const*>(srv_push->tls_tx_plaintext.data()),
                                 srv_push->tls_tx_plaintext.size());
        auto recv_push = parse_push_reply(push_sv);
        require(recv_push && recv_push->peer_id == 42 && recv_push->redirect_gateway, "client parsed server PUSH_REPLY");

        // Step D: Bidirectional P_DATA_V2 + keepalive ping round-trip!
        DataChannel cli_data;
        require(cli_data.init(Cipher::aes_256_gcm, *cli_km, 42, 0).has_value(), "client DataChannel init");
        std::vector<std::uint8_t> ip_c2s{0x45, 0x00, 0x00, 0x1c, 1, 2, 3, 4, 64, 17, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1, 0, 1, 0, 2, 0, 8, 0, 0};
        auto c2s_wire = cli_data.seal_data_v2(ip_c2s);
        require(c2s_wire.has_value(), "client seal P_DATA_V2");
        auto srv_data = server.on_wire_packet(*c2s_wire, 1100, 1700000101u);
        require(srv_data && srv_data->ip_packets.size() == 1 && srv_data->ip_packets[0] == ip_c2s, "server decrypted C2S IP packet");

        auto ping_wire = cli_data.seal_data_v2(ping_magic);
        auto srv_ping = server.on_wire_packet(*ping_wire, 1110, 1700000102u);
        require(srv_ping && srv_ping->keepalive_received && srv_ping->ip_packets.empty(), "server detected OpenVPN ping_magic");

        auto s2c_wire = server.seal_ip_packet(ip_c2s);
        require(s2c_wire.has_value(), "server seal P_DATA_V2");
        auto cli_opened = cli_data.open_data_v2(*s2c_wire);
        require(cli_opened && *cli_opened == ip_c2s, "client decrypted S2C IP packet");
    }

    auto test_openconnect_mtls_dtls_and_fallback() -> void {
        using namespace openconnect;
        // 1. mTLS XML/HTTP auth phase & DTLS header negotiation.
        auto mtls = ClientMtlsAuth::generate_ephemeral_ed25519();
        require(mtls && mtls->fingerprint_hex().size() == 64, "OpenConnect ClientMtlsAuth");
        AuthRequest req{};
        req.group = "corp-mtls";
        req.client_cert_auth = true;
        req.client_cert_fingerprint_hex = std::string(mtls->fingerprint_hex());
        auto http_req = build_http_auth_request("vpn.example.com", req, false);
        require(http_req.contains("X-Client-Cert-SHA256: ") && http_req.contains("<auth/>") && !http_req.contains("<password>"),
                "mTLS cert-only XML auth request");
        auto auth_ok = parse_config_auth_response(
            R"(<?xml version="1.0"?><config-auth client="vpn" type="complete"><session-token>tok-mtls-123</session-token></config-auth>)");
        require(auth_ok && auth_ok->authenticated && auth_ok->cert_auth_accepted && auth_ok->cookie == "tok-mtls-123",
                "mTLS auth response parsed");

        auto cstp_req = build_cstp_connect_headers("vpn.example.com", auth_ok->cookie, 1400, "00112233", "AnyConnect 5.0", true);
        require(cstp_req.contains("X-DTLS12-CipherSuite:") && cstp_req.contains("TLS_AES_256_GCM_SHA384"),
                "CSTP CONNECT advertises DTLS 1.2/1.3 ciphers");
        auto parsed_hdr = parse_cstp_connect_headers(
            "HTTP/1.1 200 OK\r\n"
            "X-CSTP-Address: 10.77.0.5\r\n"
            "X-DTLS-Session-ID: aabbccdd\r\n"
            "X-DTLS12-CipherSuite: TLS_AES_256_GCM_SHA384\r\n"
            "X-DTLS-Port: 443\r\n"
            "X-DTLS-MTU: 1380\r\n"
            "X-DTLS-DPD: 25\r\n\r\n");
        require(parsed_hdr && parsed_hdr->dtls_version == DtlsVersion::dtls1_3 && parsed_hdr->dtls_mtu == 1380 && parsed_hdr->dtls_dpd_s == 25,
                "parsed DTLS 1.3 negotiation headers");

        // 2. Full DTLS 1.2 (AES-256-GCM + ChaCha20-Poly1305) & DTLS 1.3 (RFC 9147 short header) tunnel round-trips!
        auto run_dtls_suite = [](DtlsVersion ver, DtlsCipher cipher) {
            std::array<std::uint8_t, 48> master{};
            require(crypto::random_bytes(master).has_value(), "dtls master secret rng");
            std::vector<std::uint8_t> sid{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};

            DtlsConfig c_cfg{ver, cipher, false, sid, master, 1400};
            DtlsConfig s_cfg{ver, cipher, true, sid, master, 1400};
            DtlsTransport client, server;
            require(client.init(c_cfg).has_value() && server.init(s_cfg).has_value(), "DTLS init");

            auto ch = client.build_client_hello();
            require(ch.has_value(), "DTLS ClientHello");
            auto s_flight = server.on_handshake_datagram(*ch);
            require(s_flight && !s_flight->empty(), "DTLS ServerHello flight");

            std::vector<std::vector<std::uint8_t>> c_flight;
            for (auto const& dgram : *s_flight) {
                auto r = client.on_handshake_datagram(dgram);
                require(r.has_value(), "client process server flight");
                for (auto& out : *r) c_flight.push_back(std::move(out));
            }
            require(client.established() && !c_flight.empty(), "DTLS client established");

            for (auto const& dgram : c_flight) {
                auto r = server.on_handshake_datagram(dgram);
                require(r.has_value(), "server process client flight");
            }
            require(server.established(), "DTLS server established");

            // Bidirectional AnyConnect DATA + DPD + replay rejection + tamper rejection.
            std::vector<std::uint8_t> payload{0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8};
            auto dg1 = client.seal_tunnel_frame(CstpType::data, payload);
            require(dg1.has_value(), "DTLS seal DATA");
            auto dec1 = server.open_tunnel_frame(*dg1);
            require(dec1 && dec1->type == CstpType::data && dec1->payload == payload, "DTLS open DATA");
            // Replay rejected!
            require(!server.open_tunnel_frame(*dg1).has_value(), "DTLS replay rejected");
            // Tamper rejected!
            auto bad = *dg1;
            bad.back() ^= 0xff;
            require(!server.open_tunnel_frame(bad).has_value(), "DTLS tamper rejected");

            auto dpd = server.seal_tunnel_frame(CstpType::dpd_req, {});
            require(dpd.has_value(), "DTLS server seal DPD_REQ");
            auto dec_dpd = client.open_tunnel_frame(*dpd);
            require(dec_dpd && dec_dpd->type == CstpType::dpd_req, "DTLS client open DPD_REQ");
            // P1-3: Enforce RFC 6347 / RFC 9147 16384-byte plaintext cap (16383-byte payload + 1-byte type).
            std::vector<std::uint8_t> max_ok(16383, 0x22);
            auto ok_dg = client.seal_tunnel_frame(CstpType::data, max_ok);
            require(ok_dg.has_value(), "P1-3 16383B DTLS payload allowed");
            auto ok_open = server.open_tunnel_frame(*ok_dg);
            require(ok_open && ok_open->payload.size() == 16383, "P1-3 16383B DTLS roundtrip");
            std::vector<std::uint8_t> too_big(16384, 0x33);
            require(!client.seal_tunnel_frame(CstpType::data, too_big).has_value(), "P1-3 >16383B DTLS payload rejected");
        };

        run_dtls_suite(DtlsVersion::dtls1_2, DtlsCipher::aes_256_gcm);
        run_dtls_suite(DtlsVersion::dtls1_2, DtlsCipher::aes_128_gcm);
        run_dtls_suite(DtlsVersion::dtls1_2, DtlsCipher::chacha20_poly1305);
        run_dtls_suite(DtlsVersion::dtls1_3, DtlsCipher::aes_256_gcm);
        run_dtls_suite(DtlsVersion::dtls1_3, DtlsCipher::chacha20_poly1305);

        // Verify DTLS 1.3 RFC 9147 16-bit sequence wraparound reconstruction (65535 -> 65536).
        DtlsReplayWindow win;
        require(win.check_and_record(65534) && win.check_and_record(65535), "seed near 16-bit wrap");
        require(win.reconstruct_seq16(0) == 65536, "reconstruct_seq16 wraps to 65536");
        require(win.reconstruct_seq16(65533) == 65533, "reconstruct_seq16 handles slight reorder across wrap");

        // 3. Automatic DTLS -> CSTP TCP fallback scenarios!
        {
            Session sess;
            sess.on_connected(true);
            require(sess.dtls_active(), "session starts with DTLS enabled");
            DtlsFallbackController fb(5000, 10000, 3, 5);
            fb.begin_handshake(1000);
            require(fb.poll(4000, sess) == FallbackAction::none && sess.dtls_active(), "within handshake deadline");
            require(fb.poll(6000, sess) == FallbackAction::fallback_to_cstp && !sess.dtls_active() &&
                    fb.reason() == FallbackReason::handshake_timeout, "handshake timeout triggers CSTP fallback");
        }
        {
            Session sess;
            sess.on_connected(true);
            DtlsFallbackController fb(5000, 10000, 2, 5);
            fb.begin_handshake(0);
            fb.on_established(500);
            require(fb.poll(10500, sess) == FallbackAction::send_dpd_req && sess.dtls_active(), "missed DPD #1");
            require(fb.poll(20500, sess) == FallbackAction::send_dpd_req && sess.dtls_active(), "missed DPD #2");
            require(fb.poll(30500, sess) == FallbackAction::fallback_to_cstp && !sess.dtls_active() &&
                    fb.reason() == FallbackReason::dpd_timeout, "DPD timeout triggers CSTP fallback");
        }
        {
            Session sess;
            sess.on_connected(true);
            DtlsFallbackController fb(5000, 10000, 3, 2);
            fb.begin_handshake(0);
            fb.on_established(100);
            require(fb.on_transport_error(sess) == FallbackAction::none && sess.dtls_active(), "error #1 tolerated");
            require(fb.on_transport_error(sess) == FallbackAction::fallback_to_cstp && !sess.dtls_active() &&
                    fb.reason() == FallbackReason::transport_error, "consecutive UDP errors trigger CSTP fallback");
        }
    }

    auto test_kdl_openvpn_and_openconnect_config() -> void {
        auto cfg = config::parse_kdl(
            "schema-version 1\nrole \"client\"\n"
            "inbounds { inbound \"in\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
            "outbounds {\n  outbound \"direct\" type=\"direct\"\n"
            "  outbound \"ov-crypt\" type=\"openvpn\" {\n    server host=\"vpn.example\" port=1194\n"
            "    static-key-file \"/etc/nexus/ta.key\"\n    tls-auth-mode \"tls-crypt\"\n"
            "    tls { server-name \"vpn.example\"; ca-file \"/etc/nexus/ca.pem\"; }\n  }\n"
            "  outbound \"ov-auth\" type=\"openvpn\" {\n    server host=\"vpn.example\" port=1195\n"
            "    static-key-file \"/etc/nexus/ta.key\"\n    tls-auth-mode \"tls-auth\"\n    key-direction 1\n    tls-auth-sha1 #true\n"
            "    tls { server-name \"vpn.example\"; ca-file \"/etc/nexus/ca.pem\"; }\n  }\n"
            "  outbound \"oc-dtls\" type=\"openconnect\" {\n    server host=\"gw.example\" port=443\n"
            "    dtls #true\n    dtls-fallback #false\n    authentication cookie-file=\"/etc/nexus/oc.ck\"\n"
            "    tls { server-name \"gw.example\"; ca-file \"/etc/nexus/ca.pem\"; }\n  }\n"
            "  outbound \"sel\" type=\"selector\" { members \"ov-crypt\" \"ov-auth\" \"oc-dtls\"; }\n}\nrouting { default \"sel\"; }\n");
        require(cfg.has_value(), "OpenVPN tls-auth/tls-crypt + OpenConnect DTLS KDL parse");
        require(cfg->openvpn_outbounds.size() == 2 &&
                cfg->openvpn_outbounds[0].config.tls_auth_mode == config::OpenVpnTlsAuthMode::tls_crypt &&
                cfg->openvpn_outbounds[1].config.tls_auth_mode == config::OpenVpnTlsAuthMode::tls_auth &&
                cfg->openvpn_outbounds[1].config.key_direction == 1 && cfg->openvpn_outbounds[1].config.tls_auth_sha1,
                "OpenVPN KDL tls-crypt/tls-auth fields");
        require(cfg->openconnect_outbounds.size() == 1 && cfg->openconnect_outbounds[0].config.dtls &&
                !cfg->openconnect_outbounds[0].config.dtls_fallback, "OpenConnect KDL dtls/dtls-fallback fields");
        // P1-B: fail closed on outbound client-cert-file/client-key-file when client TLS mTLS is unavailable.
        require(!config::parse_kdl(
            "schema-version 1\nrole \"client\"\n"
            "inbounds { inbound \"in\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
            "outbounds { outbound \"direct\" type=\"direct\"; outbound \"oc\" type=\"openconnect\" { server host=\"gw.example\" port=443; tls { server-name \"gw.example\"; ca-file \"/etc/nexus/ca.pem\"; client-cert-file \"/etc/nexus/cli.crt\"; client-key-file \"/etc/nexus/cli.key\"; }; }; }\n"
            "routing { default \"oc\"; }\n").has_value(), "P1-B reject outbound mTLS client-cert fail-closed");
        // P2-B3: fail closed on OpenConnect detour + dtls #true + dtls-fallback #false.
        require(!config::parse_kdl(
            "schema-version 1\nrole \"client\"\n"
            "inbounds { inbound \"in\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
            "outbounds { outbound \"direct\" type=\"direct\"; outbound \"oc\" type=\"openconnect\" { server host=\"gw.example\" port=443; dtls #true; dtls-fallback #false; detour \"direct\"; authentication cookie-file=\"/etc/nexus/oc.ck\"; tls { server-name \"gw.example\"; ca-file \"/etc/nexus/ca.pem\"; }; }; }\n"
            "routing { default \"oc\"; }\n").has_value(), "P2-B3 reject OpenConnect detour with strict DTLS");
    }
}

int main() {
    test_openvpn_tls_auth_and_tls_crypt();
    test_openvpn_push_mtls_and_server();
    test_openconnect_mtls_dtls_and_fallback();
    test_kdl_openvpn_and_openconnect_config();
    std::cout << "wave33_openvpn_openconnect_unit: ALL PASSED\n";
    return 0;
}
