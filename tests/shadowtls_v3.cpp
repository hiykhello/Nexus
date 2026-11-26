import std;
import crypto;
import shadowtls.v3;

namespace st = shadowtls;
namespace c = ::crypto;

namespace {
    auto make_client_hello(std::string_view password, std::span<std::uint8_t const, 28> random28,
                           std::string_view sni = {}) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> body;
        body.push_back(st::tls_handshake_client_hello);
        body.push_back(0); body.push_back(0); body.push_back(0); // handshake length filled below
        body.push_back(0x03); body.push_back(0x03);               // TLS 1.2 legacy version
        for (std::uint8_t i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(0x10 + i));
        body.push_back(32);                                       // session_id length = 32
        body.resize(body.size() + 32, 0);
        // cipher_suites (2 bytes + 1 suite) + compression (1 + 1)
        body.insert(body.end(), {0x00, 0x02, 0x13, 0x01, 0x01, 0x00});
        std::vector<std::uint8_t> exts;
        if (!sni.empty()) {
            // Put a dummy grease/supported_versions ext before SNI to test extension walking.
            exts.insert(exts.end(), {0x00, 43, 0x00, 0x03, 0x02, 0x03, 0x04});
            auto const nl = static_cast<std::uint16_t>(sni.size());
            auto const ll = static_cast<std::uint16_t>(3 + nl);
            auto const el = static_cast<std::uint16_t>(2 + ll);
            exts.insert(exts.end(), {0x00, 0x00, static_cast<std::uint8_t>(el >> 8), static_cast<std::uint8_t>(el),
                                     static_cast<std::uint8_t>(ll >> 8), static_cast<std::uint8_t>(ll),
                                     0x00, static_cast<std::uint8_t>(nl >> 8), static_cast<std::uint8_t>(nl)});
            exts.insert(exts.end(), sni.begin(), sni.end());
        }
        body.push_back(static_cast<std::uint8_t>(exts.size() >> 8));
        body.push_back(static_cast<std::uint8_t>(exts.size()));
        body.insert(body.end(), exts.begin(), exts.end());
        std::size_t hs_len = body.size() - 4;
        body[1] = static_cast<std::uint8_t>(hs_len >> 16);
        body[2] = static_cast<std::uint8_t>(hs_len >> 8);
        body[3] = static_cast<std::uint8_t>(hs_len);
        if (!st::stamp_client_hello_session_id(password, body, random28)) throw std::runtime_error("stamp failed");
        std::vector<std::uint8_t> record{st::tls_record_handshake, 0x03, 0x01,
                                         static_cast<std::uint8_t>(body.size() >> 8),
                                         static_cast<std::uint8_t>(body.size())};
        record.insert(record.end(), body.begin(), body.end());
        return record;
    }

    auto make_server_hello(std::span<std::uint8_t const, 32> server_random, bool tls13) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> body;
        body.push_back(st::tls_handshake_server_hello);
        body.push_back(0); body.push_back(0); body.push_back(0);
        body.push_back(0x03); body.push_back(0x03);
        body.insert(body.end(), server_random.begin(), server_random.end());
        body.push_back(4);
        body.insert(body.end(), {0xaa, 0xbb, 0xcc, 0xdd});
        body.insert(body.end(), {0x13, 0x01, 0x00}); // TLS_AES_128_GCM_SHA256 + no compression
        if (tls13) {
            body.insert(body.end(), {0x00, 0x06, 0x00, 43, 0x00, 0x02, 0x03, 0x04});
        } else {
            body.insert(body.end(), {0x00, 0x06, 0x00, 43, 0x00, 0x02, 0x03, 0x03});
        }
        std::size_t hs_len = body.size() - 4;
        body[1] = static_cast<std::uint8_t>(hs_len >> 16);
        body[2] = static_cast<std::uint8_t>(hs_len >> 8);
        body[3] = static_cast<std::uint8_t>(hs_len);
        std::vector<std::uint8_t> record{st::tls_record_handshake, 0x03, 0x03,
                                         static_cast<std::uint8_t>(body.size() >> 8),
                                         static_cast<std::uint8_t>(body.size())};
        record.insert(record.end(), body.begin(), body.end());
        return record;
    }

    auto frame_records(std::span<std::uint8_t const> stream) -> std::vector<std::vector<std::uint8_t>> {
        st::TlsRecordReader reader;
        std::vector<std::vector<std::uint8_t>> out;
        std::size_t offset = 0;
        while (offset < stream.size()) {
            auto step = reader.feed(stream.subspan(offset, std::min<std::size_t>(7, stream.size() - offset)));
            offset += step.consumed;
            if (step.status == st::RecordStatus::complete) {
                out.emplace_back(step.record.begin(), step.record.end());
                reader.consume();
            } else if (step.status != st::RecordStatus::incomplete) {
                throw std::runtime_error("unexpected record reader error");
            }
        }
        if (reader.pending()) throw std::runtime_error("trailing partial record");
        return out;
    }
}

int main() {
    constexpr std::string_view pass = "shadowtls-v3-secret";
    std::array<std::uint8_t, 28> random28{};
    for (std::size_t i = 0; i < random28.size(); ++i) random28[i] = static_cast<std::uint8_t>(i + 1);

    // 1. ClientHello tagging & verification across multiple users.
    auto ch = make_client_hello(pass, random28);
    std::array<std::string_view, 2> passwords{"wrong-user", pass};
    auto matched = st::verify_client_hello(ch, passwords);
    if (!matched || *matched != 1) return 1;
    auto tampered_ch = ch;
    tampered_ch.back() ^= 0xff;
    if (st::verify_client_hello(tampered_ch, passwords).has_value()) return 2;

    // 2. ServerHello TLS 1.3 vs TLS 1.2 detection and ServerRandom extraction.
    std::array<std::uint8_t, 32> server_random{};
    for (std::size_t i = 0; i < server_random.size(); ++i) server_random[i] = static_cast<std::uint8_t>(0xa0 + i);
    auto sh13 = make_server_hello(server_random, true);
    auto sh12 = make_server_hello(server_random, false);
    if (!st::is_server_hello_tls13(sh13) || st::is_server_hello_tls13(sh12)) return 3;
    auto extracted = st::extract_server_random(sh13);
    if (!extracted || *extracted != server_random) return 4;

    // 3. Handshake relay ApplicationData masking/unmasking + client ignore on cutover.
    auto masker = st::ServerHandshakeMasker::create(pass, server_random);
    auto unmasker = st::ClientHandshakeUnmasker::create(pass, server_random);
    if (!masker || !unmasker) return 5;
    std::vector<std::uint8_t> real_server_app{st::tls_record_application_data, 3, 3, 0, 5, 10, 20, 30, 40, 50};
    auto masked = masker->mask_record(real_server_app);
    if (!masked || masked->size() != real_server_app.size() + st::hmac_tag_size) return 6;
    auto unmasked = unmasker->unmask_record(*masked);
    if (!unmasked || *unmasked != real_server_app) return 7;

    // 4. Cutover and bidirectional chained HMAC VerifiedStream roundtrip (incl. >16 KiB multi-record).
    auto client_stream = st::VerifiedStream::create(st::StreamRole::client, pass, server_random, std::move(*unmasker).take_hmac(), false);
    auto server_stream = st::VerifiedStream::create(st::StreamRole::server, pass, server_random, {}, true);
    if (!client_stream || !server_stream) return 8;

    // Leftover server handshake record arrives at client after cutover -> ignored cleanly.
    auto masked2 = masker->mask_record(real_server_app);
    if (!masked2) return 9;
    auto ignored = client_stream->decode(*masked2);
    if (ignored.status != st::VerifiedStream::DecodeStatus::ignored_handshake) return 10;

    // Server still receives real client TLS handshake ApplicationData before client tunnel cutover.
    std::vector<std::uint8_t> real_client_hs_app{st::tls_record_application_data, 3, 3, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    if (server_stream->accept_cutover_record(real_client_hs_app).status !=
        st::VerifiedStream::DecodeStatus::ignored_handshake) return 11;

    // Client sends first >16 KiB payload to verify chunking + chained HMAC + server cutover detection.
    std::vector<std::uint8_t> big_req(20000);
    for (std::size_t i = 0; i < big_req.size(); ++i) big_req[i] = static_cast<std::uint8_t>(i * 7 + 3);
    auto encoded_req = client_stream->encode(big_req);
    if (!encoded_req) return 12;
    auto req_records = frame_records(*encoded_req);
    if (req_records.size() != 2) return 13;

    std::vector<std::uint8_t> received_req;
    auto first = server_stream->accept_cutover_record(req_records[0]);
    if (first.status != st::VerifiedStream::DecodeStatus::payload) return 14;
    received_req.insert(received_req.end(), first.payload.begin(), first.payload.end());
    auto second = server_stream->decode(req_records[1]);
    if (second.status != st::VerifiedStream::DecodeStatus::payload) return 15;
    received_req.insert(received_req.end(), second.payload.begin(), second.payload.end());
    if (received_req != big_req) return 16;

    // Server sends reply back to client (client automatically drops hmac_ignore upon valid verify frame).
    std::vector<std::uint8_t> resp{0x48, 0x54, 0x54, 0x50, 0x2f, 0x31};
    auto encoded_resp = server_stream->encode(resp);
    if (!encoded_resp) return 17;
    auto resp_records = frame_records(*encoded_resp);
    if (resp_records.size() != 1) return 18;
    auto decoded_resp = client_stream->decode(resp_records[0]);
    if (decoded_resp.status != st::VerifiedStream::DecodeStatus::payload ||
        !std::ranges::equal(decoded_resp.payload, resp)) return 19;

    // Corrupted payload must fail authentication; alert record encodes validly.
    auto bad_record = resp_records[0];
    bad_record.back() ^= 1;
    if (client_stream->decode(bad_record).status != st::VerifiedStream::DecodeStatus::auth_failed) return 20;
    auto alert = st::encode_alert_record();
    if (!alert || (*alert)[0] != st::tls_record_alert ||
        client_stream->decode(*alert).status != st::VerifiedStream::DecodeStatus::alert_closed) return 21;

    // 5. ClientHello SNI extraction, wildcard-sni SSRF validation, and handshake target selection.
    if (st::extract_client_hello_sni(ch).has_value()) return 22;
    auto ch_sni = make_client_hello(pass, random28, "API.Example.COM");
    auto got_sni = st::extract_client_hello_sni(ch_sni);
    if (!got_sni || *got_sni != "api.example.com") return 23;
    auto trunc_sni = ch_sni;
    trunc_sni.pop_back();
    if (st::extract_client_hello_sni(trunc_sni).has_value()) return 24;

    if (!st::valid_wildcard_sni_host("www.example.com") || !st::valid_wildcard_sni_host("sub-1.cdn.example.org"))
        return 25;
    for (std::string_view bad : {
        "", "localhost", "foo.localhost", "printer.local", "box.localdomain", "meta.internal",
        "gw.home.arpa", "1.0.0.127.in-addr.arpa", "127.0.0.1", "169.254.169.254", "10.0.0.1",
        "0177.0.0.1", "::1", "[::1]", ".example.com", "example.com.", "a..b.com", "-a.com", "a-.com",
        "bad_host.com", "singlelabel"
    }) {
        if (st::valid_wildcard_sni_host(bad)) return 26;
    }

    std::array<st::SniHandshakeEntry, 2> sni_map{{
        {"api.example.com", "127.0.0.1", 9444},
        {"cdn.example.com", "127.0.0.1", 9445},
    }};
    // Explicit SNI map always wins (authed or unauthed).
    auto t1 = st::select_handshake_target("API.Example.COM", false, "default.test", 443, sni_map, st::WildcardSniMode::off);
    if (t1 != st::HandshakeEndpoint{"127.0.0.1", 9444, false}) return 27;
    // wildcard-sni "authed": allows authed public SNI, denies unauthed -> default.
    auto t2 = st::select_handshake_target("other.example.com", true, "default.test", 443, sni_map, st::WildcardSniMode::authed);
    if (t2 != st::HandshakeEndpoint{"other.example.com", 443, true}) return 28;
    auto t3 = st::select_handshake_target("other.example.com", false, "default.test", 443, sni_map, st::WildcardSniMode::authed);
    if (t3 != st::HandshakeEndpoint{"default.test", 443, false}) return 29;
    // wildcard-sni "all": allows unauthed public SNI, rejects SSRF SNI -> default.
    auto t4 = st::select_handshake_target("other.example.com", false, "default.test", 8443, sni_map, st::WildcardSniMode::all);
    if (t4 != st::HandshakeEndpoint{"other.example.com", 8443, true}) return 30;
    auto t5 = st::select_handshake_target("169.254.169.254", true, "default.test", 8443, sni_map, st::WildcardSniMode::all);
    if (t5 != st::HandshakeEndpoint{"default.test", 8443, false}) return 31;
    auto t6 = st::select_handshake_target("redis.local", true, "default.test", 8443, sni_map, st::WildcardSniMode::all);
    if (t6 != st::HandshakeEndpoint{"default.test", 8443, false}) return 32;

    // 6. IP-level SSRF checks (IPv4 + IPv6 incl. fec0::/10 site-local & 64:ff9b::/96 NAT64 embedded private IPv4).
    if (!st::is_blocked_wildcard_ipv4({127, 0, 0, 1}) || !st::is_blocked_wildcard_ipv4({169, 254, 169, 254}) ||
        !st::is_blocked_wildcard_ipv4({10, 0, 0, 1}) || !st::is_blocked_wildcard_ipv4({100, 64, 0, 1}) ||
        st::is_blocked_wildcard_ipv4({1, 1, 1, 1}) || st::is_blocked_wildcard_ipv4({93, 184, 216, 34}))
        return 33;
    auto mk6 = [](std::array<std::uint8_t, 16> a) { return a; };
    if (!st::is_blocked_wildcard_ipv6(mk6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0})) ||       // ::
        !st::is_blocked_wildcard_ipv6(mk6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})) ||       // ::1
        !st::is_blocked_wildcard_ipv6(mk6({0xfe,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})) || // fe80::1
        !st::is_blocked_wildcard_ipv6(mk6({0xfe,0xc0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})) || // fec0::1 (site-local)
        !st::is_blocked_wildcard_ipv6(mk6({0xfe,0xff,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})) || // fec0::/10 upper bound
        !st::is_blocked_wildcard_ipv6(mk6({0xfd,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})) ||    // fc00::/7 ULA
        !st::is_blocked_wildcard_ipv6(mk6({0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1})) ||          // ::ffff:127.0.0.1
        !st::is_blocked_wildcard_ipv6(mk6({0,0x64,0xff,0x9b, 0,0,0,0, 0,0,0,0, 127,0,0,1})) ||       // 64:ff9b::127.0.0.1
        !st::is_blocked_wildcard_ipv6(mk6({0,0x64,0xff,0x9b, 0,0,0,0, 0,0,0,0, 169,254,169,254})) || // 64:ff9b::169.254.169.254
        !st::is_blocked_wildcard_ipv6(mk6({0,0x64,0xff,0x9b, 0,0,0,0, 0,0,0,0, 10,0,0,1})) ||        // 64:ff9b::10.0.0.1
        !st::is_blocked_wildcard_ipv6(mk6({0,0x64,0xff,0x9b, 0,1,0,0, 0,0,0,0, 1,1,1,1})))           // 64:ff9b:1::/48 local NAT64
        return 34;
    if (st::is_blocked_wildcard_ipv6(mk6({0x26,0x06,0x47,0x00, 0x47,0x00,0,0, 0,0,0,0, 0,0,0x11,0x11})) ||
        st::is_blocked_wildcard_ipv6(mk6({0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 1,1,1,1})) ||
        st::is_blocked_wildcard_ipv6(mk6({0,0x64,0xff,0x9b, 0,0,0,0, 0,0,0,0, 1,1,1,1})))            // 64:ff9b::1.1.1.1 (public)
        return 35;

    std::println("ShadowTLS v3 ClientHello HMAC/SNI, wildcard-sni SSRF validation, handshake routing and chained verified records passed");
}
