import std;
import crypto;
import shadowtls.v3;

namespace st = shadowtls;
namespace c = ::crypto;

namespace {
    auto make_client_hello(std::string_view password, std::span<std::uint8_t const, 28> random28) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> body;
        body.push_back(st::tls_handshake_client_hello);
        body.push_back(0); body.push_back(0); body.push_back(0); // handshake length filled below
        body.push_back(0x03); body.push_back(0x03);               // TLS 1.2 legacy version
        for (std::uint8_t i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(0x10 + i));
        body.push_back(32);                                       // session_id length = 32
        body.resize(body.size() + 32, 0);
        // cipher_suites (2 bytes + 1 suite) + compression (1 + 1) + minimal extensions (2)
        body.insert(body.end(), {0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00});
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

    std::println("ShadowTLS v3 ClientHello HMAC, TLS 1.3 ServerHello, handshake mask/cutover and chained verified records passed");
}
