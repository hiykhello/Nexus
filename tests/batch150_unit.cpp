import std;
import config;
import crypto;
import rules;
import ssh.wire;
import ssh.crypto;
import platform.os_fs;
import control_api.types;

namespace {
    int failures = 0;

    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            ++failures;
        }
    }

    auto b64_encode(std::span<std::uint8_t const> in) -> std::string {
        static constexpr char kTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (std::size_t i = 0; i < in.size(); i += 3) {
            std::uint32_t v = std::uint32_t(in[i]) << 16;
            if (i + 1 < in.size()) v |= std::uint32_t(in[i + 1]) << 8;
            if (i + 2 < in.size()) v |= std::uint32_t(in[i + 2]);
            out.push_back(kTab[(v >> 18) & 63]);
            out.push_back(kTab[(v >> 12) & 63]);
            out.push_back(i + 1 < in.size() ? kTab[(v >> 6) & 63] : '=');
            out.push_back(i + 2 < in.size() ? kTab[v & 63] : '=');
        }
        return out;
    }

    auto make_rfc8032_tv1_openssh_pem() -> std::string {
        // RFC 8032 §7.1 Test Vector 1 (public mathematical test vector, not a production key).
        static constexpr std::array<std::uint8_t, 32> seed{
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        };
        static constexpr std::array<std::uint8_t, 32> pub{
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
        };
        std::array<std::uint8_t, 64> sk64{};
        std::ranges::copy(seed, sk64.begin());
        std::ranges::copy(pub, sk64.begin() + 32);
        ssh::Writer pub_w;
        pub_w.string("ssh-ed25519").string(pub);
        ssh::Writer priv_w;
        priv_w.u32(0x11223344u).u32(0x11223344u).string("ssh-ed25519").string(pub).string(sk64).string("tv1");
        while (priv_w.buf.size() % 8 != 0) priv_w.byte(static_cast<std::uint8_t>((priv_w.buf.size() % 8) + 1));
        ssh::Writer root;
        for (char c : std::string_view("openssh-key-v1\0", 15)) root.byte(static_cast<std::uint8_t>(c));
        root.string("none").string("none").string("").u32(1).string(pub_w.buf).string(priv_w.buf);
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + b64_encode(root.buf) + "\n-----END OPENSSH PRIVATE KEY-----\n";
    }

    auto test_wire_and_pins() -> void {
        ssh::Writer w;
        w.byte(ssh::kMsgKexInit).boolean(true).u32(0x12345678u).string("hello");
        ssh::Reader r{w.buf};
        auto b = r.byte();
        auto bl = r.boolean();
        auto u = r.u32();
        auto s = r.text();
        expect(b && *b == ssh::kMsgKexInit && bl && *bl && u && *u == 0x12345678u && s && *s == "hello" && r.empty(),
            "150A: SSH wire codec roundtrip");
        expect(!r.byte().has_value(), "150A: Reader rejects truncated read");

        ssh::KexInit ki{};
        ki.cookie[0] = 0x5a;
        ki.kex_algorithms = "curve25519-sha256";
        ki.server_host_key_algorithms = "ssh-ed25519";
        ki.enc_c2s = ki.enc_s2c = "chacha20-poly1305@openssh.com";
        auto raw_ki = ssh::encode_kexinit(ki);
        auto dec_ki = ssh::decode_kexinit(raw_ki);
        expect(dec_ki && dec_ki->cookie[0] == 0x5a && dec_ki->kex_algorithms == "curve25519-sha256" &&
               ssh::list_contains(dec_ki->enc_c2s, "chacha20-poly1305@openssh.com"),
            "150A: KEXINIT encode/decode roundtrip");

        auto pin_b64 = ssh::parse_host_key_sha256("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
        expect(pin_b64.has_value() && (*pin_b64)[0] == 0xe3 && (*pin_b64)[31] == 0x55, "150A: parse SHA256 base64 pin");
        expect(!ssh::parse_host_key_sha256("SHA256:invalid").has_value(), "150A: reject short pin");
        expect(!ssh::parse_host_key_sha256("").has_value(), "150A: reject empty pin");

        expect(ssh::parse_cipher_kind("chacha20-poly1305@openssh.com") == ssh::CipherKind::chacha20_poly1305 &&
               ssh::cipher_key_bytes(ssh::CipherKind::chacha20_poly1305) == 64 &&
               ssh::cipher_key_bytes(ssh::CipherKind::aes256_gcm) == 32 &&
               ssh::cipher_key_bytes(ssh::CipherKind::aes128_gcm) == 16 &&
               !ssh::parse_cipher_kind("aes256-ctr").has_value(),
            "150A: cipher table & key lengths");
    }

    auto test_crypto_ciphers_and_keys() -> void {
        std::array<std::uint8_t, 32> secret{};
        std::ranges::fill(secret, std::uint8_t{0x42});
        std::array<std::uint8_t, 4> kex_c{20, 1, 2, 3}, kex_s{20, 4, 5, 6};
        std::array<std::uint8_t, 32> qc{}, qs{}, hblob{};
        auto h1 = ssh::compute_exchange_hash(ssh::kClientVersion, "SSH-2.0-OpenSSH_10.0", kex_c, kex_s, hblob, qc, qs, secret);
        auto h2 = ssh::compute_exchange_hash(ssh::kClientVersion, "SSH-2.0-OpenSSH_10.0", kex_c, kex_s, hblob, qc, qs, secret);
        expect(h1 && h2 && *h1 == *h2, "150A: exchange hash determinism");

        for (auto kind : {ssh::CipherKind::chacha20_poly1305, ssh::CipherKind::aes256_gcm, ssh::CipherKind::aes128_gcm}) {
            auto key = ssh::derive_key(secret, *h1, 'C', *h1, ssh::cipher_key_bytes(kind));
            auto iv = ssh::derive_key(secret, *h1, 'A', *h1, ssh::cipher_iv_bytes(kind));
            expect(key && iv, "150A: KDF key/iv");
            ssh::PacketCipher enc, dec;
            expect(enc.activate(kind, *key, *iv) && dec.activate(kind, *key, *iv), "150A: activate cipher");

            for (std::uint32_t seq = 0; seq < 3; ++seq) {
                std::vector<std::uint8_t> payload(64 + seq * 17, static_cast<std::uint8_t>(0x30 + seq));
                auto pkt = enc.encrypt(seq, payload);
                expect(pkt.has_value() && pkt->size() > payload.size(), "150A: AEAD encrypt");
                auto hdr = std::span<std::uint8_t const, 4>(pkt->data(), 4);
                auto body_len = dec.decrypt_length(seq, hdr);
                expect(body_len && *body_len + dec.tag_bytes() + 4 == pkt->size(), "150A: AEAD length");
                auto plain = dec.decrypt_body(seq, hdr, std::span(*pkt).subspan(4));
                expect(plain && *plain == payload, "150A: AEAD decrypt roundtrip");

                auto tampered = *pkt;
                tampered.back() ^= 0x01;
                expect(!dec.decrypt_body(seq, std::span<std::uint8_t const, 4>(tampered.data(), 4),
                    std::span(tampered).subspan(4)).has_value(), "150A: AEAD rejects tampered tag");
            }
        }

        auto pk = ssh::PrivateKey::parse(make_rfc8032_tv1_openssh_pem());
        expect(pk.has_value() && pk->algorithm() == "ssh-ed25519", "150A: parse Ed25519 OpenSSH key");
        auto sig = pk->sign(*h1);
        expect(sig.has_value(), "150A: sign exchange hash with Ed25519");
        auto fp_vec = crypto::digest(crypto::Hash::sha256, pk->public_key_blob());
        expect(fp_vec && fp_vec->size() == 32, "150A: sha256 public key blob");
        std::array<std::uint8_t, 32> fp_arr{};
        std::ranges::copy(*fp_vec, fp_arr.begin());
        auto pin_str = ssh::format_host_key_sha256(fp_arr);
        auto pin = ssh::parse_host_key_sha256(pin_str);
        expect(pin.has_value() && ssh::verify_host_key(pk->public_key_blob(), std::span{&*pin, 1}, *h1, *sig).has_value(),
            "150A: verify_host_key with matching pin and signature");

        auto wrong_pin = *pin;
        wrong_pin[0] ^= 0xff;
        expect(!ssh::verify_host_key(pk->public_key_blob(), std::span{&wrong_pin, 1}, *h1, *sig).has_value(),
            "150A: reject mismatched host-key-sha256 pin");
        auto bad_sig = *sig;
        bad_sig.back() ^= 0xff;
        expect(!ssh::verify_host_key(pk->public_key_blob(), std::span{&*pin, 1}, *h1, bad_sig).has_value(),
            "150A: reject corrupted host key signature");
    }

    auto test_kdl_ssh_outbound() -> void {
        auto ok = config::parse_kdl(R"(
            schema-version 1
            role "client"
            dns { servers { server "boot" type="udp" host="1.1.1.1" port=53; }; final "boot"; }
            inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds {
                outbound "direct" type="direct"
                outbound "jump" type="ssh" {
                    server host="ssh.example.com" port=2222
                    user "alice"
                    private-key-file "/etc/nexus/id_ed25519"
                    host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
                    cipher "chacha20-poly1305@openssh.com"
                    keepalive-interval-ms 15000
                    max-sessions 8
                    bootstrap-resolver "boot"
                    detour "direct"
                }
                outbound "pool" type="selector" { member "jump"; selected "jump"; }
            }
            routing { default-outbound "pool"; }
        )");
        expect(ok.has_value() && ok->ssh_outbounds.size() == 1 &&
               ok->ssh_outbounds[0].config.user == "alice" &&
               ok->ssh_outbounds[0].config.port == 2222 &&
               ok->ssh_outbounds[0].config.max_sessions == 8 &&
               ok->ssh_outbounds[0].config.bootstrap_index == 0 &&
               ok->ssh_outbounds[0].config.detour_index == 0,
            ok ? "150B: unexpected parsed ssh outbound field" : ("150B: parse valid ssh KDL failed: " + ok.error()));

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds { outbound "jump" type="ssh" { server host="127.0.0.1" port=22; user "a"; password-file "/tmp/p"; }; }
            routing { default-outbound "jump"; }
        )").has_value(), "150B: reject missing host-key-sha256");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds { outbound "jump" type="ssh" { server host="127.0.0.1" port=22; user "a"; host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"; }; }
            routing { default-outbound "jump"; }
        )").has_value(), "150B: reject ssh outbound without password-file or private-key-file");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds { outbound "jump" type="ssh" { server host="127.0.0.1" port=22; user "a"; password-file "rel/pw"; host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"; }; }
            routing { default-outbound "jump"; }
        )").has_value(), "150B: reject relative password-file");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds { outbound "jump" type="ssh" { server host="127.0.0.1" port=22; user "a"; password-file "/tmp/p"; cipher "aes256-ctr"; host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"; }; }
            routing { default-outbound "jump"; }
        )").has_value(), "150B: reject legacy non-AEAD cipher");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds { outbound "jump" type="ssh" { server host="127.0.0.1" port=22; user "a"; password-file "/tmp/p"; host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"; }; }
            routing { rule domain="example.com" network="udp" action="jump"; default-outbound "jump"; }
        )").has_value(), "150B: reject explicit UDP rule pointing to TCP-only ssh outbound");
    }

    auto test_os_fs_primitives() -> void {
        expect(platform::normalize_windows_pipe_name("nexus-control") == "\\\\.\\pipe\\nexus-control",
            "150C: normalize bare pipe name");
        expect(platform::normalize_windows_pipe_name("\\\\.\\PIPE\\NexusCtrl") == "\\\\.\\pipe\\NexusCtrl",
            "150C: normalize prefixed pipe name");
        expect(!platform::normalize_windows_pipe_name("\\\\remote\\pipe\\bad").has_value() &&
               !platform::normalize_windows_pipe_name("bad/slash").has_value() &&
               !platform::normalize_windows_pipe_name("..").has_value() &&
               !platform::normalize_windows_pipe_name("").has_value(),
            "150C: reject unsafe/remote pipe names");

        auto dir = std::filesystem::temp_directory_path() / "nexus-batch150-osfs";
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir);
        auto p1 = dir / "stage.tmp";
        auto p2 = dir / "final.dat";
        auto sl = dir / "sym.lnk";
        { std::ofstream f1(p1); f1 << "new-data"; }
        { std::ofstream f2(p2); f2 << "old"; }
        std::filesystem::create_symlink(p2, sl);

        auto r_reg = platform::is_reparse_or_symlink(p1);
        auto r_sym = platform::is_reparse_or_symlink(sl);
        auto r_miss = platform::is_reparse_or_symlink(dir / "missing");
        expect(r_reg && !*r_reg && r_sym && *r_sym && r_miss && !*r_miss, "150C: symlink detection");

        expect(!platform::atomic_replace_path(p1, p2), "150C: atomic_replace_path");
        std::string content;
        { std::ifstream in(p2); std::getline(in, content); }
        expect(content == "new-data", "150C: replaced file content matches");
        expect(platform::sync_native_handle(static_cast<std::uintptr_t>(-1)) < 0, "150C: invalid handle returns -1");
        std::filesystem::remove_all(dir, ec);
    }
}

auto main() -> int {
    test_wire_and_pins();
    test_crypto_ciphers_and_keys();
    test_kdl_ssh_outbound();
    test_os_fs_primitives();
    if (failures) {
        std::cerr << "batch150-unit FAILED (" << failures << " checks)\n";
        return 1;
    }
    std::cout << "batch150-unit: ALL PASSED\n";
    return 0;
}
