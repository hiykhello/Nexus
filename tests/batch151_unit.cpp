import std;
import config;
import crypto;
import naive.padding;
import socks5;
import tls.profiles;
import tls.server_credential;
import tls.server_handshake_io;

namespace {
    int failures = 0;

    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            ++failures;
        }
    }

    struct TempCertDir {
        std::filesystem::path dir;
        std::string cert_file;
        std::string key_file;
        TempCertDir(std::filesystem::path d, std::string c, std::string k)
            : dir(std::move(d)), cert_file(std::move(c)), key_file(std::move(k)) {}
        TempCertDir(TempCertDir&& o) noexcept
            : dir(std::exchange(o.dir, {})), cert_file(std::move(o.cert_file)), key_file(std::move(o.key_file)) {}
        TempCertDir& operator=(TempCertDir&&) = delete;
        ~TempCertDir() { if (!dir.empty()) { std::error_code ec; std::filesystem::remove_all(dir, ec); } }
    };

    auto make_temp_cert() -> std::optional<TempCertDir> {
        auto dir = std::filesystem::temp_directory_path() /
                   ("nexus-b151-unit-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        TempCertDir out{dir, (dir / "cert.pem").string(), (dir / "key.pem").string()};
        auto cmd = std::format(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
            "-keyout '{}' -out '{}' -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -days 1 >/dev/null 2>&1",
            out.key_file, out.cert_file);
        if (std::system(cmd.c_str()) != 0) return std::nullopt;
        return out;
    }

    auto read_bytes(std::string const& path) -> std::vector<std::uint8_t> {
        std::ifstream f(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), {}};
    }

    auto test_naive_auth_and_headers() -> void {
        auto hdr = naive::make_basic_auth("alice", "s3cr3t");
        expect(hdr.starts_with("Basic "), "151B: make_basic_auth prefix");
        std::vector<naive::UserCredential> users;
        users.emplace_back("alice-tag", "alice", "s3cr3t");
        users.emplace_back("bob-tag", "bob", "hunter2");
        auto matched = naive::verify_basic_auth(hdr, users);
        expect(matched && *matched == "alice-tag", "151B: verify_basic_auth valid user");
        expect(naive::verify_basic_auth("basic " + hdr.substr(6), users) == std::optional<std::string_view>{"alice-tag"},
            "151B: verify_basic_auth case-insensitive scheme");
        expect(!naive::verify_basic_auth(naive::make_basic_auth("alice", "wrong"), users).has_value(),
            "151B: reject wrong password");
        expect(!naive::verify_basic_auth("Bearer token", users).has_value(), "151B: reject non-Basic auth");
        expect(!naive::verify_basic_auth("Basic !!!", users).has_value(), "151B: reject corrupt base64");

        auto p1 = naive::generate_padding_header();
        auto p2 = naive::generate_padding_header();
        expect(!p1.empty() && p1.size() >= 16 && p1.size() <= 32 && p1 != p2, "151B: generate_padding_header");
        expect(!p1.contains('\r') && !p1.contains('\n'), "151B: padding header single-line ASCII");

        expect(naive::parse_padding_type_request("1, 0"), "151B: padding-type-request 1,0");
        expect(naive::parse_padding_type_request("0,1"), "151B: padding-type-request 0,1");
        expect(!naive::parse_padding_type_request("0"), "151B: padding-type-request 0 only");
        expect(naive::parse_padding_type_reply("1"), "151B: padding-type-reply 1");
        expect(!naive::parse_padding_type_reply("0"), "151B: padding-type-reply 0");

        auto dom = naive::parse_connect_authority("example.com:8443");
        expect(dom && dom->address_type == 3 && dom->port == 8443, "151B: parse domain authority");
        auto v4 = naive::parse_connect_authority("127.0.0.1:443");
        expect(v4 && v4->address_type == 1 && v4->port == 443, "151B: parse IPv4 authority");
        auto v6 = naive::parse_connect_authority("[::1]:8443");
        expect(v6 && v6->address_type == 4 && v6->port == 8443, "151B: parse IPv6 authority");
        expect(!naive::parse_connect_authority("example.com").has_value() &&
               !naive::parse_connect_authority(":443").has_value() &&
               !naive::parse_connect_authority("example.com:0").has_value(),
            "151B: reject invalid CONNECT authorities");

        expect(naive::decoy_html_body(404).contains("404 Not Found") && naive::decoy_html_body(200).contains("Welcome"),
            "151B: decoy HTML bodies");
    }

    auto test_naive_padding_framing() -> void {
        naive::PaddingEncoder plain_enc{false};
        naive::PaddingDecoder plain_dec{false};
        expect(plain_enc.in_passthrough() && plain_dec.in_passthrough(), "151B: disabled padding is passthrough");
        std::array<std::uint8_t, 5> sample{1, 2, 3, 4, 5};
        std::vector<std::uint8_t> out;
        expect(plain_enc.encode(sample, out) && out.size() == 5 && std::ranges::equal(sample, out),
            "151B: disabled encoder passthrough");

        naive::PaddingEncoder enc{true};
        naive::PaddingDecoder dec{true};
        expect(!enc.in_passthrough() && !dec.in_passthrough(), "151B: enabled padding starts active");

        std::vector<std::uint8_t> expected_stream;
        std::vector<std::uint8_t> encoded_wire;
        std::vector<std::uint8_t> large(70000);
        for (std::size_t i = 0; i < large.size(); ++i) large[i] = static_cast<std::uint8_t>((i * 31) & 0xff);

        for (unsigned step = 0; step < 12; ++step) {
            std::vector<std::uint8_t> chunk;
            if (step == 2) chunk.clear();
            else if (step == 5) chunk = large;
            else {
                chunk.resize(13 + step * 7);
                for (std::size_t i = 0; i < chunk.size(); ++i) chunk[i] = static_cast<std::uint8_t>((step + i) & 0xff);
            }
            expected_stream.insert(expected_stream.end(), chunk.begin(), chunk.end());
            expect(enc.encode(chunk, encoded_wire), "151B: encode chunk");
            if (step >= 7) {
                // Note step 5 (`large` = 70000B > 65535B) already consumed >= 2 frames!
                expect(enc.in_passthrough(), "151B: encoder switches to passthrough after 8 frames");
            }
        }

        // Feed 1 byte at a time to test extreme TLS/H2/H3 fragmentation safety.
        std::vector<std::uint8_t> decoded_stream;
        for (std::size_t i = 0; i < encoded_wire.size(); ++i) {
            expect(dec.feed(std::span<std::uint8_t const>(&encoded_wire[i], 1), decoded_stream),
                "151B: 1-byte fragmented decode");
        }
        expect(decoded_stream == expected_stream, "151B: 1-byte fragmented roundtrip matches byte-for-byte");
        expect(dec.in_passthrough() && dec.frames_received() == 8, "151B: decoder switched to passthrough at frame 8");

        naive::PaddingEncoder manual_enc{true};
        naive::PaddingDecoder manual_dec{true};
        std::vector<std::uint8_t> fw, fp;
        std::array<std::uint8_t, 3> p3{9, 8, 7};
        expect(manual_enc.encode_with_pad_len(p3, 19, fw) && fw.size() == 3 + 3 + 19, "151B: exact pad_len wire size");
        expect(manual_dec.feed(fw, fp) && fp.size() == 3 && std::ranges::equal(p3, fp), "151B: manual pad_len decode");
    }

    auto test_multi_alpn_server_handshake() -> void {
        auto tmp = make_temp_cert();
        expect(tmp.has_value(), "151A: generate ephemeral test cert");
        if (!tmp) return;
        auto cert = read_bytes(tmp->cert_file);
        auto key = read_bytes(tmp->key_file);
        auto cred = tls::ServerCredential::create_file_contents(cert, key);
        crypto::cleanse(key);
        expect(cred.has_value(), "151A: load test ServerCredential");
        if (!cred) return;

        auto c1 = cred->clone();
        expect(c1.has_value(), "151A: clone ServerCredential");
        if (c1) {
            std::array<std::string_view, 2> prefs{"h2", "http/1.1"};
            auto hs = tls::ServerHandshakeIo::create_alpn(std::move(*c1), 100, 10000, prefs, true);
            expect(hs.has_value(), "151A: ServerHandshakeIo::create_alpn accepts h2 + http/1.1");
        }
        auto c2 = cred->clone();
        if (c2) {
            std::array<std::string_view, 1> bad_prefs{""};
            auto hs_bad = tls::ServerHandshakeIo::create_alpn(std::move(*c2), 100, 10000, bad_prefs, true);
            expect(!hs_bad.has_value(), "151A: create_alpn rejects empty ALPN token");
        }
        auto mk = tls::make_server_handshake(*cred, 100, 10000, {}, std::array<std::string_view, 2>{"h2", "http/1.1"}, true);
        expect(mk.has_value(), "151A: tls::make_server_handshake multi-ALPN succeeds");
    }

    auto test_kdl_configs() -> void {
        auto ok_naive = config::parse_kdl(R"(
            schema-version 1
            role "client"
            dns { servers { server "boot" type="udp" host="1.1.1.1" port=53; }; final "boot"; }
            inbounds {
                inbound "n-in" type="naive" {
                    listen host="127.0.0.1" port=8443
                    protocol "both"
                    tls { certificate-file "/etc/nexus/cert.pem"; private-key-file "/etc/nexus/key.pem"; }
                    authentication {
                        user "alice" username="alice" password-file="/tmp/pw"
                    }
                    padding #true
                    fallback-status 200
                    handshake-timeout-ms 5000
                    idle-timeout-ms 30000
                    native-bytes 4194304
                }
            }
            outbounds {
                outbound "n-out-h3" type="naive" {
                    protocol "h3"
                    server host="naive.example.com" port=443
                    authentication username="alice" password-file="/tmp/pw"
                    tls {
                        server-name "naive.example.com"
                        ca-file "/etc/nexus/ca.pem"
                        fingerprint "chrome"
                        verify #true
                    }
                    padding #true
                    extra-header "X-Probe" "1"
                    max-sessions 4
                    bootstrap-resolver "boot"
                }
                outbound "n-out-h2" type="naive" {
                    protocol "h2"
                    server host="127.0.0.1" port=8443
                    authentication username="alice" password-file="/tmp/pw"
                    tls {
                        server-name "localhost"
                        ca-file "/etc/nexus/ca.pem"
                        verify #true
                    }
                    tcp-fast-open #true
                }
                outbound "direct" type="direct"
                outbound "grp" type="selector" { member "n-out-h3"; member "n-out-h2"; selected "n-out-h3"; }
            }
            routing { final "grp"; }
        )");
        expect(ok_naive.has_value(), ok_naive ? "151B: naive KDL ok" : ("151B: naive KDL failed: " + ok_naive.error()));
        if (ok_naive) {
            expect(ok_naive->inbound == config::Inbound::naive && !ok_naive->inbounds.empty() &&
                   ok_naive->inbounds[0].naive &&
                   ok_naive->inbounds[0].naive->protocol == config::NaiveProtocol::both &&
                   ok_naive->inbounds[0].naive->fallback_status == 200 &&
                   ok_naive->inbounds[0].naive->users.size() == 1 &&
                   ok_naive->naive_outbounds.size() == 2 &&
                   ok_naive->naive_outbounds[0].config.protocol == config::NaiveProtocol::h3 &&
                   ok_naive->naive_outbounds[0].config.extra_headers.size() == 1 &&
                   ok_naive->naive_outbounds[1].config.tcp_fast_open == std::optional<bool>{true},
                "151B: parsed naive inbound/outbound fields");
        }

        auto ok_http = config::parse_kdl(R"(
            schema-version 1
            role "client"
            dns { servers { server "boot" type="udp" host="1.1.1.1" port=53; }; final "boot"; }
            inbounds {
                inbound "h-in" type="http" {
                    listen host="127.0.0.1" port=8444
                    authentication "password" username="u" password-file="/tmp/pw"
                    tls {
                        certificate-file "/etc/nexus/cert.pem"
                        private-key-file "/etc/nexus/key.pem"
                    }
                    http2 #true
                    http3 #true
                    connect-udp #true
                }
            }
            outbounds {
                outbound "hc-h3" type="http-connect" {
                    http-version "h3"
                    server host="proxy.example.com" port=443
                    authentication username="u" password-file="/tmp/pw"
                    udp #true
                    tls {
                        server-name "proxy.example.com"
                        ca-file "/etc/nexus/ca.pem"
                        fingerprint "chrome"
                        verify #true
                    }
                    bootstrap-resolver "boot"
                }
                outbound "hc-auto" type="http-connect" {
                    http-version "auto"
                    server host="127.0.0.1" port=8444
                    tls {
                        server-name "localhost"
                        ca-file "/etc/nexus/ca.pem"
                        fingerprint "firefox"
                        verify #true
                    }
                }
                outbound "direct" type="direct"
                outbound "pool" type="selector" { member "hc-h3"; member "hc-auto"; selected "hc-h3"; }
            }
            routing { final "pool"; }
        )");
        expect(ok_http.has_value(), ok_http ? "151A: modern HTTP KDL ok" : ("151A: modern HTTP KDL failed: " + ok_http.error()));
        if (ok_http) {
            expect(!ok_http->inbounds.empty() && ok_http->inbounds[0].http &&
                   ok_http->inbounds[0].http->has_tls && ok_http->inbounds[0].http->http2 &&
                   ok_http->inbounds[0].http->http3 && ok_http->inbounds[0].http->connect_udp &&
                   ok_http->tcp_proxy_outbounds.size() == 2 &&
                   ok_http->tcp_proxy_outbounds[0].config.http_version == config::HttpProxyVersion::h3 &&
                   ok_http->tcp_proxy_outbounds[0].config.udp &&
                   ok_http->tcp_proxy_outbounds[1].config.http_version == config::HttpProxyVersion::auto_h2,
                "151A: parsed modern HTTP inbound/outbound fields");
        }

        // Validation negative tests
        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "h" type="http" { listen host="127.0.0.1" port=8080; authentication "none"; http2 #true; }; }
            outbounds { outbound "d" type="direct"; }; routing { final "d"; }
        )").has_value(), "151A: reject http2 without tls on http inbound");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds {
                inbound "h" type="http" {
                    listen host="127.0.0.1" port=8443; authentication "none"
                    tls { certificate-file "/etc/c.pem"; private-key-file "/etc/k.pem"; }
                    http2 #true; connect-udp #true
                }
            }
            outbounds { outbound "d" type="direct"; }; routing { final "d"; }
        )").has_value(), "151A: reject connect-udp without http3 #true");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds {
                outbound "hc" type="http-connect" {
                    http-version "h2"; server host="127.0.0.1" port=8443; udp #true
                    tls { server-name "localhost"; ca-file "/etc/ca.pem"; verify #true; }
                }
                outbound "direct" type="direct"
            }
            routing { final "hc"; }
        )").has_value(), "151A: reject http-connect udp without h3");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds {
                inbound "n" type="naive" {
                    listen host="127.0.0.1" port=8443
                    tls { certificate-file "/etc/c.pem"; private-key-file "/etc/k.pem"; }
                    authentication { user "u" username="u" password-file="/tmp/p"; }
                    fallback-status 407
                }
            }
            outbounds { outbound "d" type="direct"; }; routing { final "d"; }
        )").has_value(), "151B: reject naive fallback-status 407");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds {
                outbound "n" type="naive" {
                    protocol "h3"; server host="127.0.0.1" port=8443
                    authentication username="u" password-file="/tmp/p"
                    tls { server-name "localhost"; ca-file "/etc/ca.pem"; fingerprint "tls12"; verify #true; }
                }
                outbound "direct" type="direct"
            }
            routing { final "n"; }
        )").has_value(), "151B: reject naive h3 with tls12 fingerprint");

        expect(!config::parse_kdl(R"(
            schema-version 1; role "client"
            inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
            outbounds {
                outbound "n" type="naive" {
                    protocol "h2"; server host="127.0.0.1" port=8443
                    authentication username="u" password-file="/tmp/p"
                    tls { server-name "localhost"; ca-file "/etc/ca.pem"; verify #true; }
                    extra-header "Proxy-Authorization" "Basic abc"
                }
                outbound "direct" type="direct"
            }
            routing { final "n"; }
        )").has_value(), "151B: reject forbidden Proxy-Authorization extra-header");
    }
}

auto main() -> int {
    test_naive_auth_and_headers();
    test_naive_padding_framing();
    test_multi_alpn_server_handshake();
    test_kdl_configs();
    if (failures) {
        std::cerr << "batch151-unit FAILED (" << failures << " checks)\n";
        return 1;
    }
    std::cout << "batch151-unit: ALL PASSED\n";
    return 0;
}
