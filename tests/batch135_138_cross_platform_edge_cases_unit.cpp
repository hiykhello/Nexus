#include <cerrno>
#include <cstring>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

import std;
import crypto;
import platform.ip_address;
import platform.platform_defaults;
import dns.local_config;
import net.happy_eyeballs;
import quic.packet_keys;
import quic.varint;
import sniff.quic;
import tls.record;
import tls.client_flight;
import tls.application_io;
import tls.ktls;

#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

namespace {
    constexpr std::string_view kSampleCryptoPayload =
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113"
        "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1"
        "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806"
        "048000ffff";

    auto hex_bytes(std::string_view value) -> std::vector<std::uint8_t> {
        auto digit = [](char c) -> int { return c <= '9' ? c - '0' : c - 'a' + 10; };
        std::vector<std::uint8_t> out;
        out.reserve(value.size() / 2);
        for (std::size_t i = 0; i < value.size(); i += 2)
            out.push_back(static_cast<std::uint8_t>((digit(value[i]) << 4) | digit(value[i + 1])));
        return out;
    }

    auto seal_initial_packet(std::uint8_t pn_byte, std::vector<std::uint8_t> plain) -> std::vector<std::uint8_t> {
        while (plain.size() < 4) plain.push_back(0);
        auto cid = hex_bytes("8394c8f03e515708");
        quic::InitialSecrets secrets;
        if (!secrets.reset(1, cid)) std::abort();
        quic::PacketKeys keys;
        if (!keys.reset(quic::PacketSuite::aes128_gcm_sha256, secrets.client())) std::abort();
        std::vector<std::uint8_t> header{0xc0, 0, 0, 0, 1, 8};
        header.insert(header.end(), cid.begin(), cid.end());
        header.push_back(0);
        header.push_back(0);
        std::array<std::uint8_t, 2> length{};
        if (!quic::write_varint(length, 1 + plain.size() + 16, 2)) std::abort();
        header.insert(header.end(), length.begin(), length.end());
        auto pn_off = header.size();
        header.push_back(pn_byte);
        auto nonce = quic::packet_nonce(keys.iv(), pn_byte);
        if (!nonce) std::abort();
        std::vector<std::uint8_t> ct(plain.size() + 16);
        if (!keys.seal_to(ct, *nonce, plain, header)) std::abort();
        auto wire = header;
        wire.insert(wire.end(), ct.begin(), ct.end());
        std::array<std::uint8_t, 16> mask{};
        if (!keys.mask_to(mask, std::span<std::uint8_t const, 16>(wire.data() + pn_off + 4, 16))) std::abort();
        wire[0] ^= mask[0] & 0x0f;
        wire[pn_off] ^= mask[1];
        return wire;
    }

    struct MockKtls {
        int ulp_calls = 0;
        int tx_calls = 0;
        int rx_calls = 0;
        int zerocopy_calls = 0;
        int nopad_calls = 0;
    };
    MockKtls g_mock;

    auto mock_setsockopt(int, int level, int optname, void const*, std::size_t) noexcept -> int {
        if (level == SOL_TCP && optname == TCP_ULP) { ++g_mock.ulp_calls; return 0; }
        if (level == SOL_TLS && optname == TLS_TX) { ++g_mock.tx_calls; return 0; }
        if (level == SOL_TLS && optname == TLS_RX) { ++g_mock.rx_calls; return 0; }
#ifdef TLS_TX_ZEROCOPY_RO
        if (level == SOL_TLS && optname == TLS_TX_ZEROCOPY_RO) { ++g_mock.zerocopy_calls; return 0; }
#endif
#ifdef TLS_RX_EXPECT_NO_PAD
        if (level == SOL_TLS && optname == TLS_RX_EXPECT_NO_PAD) { ++g_mock.nopad_calls; return 0; }
#endif
        return ENOPROTOOPT;
    }

    auto mock_send(int, std::uint8_t, std::uint8_t const*, std::size_t len, int*) noexcept -> std::ptrdiff_t {
        return static_cast<std::ptrdiff_t>(len);
    }
    auto mock_recv(int, std::uint8_t*, std::size_t, std::uint8_t*, int*) noexcept -> std::ptrdiff_t { return 0; }

    auto make_app_io(crypto::Aead aead) -> tls::ApplicationIo {
        std::size_t klen = (aead == crypto::Aead::aes_128_gcm) ? 16 : 32;
        std::vector<std::uint8_t> wkey(klen, 0x11), rkey(klen, 0x22);
        std::array<std::uint8_t, 12> wiv{1,2,3,4,5,6,7,8,9,10,11,12};
        std::array<std::uint8_t, 12> riv{21,22,23,24,25,26,27,28,29,30,31,32};
        auto wl = tls::RecordLayer::create(tls::RecordDirection::send, aead, wkey, wiv);
        auto rl = tls::RecordLayer::create(tls::RecordDirection::receive, aead, rkey, riv);
        if (!wl || !rl) std::abort();
        crypto::Bytes ws(32, 0x33), rs(32, 0x44);
        tls::Secret wsec(std::move(ws)), rsec(std::move(rs));
        tls::ApplicationRecords recs(std::move(*wl), std::move(*rl), 16385, 16385,
            crypto::Hash::sha256, aead, klen, std::move(wsec), std::move(rsec), tls::ApplicationRole::client);
        return tls::ApplicationIo(std::move(recs));
    }

    auto test_platform_defaults() -> int {
        using platform::TargetPlatform;
        // MTU defaults & safe ceilings
        if (platform::default_tun_mtu(TargetPlatform::apple_network_extension) != 4064) return 1;
        if (platform::default_tun_mtu(TargetPlatform::android_vpn) != 9000) return 2;
        if (platform::default_tun_mtu(TargetPlatform::windows_wintun) != 1500) return 3;
        if (platform::clamp_tun_mtu(TargetPlatform::apple_network_extension, 9000) != 4064) return 4;
        if (platform::clamp_tun_mtu(TargetPlatform::apple_network_extension, 4096) != 4064) return 5;
        if (platform::clamp_tun_mtu(TargetPlatform::android_vpn, 65535) != 9000) return 6;
        if (platform::clamp_tun_mtu(TargetPlatform::linux_native, 500) != 1280) return 7;
        if (platform::clamp_tun_mtu(TargetPlatform::apple_network_extension, 0) != 4064) return 8;

        // Linux TUN GSO < 49152
        if (!platform::allow_tun_gso(TargetPlatform::linux_native, 9000)) return 9;
        if (!platform::allow_tun_gso(TargetPlatform::linux_native, 49151)) return 10;
        if (platform::allow_tun_gso(TargetPlatform::linux_native, 49152)) return 11;
        if (platform::allow_tun_gso(TargetPlatform::apple_network_extension, 4064)) return 12;

        // Darwin pcblist_n alignment stride & Windows PIDs & Android AppID/Zygote
        if (platform::darwin_pcblist_struct_size(21) != 384 || platform::darwin_pcblist_struct_size(22) != 408) return 13;
        if (platform::windows_special_process_name(0) != ":System Idle Process" ||
            platform::windows_special_process_name(4) != ":System" ||
            !platform::windows_special_process_name(42).empty()) return 14;
        if (platform::android_app_id(10042) != 10042 || platform::android_app_id(110042) != 10042 ||
            platform::android_app_id(1010042) != 10042) return 15;
        if (!platform::is_android_zygote_noise("/system/bin/app_process64") ||
            !platform::is_android_zygote_noise("/system/bin/app_process32") ||
            platform::is_android_zygote_noise("/usr/bin/curl")) return 16;

        // Winsock2 IP_UNICAST_IF (big-endian) vs IPV6_UNICAST_IF (host-endian)
        if (platform::windows_unicast_if_option_value(5, true) != 5u) return 17;
        if (platform::windows_unicast_if_option_value(5, false) != platform::host_to_net32(5u)) return 18;
        if (std::endian::native == std::endian::little &&
            platform::windows_unicast_if_option_value(0x01020304u, false) != 0x04030201u) return 19;

        // Windows fec0::/10 phantom IPv6 DNS detector
        auto fake = platform::parse_ip_address("fec0:0:0:ffff::1");
        auto edge = platform::parse_ip_address("feff::1");
        auto link_local = platform::parse_ip_address("fe80::1");
        auto google = platform::parse_ip_address("2001:4860:4860::8888");
        if (!fake || !edge || !link_local || !google) return 20;
        if (!platform::is_windows_site_local_fake_dns(fake->bytes) ||
            !platform::is_windows_site_local_fake_dns(edge->bytes) ||
            platform::is_windows_site_local_fake_dns(link_local->bytes) ||
            platform::is_windows_site_local_fake_dns(google->bytes)) return 21;
        return 0;
    }

    auto test_dns_fec0_filter() -> int {
        auto parsed = dns::parse_local_resolv(
            "nameserver fec0:0:0:ffff::1\n"
            "nameserver fec0:0:0:ffff::2\n"
            "nameserver fec0:0:0:ffff::3\n"
            "nameserver 8.8.8.8\n"
            "nameserver 2001:4860:4860::8888\n");
        if (!parsed || parsed->servers.size() != 2) return 30;
        if (parsed->servers[0].ipv6 || !parsed->servers[1].ipv6) return 31;

        auto only_fake = dns::parse_local_resolv("nameserver fec0:0:0:ffff::1\nnameserver fec0:0:0:ffff::2\n");
        if (only_fake || only_fake.error() != dns::LocalConfigError::no_servers) return 32;
        return 0;
    }

    auto test_happy_eyeballs() -> int {
        struct Ep { bool v6; int id; auto operator==(Ep const&) const -> bool = default; };
        auto is_v6 = [](Ep const& e) noexcept { return e.v6; };

        std::array<Ep, 5> dual{{{true, 1}, {true, 2}, {true, 3}, {false, 10}, {false, 20}}};
        if (!net::has_dual_stack_families(std::span<Ep const>(dual), is_v6)) return 40;
        auto interleaved = net::interleave_happy_eyeballs(std::span<Ep const>(dual), is_v6, true);
        std::vector<Ep> expect_v6_first{{true, 1}, {false, 10}, {true, 2}, {false, 20}, {true, 3}};
        if (interleaved != expect_v6_first) return 41;

        auto v4_first = net::interleave_happy_eyeballs(std::span<Ep const>(dual), is_v6, false);
        std::vector<Ep> expect_v4_first{{false, 10}, {true, 1}, {false, 20}, {true, 2}, {true, 3}};
        if (v4_first != expect_v4_first) return 42;

        std::array<Ep, 2> single_v4{{{false, 1}, {false, 2}}};
        if (net::has_dual_stack_families(std::span<Ep const>(single_v4), is_v6)) return 43;
        auto keep = net::interleave_happy_eyeballs(std::span<Ep const>(single_v4), is_v6);
        if (keep.size() != 2 || keep[0] != single_v4[0] || keep[1] != single_v4[1]) return 44;
        if (net::kHappyEyeballsFallbackDelay != std::chrono::milliseconds{300}) return 45;
        return 0;
    }

    auto test_ktls_kernel_matrix() -> int {
        auto k419 = tls::parse_linux_kernel_release("4.19.128-lts");
        if (k419.tx_aes_gcm || k419.rx_tls13 || k419.chacha20_poly1305 || k419.supports_cipher(crypto::Aead::aes_128_gcm)) return 50;
        auto k51 = tls::parse_linux_kernel_release("5.1.0");
        if (!k51.tx_aes_gcm || !k51.rx_tls13 || k51.chacha20_poly1305 || k51.tx_zerocopy_ro) return 51;
        auto k510 = tls::parse_linux_kernel_release("5.10.220-android12");
        if (!k510.supports_cipher(crypto::Aead::aes_256_gcm) || k510.supports_cipher(crypto::Aead::chacha20_poly1305)) return 52;
        auto k511 = tls::parse_linux_kernel_release("5.11.0-generic");
        if (!k511.chacha20_poly1305 || k511.tx_zerocopy_ro) return 53;
        auto k519 = tls::parse_linux_kernel_release("5.19.17");
        if (!k519.tx_zerocopy_ro || k519.rx_expect_no_pad) return 54;
        auto k60 = tls::parse_linux_kernel_release("6.0.0");
        if (!k60.rx_expect_no_pad || k60.key_update) return 55;
        auto k614 = tls::parse_linux_kernel_release("6.14.2-arch1");
        if (!k614.key_update) return 56;
        auto k73 = tls::parse_linux_kernel_release("7.3.5-2-cachyos");
        if (!k73.key_update || !k73.rx_expect_no_pad || !k73.tx_zerocopy_ro) return 57;
        auto bad = tls::parse_linux_kernel_release("invalid");
        if (bad.tx_aes_gcm || bad.rx_tls13) return 58;

        // Pre-handoff kernel matrix check: 5.4 rejects ChaCha20 BEFORE touching setsockopt or user-space keys!
        g_mock = {};
        tls::KtlsOps old_ops{&mock_setsockopt, &mock_send, &mock_recv, tls::parse_linux_kernel_release("5.4.0")};
        auto io_chacha = make_app_io(crypto::Aead::chacha20_poly1305);
        tls::KtlsSession s_old(tls::ApplicationRole::client, old_ops);
        if (s_old.offload(77, io_chacha) != tls::KtlsStatus::unavailable) return 59;
        if (g_mock.ulp_calls != 0 || g_mock.tx_calls != 0 || g_mock.rx_calls != 0) return 60;
        std::array<std::uint8_t, 4> payload{'t','e','s','t'};
        if (!io_chacha.send(payload) || io_chacha.pending_output().empty()) return 61;

        // Modern 6.6 kernel installs TX+RX and applies best-effort perf sockopts!
        g_mock = {};
        tls::KtlsOps modern_ops{&mock_setsockopt, &mock_send, &mock_recv, tls::parse_linux_kernel_release("6.6.12")};
        auto io_aes = make_app_io(crypto::Aead::aes_128_gcm);
        tls::KtlsSession s_new(tls::ApplicationRole::client, modern_ops);
        if (s_new.offload(77, io_aes) != tls::KtlsStatus::ok) return 62;
        if (g_mock.ulp_calls != 1 || g_mock.tx_calls != 1 || g_mock.rx_calls != 1) return 63;
#ifdef TLS_TX_ZEROCOPY_RO
        if (g_mock.zerocopy_calls != 1) return 64;
#endif
#ifdef TLS_RX_EXPECT_NO_PAD
        if (g_mock.nopad_calls != 1) return 65;
#endif
        return 0;
    }

    auto test_quic_connection_close_sniff() -> int {
        auto sample = hex_bytes(kSampleCryptoPayload);
        auto hello = std::span(sample).subspan(4);

        // Build Initial plaintext: CONNECTION_CLOSE (0x1c) followed by CRYPTO (0x06) frame.
        std::vector<std::uint8_t> plain;
        (void)quic::append_varint(plain, 0x1c); // CONNECTION_CLOSE (transport)
        (void)quic::append_varint(plain, 0x0a); // error_code
        (void)quic::append_varint(plain, 0x06); // frame_type
        std::string_view reason = "early-close";
        (void)quic::append_varint(plain, reason.size());
        plain.insert(plain.end(), reason.begin(), reason.end());
        (void)quic::append_varint(plain, 0x06); // CRYPTO
        (void)quic::append_varint(plain, 0);    // offset
        (void)quic::append_varint(plain, hello.size());
        plain.insert(plain.end(), hello.begin(), hello.end());

        auto pkt = seal_initial_packet(0, std::move(plain));
        sniff::QuicSniffer sniffer;
        auto res = sniffer.feed(pkt);
        if (res.status != sniff::QuicSniffStatus::matched || res.server_name != "example.com") return 70;

        // Truncated CONNECTION_CLOSE reason_len > remaining must return malformed!
        std::vector<std::uint8_t> bad_plain;
        (void)quic::append_varint(bad_plain, 0x1c);
        (void)quic::append_varint(bad_plain, 0x01);
        (void)quic::append_varint(bad_plain, 0x00);
        (void)quic::append_varint(bad_plain, 99);
        bad_plain.push_back('x');
        auto bad_pkt = seal_initial_packet(0, std::move(bad_plain));
        sniff::QuicSniffer bad_sniffer;
        if (bad_sniffer.feed(bad_pkt).status != sniff::QuicSniffStatus::malformed) return 71;
        return 0;
    }
}

auto main() -> int {
    if (auto rc = test_platform_defaults(); rc != 0) { std::println("FAIL platform_defaults rc={}", rc); return rc; }
    if (auto rc = test_dns_fec0_filter(); rc != 0) { std::println("FAIL dns_fec0_filter rc={}", rc); return rc; }
    if (auto rc = test_happy_eyeballs(); rc != 0) { std::println("FAIL happy_eyeballs rc={}", rc); return rc; }
    if (auto rc = test_ktls_kernel_matrix(); rc != 0) { std::println("FAIL ktls_kernel_matrix rc={}", rc); return rc; }
    if (auto rc = test_quic_connection_close_sniff(); rc != 0) { std::println("FAIL quic_0x1c rc={}", rc); return rc; }
    std::println("ALL BATCH 135-138 CROSS-PLATFORM & EDGE-CASE UNIT TESTS PASSED!");
    return 0;
}
