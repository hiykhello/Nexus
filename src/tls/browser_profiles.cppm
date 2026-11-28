// Declarative browser uTLS ClientHello profile catalog.
// Single source of truth for per-browser wire shapes verified against real browsers
// and upstream refraction-networking/utls (audited by scripts/audit-utls.py).
// Every advertised capability here is backed by Nexus's real TLS state machine.
export module tls.browser_profiles;
import std;
export import utility.tls_fingerprint;
import tls.certificate_compression;

export namespace tls {
    using Fingerprint = utility::TlsFingerprintId;

    struct BrowserPresetSpec {
        bool valid = false;
        bool browser = false;
        std::string_view baseline{};
        bool grease = false;
        bool grease_sigalgs = false;
        bool permute = false;
        bool psk_kex_modes = false;
        bool compat_sid = false;
        bool grease_ech = false;
        bool alps_h2 = false;
        bool delegated_credentials = false;
        bool trust_anchors = false;
        bool include_p521 = false;
        bool third_key_share_p256 = false;
        std::uint16_t tcp_min_pad = 0;
        std::optional<std::uint16_t> default_rsl{};
        std::array<std::uint16_t, 3> ciphers{0x1301, 0x1302, 0x1303};
        std::uint8_t cipher_count = 3;
        std::array<std::uint16_t, 6> tls12_ciphers{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8};
        std::array<std::uint16_t, 10> signatures{0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0503, 0x0603};
        std::uint8_t sig_count = 3;
        std::array<CertificateCompression, 3> cert_comp{};
        std::uint8_t cert_comp_count = 0;
        std::array<std::uint16_t, 20> ext_order{};
        std::uint8_t ext_count = 0;
    };

    [[nodiscard]] constexpr auto browser_preset_spec(Fingerprint profile) noexcept -> BrowserPresetSpec {
        using CC = CertificateCompression;
        switch (profile) {
        case Fingerprint::native:
            return BrowserPresetSpec{
                .valid = true, .baseline = "native",
            };
        case Fingerprint::tls13_grease:
            return BrowserPresetSpec{
                .valid = true, .baseline = "tls13-grease",
                .grease = true, .grease_sigalgs = true, .compat_sid = true,
            };
        case Fingerprint::tls13_randomized:
            return BrowserPresetSpec{
                .valid = true, .baseline = "tls13-randomized",
                .grease = true, .grease_sigalgs = true, .permute = true, .compat_sid = true,
                .cert_comp = {CC::zlib, CC::brotli, CC::zstd}, .cert_comp_count = 3,
            };
        case Fingerprint::chrome:
            // Baseline: Chrome 158 (verified against Chromium main ssl_client_socket_impl.cc &
            // chrome_root_store/root_store.textproto: GREASE sigalgs, ML-DSA-44/65/87, 28 TrustAnchors 0xca34,
            // Brotli cert compression, ALPS 0x44cd, GREASE ECH, interior extension shuffle).
            return BrowserPresetSpec{
                .valid = true, .browser = true, .baseline = "chrome-158",
                .grease = true, .grease_sigalgs = true, .permute = true,
                .psk_kex_modes = true, .compat_sid = true, .grease_ech = true, .alps_h2 = true,
                .trust_anchors = true,
                .tcp_min_pad = 517,
                .ciphers = {0x1301, 0x1302, 0x1303}, .cipher_count = 3,
                .tls12_ciphers = {0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
                .signatures = {0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0503, 0x0805, 0x0806}, .sig_count = 8,
                .cert_comp = {CC::brotli}, .cert_comp_count = 1,
            };
        case Fingerprint::edge:
            // Baseline: Chromium Edge 158 (aligned with Chromium 158 BoringSSL stack).
            return BrowserPresetSpec{
                .valid = true, .browser = true, .baseline = "edge-158",
                .grease = true, .grease_sigalgs = true, .permute = true,
                .psk_kex_modes = true, .compat_sid = true, .grease_ech = true, .alps_h2 = true,
                .trust_anchors = true,
                .tcp_min_pad = 517,
                .ciphers = {0x1301, 0x1302, 0x1303}, .cipher_count = 3,
                .tls12_ciphers = {0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
                .signatures = {0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0503, 0x0805, 0x0806}, .sig_count = 8,
                .cert_comp = {CC::brotli}, .cert_comp_count = 1,
            };
        case Fingerprint::firefox:
            // Baseline: Firefox 161 (verified against live Mozilla Firefox 161.0:
            // 3 initial key shares X25519MLKEM768+X25519+P256, zlib/brotli/zstd cert comp,
            // P-521 group without FFDHE, ChaCha-before-AES256, SCT before KeyShare, delegated_credentials, GREASE ECH, RSL 16385).
            return BrowserPresetSpec{
                .valid = true, .browser = true, .baseline = "firefox-161",
                .psk_kex_modes = true, .compat_sid = true, .grease_ech = true,
                .delegated_credentials = true, .include_p521 = true, .third_key_share_p256 = true,
                .default_rsl = std::uint16_t{16385},
                .ciphers = {0x1301, 0x1303, 0x1302}, .cipher_count = 3,
                .tls12_ciphers = {0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030},
                .signatures = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806}, .sig_count = 6,
                .cert_comp = {CC::zlib, CC::brotli, CC::zstd}, .cert_comp_count = 3,
                .ext_order = {0, 23, 0xff01, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 0x39, 0xfe0d},
                .ext_count = 18,
            };
        case Fingerprint::safari:
            // Baseline: Safari 26.3 (AES-256-GCM first, P-521 group, zlib cert compression,
            // Apple SecureTransport/BoringSSL extension layout with GREASE bookends).
            return BrowserPresetSpec{
                .valid = true, .browser = true, .baseline = "safari-26.3",
                .grease = true, .psk_kex_modes = true, .compat_sid = true, .include_p521 = true,
                .tcp_min_pad = 517,
                .ciphers = {0x1302, 0x1303, 0x1301}, .cipher_count = 3,
                .tls12_ciphers = {0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8},
                .signatures = {0x0403, 0x0804, 0x0503, 0x0805, 0x0806}, .sig_count = 5,
                .cert_comp = {CC::zlib}, .cert_comp_count = 1,
                .ext_order = {0, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 35, 0x39},
                .ext_count = 15,
            };
        case Fingerprint::ios:
            // Baseline: iOS 26.3 WebKit/Network.framework (aligned with Safari 26.3 PQ + zlib cert comp).
            return BrowserPresetSpec{
                .valid = true, .browser = true, .baseline = "ios-26.3",
                .grease = true, .psk_kex_modes = true, .compat_sid = true, .include_p521 = true,
                .tcp_min_pad = 517,
                .ciphers = {0x1302, 0x1303, 0x1301}, .cipher_count = 3,
                .tls12_ciphers = {0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8},
                .signatures = {0x0403, 0x0804, 0x0503, 0x0805, 0x0806}, .sig_count = 5,
                .cert_comp = {CC::zlib}, .cert_comp_count = 1,
                .ext_order = {0, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 35, 0x39},
                .ext_count = 15,
            };
        case Fingerprint::android:
            // Baseline: Android 16 Conscrypt/OkHttp (TLS 1.3 + modern AEAD TLS 1.2 + PQ hybrid curves).
            return BrowserPresetSpec{
                .valid = true, .browser = true, .baseline = "android-16",
                .psk_kex_modes = true, .compat_sid = true,
                .ciphers = {0x1301, 0x1302, 0x1303}, .cipher_count = 3,
                .tls12_ciphers = {0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8},
                .signatures = {0x0403, 0x0804, 0x0503, 0x0805, 0x0806}, .sig_count = 5,
                .ext_order = {0, 23, 0xff01, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 0x39},
                .ext_count = 14,
            };
        default:
            return BrowserPresetSpec{};
        }
    }
}
