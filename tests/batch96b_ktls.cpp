#include <cerrno>
#include <cstring>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import crypto;
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
    struct MockKernel {
        int ulp_errno = 0;
        int tx_errno = 0;
        int rx_errno = 0;
        int tx_installs = 0;
        int rx_installs = 0;
        std::vector<std::uint8_t> last_tx_opt;
        std::vector<std::uint8_t> last_rx_opt;
        std::uint8_t last_sent_type = 0;
        std::vector<std::uint8_t> last_sent_data;
        std::uint8_t next_recv_type = 23;
        std::vector<std::uint8_t> next_recv_data;
        int next_recv_errno = 0;
    };
    MockKernel g_mock;

    auto mock_setsockopt(int, int level, int optname, void const* optval, std::size_t optlen) noexcept -> int {
        if (level == SOL_TCP && optname == TCP_ULP) return g_mock.ulp_errno;
        if (level == SOL_TLS && optname == TLS_TX) {
            if (g_mock.tx_errno) return g_mock.tx_errno;
            ++g_mock.tx_installs;
            g_mock.last_tx_opt.assign(static_cast<std::uint8_t const*>(optval),
                static_cast<std::uint8_t const*>(optval) + optlen);
            return 0;
        }
        if (level == SOL_TLS && optname == TLS_RX) {
            if (g_mock.rx_errno) return g_mock.rx_errno;
            ++g_mock.rx_installs;
            g_mock.last_rx_opt.assign(static_cast<std::uint8_t const*>(optval),
                static_cast<std::uint8_t const*>(optval) + optlen);
            return 0;
        }
        return ENOPROTOOPT;
    }

    auto mock_send(int, std::uint8_t rtype, std::uint8_t const* data, std::size_t len, int*) noexcept -> std::ptrdiff_t {
        g_mock.last_sent_type = rtype;
        g_mock.last_sent_data.assign(data, data + len);
        return static_cast<std::ptrdiff_t>(len);
    }

    auto mock_recv(int, std::uint8_t* data, std::size_t cap, std::uint8_t* rtype, int* err) noexcept -> std::ptrdiff_t {
        if (g_mock.next_recv_errno) {
            if (err) *err = g_mock.next_recv_errno;
            return -1;
        }
        auto n = std::min(cap, g_mock.next_recv_data.size());
        std::memcpy(data, g_mock.next_recv_data.data(), n);
        if (rtype) *rtype = g_mock.next_recv_type;
        return static_cast<std::ptrdiff_t>(n);
    }

    auto mock_ops() noexcept -> tls::KtlsOps {
        return {&mock_setsockopt, &mock_send, &mock_recv, tls::parse_linux_kernel_release("6.14.0")};
    }

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

    auto test_abi_layouts() -> int {
        // AES-128-GCM
        tls::KtlsKeyMaterial m128;
        m128.algorithm = crypto::Aead::aes_128_gcm;
        m128.key.assign(16, 0xAB);
        m128.iv = {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
        m128.sequence = 0x0102030405060708ull;
        auto b128 = tls::encode_ktls_crypto_info(m128);
        if (!b128 || b128->size != sizeof(tls12_crypto_info_aes_gcm_128)) return 1;
        tls12_crypto_info_aes_gcm_128 c128{};
        std::memcpy(&c128, b128->bytes.data(), sizeof(c128));
        if (c128.info.version != TLS_1_3_VERSION || c128.info.cipher_type != TLS_CIPHER_AES_GCM_128) return 2;
        if (c128.salt[0] != 0x01 || c128.salt[3] != 0x04 || c128.iv[0] != 0x05 || c128.iv[7] != 0x0C) return 3;
        if (c128.rec_seq[0] != 0x01 || c128.rec_seq[7] != 0x08) return 4;

        // AES-256-GCM
        tls::KtlsKeyMaterial m256;
        m256.algorithm = crypto::Aead::aes_256_gcm;
        m256.key.assign(32, 0xCD);
        m256.iv = {1,2,3,4,5,6,7,8,9,10,11,12};
        m256.sequence = 42;
        auto b256 = tls::encode_ktls_crypto_info(m256);
        if (!b256 || b256->size != sizeof(tls12_crypto_info_aes_gcm_256)) return 5;

        // ChaCha20-Poly1305
        tls::KtlsKeyMaterial mch;
        mch.algorithm = crypto::Aead::chacha20_poly1305;
        mch.key.assign(32, 0xEF);
        mch.iv = {10,11,12,13,14,15,16,17,18,19,20,21};
        mch.sequence = 9;
        auto bch = tls::encode_ktls_crypto_info(mch);
        if (!bch || bch->size != sizeof(tls12_crypto_info_chacha20_poly1305)) return 6;
        tls12_crypto_info_chacha20_poly1305 cch{};
        std::memcpy(&cch, bch->bytes.data(), sizeof(cch));
        if (cch.info.cipher_type != TLS_CIPHER_CHACHA20_POLY1305 || cch.iv[0] != 10 || cch.iv[11] != 21 || cch.rec_seq[7] != 9) return 7;
        return 0;
    }

    auto test_unavailable_fallback_preserves_userspace() -> int {
        g_mock = {};
        g_mock.ulp_errno = ENOENT;
        auto io = make_app_io(crypto::Aead::aes_128_gcm);
        tls::KtlsSession ktls(tls::ApplicationRole::client, mock_ops());
        if (ktls.offload(99, io) != tls::KtlsStatus::unavailable) return 10;
        if (ktls.tx_active() || ktls.rx_active()) return 11;
        // User-space TLS MUST still work cleanly with zero state mutation!
        std::array<std::uint8_t, 5> msg{'h','e','l','l','o'};
        if (!io.send(msg) || io.pending_output().empty()) return 12;
        return 0;
    }

    auto test_handoff_no_nonce_reuse_and_key_update() -> int {
        g_mock = {};
        auto io = make_app_io(crypto::Aead::aes_256_gcm);
        // Send 1 user-space record first (sequence becomes 1!)
        std::array<std::uint8_t, 4> pre{'p','i','n','g'};
        if (!io.send(pre)) return 20;
        auto plen = io.pending_output().size();
        if (!io.written(plen)) return 21;

        tls::KtlsSession ktls(tls::ApplicationRole::client, mock_ops());
        if (ktls.offload(99, io) != tls::KtlsStatus::ok) return 22;
        if (!ktls.tx_active() || !ktls.rx_active() || g_mock.tx_installs != 1 || g_mock.rx_installs != 1) return 23;
        // Verify handed-off TX sequence is EXACTLY 1 (not 0!)
        tls12_crypto_info_aes_gcm_256 tx_info{};
        std::memcpy(&tx_info, g_mock.last_tx_opt.data(), sizeof(tx_info));
        if (tx_info.rec_seq[7] != 1) return 24;
        // Verify user-space ApplicationIo can NEVER reuse handed-off keys!
        if (io.send(pre)) return 25;
        if (io.take_ktls_tx().has_value() || io.take_ktls_rx().has_value()) return 26;

        // Verify recvmsg control messages: app data, KeyUpdate(request=1) -> RX rekey + TX rekey, close_notify
        std::array<std::uint8_t, 64> buf{};
        g_mock.next_recv_type = 23;
        g_mock.next_recv_data = {'o','k'};
        auto r1 = ktls.recv_record(99, buf);
        if (r1.kind != tls::KtlsRecvKind::data || r1.bytes != 2) return 27;

        // Peer sends KeyUpdate with update_requested=1
        g_mock.next_recv_type = 22;
        g_mock.next_recv_data = {24, 0, 0, 1, 1};
        auto old_rx_opt = g_mock.last_rx_opt;
        auto r2 = ktls.recv_record(99, buf);
        if (r2.kind != tls::KtlsRecvKind::key_update_requested) return 28;
        if (g_mock.rx_installs != 2 || g_mock.last_rx_opt == old_rx_opt) return 29;
        // Respond with TX KeyUpdate(0)
        auto old_tx_opt = g_mock.last_tx_opt;
        if (ktls.rekey_tx(99, false) != tls::KtlsStatus::ok) return 30;
        if (g_mock.last_sent_type != 22 || g_mock.last_sent_data != std::vector<std::uint8_t>{24,0,0,1,0}) return 31;
        if (g_mock.tx_installs != 2 || g_mock.last_tx_opt == old_tx_opt) return 32;
        // New TX rec_seq must be reset to 0 after KeyUpdate!
        std::memcpy(&tx_info, g_mock.last_tx_opt.data(), sizeof(tx_info));
        if (tx_info.rec_seq[7] != 0) return 33;

        // Close notify alert
        g_mock.next_recv_type = 21;
        g_mock.next_recv_data = {1, 0};
        auto r3 = ktls.recv_record(99, buf);
        if (r3.kind != tls::KtlsRecvKind::close_notify) return 34;
        if (ktls.send_close_notify(99) != tls::KtlsStatus::ok || g_mock.last_sent_type != 21) return 35;

        // Control-message truncation (EBADMSG returned by posix_recv_record on MSG_CTRUNC)
        g_mock.next_recv_errno = EBADMSG;
        auto r4 = ktls.recv_record(99, buf);
        if (r4.kind == tls::KtlsRecvKind::data) return 36;
        g_mock.next_recv_errno = 0;
        return 0;
    }

    auto test_half_install_safety() -> int {
        g_mock = {};
        g_mock.rx_errno = EOPNOTSUPP;
        auto io = make_app_io(crypto::Aead::chacha20_poly1305);
        tls::KtlsSession ktls(tls::ApplicationRole::client, mock_ops());
        if (ktls.offload(99, io) != tls::KtlsStatus::fatal_error) return 40;
        if (!ktls.failed() || ktls.tx_active() || ktls.rx_active()) return 41;
        // Extracted TX/RX keys must NOT be usable in user space after half-failure!
        std::array<std::uint8_t, 3> d{1,2,3};
        if (io.send(d)) return 42;
        return 0;
    }

    auto test_real_kernel_probe() -> int {
        int fds[2]{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return 50;
        auto st = tls::probe_ktls_ulp(fds[0]); // AF_UNIX doesn't support TCP_ULP -> unavailable or fatal
        ::close(fds[0]); ::close(fds[1]);
        if (st == tls::KtlsStatus::ok) return 51;
        return 0;
    }
}

auto main() -> int {
    if (auto rc = test_abi_layouts(); rc != 0) return rc;
    if (auto rc = test_unavailable_fallback_preserves_userspace(); rc != 0) return rc;
    if (auto rc = test_handoff_no_nonce_reuse_and_key_update(); rc != 0) return rc;
    if (auto rc = test_half_install_safety(); rc != 0) return rc;
    if (auto rc = test_real_kernel_probe(); rc != 0) return rc;
    std::println("ALL BATCH 96B LINUX kTLS TESTS PASSED (ABI, fallback, zero-nonce-reuse, KeyUpdate, close_notify, half-install)");
    return 0;
}
