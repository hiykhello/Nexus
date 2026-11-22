module;
#include <cerrno>
#include <cstring>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/utsname.h>

module tls.ktls;
import tls.handshake;
import tls.post_handshake;
import std;

#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

namespace tls {
    namespace {
        auto write_be64(std::uint8_t* dst, std::uint64_t v) noexcept -> void {
            for (std::size_t i = 0; i < 8; ++i)
                dst[7 - i] = static_cast<std::uint8_t>(v >> (8 * i));
        }

        auto posix_setsockopt(int fd, int level, int optname, void const* optval, std::size_t optlen) noexcept -> int {
            if (::setsockopt(fd, level, optname, optval, static_cast<socklen_t>(optlen)) == 0) return 0;
            return errno;
        }

        auto posix_send_record(int fd, std::uint8_t record_type, std::uint8_t const* data, std::size_t len, int* err_out) noexcept -> std::ptrdiff_t {
            msghdr msg{};
            iovec iov{const_cast<std::uint8_t*>(data), len};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(std::uint8_t))> cbuf{};
            if (record_type != static_cast<std::uint8_t>(ContentType::application_data)) {
                msg.msg_control = cbuf.data();
                msg.msg_controllen = cbuf.size();
                auto* cm = CMSG_FIRSTHDR(&msg);
                cm->cmsg_level = SOL_TLS;
                cm->cmsg_type = TLS_SET_RECORD_TYPE;
                cm->cmsg_len = CMSG_LEN(sizeof(std::uint8_t));
                std::memcpy(CMSG_DATA(cm), &record_type, sizeof(std::uint8_t));
            }
            ssize_t n = -1;
            do {
                n = ::sendmsg(fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
            } while (n < 0 && errno == EINTR);
            if (n < 0 && err_out) *err_out = errno;
            return n;
        }

        auto posix_recv_record(int fd, std::uint8_t* data, std::size_t cap, std::uint8_t* record_type_out, int* err_out) noexcept -> std::ptrdiff_t {
            msghdr msg{};
            iovec iov{data, cap};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(std::uint8_t)) + 64> cbuf{};
            msg.msg_control = cbuf.data();
            msg.msg_controllen = cbuf.size();
            ssize_t n = -1;
            do {
                n = ::recvmsg(fd, &msg, MSG_DONTWAIT);
            } while (n < 0 && errno == EINTR);
            if (n < 0) {
                if (err_out) *err_out = errno;
                return -1;
            }
            std::uint8_t rtype = static_cast<std::uint8_t>(ContentType::application_data);
            for (auto* cm = CMSG_FIRSTHDR(&msg); cm != nullptr; cm = CMSG_NXTHDR(&msg, cm)) {
                if (cm->cmsg_level == SOL_TLS && cm->cmsg_type == TLS_GET_RECORD_TYPE &&
                    cm->cmsg_len >= CMSG_LEN(sizeof(std::uint8_t))) {
                    std::memcpy(&rtype, CMSG_DATA(cm), sizeof(std::uint8_t));
                    break;
                }
            }
            if (record_type_out) *record_type_out = rtype;
            return n;
        }

        auto is_unavailable_errno(int err) noexcept -> bool {
            return err == ENOENT || err == ENOPROTOOPT || err == EOPNOTSUPP || err == EPROTONOSUPPORT || err == EAFNOSUPPORT;
        }
    }

    auto parse_linux_kernel_release(std::string_view release) noexcept -> KtlsKernelSupport {
        KtlsKernelSupport s;
        auto dot = release.find('.');
        if (dot == release.npos || dot == 0) return s;
        int maj = 0, min = 0;
        auto [p1, e1] = std::from_chars(release.data(), release.data() + dot, maj);
        if (e1 != std::errc{} || p1 != release.data() + dot || maj < 0) return s;
        auto rest = release.substr(dot + 1);
        std::size_t digits = 0;
        while (digits < rest.size() && rest[digits] >= '0' && rest[digits] <= '9') ++digits;
        if (!digits) return s;
        auto [p2, e2] = std::from_chars(rest.data(), rest.data() + digits, min);
        if (e2 != std::errc{} || p2 != rest.data() + digits || min < 0) return s;
        auto at_least = [&](int req_maj, int req_min) noexcept -> bool {
            return maj > req_maj || (maj == req_maj && min >= req_min);
        };
        s.major = maj;
        s.minor = min;
        s.tx_aes_gcm = at_least(5, 1);
        s.rx_tls13 = at_least(5, 1);
        s.chacha20_poly1305 = at_least(5, 11);
        s.tx_zerocopy_ro = at_least(5, 19);
        s.rx_expect_no_pad = at_least(6, 0);
        s.key_update = at_least(6, 14);
        return s;
    }

    auto probe_ktls_kernel_support() noexcept -> KtlsKernelSupport {
        static KtlsKernelSupport const cached = []() noexcept -> KtlsKernelSupport {
            struct utsname info{};
            if (::uname(&info) != 0) return {};
            return parse_linux_kernel_release(std::string_view(info.release));
        }();
        return cached;
    }

    auto default_ktls_ops() noexcept -> KtlsOps {
        return {&posix_setsockopt, &posix_send_record, &posix_recv_record, std::nullopt};
    }

    auto encode_ktls_crypto_info(KtlsKeyMaterial const& m) noexcept -> std::optional<KtlsCryptoBlob> {
        KtlsCryptoBlob blob;
        if (m.algorithm == crypto::Aead::aes_128_gcm) {
            if (m.key.size() != TLS_CIPHER_AES_GCM_128_KEY_SIZE) return {};
            tls12_crypto_info_aes_gcm_128 info{};
            info.info.version = TLS_1_3_VERSION;
            info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
            std::memcpy(info.salt, m.iv.data(), TLS_CIPHER_AES_GCM_128_SALT_SIZE);
            std::memcpy(info.iv, m.iv.data() + TLS_CIPHER_AES_GCM_128_SALT_SIZE, TLS_CIPHER_AES_GCM_128_IV_SIZE);
            std::memcpy(info.key, m.key.data(), TLS_CIPHER_AES_GCM_128_KEY_SIZE);
            write_be64(info.rec_seq, m.sequence);
            static_assert(sizeof(info) <= sizeof(blob.bytes));
            std::memcpy(blob.bytes.data(), &info, sizeof(info));
            blob.size = sizeof(info);
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&info), sizeof(info)));
            return blob;
        }
        if (m.algorithm == crypto::Aead::aes_256_gcm) {
            if (m.key.size() != TLS_CIPHER_AES_GCM_256_KEY_SIZE) return {};
            tls12_crypto_info_aes_gcm_256 info{};
            info.info.version = TLS_1_3_VERSION;
            info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
            std::memcpy(info.salt, m.iv.data(), TLS_CIPHER_AES_GCM_256_SALT_SIZE);
            std::memcpy(info.iv, m.iv.data() + TLS_CIPHER_AES_GCM_256_SALT_SIZE, TLS_CIPHER_AES_GCM_256_IV_SIZE);
            std::memcpy(info.key, m.key.data(), TLS_CIPHER_AES_GCM_256_KEY_SIZE);
            write_be64(info.rec_seq, m.sequence);
            static_assert(sizeof(info) <= sizeof(blob.bytes));
            std::memcpy(blob.bytes.data(), &info, sizeof(info));
            blob.size = sizeof(info);
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&info), sizeof(info)));
            return blob;
        }
        if (m.algorithm == crypto::Aead::chacha20_poly1305) {
            if (m.key.size() != TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE) return {};
            tls12_crypto_info_chacha20_poly1305 info{};
            info.info.version = TLS_1_3_VERSION;
            info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
            std::memcpy(info.iv, m.iv.data(), TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
            std::memcpy(info.key, m.key.data(), TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
            write_be64(info.rec_seq, m.sequence);
            static_assert(sizeof(info) <= sizeof(blob.bytes));
            std::memcpy(blob.bytes.data(), &info, sizeof(info));
            blob.size = sizeof(info);
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&info), sizeof(info)));
            return blob;
        }
        return {};
    }

    auto probe_ktls_ulp(int fd, KtlsOps ops) noexcept -> KtlsStatus {
        if (fd < 0 || !ops.setsockopt_fn) return KtlsStatus::invalid_state;
        int err = ops.setsockopt_fn(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
        if (err == 0 || err == EEXIST) return KtlsStatus::ok;
        if (is_unavailable_errno(err)) return KtlsStatus::unavailable;
        return KtlsStatus::fatal_error;
    }

    auto KtlsSession::attach_ulp(int fd) noexcept -> KtlsStatus {
        if (failed_) return KtlsStatus::fatal_error;
        if (ulp_attached_) return KtlsStatus::ok;
        auto status = probe_ktls_ulp(fd, ops_);
        if (status == KtlsStatus::ok) ulp_attached_ = true;
        return status;
    }

    auto KtlsSession::install_raw(int fd, KtlsDirection dir, KtlsKeyMaterial const& material) noexcept -> KtlsStatus {
        if (fd < 0 || !ops_.setsockopt_fn || !ulp_attached_ || failed_) return KtlsStatus::invalid_state;
        auto blob = encode_ktls_crypto_info(material);
        if (!blob) { failed_ = true; return KtlsStatus::fatal_error; }
        int opt = (dir == KtlsDirection::tx) ? TLS_TX : TLS_RX;
        int err = ops_.setsockopt_fn(fd, SOL_TLS, opt, blob->bytes.data(), blob->size);
        if (err != 0) {
            failed_ = true;
            return KtlsStatus::fatal_error;
        }
        return KtlsStatus::ok;
    }

    auto KtlsSession::install_tx(int fd, ApplicationRecords::KtlsDirectionHandoff&& handoff) noexcept -> KtlsStatus {
        if (tx_active_ || failed_ || !ulp_attached_) return KtlsStatus::invalid_state;
        auto st = install_raw(fd, KtlsDirection::tx, handoff.keys);
        if (st != KtlsStatus::ok) return st;
        algorithm_ = handoff.keys.algorithm;
        hash_ = handoff.hash;
        tx_secret_.emplace(std::move(handoff.secret));
        tx_active_ = true;
        return KtlsStatus::ok;
    }

    auto KtlsSession::install_rx(int fd, ApplicationRecords::KtlsDirectionHandoff&& handoff) noexcept -> KtlsStatus {
        if (rx_active_ || failed_ || !ulp_attached_) return KtlsStatus::invalid_state;
        auto st = install_raw(fd, KtlsDirection::rx, handoff.keys);
        if (st != KtlsStatus::ok) return st;
        algorithm_ = handoff.keys.algorithm;
        hash_ = handoff.hash;
        rx_secret_.emplace(std::move(handoff.secret));
        rx_active_ = true;
        return KtlsStatus::ok;
    }

    auto KtlsSession::offload(int fd, ApplicationIo& io, bool want_tx, bool want_rx) noexcept -> KtlsStatus {
        if ((!want_tx && !want_rx) || failed_) return KtlsStatus::invalid_state;
        if (want_tx && !io.can_handoff_ktls_tx()) return KtlsStatus::invalid_state;
        if (want_rx && !io.can_handoff_ktls_rx()) return KtlsStatus::invalid_state;
        auto const support = ops_.kernel_override.value_or(probe_ktls_kernel_support());
        auto const alg = io.ktls_algorithm();
        if (!alg || !support.supports_cipher(*alg) || (want_rx && !support.rx_tls13))
            return KtlsStatus::unavailable;
        auto ulp = attach_ulp(fd);
        if (ulp != KtlsStatus::ok) return ulp; // User-space keys untouched on unavailable!
        if (want_tx) {
            auto tx = io.take_ktls_tx();
            if (!tx) { failed_ = true; return KtlsStatus::fatal_error; }
            if (auto st = install_tx(fd, std::move(*tx)); st != KtlsStatus::ok) return st;
#ifdef TLS_TX_ZEROCOPY_RO
            if (support.tx_zerocopy_ro && ops_.setsockopt_fn) {
                int one = 1;
                (void)ops_.setsockopt_fn(fd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &one, sizeof(one));
            }
#endif
        }
        if (want_rx) {
            auto rx = io.take_ktls_rx();
            if (!rx) { failed_ = true; return KtlsStatus::fatal_error; }
            if (auto st = install_rx(fd, std::move(*rx)); st != KtlsStatus::ok) return st;
#ifdef TLS_RX_EXPECT_NO_PAD
            if (support.rx_expect_no_pad && ops_.setsockopt_fn) {
                int one = 1;
                (void)ops_.setsockopt_fn(fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD, &one, sizeof(one));
            }
#endif
        }
        return KtlsStatus::ok;
    }

    auto KtlsSession::send_application(int fd, std::span<std::uint8_t const> data, int* err_out) noexcept -> std::ptrdiff_t {
        if (!tx_active_ || tx_closed_ || failed_ || !ops_.send_record_fn) {
            if (err_out) *err_out = EINVAL;
            return -1;
        }
        return ops_.send_record_fn(fd, static_cast<std::uint8_t>(ContentType::application_data),
            data.data(), data.size(), err_out);
    }

    auto KtlsSession::send_close_notify(int fd) noexcept -> KtlsStatus {
        if (!tx_active_ || tx_closed_ || failed_ || !ops_.send_record_fn) return KtlsStatus::invalid_state;
        constexpr std::array<std::uint8_t, 2> alert{1, 0};
        int err = 0;
        auto n = ops_.send_record_fn(fd, static_cast<std::uint8_t>(ContentType::alert), alert.data(), alert.size(), &err);
        if (n != 2) { failed_ = true; return KtlsStatus::fatal_error; }
        tx_closed_ = true;
        return KtlsStatus::ok;
    }

    auto KtlsSession::rotate_direction(int fd, KtlsDirection dir) -> KtlsStatus {
        auto& secret = (dir == KtlsDirection::tx) ? tx_secret_ : rx_secret_;
        if (!secret) { failed_ = true; return KtlsStatus::fatal_error; }
        auto hash_len = (hash_ == crypto::Hash::sha256) ? 32u : (hash_ == crypto::Hash::sha384 ? 48u : 0u);
        auto key_len = (algorithm_ == crypto::Aead::aes_128_gcm) ? 16u : 32u;
        if (!hash_len) { failed_ = true; return KtlsStatus::fatal_error; }
        auto next = expand_label(hash_, secret->view(), "traffic upd", {}, hash_len);
        if (!next) { failed_ = true; return KtlsStatus::fatal_error; }
        auto key = expand_label(hash_, next->view(), "key", {}, key_len);
        auto iv = expand_label(hash_, next->view(), "iv", {}, 12);
        if (!key || !iv) { failed_ = true; return KtlsStatus::fatal_error; }
        KtlsKeyMaterial mat;
        mat.algorithm = algorithm_;
        mat.key.assign(key->view().begin(), key->view().end());
        std::ranges::copy(iv->view(), mat.iv.begin());
        mat.sequence = 0;
        auto st = install_raw(fd, dir, mat);
        if (st != KtlsStatus::ok) return st;
        secret = std::move(*next);
        return KtlsStatus::ok;
    }

    auto KtlsSession::rekey_tx(int fd, bool request_peer_update) -> KtlsStatus {
        if (!tx_active_ || tx_closed_ || failed_ || !ops_.send_record_fn) return KtlsStatus::invalid_state;
        std::array<std::uint8_t, 5> msg{24, 0, 0, 1, static_cast<std::uint8_t>(request_peer_update ? 1 : 0)};
        int err = 0;
        auto n = ops_.send_record_fn(fd, static_cast<std::uint8_t>(ContentType::handshake), msg.data(), msg.size(), &err);
        if (n != 5) { failed_ = true; return KtlsStatus::fatal_error; }
        return rotate_direction(fd, KtlsDirection::tx);
    }

    auto KtlsSession::handle_handshake(int fd, std::span<std::uint8_t const> payload) -> KtlsRecvResult {
        constexpr std::size_t max_pending = 4 + max_new_session_ticket + 16384;
        if (payload.empty() || payload.size() > max_pending - handshake_pending_.size()) {
            failed_ = true;
            return {KtlsRecvKind::protocol_error};
        }
        handshake_pending_.insert(handshake_pending_.end(), payload.begin(), payload.end());
        std::size_t offset = 0;
        while (handshake_pending_.size() - offset >= 4) {
            auto mtype = handshake_pending_[offset];
            auto mlen = (std::size_t{handshake_pending_[offset + 1]} << 16) |
                (std::size_t{handshake_pending_[offset + 2]} << 8) | handshake_pending_[offset + 3];
            if ((mtype != 4 && mtype != 24) || (mtype == 4 && (role_ != ApplicationRole::client || mlen > max_new_session_ticket)) ||
                (mtype == 24 && mlen != 1)) {
                failed_ = true;
                return {KtlsRecvKind::protocol_error};
            }
            if (mlen > handshake_pending_.size() - offset - 4) break;
            auto body = std::span(handshake_pending_).subspan(offset + 4, mlen);
            offset += 4 + mlen;
            if (mtype == 4) {
                if (!valid_new_session_ticket(body)) { failed_ = true; return {KtlsRecvKind::protocol_error}; }
                continue;
            }
            auto req = body[0];
            if (offset != handshake_pending_.size() || req > 1) { failed_ = true; return {KtlsRecvKind::protocol_error}; }
            crypto::Bytes{}.swap(handshake_pending_);
            if (rotate_direction(fd, KtlsDirection::rx) != KtlsStatus::ok) return {KtlsRecvKind::protocol_error};
            return {req ? KtlsRecvKind::key_update_requested : KtlsRecvKind::key_update};
        }
        handshake_pending_.erase(handshake_pending_.begin(), handshake_pending_.begin() + static_cast<std::ptrdiff_t>(offset));
        if (handshake_pending_.empty()) crypto::Bytes{}.swap(handshake_pending_);
        return {KtlsRecvKind::ticket_discarded};
    }

    auto KtlsSession::recv_record(int fd, std::span<std::uint8_t> out) -> KtlsRecvResult {
        if (!rx_active_ || rx_closed_ || failed_ || !ops_.recv_record_fn || out.empty())
            return {KtlsRecvKind::io_error, 0, 0, EINVAL};
        std::uint8_t rtype = 0;
        int err = 0;
        auto n = ops_.recv_record_fn(fd, out.data(), out.size(), &rtype, &err);
        if (n < 0) {
            if (err == EAGAIN || err == EWOULDBLOCK) return {KtlsRecvKind::would_block, 0, 0, err};
            failed_ = true;
            return {err == EBADMSG ? KtlsRecvKind::protocol_error : KtlsRecvKind::io_error, 0, 0, err};
        }
        if (n == 0) return {KtlsRecvKind::eof};
        auto len = static_cast<std::size_t>(n);
        if (!handshake_pending_.empty() && rtype != static_cast<std::uint8_t>(ContentType::handshake)) {
            failed_ = true;
            return {KtlsRecvKind::protocol_error};
        }
        if (rtype == static_cast<std::uint8_t>(ContentType::application_data))
            return {KtlsRecvKind::data, len};
        if (rtype == static_cast<std::uint8_t>(ContentType::alert)) {
            if (len != 2) { failed_ = true; return {KtlsRecvKind::protocol_error}; }
            auto desc = out[1];
            if (desc == 0) { rx_closed_ = true; return {KtlsRecvKind::close_notify, 0, 0}; }
            if (desc == 90) return {KtlsRecvKind::user_canceled, 0, desc};
            failed_ = true;
            return {KtlsRecvKind::fatal_alert, 0, desc};
        }
        if (rtype == static_cast<std::uint8_t>(ContentType::handshake))
            return handle_handshake(fd, out.first(len));
        failed_ = true;
        return {KtlsRecvKind::protocol_error};
    }
}
