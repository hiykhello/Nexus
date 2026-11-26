module openconnect.dtls;
import std;

namespace openconnect {
    auto DtlsReplayWindow::check_and_record(std::uint64_t seq) noexcept -> bool {
        if (!initialized_) {
            initialized_ = true;
            highest_ = seq;
            bitmap_ = 1;
            return true;
        }
        if (seq > highest_) {
            auto shift = seq - highest_;
            bitmap_ = (shift >= 64) ? std::uint64_t{1} : ((bitmap_ << shift) | std::uint64_t{1});
            highest_ = seq;
            return true;
        }
        auto delta = highest_ - seq;
        if (delta >= 64) return false;
        std::uint64_t bit = std::uint64_t{1} << delta;
        if (bitmap_ & bit) return false;
        bitmap_ |= bit;
        return true;
    }

    // RFC 9147 Section 4.2.2: reconstruct full 48-bit sequence number from 16-bit wire value.
    auto DtlsReplayWindow::reconstruct_seq16(std::uint16_t seq16) const noexcept -> std::uint64_t {
        if (!initialized_) return seq16;
        std::uint64_t expected = highest_ + 1;
        std::uint64_t win = std::uint64_t{1} << 16;
        std::uint64_t half = win >> 1;
        std::uint64_t candidate = (expected & ~(win - 1)) | seq16;
        if (candidate + half <= expected && candidate + win < (std::uint64_t{1} << 48)) {
            candidate += win;
        } else if (candidate > expected + half && candidate >= win) {
            candidate -= win;
        }
        return candidate;
    }

    DtlsFallbackController::DtlsFallbackController(std::uint64_t handshake_timeout_ms,
                                                   std::uint64_t dpd_interval_ms,
                                                   std::uint32_t max_missed_dpd,
                                                   std::uint32_t max_consecutive_errors) noexcept
        : handshake_timeout_ms_(handshake_timeout_ms),
          dpd_interval_ms_(dpd_interval_ms),
          max_missed_dpd_(max_missed_dpd),
          max_consecutive_errors_(max_consecutive_errors) {}

    auto DtlsFallbackController::begin_handshake(std::uint64_t now_ms) noexcept -> void {
        handshake_start_ms_ = now_ms;
        last_rx_ms_ = now_ms;
        last_dpd_tx_ms_ = now_ms;
        missed_dpd_ = 0;
        consecutive_errors_ = 0;
        active_ = true;
        established_ = false;
        reason_ = FallbackReason::none;
    }

    auto DtlsFallbackController::on_established(std::uint64_t now_ms) noexcept -> void {
        established_ = true;
        last_rx_ms_ = now_ms;
        last_dpd_tx_ms_ = now_ms;
        missed_dpd_ = 0;
        consecutive_errors_ = 0;
    }

    auto DtlsFallbackController::on_rx_valid(std::uint64_t now_ms) noexcept -> void {
        last_rx_ms_ = now_ms;
        missed_dpd_ = 0;
        consecutive_errors_ = 0;
    }

    auto DtlsFallbackController::on_dpd_response(std::uint64_t now_ms) noexcept -> void {
        on_rx_valid(now_ms);
    }

    auto DtlsFallbackController::on_transport_error(Session& session) noexcept -> FallbackAction {
        if (!active_) return FallbackAction::none;
        if (++consecutive_errors_ >= max_consecutive_errors_) {
            active_ = false;
            established_ = false;
            reason_ = FallbackReason::transport_error;
            session.fallback_to_cstp();
            return FallbackAction::fallback_to_cstp;
        }
        return FallbackAction::none;
    }

    auto DtlsFallbackController::on_unsupported(Session& session) noexcept -> FallbackAction {
        active_ = false;
        established_ = false;
        reason_ = FallbackReason::unsupported_peer;
        session.fallback_to_cstp();
        return FallbackAction::fallback_to_cstp;
    }

    auto DtlsFallbackController::poll(std::uint64_t now_ms, Session& session) noexcept -> FallbackAction {
        if (!active_) return FallbackAction::none;
        if (!established_) {
            if (now_ms >= handshake_start_ms_ && (now_ms - handshake_start_ms_) >= handshake_timeout_ms_) {
                active_ = false;
                reason_ = FallbackReason::handshake_timeout;
                session.fallback_to_cstp();
                return FallbackAction::fallback_to_cstp;
            }
            return FallbackAction::none;
        }
        if (dpd_interval_ms_ == 0) return FallbackAction::none;
        if (now_ms >= last_rx_ms_ && (now_ms - last_rx_ms_) >= dpd_interval_ms_ &&
            now_ms >= last_dpd_tx_ms_ && (now_ms - last_dpd_tx_ms_) >= dpd_interval_ms_) {
            last_dpd_tx_ms_ = now_ms;
            if (++missed_dpd_ > max_missed_dpd_) {
                active_ = false;
                established_ = false;
                reason_ = FallbackReason::dpd_timeout;
                session.fallback_to_cstp();
                return FallbackAction::fallback_to_cstp;
            }
            return FallbackAction::send_dpd_req;
        }
        return FallbackAction::none;
    }

    auto parse_dtls_cipher_name(std::string_view name) noexcept -> DtlsCipher {
        auto has = [&](std::string_view needle) noexcept {
            if (name.size() < needle.size()) return false;
            for (std::size_t i = 0; i + needle.size() <= name.size(); ++i) {
                bool ok = true;
                for (std::size_t j = 0; j < needle.size(); ++j) {
                    auto ca = static_cast<unsigned char>(name[i + j]);
                    auto cb = static_cast<unsigned char>(needle[j]);
                    if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                    if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                    if (ca != cb) { ok = false; break; }
                }
                if (ok) return true;
            }
            return false;
        };
        if (has("chacha20")) return DtlsCipher::chacha20_poly1305;
        if (has("aes128") || has("aes_128") || has("aes-128")) return DtlsCipher::aes_128_gcm;
        return DtlsCipher::aes_256_gcm;
    }
}
