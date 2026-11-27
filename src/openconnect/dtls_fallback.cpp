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

namespace openconnect::detail {
    namespace {
        constexpr std::uint16_t kDtlsLegacy12 = 0xfefdu;
        constexpr std::uint16_t kDtls13 = 0xfefcu;
        constexpr std::uint16_t kExtSupportedVersions = 0x002bu;

        auto read_u16(std::span<std::uint8_t const> s, std::size_t off) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(s[off]) << 8) | s[off + 1]);
        }

        auto push_u16(std::vector<std::uint8_t>& out, std::uint16_t v) -> void {
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v));
        }
    }

    auto append_supported_versions_ch(std::vector<std::uint8_t>& body, DtlsVersion version) -> void {
        if (version != DtlsVersion::dtls1_3) return;
        // RFC 9147 §5.3 / RFC 8446 §4.2.1: extensions_len(7) + type(0x002b) + ext_len(3) + list_len(2) + 0xfefc.
        push_u16(body, 7u);
        push_u16(body, kExtSupportedVersions);
        push_u16(body, 3u);
        body.push_back(2u);
        push_u16(body, kDtls13);
    }

    auto append_supported_versions_sh(std::vector<std::uint8_t>& body, DtlsVersion version) -> void {
        if (version != DtlsVersion::dtls1_3) return;
        // RFC 9147 §5.3 / RFC 8446 §4.2.1: extensions_len(6) + type(0x002b) + ext_len(2) + selected(0xfefc).
        push_u16(body, 6u);
        push_u16(body, kExtSupportedVersions);
        push_u16(body, 2u);
        push_u16(body, kDtls13);
    }

    auto validate_client_hello_version(std::span<std::uint8_t const> body,
                                       std::size_t after_session_id,
                                       DtlsVersion expected) noexcept -> std::expected<void, std::string> {
        if (body.size() < 2u || read_u16(body, 0) != kDtlsLegacy12)
            return std::unexpected("DTLS ClientHello legacy_version must be 0xfefd");
        std::size_t pos = after_session_id;
        if (pos >= body.size()) return std::unexpected("truncated DTLS ClientHello cookie");
        std::size_t cookie_len = body[pos++];
        if (pos + cookie_len + 2u > body.size()) return std::unexpected("truncated DTLS ClientHello cipher suites");
        pos += cookie_len;
        std::size_t cs_len = read_u16(body, pos);
        pos += 2u;
        if (cs_len < 2u || (cs_len % 2u) != 0u || pos + cs_len + 1u > body.size())
            return std::unexpected("invalid DTLS ClientHello cipher suites");
        pos += cs_len;
        std::size_t cm_len = body[pos++];
        if (cm_len == 0u || pos + cm_len > body.size())
            return std::unexpected("invalid DTLS ClientHello compression methods");
        pos += cm_len;

        bool saw_sv = false, has_12 = false, has_13 = false;
        if (pos < body.size()) {
            if (pos + 2u > body.size()) return std::unexpected("truncated DTLS ClientHello extensions");
            std::size_t ext_total = read_u16(body, pos);
            pos += 2u;
            if (pos + ext_total != body.size()) return std::unexpected("invalid DTLS ClientHello extensions length");
            while (pos < body.size()) {
                if (pos + 4u > body.size()) return std::unexpected("truncated DTLS ClientHello extension header");
                auto ext_type = read_u16(body, pos);
                auto ext_len = read_u16(body, pos + 2u);
                pos += 4u;
                if (pos + ext_len > body.size()) return std::unexpected("truncated DTLS ClientHello extension body");
                if (ext_type == kExtSupportedVersions) {
                    if (saw_sv) return std::unexpected("duplicate DTLS ClientHello supported_versions");
                    saw_sv = true;
                    if (ext_len < 3u) return std::unexpected("invalid DTLS ClientHello supported_versions length");
                    std::size_t list_len = body[pos];
                    if (list_len < 2u || (list_len % 2u) != 0u || 1u + list_len != ext_len)
                        return std::unexpected("malformed DTLS ClientHello supported_versions list");
                    for (std::size_t i = 0; i < list_len; i += 2u) {
                        auto v = read_u16(body, pos + 1u + i);
                        if (v == kDtls13) has_13 = true;
                        else if (v == kDtlsLegacy12) has_12 = true;
                    }
                }
                pos += ext_len;
            }
        }
        if (expected == DtlsVersion::dtls1_3) {
            if (!saw_sv || !has_13)
                return std::unexpected("DTLS 1.3 ClientHello missing supported_versions 0xfefc");
        } else if (saw_sv && !has_12) {
            return std::unexpected("DTLS 1.2 not offered in ClientHello supported_versions");
        }
        return {};
    }

    auto validate_server_hello_version(std::span<std::uint8_t const> body,
                                       std::size_t after_session_id,
                                       DtlsVersion expected) noexcept -> std::expected<void, std::string> {
        if (body.size() < 2u || read_u16(body, 0) != kDtlsLegacy12)
            return std::unexpected("DTLS ServerHello legacy_version must be 0xfefd");
        std::size_t pos = after_session_id;
        if (pos + 3u > body.size() || body[pos + 2u] != 0u)
            return std::unexpected("invalid DTLS ServerHello cipher or compression");
        pos += 3u;
        std::optional<std::uint16_t> selected;
        if (pos < body.size()) {
            if (pos + 2u > body.size()) return std::unexpected("truncated DTLS ServerHello extensions");
            std::size_t ext_total = read_u16(body, pos);
            pos += 2u;
            if (pos + ext_total != body.size()) return std::unexpected("invalid DTLS ServerHello extensions length");
            while (pos < body.size()) {
                if (pos + 4u > body.size()) return std::unexpected("truncated DTLS ServerHello extension header");
                auto ext_type = read_u16(body, pos);
                auto ext_len = read_u16(body, pos + 2u);
                pos += 4u;
                if (pos + ext_len > body.size()) return std::unexpected("truncated DTLS ServerHello extension body");
                if (ext_type == kExtSupportedVersions) {
                    if (selected) return std::unexpected("duplicate DTLS ServerHello supported_versions");
                    if (ext_len != 2u) return std::unexpected("invalid DTLS ServerHello supported_versions length");
                    selected = read_u16(body, pos);
                }
                pos += ext_len;
            }
        }
        if (expected == DtlsVersion::dtls1_3) {
            if (!selected || *selected != kDtls13)
                return std::unexpected("DTLS 1.3 ServerHello missing supported_versions 0xfefc");
        } else if (selected && *selected != kDtlsLegacy12) {
            return std::unexpected("DTLS 1.2 ServerHello supported_versions mismatch");
        }
        return {};
    }
}
