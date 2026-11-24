module relay.sni_demux;
import std;

namespace relay {
    namespace {
        auto ascii_lower_eq(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                auto lo = [](unsigned char c) noexcept {
                    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : static_cast<char>(c);
                };
                if (lo(static_cast<unsigned char>(a[i])) != lo(static_cast<unsigned char>(b[i]))) return false;
            }
            return true;
        }

        auto host_matches(std::string_view pattern, std::string_view host) noexcept -> bool {
            if (pattern.empty() || pattern == "*") return true;
            if (pattern.starts_with("*.")) {
                auto suffix = pattern.substr(1); // includes leading '.'
                if (host.size() <= suffix.size()) return false;
                return ascii_lower_eq(host.substr(host.size() - suffix.size()), suffix);
            }
            return ascii_lower_eq(pattern, host);
        }

        auto valid_hostname(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size() > 253) return false;
            std::size_t start = 0;
            bool non_num = false;
            for (std::size_t i = 0; i <= name.size(); ++i) {
                if (i == name.size() || name[i] == '.') {
                    if (i == start || i - start > 63 || name[start] == '-' || name[i - 1] == '-') return false;
                    start = i + 1;
                } else {
                    char c = name[i];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
                        return false;
                    non_num |= !(c >= '0' && c <= '9');
                }
            }
            return non_num;
        }
    }

    auto inspect_client_hello(std::span<std::uint8_t const> bytes) noexcept -> SniPeekResult {
        if (bytes.empty()) return {.status = SniPeekStatus::incomplete};
        if (bytes[0] != 0x16) return {.status = SniPeekStatus::non_tls};
        if (bytes.size() < 5) return {.status = SniPeekStatus::incomplete};
        if (bytes[1] != 0x03 || bytes[2] > 0x03) return {.status = SniPeekStatus::malformed};
        std::size_t rec_len = (std::size_t(bytes[3]) << 8) | bytes[4];
        if (rec_len == 0 || rec_len > 16384) return {.status = SniPeekStatus::malformed};
        if (bytes.size() < 5 + rec_len) {
            if (bytes.size() >= 6 && bytes[5] != 0x01) return {.status = SniPeekStatus::non_tls};
            return {.status = SniPeekStatus::incomplete, .record_length = rec_len};
        }
        auto rec = bytes.subspan(5, rec_len);
        if (rec.size() < 4) return {.status = SniPeekStatus::malformed};
        if (rec[0] != 0x01) return {.status = SniPeekStatus::non_tls};
        std::size_t hs_len = (std::size_t(rec[1]) << 16) | (std::size_t(rec[2]) << 8) | rec[3];
        if (hs_len == 0 || hs_len > rec.size() - 4) return {.status = SniPeekStatus::malformed};
        auto body = rec.subspan(4, hs_len);

        std::size_t pos = 0;
        auto take = [&](std::size_t n) noexcept -> std::span<std::uint8_t const> {
            if (n > body.size() - pos) return {};
            auto s = body.subspan(pos, n);
            pos += n;
            return s;
        };
        auto u8 = [&](std::size_t& v) noexcept -> bool {
            auto s = take(1);
            if (s.empty()) return false;
            v = s[0];
            return true;
        };
        auto u16 = [&](std::size_t& v) noexcept -> bool {
            auto s = take(2);
            if (s.empty()) return false;
            v = (std::size_t(s[0]) << 8) | s[1];
            return true;
        };

        auto ver = take(2);
        if (ver.size() != 2 || ver[0] != 0x03 || ver[1] > 0x03 || take(32).size() != 32)
            return {.status = SniPeekStatus::malformed};
        std::size_t n = 0;
        if (!u8(n) || n > 32 || take(n).size() != n) return {.status = SniPeekStatus::malformed};
        if (!u16(n) || n < 2 || (n % 2) != 0 || take(n).size() != n) return {.status = SniPeekStatus::malformed};
        if (!u8(n) || n == 0 || take(n).size() != n) return {.status = SniPeekStatus::malformed};

        SniPeekResult out{.status = SniPeekStatus::matched, .record_length = rec_len};
        if (pos == body.size()) return out;
        if (!u16(n) || n != body.size() - pos) return {.status = SniPeekStatus::malformed};

        std::bitset<65536> seen;
        while (pos < body.size()) {
            std::size_t type = 0, len = 0;
            if (!u16(type) || !u16(len) || len > body.size() - pos || seen.test(type))
                return {.status = SniPeekStatus::malformed};
            seen.set(type);
            auto ext = take(len);
            if (type == 0x0000) {
                if (ext.size() < 2) return {.status = SniPeekStatus::malformed};
                std::size_t list_len = (std::size_t(ext[0]) << 8) | ext[1];
                if (list_len == 0 || list_len != ext.size() - 2) return {.status = SniPeekStatus::malformed};
                std::size_t off = 2;
                while (off < ext.size()) {
                    if (ext.size() - off < 3) return {.status = SniPeekStatus::malformed};
                    auto kind = ext[off++];
                    std::size_t slen = (std::size_t(ext[off]) << 8) | ext[off + 1];
                    off += 2;
                    if (slen == 0 || slen > ext.size() - off) return {.status = SniPeekStatus::malformed};
                    if (kind == 0) {
                        if (!out.server_name.empty()) return {.status = SniPeekStatus::malformed};
                        std::string_view sv(reinterpret_cast<char const*>(ext.data() + off), slen);
                        if (!valid_hostname(sv)) return {.status = SniPeekStatus::malformed};
                        out.server_name = std::string(sv);
                    }
                    off += slen;
                }
            } else if (type == 0x0010) {
                if (ext.size() < 2) return {.status = SniPeekStatus::malformed};
                std::size_t list_len = (std::size_t(ext[0]) << 8) | ext[1];
                if (list_len == 0 || list_len != ext.size() - 2) return {.status = SniPeekStatus::malformed};
                std::size_t off = 2;
                while (off < ext.size()) {
                    std::size_t plen = ext[off++];
                    if (plen == 0 || plen > ext.size() - off) return {.status = SniPeekStatus::malformed};
                    std::string_view proto(reinterpret_cast<char const*>(ext.data() + off), plen);
                    (void)out.alpn_protocols.try_emplace_back(std::string(proto));
                    off += plen;
                }
            }
        }
        return out;
    }

    auto SniDemuxRouter::add_rule(DemuxRule rule) -> void { rules_.push_back(std::move(rule)); }

    auto SniDemuxRouter::set_fallback(DemuxRole role, std::string upstream) -> void {
        fallback_role_ = role;
        fallback_upstream_ = std::move(upstream);
    }

    auto SniDemuxRouter::route(std::span<std::uint8_t const> peek_bytes) const -> DemuxDecision {
        auto peek = inspect_client_hello(peek_bytes);
        if (peek.status == SniPeekStatus::matched) {
            for (auto const& rule : rules_) {
                if (!host_matches(rule.host_pattern, peek.server_name)) continue;
                if (rule.required_alpn.empty()) {
                    std::string first_alpn = peek.alpn_protocols.empty() ? std::string{} : peek.alpn_protocols[0];
                    return {true, rule.role, rule.target_upstream, std::move(peek.server_name), std::move(first_alpn), peek_bytes};
                }
                for (auto const& alpn : peek.alpn_protocols) {
                    if (alpn == rule.required_alpn) {
                        return {true, rule.role, rule.target_upstream, std::move(peek.server_name), alpn, peek_bytes};
                    }
                }
            }
        }
        return {false, fallback_role_, fallback_upstream_, std::move(peek.server_name), {}, peek_bytes};
    }
}
