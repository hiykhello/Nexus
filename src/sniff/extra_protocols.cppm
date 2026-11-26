export module sniff.extra;
import std;

export namespace sniff {
    enum class ExtraSniffStatus : std::uint8_t { need_more, matched, not_recognized };

    // BitTorrent peer wire protocol handshake: 0x13 "BitTorrent protocol" (20 bytes).
    [[nodiscard]] inline auto inspect_bittorrent_tcp(std::span<std::uint8_t const> wire) noexcept -> ExtraSniffStatus {
        static constexpr std::array<std::uint8_t, 20> kMagic{
            0x13, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't',
            ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'
        };
        if (wire.empty()) return ExtraSniffStatus::need_more;
        auto check = std::min(wire.size(), kMagic.size());
        for (std::size_t i = 0; i < check; ++i) {
            if (wire[i] != kMagic[i]) return ExtraSniffStatus::not_recognized;
        }
        return wire.size() >= kMagic.size() ? ExtraSniffStatus::matched : ExtraSniffStatus::need_more;
    }

    // RDP over TPKT v3 + X.224 Connection Request (CR TPDU, DST-REF = 0).
    [[nodiscard]] inline auto inspect_rdp_tcp(std::span<std::uint8_t const> wire) noexcept -> ExtraSniffStatus {
        if (wire.empty()) return ExtraSniffStatus::need_more;
        if (wire[0] != 0x03) return ExtraSniffStatus::not_recognized;
        if (wire.size() >= 2 && wire[1] != 0x00) return ExtraSniffStatus::not_recognized;
        if (wire.size() < 11) return ExtraSniffStatus::need_more;
        std::size_t tpkt_len = (std::size_t{wire[2]} << 8) | wire[3];
        if (tpkt_len < 11 || wire[4] < 6 || wire[5] != 0xe0 || wire[6] != 0x00 || wire[7] != 0x00)
            return ExtraSniffStatus::not_recognized;
        return ExtraSniffStatus::matched;
    }

    struct TcpDnsResult {
        ExtraSniffStatus status = ExtraSniffStatus::not_recognized;
        std::optional<std::string_view> domain{};
    };

    // RFC 1035 TCP DNS query: 2-byte big-endian length prefix + DNS query message.
    [[nodiscard]] inline auto inspect_dns_tcp(std::span<std::uint8_t const> wire,
                                              std::span<std::uint8_t> scratch) noexcept -> TcpDnsResult {
        if (wire.size() < 2) return {ExtraSniffStatus::need_more};
        std::size_t msg_len = (std::size_t{wire[0]} << 8) | wire[1];
        if (msg_len < 12 || msg_len > 4096) return {ExtraSniffStatus::not_recognized};
        auto hdr = wire.subspan(2);
        if (hdr.size() > 2) {
            bool is_response = (hdr[2] & 0x80u) != 0;
            unsigned opcode = (hdr[2] >> 3) & 0x0fu;
            bool aa = (hdr[2] & 0x04u) != 0;
            bool tc = (hdr[2] & 0x02u) != 0;
            if (is_response || opcode != 0 || aa || tc) return {ExtraSniffStatus::not_recognized};
        }
        if (hdr.size() > 3) {
            bool ra = (hdr[3] & 0x80u) != 0;
            bool z = (hdr[3] & 0x40u) != 0;
            unsigned rcode = hdr[3] & 0x0fu;
            if (ra || z || rcode != 0) return {ExtraSniffStatus::not_recognized};
        }
        if (hdr.size() > 5) {
            unsigned qd = (unsigned(hdr[4]) << 8) | hdr[5];
            if (qd == 0 || qd > 8) return {ExtraSniffStatus::not_recognized};
        }
        if (hdr.size() > 7 && ((unsigned(hdr[6]) << 8) | hdr[7]) != 0) return {ExtraSniffStatus::not_recognized};
        if (hdr.size() > 9 && ((unsigned(hdr[8]) << 8) | hdr[9]) != 0) return {ExtraSniffStatus::not_recognized};
        if (hdr.size() > 11 && ((unsigned(hdr[10]) << 8) | hdr[11]) > 8) return {ExtraSniffStatus::not_recognized};
        if (wire.size() < 2 + msg_len) return {ExtraSniffStatus::need_more};

        auto msg = wire.subspan(2, msg_len);
        unsigned qdcount = (unsigned(msg[4]) << 8) | msg[5];
        unsigned arcount = (unsigned(msg[10]) << 8) | msg[11];
        std::size_t pos = 12;
        std::optional<std::string_view> extracted;

        auto parse_name = [&](bool capture, bool allow_ptr) noexcept -> bool {
            std::size_t out_len = 0;
            bool valid_host = true;
            std::size_t labels = 0;
            for (;;) {
                if (pos >= msg.size() || ++labels > 128) return false;
                std::uint8_t len = msg[pos++];
                if (len == 0) break;
                if ((len & 0xc0u) == 0xc0u) {
                    if (!allow_ptr || pos >= msg.size()) return false;
                    std::size_t ptr = (std::size_t(len & 0x3fu) << 8) | msg[pos++];
                    if (ptr < 12 || ptr >= pos - 2) return false;
                    break;
                }
                if (len > 63 || len > msg.size() - pos) return false;
                if (capture && valid_host) {
                    if (out_len > 0) {
                        if (out_len >= scratch.size() || out_len >= 253) valid_host = false;
                        else scratch[out_len++] = '.';
                    }
                    if (valid_host && (msg[pos] == '-' || msg[pos + len - 1] == '-')) valid_host = false;
                    for (std::size_t i = 0; i < len && valid_host; ++i) {
                        unsigned char c = msg[pos + i];
                        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
                        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) { valid_host = false; break; }
                        if (out_len >= scratch.size() || out_len >= 253) { valid_host = false; break; }
                        scratch[out_len++] = c;
                    }
                }
                pos += len;
            }
            if (capture && valid_host && out_len > 0)
                extracted = std::string_view(reinterpret_cast<char const*>(scratch.data()), out_len);
            return true;
        };

        for (unsigned q = 0; q < qdcount; ++q) {
            if (!parse_name(q == 0, q != 0)) return {ExtraSniffStatus::not_recognized};
            if (pos + 4 > msg.size()) return {ExtraSniffStatus::not_recognized};
            unsigned qtype = (unsigned(msg[pos]) << 8) | msg[pos + 1];
            unsigned qclass = (unsigned(msg[pos + 2]) << 8) | msg[pos + 3];
            if (qtype == 0 || qclass == 0) return {ExtraSniffStatus::not_recognized};
            pos += 4;
        }
        for (unsigned a = 0; a < arcount; ++a) {
            if (!parse_name(false, true)) return {ExtraSniffStatus::not_recognized};
            if (pos + 10 > msg.size()) return {ExtraSniffStatus::not_recognized};
            std::size_t rdlen = (std::size_t{msg[pos + 8]} << 8) | msg[pos + 9];
            pos += 10;
            if (rdlen > msg.size() - pos) return {ExtraSniffStatus::not_recognized};
            pos += rdlen;
        }
        if (pos != msg.size()) return {ExtraSniffStatus::not_recognized};
        return {ExtraSniffStatus::matched, extracted};
    }

    [[nodiscard]] inline auto inspect_dtls_udp(std::span<std::uint8_t const> pkt) noexcept -> bool {
        if (pkt.size() < 13) return false;
        if (pkt[0] != 0x16 || pkt[1] != 0xfe || (pkt[2] != 0xfd && pkt[2] != 0xff)) return false;
        std::size_t frag_len = (std::size_t{pkt[11]} << 8) | pkt[12];
        return frag_len > 0 && frag_len <= pkt.size() - 13;
    }

    [[nodiscard]] inline auto inspect_ntp_udp(std::span<std::uint8_t const> pkt) noexcept -> bool {
        if (pkt.size() != 48) return false;
        auto version = static_cast<unsigned>((pkt[0] >> 3) & 0x07);
        auto mode = static_cast<unsigned>(pkt[0] & 0x07);
        if (version < 3 || version > 4) return false;
        return mode == 3 || mode == 4;
    }

    [[nodiscard]] inline auto inspect_bittorrent_udp(std::span<std::uint8_t const> pkt) noexcept -> bool {
        // BEP 15 UDP tracker connect request magic 0x0000041727101980.
        if (pkt.size() >= 16) {
            static constexpr std::array<std::uint8_t, 8> kTrackerMagic{0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80};
            if (std::ranges::equal(pkt.first<8>(), kTrackerMagic) &&
                pkt[8] == 0 && pkt[9] == 0 && pkt[10] == 0 && pkt[11] <= 3) {
                return true;
            }
        }
        // BEP 29 uTP v1 ST_SYN header (20 bytes + optional extension chain; version=1, type=4, ts_diff=0, ack_nr=0).
        if (pkt.size() >= 20 && pkt[0] == 0x41) {
            std::uint8_t ext = pkt[1];
            std::size_t pos = 20;
            unsigned ext_count = 0;
            bool valid_ext = true;
            while (ext != 0) {
                if (ext > 2 || pos + 2 > pkt.size() || ++ext_count > 8) { valid_ext = false; break; }
                std::uint8_t next = pkt[pos], len = pkt[pos + 1];
                if (len == 0 || pos + 2 + len > pkt.size() || (ext == 1 && (len % 4) != 0)) {
                    valid_ext = false;
                    break;
                }
                pos += 2 + len;
                ext = next;
            }
            if (valid_ext && pos == pkt.size() &&
                pkt[8] == 0 && pkt[9] == 0 && pkt[10] == 0 && pkt[11] == 0 &&
                pkt[18] == 0 && pkt[19] == 0) {
                return true;
            }
        }
        // BEP 5 DHT bencoded KRPC message dictionary.
        if (pkt.size() >= 12 && pkt.front() == 'd' && pkt.back() == 'e') {
            std::string_view sv(reinterpret_cast<char const*>(pkt.data()), pkt.size());
            return sv.contains("1:y1:") && (sv.contains("1:q") || sv.contains("1:r") || sv.contains("1:e"));
        }
        return false;
    }
}
