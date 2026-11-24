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
