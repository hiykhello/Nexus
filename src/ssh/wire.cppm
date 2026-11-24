export module ssh.wire;
import std;
import encoding.base64;

export namespace ssh {
    inline constexpr std::uint8_t kMsgDisconnect = 1;
    inline constexpr std::uint8_t kMsgIgnore = 2;
    inline constexpr std::uint8_t kMsgUnimplemented = 3;
    inline constexpr std::uint8_t kMsgDebug = 4;
    inline constexpr std::uint8_t kMsgServiceRequest = 5;
    inline constexpr std::uint8_t kMsgServiceAccept = 6;
    inline constexpr std::uint8_t kMsgExtInfo = 7;
    inline constexpr std::uint8_t kMsgKexInit = 20;
    inline constexpr std::uint8_t kMsgNewKeys = 21;
    inline constexpr std::uint8_t kMsgKexEcdhInit = 30;
    inline constexpr std::uint8_t kMsgKexEcdhReply = 31;
    inline constexpr std::uint8_t kMsgUserauthRequest = 50;
    inline constexpr std::uint8_t kMsgUserauthFailure = 51;
    inline constexpr std::uint8_t kMsgUserauthSuccess = 52;
    inline constexpr std::uint8_t kMsgUserauthBanner = 53;
    inline constexpr std::uint8_t kMsgUserauthPkOk = 60;
    inline constexpr std::uint8_t kMsgGlobalRequest = 80;
    inline constexpr std::uint8_t kMsgRequestSuccess = 81;
    inline constexpr std::uint8_t kMsgRequestFailure = 82;
    inline constexpr std::uint8_t kMsgChannelOpen = 90;
    inline constexpr std::uint8_t kMsgChannelOpenConfirm = 91;
    inline constexpr std::uint8_t kMsgChannelOpenFailure = 92;
    inline constexpr std::uint8_t kMsgChannelWindowAdjust = 93;
    inline constexpr std::uint8_t kMsgChannelData = 94;
    inline constexpr std::uint8_t kMsgChannelExtData = 95;
    inline constexpr std::uint8_t kMsgChannelEof = 96;
    inline constexpr std::uint8_t kMsgChannelClose = 97;

    inline constexpr std::size_t kMaxPacketBytes = 262144;
    inline constexpr std::string_view kClientVersion = "SSH-2.0-Nexus_0.1";
    inline constexpr std::string_view kStrictClientKex = "kex-strict-c-v00@openssh.com";
    inline constexpr std::string_view kStrictServerKex = "kex-strict-s-v00@openssh.com";

    struct Writer {
        std::vector<std::uint8_t> buf;
        auto byte(std::uint8_t v) -> Writer& { buf.push_back(v); return *this; }
        auto boolean(bool v) -> Writer& { buf.push_back(v ? 1u : 0u); return *this; }
        auto u32(std::uint32_t v) -> Writer& {
            buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xffu));
            buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xffu));
            buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xffu));
            buf.push_back(static_cast<std::uint8_t>(v & 0xffu));
            return *this;
        }
        auto raw(std::span<std::uint8_t const> s) -> Writer& {
            buf.insert(buf.end(), s.begin(), s.end());
            return *this;
        }
        auto string(std::span<std::uint8_t const> s) -> Writer& {
            u32(static_cast<std::uint32_t>(s.size()));
            return raw(s);
        }
        auto string(std::string_view s) -> Writer& {
            return string(std::span<std::uint8_t const>(
                reinterpret_cast<std::uint8_t const*>(s.data()), s.size()));
        }
        auto mpint(std::span<std::uint8_t const> mag) -> Writer& {
            while (!mag.empty() && mag.front() == 0) mag = mag.subspan(1);
            if (mag.empty()) return u32(0);
            bool pad = (mag.front() & 0x80u) != 0;
            u32(static_cast<std::uint32_t>(mag.size() + (pad ? 1u : 0u)));
            if (pad) byte(0);
            return raw(mag);
        }
    };

    struct Reader {
        std::span<std::uint8_t const> s;
        [[nodiscard]] auto remaining() const noexcept -> std::size_t { return s.size(); }
        [[nodiscard]] auto empty() const noexcept -> bool { return s.empty(); }
        auto byte() -> std::optional<std::uint8_t> {
            if (s.empty()) return {};
            auto v = s.front();
            s = s.subspan(1);
            return v;
        }
        auto boolean() -> std::optional<bool> {
            auto b = byte();
            return b ? std::optional<bool>(*b != 0) : std::nullopt;
        }
        auto u32() -> std::optional<std::uint32_t> {
            if (s.size() < 4) return {};
            std::uint32_t v = (std::uint32_t(s[0]) << 24) | (std::uint32_t(s[1]) << 16) |
                              (std::uint32_t(s[2]) << 8) | std::uint32_t(s[3]);
            s = s.subspan(4);
            return v;
        }
        auto bytes(std::size_t n) -> std::optional<std::span<std::uint8_t const>> {
            if (s.size() < n) return {};
            auto out = s.first(n);
            s = s.subspan(n);
            return out;
        }
        auto string() -> std::optional<std::span<std::uint8_t const>> {
            auto len = u32();
            if (!len || *len > s.size()) return {};
            return bytes(*len);
        }
        auto text() -> std::optional<std::string_view> {
            auto b = string();
            if (!b) return {};
            return std::string_view(reinterpret_cast<char const*>(b->data()), b->size());
        }
        auto mpint() -> std::optional<std::span<std::uint8_t const>> {
            auto b = string();
            if (!b) return {};
            if (!b->empty() && (b->front() & 0x80u) != 0) return {}; // positive expected
            while (b->size() > 1 && b->front() == 0) *b = b->subspan(1);
            return b;
        }
    };

    struct KexInit {
        std::array<std::uint8_t, 16> cookie{};
        std::string kex_algorithms;
        std::string server_host_key_algorithms;
        std::string enc_c2s;
        std::string enc_s2c;
        std::string mac_c2s;
        std::string mac_s2c;
        std::string comp_c2s{"none"};
        std::string comp_s2c{"none"};
        std::string lang_c2s;
        std::string lang_s2c;
        bool first_kex_packet_follows = false;
        std::uint32_t reserved = 0;
    };

    inline auto encode_kexinit(KexInit const& k) -> std::vector<std::uint8_t> {
        Writer w;
        w.byte(kMsgKexInit).raw(k.cookie)
            .string(k.kex_algorithms).string(k.server_host_key_algorithms)
            .string(k.enc_c2s).string(k.enc_s2c)
            .string(k.mac_c2s).string(k.mac_s2c)
            .string(k.comp_c2s).string(k.comp_s2c)
            .string(k.lang_c2s).string(k.lang_s2c)
            .boolean(k.first_kex_packet_follows).u32(k.reserved);
        return std::move(w.buf);
    }

    inline auto decode_kexinit(std::span<std::uint8_t const> payload) -> std::optional<KexInit> {
        Reader r{payload};
        auto msg = r.byte();
        auto cookie = r.bytes(16);
        if (!msg || *msg != kMsgKexInit || !cookie) return {};
        KexInit out;
        std::ranges::copy(*cookie, out.cookie.begin());
        std::array<std::string*, 10> fields{
            &out.kex_algorithms, &out.server_host_key_algorithms, &out.enc_c2s, &out.enc_s2c,
            &out.mac_c2s, &out.mac_s2c, &out.comp_c2s, &out.comp_s2c, &out.lang_c2s, &out.lang_s2c
        };
        for (auto* dst : fields) {
            auto t = r.text();
            if (!t) return {};
            *dst = std::string(*t);
        }
        auto f = r.boolean();
        auto res = r.u32();
        if (!f || !res) return {};
        out.first_kex_packet_follows = *f;
        out.reserved = *res;
        return out;
    }

    inline auto list_contains(std::string_view csv, std::string_view target) -> bool {
        while (!csv.empty()) {
            auto comma = csv.find(',');
            auto item = comma == std::string_view::npos ? csv : csv.substr(0, comma);
            if (item == target) return true;
            if (comma == std::string_view::npos) break;
            csv.remove_prefix(comma + 1);
        }
        return false;
    }

    inline auto negotiate_algorithm(std::string_view client_csv, std::string_view server_csv)
        -> std::optional<std::string_view> {
        while (!client_csv.empty()) {
            auto comma = client_csv.find(',');
            auto item = comma == std::string_view::npos ? client_csv : client_csv.substr(0, comma);
            if (!item.empty() && list_contains(server_csv, item)) return item;
            if (comma == std::string_view::npos) break;
            client_csv.remove_prefix(comma + 1);
        }
        return {};
    }

    inline auto decode_base64(std::string_view text) -> std::optional<std::vector<std::uint8_t>> {
        return encoding::decode_base64_pem(text);
    }

    inline auto encode_base64(std::span<std::uint8_t const> bytes, bool pad = false) -> std::string {
        return encoding::encode_base64(bytes, false, pad);
    }

    inline auto parse_host_key_sha256(std::string_view text) -> std::optional<std::array<std::uint8_t, 32>> {
        if (text.starts_with("SHA256:") || text.starts_with("sha256:")) {
            auto b = decode_base64(text.substr(7));
            if (!b || b->size() != 32) return {};
            std::array<std::uint8_t, 32> out{};
            std::ranges::copy(*b, out.begin());
            return out;
        }
        if (text.size() != 64 && text.size() != 95) return {};
        std::array<std::uint8_t, 32> out{};
        auto stride = text.size() == 64 ? 2u : 3u;
        for (std::size_t i = 0; i < out.size(); ++i) {
            auto begin = text.data() + i * stride;
            auto [end, ec] = std::from_chars(begin, begin + 2, out[i], 16);
            if (ec != std::errc{} || end != begin + 2 || (stride == 3 && i + 1 < out.size() && begin[2] != ':'))
                return {};
        }
        return out;
    }

    inline auto format_host_key_sha256(std::span<std::uint8_t const, 32> fp) -> std::string {
        return "SHA256:" + encode_base64(fp, false);
    }
}
