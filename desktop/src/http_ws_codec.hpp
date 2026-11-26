// Internal pure-C++ RFC 3174 SHA-1, Base64, RFC 6455 frame codec, and /v1/ws JSON helpers for desktop/src/http_ws.cpp.
// Included inside module desktop.http_control after OS headers, `import std;`, and `import desktop.mini_json;`.
#pragma once

namespace desktop::ws_detail {
    inline constexpr std::string_view kWsMagicGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    inline constexpr std::size_t kMaxWsFrameBytes = 256u * 1024u;

    inline auto sha1_digest(std::string_view input) -> std::array<std::uint8_t, 20> {
        std::uint32_t h0 = 0x67452301u, h1 = 0xEFCDAB89u, h2 = 0x98BADCFEu, h3 = 0x10325476u, h4 = 0xC3D2E1F0u;
        std::vector<std::uint8_t> msg(input.begin(), input.end());
        std::uint64_t const bit_len = static_cast<std::uint64_t>(msg.size()) * 8ULL;
        msg.push_back(0x80u);
        while ((msg.size() % 64u) != 56u) msg.push_back(0x00u);
        for (int shift = 56; shift >= 0; shift -= 8) msg.push_back(static_cast<std::uint8_t>((bit_len >> shift) & 0xffu));

        auto rol = [](std::uint32_t v, unsigned n) noexcept -> std::uint32_t { return (v << n) | (v >> (32u - n)); };
        for (std::size_t off = 0; off < msg.size(); off += 64u) {
            std::uint32_t w[80]{};
            for (std::size_t i = 0; i < 16; ++i) {
                std::size_t p = off + i * 4u;
                w[i] = (std::uint32_t{msg[p]} << 24) | (std::uint32_t{msg[p + 1]} << 16) |
                       (std::uint32_t{msg[p + 2]} << 8) | std::uint32_t{msg[p + 3]};
            }
            for (std::size_t i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1u);
            std::uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
            for (std::size_t i = 0; i < 80; ++i) {
                std::uint32_t f = 0, k = 0;
                if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999u; }
                else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
                std::uint32_t temp = rol(a, 5u) + f + e + k + w[i];
                e = d; d = c; c = rol(b, 30u); b = a; a = temp;
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        }
        std::array<std::uint8_t, 20> out{};
        std::uint32_t const hs[5]{h0, h1, h2, h3, h4};
        for (std::size_t i = 0; i < 5; ++i) {
            out[i * 4 + 0] = static_cast<std::uint8_t>((hs[i] >> 24) & 0xffu);
            out[i * 4 + 1] = static_cast<std::uint8_t>((hs[i] >> 16) & 0xffu);
            out[i * 4 + 2] = static_cast<std::uint8_t>((hs[i] >> 8) & 0xffu);
            out[i * 4 + 3] = static_cast<std::uint8_t>(hs[i] & 0xffu);
        }
        return out;
    }

    inline auto base64_encode(std::span<std::uint8_t const> bytes) -> std::string {
        static constexpr char kTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((bytes.size() + 2u) / 3u) * 4u);
        for (std::size_t i = 0; i < bytes.size(); i += 3u) {
            std::uint32_t v = std::uint32_t{bytes[i]} << 16;
            if (i + 1 < bytes.size()) v |= std::uint32_t{bytes[i + 1]} << 8;
            if (i + 2 < bytes.size()) v |= std::uint32_t{bytes[i + 2]};
            out.push_back(kTab[(v >> 18) & 0x3fu]);
            out.push_back(kTab[(v >> 12) & 0x3fu]);
            out.push_back(i + 1 < bytes.size() ? kTab[(v >> 6) & 0x3fu] : '=');
            out.push_back(i + 2 < bytes.size() ? kTab[v & 0x3fu] : '=');
        }
        return out;
    }

    inline auto ws_iequals(std::string_view a, std::string_view b) noexcept -> bool {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
        }
        return true;
    }

    inline auto ws_ct_equal(std::string_view a, std::string_view b) noexcept -> bool {
        if (a.size() != b.size()) return false;
        unsigned char diff = 0;
        for (std::size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
        }
        return diff == 0;
    }

    inline auto ws_trim(std::string_view sv) noexcept -> std::string_view {
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
        while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t')) sv.remove_suffix(1);
        return sv;
    }

    inline auto is_loopback_ws_host(std::string_view host) noexcept -> bool {
        return host == "127.0.0.1" || host == "::1" || host == "[::1]" || ws_iequals(host, "localhost");
    }

    inline auto has_ws_forbidden_ctrl(std::string_view sv) noexcept -> bool {
        for (unsigned char c : sv) {
            if (c == '\r' || c == '\n' || c == '\0' || c < 0x20 || c == 0x7F) return true;
        }
        return false;
    }

    inline auto header_value_ci(std::string_view hdrs, std::string_view name) noexcept -> std::string_view {
        while (!hdrs.empty()) {
            auto eol = hdrs.find("\r\n");
            auto line = eol == std::string_view::npos ? hdrs : hdrs.substr(0, eol);
            if (auto colon = line.find(':'); colon != std::string_view::npos) {
                if (ws_iequals(ws_trim(line.substr(0, colon)), name)) return ws_trim(line.substr(colon + 1));
            }
            if (eol == std::string_view::npos) break;
            hdrs.remove_prefix(eol + 2);
        }
        return {};
    }

    inline auto header_has_token_ci(std::string_view val, std::string_view tok) noexcept -> bool {
        while (!val.empty()) {
            auto c = val.find(',');
            if (ws_iequals(ws_trim(c == std::string_view::npos ? val : val.substr(0, c)), tok)) return true;
            if (c == std::string_view::npos) break;
            val.remove_prefix(c + 1);
        }
        return false;
    }

    inline auto generate_ws_key() -> std::string {
        std::array<std::uint8_t, 16> raw{};
        std::random_device rd;
        for (std::size_t i = 0; i < 16; i += 4) {
            std::uint32_t v = rd();
            raw[i + 0] = static_cast<std::uint8_t>(v & 0xffu);
            raw[i + 1] = static_cast<std::uint8_t>((v >> 8) & 0xffu);
            raw[i + 2] = static_cast<std::uint8_t>((v >> 16) & 0xffu);
            raw[i + 3] = static_cast<std::uint8_t>((v >> 24) & 0xffu);
        }
        return base64_encode(raw);
    }

    inline auto encode_ws_client_frame(std::uint8_t opcode, std::string_view payload) -> std::string {
        std::string out;
        out.reserve(payload.size() + 14);
        out.push_back(static_cast<char>(0x80u | (opcode & 0x0fu)));
        if (payload.size() < 126u) {
            out.push_back(static_cast<char>(0x80u | payload.size()));
        } else if (payload.size() <= 0xffffu) {
            out.push_back(static_cast<char>(0x80u | 126u));
            out.push_back(static_cast<char>((payload.size() >> 8) & 0xffu));
            out.push_back(static_cast<char>(payload.size() & 0xffu));
        } else {
            out.push_back(static_cast<char>(0x80u | 127u));
            std::uint64_t n = static_cast<std::uint64_t>(payload.size());
            for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<char>((n >> shift) & 0xffu));
        }
        std::random_device rd;
        std::uint32_t r = rd();
        std::array<std::uint8_t, 4> mask{
            static_cast<std::uint8_t>(r & 0xffu), static_cast<std::uint8_t>((r >> 8) & 0xffu),
            static_cast<std::uint8_t>((r >> 16) & 0xffu), static_cast<std::uint8_t>((r >> 24) & 0xffu),
        };
        for (auto m : mask) out.push_back(static_cast<char>(m));
        for (std::size_t i = 0; i < payload.size(); ++i) {
            out.push_back(static_cast<char>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
        }
        return out;
    }

    inline auto encode_ws_client_close(std::uint16_t code) -> std::string {
        char body[2]{static_cast<char>((code >> 8) & 0xffu), static_cast<char>(code & 0xffu)};
        return encode_ws_client_frame(0x8u, std::string_view(body, 2));
    }

    enum class FrameStatus : std::uint8_t { need_more, ok, protocol_error, too_large };
    struct ServerFrame { std::uint8_t opcode = 0; bool fin = true; std::string payload; };

    inline auto decode_ws_server_frame(std::string& buf, ServerFrame& out, std::size_t max_bytes = kMaxWsFrameBytes) -> FrameStatus {
        if (buf.size() < 2) return FrameStatus::need_more;
        auto b0 = static_cast<std::uint8_t>(buf[0]);
        auto b1 = static_cast<std::uint8_t>(buf[1]);
        if ((b0 & 0x70u) != 0 || (b1 & 0x80u) != 0) return FrameStatus::protocol_error;
        bool fin = (b0 & 0x80u) != 0;
        std::uint8_t op = b0 & 0x0fu;
        if (op != 0x0 && op != 0x1 && op != 0x2 && op != 0x8 && op != 0x9 && op != 0xA) return FrameStatus::protocol_error;
        std::uint64_t len = b1 & 0x7fu;
        std::size_t hdr = 2;
        if (op >= 0x8 && (!fin || len >= 126)) return FrameStatus::protocol_error;
        if (len == 126) {
            if (buf.size() < 4) return FrameStatus::need_more;
            len = (std::uint64_t{static_cast<std::uint8_t>(buf[2])} << 8) | static_cast<std::uint8_t>(buf[3]);
            hdr = 4;
        } else if (len == 127) {
            if (buf.size() < 10) return FrameStatus::need_more;
            if ((static_cast<std::uint8_t>(buf[2]) & 0x80u) != 0) return FrameStatus::protocol_error;
            len = 0;
            for (std::size_t i = 0; i < 8; ++i) len = (len << 8) | static_cast<std::uint8_t>(buf[2 + i]);
            hdr = 10;
        }
        if (len > max_bytes) return FrameStatus::too_large;
        std::size_t total = hdr + static_cast<std::size_t>(len);
        if (buf.size() < total) return FrameStatus::need_more;
        out.fin = fin;
        out.opcode = op;
        out.payload.assign(buf, hdr, static_cast<std::size_t>(len));
        buf.erase(0, total);
        return FrameStatus::ok;
    }

    inline auto json_to_u64(JsonValue const* v) noexcept -> std::optional<std::uint64_t> {
        if (!v) return std::nullopt;
        if (v->is_i64()) {
            auto n = std::get<std::int64_t>(v->data);
            return n >= 0 ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(n)) : std::nullopt;
        }
        if (v->is_string()) {
            auto const& s = std::get<std::string>(v->data);
            std::uint64_t out = 0;
            auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
            if (ec == std::errc{} && ptr == s.data() + s.size()) return out;
        }
        return std::nullopt;
    }

    inline auto compute_accept(std::string_view sec_ws_key) -> std::string {
        std::string combined;
        combined.reserve(sec_ws_key.size() + kWsMagicGuid.size());
        combined.append(sec_ws_key);
        combined.append(kWsMagicGuid);
        return base64_encode(sha1_digest(combined));
    }

    inline auto parse_envelope(std::string_view json) -> std::optional<WsEvent> {
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) return std::nullopt;
        auto const& obj = std::get<JsonObject>(parsed->data);
        auto type = json_get_string(obj, "type");
        if (type.empty()) return std::nullopt;
        std::string data_json;
        if (auto const* data_val = json_find(obj, "data")) data_json = json_stringify(*data_val, false);
        return WsEvent{std::move(type), std::move(data_json)};
    }

    inline auto parse_metrics(std::string_view json) -> std::optional<MetricsSnapshot> {
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) return std::nullopt;
        auto const& obj = std::get<JsonObject>(parsed->data);
        MetricsSnapshot out{};
        bool any = false;
        if (auto v = json_to_u64(json_find(obj, "control_generation"))) { out.control_generation = *v; any = true; }
        if (auto v = json_to_u64(json_find(obj, "active_sessions"))) { out.active_sessions = *v; any = true; }
        if (auto v = json_to_u64(json_find(obj, "upload_bytes_total"))) { out.upload_bytes = *v; any = true; }
        else if (auto v2 = json_to_u64(json_find(obj, "upload_bytes"))) { out.upload_bytes = *v2; any = true; }
        if (auto v = json_to_u64(json_find(obj, "download_bytes_total"))) { out.download_bytes = *v; any = true; }
        else if (auto v2 = json_to_u64(json_find(obj, "download_bytes"))) { out.download_bytes = *v2; any = true; }
        return any ? std::optional<MetricsSnapshot>(out) : std::nullopt;
    }
}
