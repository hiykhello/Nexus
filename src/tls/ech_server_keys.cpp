module;
#include <openssl/hpke.h>

module tls.ech_server;
import std;
import crypto;
import rulefile;

namespace tls {
    namespace {
        using Bytes = std::span<std::uint8_t const>;
        constexpr std::uint16_t ech_ext_type = 0xfe0d;

        auto read16(Bytes s, std::size_t pos) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{s[pos]} << 8) | s[pos + 1]);
        }

        auto valid_hpke_aead(std::uint16_t id) noexcept -> bool {
            return id == 1 || id == 2 || id == 3;
        }

        auto trim_ws(std::string_view s) noexcept -> std::string_view {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
                s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
                s.remove_suffix(1);
            return s;
        }

        auto decode_b64(std::string_view input) -> std::optional<crypto::Bytes> {
            crypto::Bytes out;
            out.reserve((input.size() * 3) / 4 + 4);
            std::uint32_t acc = 0;
            int bits = 0, pad = 0;
            for (char ch : input) {
                if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
                if (ch == '=') { ++pad; continue; }
                if (pad) return std::nullopt;
                int v = -1;
                if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
                else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
                else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
                else if (ch == '+' || ch == '-') v = 62;
                else if (ch == '/' || ch == '_') v = 63;
                else return std::nullopt;
                acc = (acc << 6) | static_cast<std::uint32_t>(v);
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff));
                }
            }
            if (pad > 2 || (bits > 0 && ((acc & ((1u << bits) - 1u)) != 0))) return std::nullopt;
            return out;
        }

        auto extract_raw_x25519_key(Bytes raw) -> std::optional<std::array<std::uint8_t, 32>> {
            std::array<std::uint8_t, 32> out{};
            if (raw.size() == 32) {
                std::ranges::copy(raw, out.begin());
                return out;
            }
            constexpr std::array<std::uint8_t, 16> pkcs8_prefix{
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20};
            if (raw.size() == 48 && std::ranges::equal(raw.first(16), pkcs8_prefix)) {
                std::ranges::copy(raw.subspan(16, 32), out.begin());
                return out;
            }
            return std::nullopt;
        }

        auto derive_x25519_public(std::span<std::uint8_t const, 32> priv)
            -> std::optional<std::array<std::uint8_t, 32>> {
            EVP_HPKE_KEY key;
            EVP_HPKE_KEY_zero(&key);
            struct Guard { EVP_HPKE_KEY* k; ~Guard() { EVP_HPKE_KEY_cleanup(k); } } guard{&key};
            if (!EVP_HPKE_KEY_init(&key, EVP_hpke_x25519_hkdf_sha256(), priv.data(), priv.size()))
                return std::nullopt;
            std::array<std::uint8_t, 32> pub{};
            std::size_t pub_len = 0;
            if (!EVP_HPKE_KEY_public_key(&key, pub.data(), &pub_len, pub.size()) || pub_len != 32)
                return std::nullopt;
            return pub;
        }

        struct ParsedConfig {
            std::uint8_t id = 0;
            std::uint8_t max_name_len = 0;
            std::array<std::uint8_t, 32> pub_key{};
            std::string public_name;
            std::vector<std::pair<std::uint16_t, std::uint16_t>> suites;
            crypto::Bytes wire;
        };

        auto parse_single_ech_config(Bytes wire) -> std::optional<ParsedConfig> {
            if (wire.size() < 13 || read16(wire, 0) != ech_ext_type) return std::nullopt;
            auto content_len = std::size_t{read16(wire, 2)};
            if (4 + content_len != wire.size()) return std::nullopt;
            auto c = wire.subspan(4, content_len);
            if (c.size() < 9) return std::nullopt;
            ParsedConfig out;
            out.id = c[0];
            if (read16(c, 1) != 0x0020) return std::nullopt;
            auto pk_len = std::size_t{read16(c, 3)};
            if (pk_len != 32 || c.size() < 5 + 32 + 2) return std::nullopt;
            std::ranges::copy(c.subspan(5, 32), out.pub_key.begin());
            std::size_t pos = 37;
            auto cs_len = std::size_t{read16(c, pos)}; pos += 2;
            if (cs_len == 0 || (cs_len % 4) != 0 || cs_len > c.size() - pos) return std::nullopt;
            for (std::size_t i = 0; i < cs_len; i += 4) {
                auto kdf = read16(c, pos + i);
                auto aead = read16(c, pos + i + 2);
                if (kdf == 0x0001 && valid_hpke_aead(aead)) out.suites.emplace_back(kdf, aead);
            }
            if (out.suites.empty()) return std::nullopt;
            pos += cs_len;
            if (c.size() - pos < 4) return std::nullopt;
            out.max_name_len = c[pos++];
            auto name_len = std::size_t{c[pos++]};
            if (name_len == 0 || name_len > c.size() - pos || c.size() - (pos + name_len) < 2) return std::nullopt;
            out.public_name.assign(reinterpret_cast<char const*>(c.data() + pos), name_len);
            pos += name_len;
            auto ext_len = std::size_t{read16(c, pos)}; pos += 2;
            if (ext_len != c.size() - pos) return std::nullopt;
            out.wire.assign(wire.begin(), wire.end());
            return out;
        }

        auto parse_ech_config_list(Bytes list_bytes) -> std::optional<std::vector<ParsedConfig>> {
            std::vector<ParsedConfig> result;
            if (list_bytes.size() >= 4 && read16(list_bytes, 0) == ech_ext_type &&
                std::size_t{read16(list_bytes, 2)} + 4 == list_bytes.size()) {
                if (auto single = parse_single_ech_config(list_bytes)) {
                    result.push_back(std::move(*single));
                    return result;
                }
                return std::nullopt;
            }
            if (list_bytes.size() < 6) return std::nullopt;
            auto total = std::size_t{read16(list_bytes, 0)};
            if (total == 0 || total != list_bytes.size() - 2) return std::nullopt;
            std::size_t pos = 2;
            while (pos < list_bytes.size()) {
                if (list_bytes.size() - pos < 4) return std::nullopt;
                auto version = read16(list_bytes, pos);
                auto clen = std::size_t{read16(list_bytes, pos + 2)};
                if (clen > list_bytes.size() - (pos + 4)) return std::nullopt;
                if (version == ech_ext_type) {
                    auto cfg = parse_single_ech_config(list_bytes.subspan(pos, 4 + clen));
                    if (!cfg) return std::nullopt;
                    result.push_back(std::move(*cfg));
                }
                pos += 4 + clen;
            }
            if (result.empty()) return std::nullopt;
            return result;
        }

        auto append_matched_entry(std::vector<EchServerKeyEntry>& entries,
                                  std::array<std::uint8_t, 32> const& priv,
                                  Bytes config_list) -> std::expected<void, std::string> {
            auto pub = derive_x25519_public(priv);
            if (!pub) return std::unexpected("invalid ECH X25519 private key");
            auto parsed = parse_ech_config_list(config_list);
            if (!parsed) return std::unexpected("invalid ECHConfigList");
            bool matched = false;
            for (auto& cfg : *parsed) {
                if (cfg.pub_key != *pub) continue;
                EchServerKeyEntry entry;
                entry.config_id = cfg.id;
                entry.maximum_name_length = cfg.max_name_len;
                entry.public_name = std::move(cfg.public_name);
                entry.suites = std::move(cfg.suites);
                entry.config_wire = std::move(cfg.wire);
                entry.private_key = priv;
                entries.push_back(std::move(entry));
                matched = true;
            }
            if (!matched) return std::unexpected("ECH private key does not match any ECHConfig public key");
            return {};
        }

        auto build_keys_object(std::vector<EchServerKeyEntry>&& entries)
            -> std::expected<std::shared_ptr<EchServerKeys const>, std::string> {
            if (entries.empty()) return std::unexpected("no ECH server keys found");
            std::size_t total = 0;
            for (auto const& e : entries) {
                if (e.config_wire.size() > 65535 - total) return std::unexpected("ECH retry_configs list too large");
                total += e.config_wire.size();
            }
            crypto::Bytes retry_wire;
            retry_wire.reserve(2 + total);
            retry_wire.push_back(static_cast<std::uint8_t>(total >> 8));
            retry_wire.push_back(static_cast<std::uint8_t>(total & 0xff));
            for (auto const& e : entries) retry_wire.insert(retry_wire.end(), e.config_wire.begin(), e.config_wire.end());
            return std::make_shared<EchServerKeys const>(std::move(entries), std::move(retry_wire));
        }

        auto parse_pem_blocks(std::string_view text) -> std::optional<std::vector<std::pair<std::string, crypto::Bytes>>> {
            std::vector<std::pair<std::string, crypto::Bytes>> blocks;
            std::size_t pos = 0;
            while (pos < text.size()) {
                auto begin_hdr = text.find("-----BEGIN ", pos);
                if (begin_hdr == std::string_view::npos) break;
                auto begin_end = text.find("-----", begin_hdr + 11);
                if (begin_end == std::string_view::npos) return std::nullopt;
                auto label = std::string(text.substr(begin_hdr + 11, begin_end - (begin_hdr + 11)));
                auto body_start = begin_end + 5;
                auto end_marker = "-----END " + label + "-----";
                auto end_hdr = text.find(end_marker, body_start);
                if (end_hdr == std::string_view::npos) return std::nullopt;
                auto decoded = decode_b64(text.substr(body_start, end_hdr - body_start));
                if (!decoded) return std::nullopt;
                blocks.emplace_back(std::move(label), std::move(*decoded));
                pos = end_hdr + end_marker.size();
            }
            if (blocks.empty()) return std::nullopt;
            return blocks;
        }
    }

    auto parse_ech_server_keys(Bytes bytes) -> std::expected<std::shared_ptr<EchServerKeys const>, std::string> {
        if (bytes.empty()) return std::unexpected("empty ECH server key data");
        std::vector<EchServerKeyEntry> entries;
        std::string_view text(reinterpret_cast<char const*>(bytes.data()), bytes.size());

        // Format 1: PEM ("ECH KEYS" or "ECH PRIVATE KEY"/"PRIVATE KEY" + "ECH CONFIG"/"ECHCONFIG").
        if (text.find("-----BEGIN ") != std::string_view::npos) {
            auto blocks = parse_pem_blocks(text);
            if (!blocks) return std::unexpected("malformed PEM ECH key block");
            std::optional<std::array<std::uint8_t, 32>> pending_priv;
            struct CleanPending { std::optional<std::array<std::uint8_t, 32>>& p; ~CleanPending() { if (p) crypto::cleanse(*p); } } cp{pending_priv};
            for (auto& [label, payload] : *blocks) {
                struct CleanBuf { crypto::Bytes& b; ~CleanBuf() { crypto::cleanse(b); } } cb{payload};
                if (label == "ECH KEYS") {
                    if (payload.size() >= 38 && read16(payload, 0) == 32 &&
                        36 + std::size_t{read16(payload, 34)} == payload.size()) {
                        auto priv = extract_raw_x25519_key(Bytes(payload).subspan(2, 32));
                        if (!priv) return std::unexpected("invalid ECH KEYS private key");
                        auto ok = append_matched_entry(entries, *priv, Bytes(payload).subspan(36));
                        crypto::cleanse(*priv);
                        if (!ok) return std::unexpected(ok.error());
                    } else if (payload.size() >= 38) {
                        auto priv = extract_raw_x25519_key(Bytes(payload).first(32));
                        if (!priv) return std::unexpected("invalid ECH KEYS payload");
                        auto ok = append_matched_entry(entries, *priv, Bytes(payload).subspan(32));
                        crypto::cleanse(*priv);
                        if (!ok) return std::unexpected(ok.error());
                    } else {
                        return std::unexpected("truncated PEM ECH KEYS block");
                    }
                } else if (label == "ECH PRIVATE KEY" || label == "PRIVATE KEY") {
                    auto priv = extract_raw_x25519_key(payload);
                    if (!priv) return std::unexpected("unsupported ECH private key PEM format");
                    if (pending_priv) crypto::cleanse(*pending_priv);
                    pending_priv = *priv;
                    crypto::cleanse(*priv);
                } else if (label == "ECH CONFIG" || label == "ECHCONFIG" || label == "ECH CONFIGS" || label == "ECHCONFIGS") {
                    if (!pending_priv) return std::unexpected("ECH CONFIG PEM block missing preceding private key");
                    auto ok = append_matched_entry(entries, *pending_priv, payload);
                    crypto::cleanse(*pending_priv);
                    pending_priv.reset();
                    if (!ok) return std::unexpected(ok.error());
                }
            }
            return build_keys_object(std::move(entries));
        }

        // Format 2: `nexus generate ech-keypair` text ("PrivateKey: ...\nEchConfigList: ...").
        if (text.find("PrivateKey:") != std::string_view::npos || text.find("EchConfigList:") != std::string_view::npos) {
            std::optional<std::array<std::uint8_t, 32>> pending_priv;
            struct CleanPending { std::optional<std::array<std::uint8_t, 32>>& p; ~CleanPending() { if (p) crypto::cleanse(*p); } } cp{pending_priv};
            std::size_t line_start = 0;
            while (line_start < text.size()) {
                auto nl = text.find('\n', line_start);
                auto line = trim_ws(nl == std::string_view::npos ? text.substr(line_start) : text.substr(line_start, nl - line_start));
                line_start = (nl == std::string_view::npos) ? text.size() : nl + 1;
                if (line.empty() || line.front() == '#') continue;
                if (line.starts_with("PrivateKey:")) {
                    auto decoded = decode_b64(trim_ws(line.substr(11)));
                    if (!decoded) return std::unexpected("invalid base64 PrivateKey in ECH key file");
                    auto priv = extract_raw_x25519_key(*decoded);
                    crypto::cleanse(*decoded);
                    if (!priv) return std::unexpected("ECH PrivateKey must decode to 32 bytes");
                    if (pending_priv) crypto::cleanse(*pending_priv);
                    pending_priv = *priv;
                    crypto::cleanse(*priv);
                } else if (line.starts_with("EchConfigList:")) {
                    if (!pending_priv) return std::unexpected("EchConfigList missing preceding PrivateKey");
                    auto decoded = decode_b64(trim_ws(line.substr(14)));
                    if (!decoded) return std::unexpected("invalid base64 EchConfigList in ECH key file");
                    auto ok = append_matched_entry(entries, *pending_priv, *decoded);
                    crypto::cleanse(*pending_priv);
                    pending_priv.reset();
                    if (!ok) return std::unexpected(ok.error());
                } else {
                    return std::unexpected("unexpected line in ECH key file");
                }
            }
            return build_keys_object(std::move(entries));
        }

        // Format 3: Raw binary [32B priv][ECHConfigList].
        if (bytes.size() >= 38) {
            if (auto priv = extract_raw_x25519_key(bytes.first(32))) {
                auto ok = append_matched_entry(entries, *priv, bytes.subspan(32));
                crypto::cleanse(*priv);
                if (!ok) return std::unexpected(ok.error());
                return build_keys_object(std::move(entries));
            }
        }
        return std::unexpected("unrecognized ECH server key format");
    }

    auto load_ech_server_keys_file(std::string_view path)
        -> std::expected<std::shared_ptr<EchServerKeys const>, std::string> {
        auto file = rulefile::read_private_file(path);
        if (!file) return std::unexpected("ECH key file: " + file.error());
        auto raw = file->bytes();
        return parse_ech_server_keys(Bytes(reinterpret_cast<std::uint8_t const*>(raw.data()), raw.size()));
    }
}
