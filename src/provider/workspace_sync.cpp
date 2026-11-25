// E2EE cross-device workspace sync envelope (nexus-sync-v1: scrypt + XChaCha20-Poly1305).
module provider.workspace_compose;
import std;
import crypto;
import encoding.base64;
import encoding.hex;
import glaze;
import :detail;

namespace provider {
    using namespace ws_detail;

    namespace {
        constexpr std::size_t kMaxWorkspaceBytes = 8u * 1024u * 1024u;
        constexpr std::size_t kMaxEnvelopeBytes = 16u * 1024u * 1024u;
        constexpr std::size_t kMaxPassphraseBytes = 4096u;
        constexpr std::uint64_t kDefaultScryptN = 32768u;
        constexpr std::uint64_t kDefaultScryptR = 8u;
        constexpr std::uint64_t kDefaultScryptP = 1u;
        constexpr std::size_t kScryptMaxMem = 64u * 1024u * 1024u;

        struct SyncEnvelope {
            std::string format = "nexus-sync-v1";
            std::string kdf = "scrypt";
            std::uint64_t kdf_n = kDefaultScryptN;
            std::uint64_t kdf_r = kDefaultScryptR;
            std::uint64_t kdf_p = kDefaultScryptP;
            std::string aead = "xchacha20-poly1305";
            std::string salt_b64;
            std::string nonce_b64;
            std::int64_t revision = 0;
            std::int64_t updated_at_ms = 0;
            std::string device_label;
            std::string plaintext_sha256;
            std::string ciphertext_b64;
        };

        struct BytesCleaner {
            crypto::Bytes& buf;
            ~BytesCleaner() { crypto::cleanse(buf); }
        };

        struct StringCleaner {
            std::string& buf;
            ~StringCleaner() {
                if (!buf.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(buf.data()), buf.size()});
            }
        };

        auto make_sync_aad(SyncEnvelope const& env) -> std::string {
            return std::format("nexus-sync-v1|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                env.kdf, env.kdf_n, env.kdf_r, env.kdf_p, env.aead,
                env.salt_b64, env.nonce_b64, env.revision, env.updated_at_ms);
        }

        auto sanitize_device_label(std::string_view raw) -> std::string {
            auto s = trim(raw);
            std::string out;
            auto cont = [](unsigned char b) noexcept { return (b & 0xC0u) == 0x80u; };
            for (std::size_t i = 0; i < s.size();) {
                auto c = static_cast<unsigned char>(s[i]);
                std::size_t cp_len = 0;
                if (c < 0x80u) {
                    if (c < 0x20u || c == 0x7fu) { ++i; continue; }
                    cp_len = 1u;
                } else if (c >= 0xC2u && c <= 0xDFu && i + 1u < s.size() && cont(static_cast<unsigned char>(s[i + 1u]))) {
                    cp_len = 2u;
                } else if (c >= 0xE0u && c <= 0xEFu && i + 2u < s.size()) {
                    auto b1 = static_cast<unsigned char>(s[i + 1u]), b2 = static_cast<unsigned char>(s[i + 2u]);
                    if (cont(b1) && cont(b2) && !(c == 0xE0u && b1 < 0xA0u) && !(c == 0xEDu && b1 >= 0xA0u)) cp_len = 3u;
                } else if (c >= 0xF0u && c <= 0xF4u && i + 3u < s.size()) {
                    auto b1 = static_cast<unsigned char>(s[i + 1u]), b2 = static_cast<unsigned char>(s[i + 2u]), b3 = static_cast<unsigned char>(s[i + 3u]);
                    if (cont(b1) && cont(b2) && cont(b3) && !(c == 0xF0u && b1 < 0x90u) && !(c == 0xF4u && b1 >= 0x90u)) cp_len = 4u;
                }
                if (cp_len == 0u) { ++i; continue; }
                if (out.size() + cp_len > 128u) break;
                out.append(s.data() + i, cp_len);
                i += cp_len;
            }
            return out;
        }

        auto sha256_bytes(std::string_view data) -> std::expected<crypto::Bytes, std::string> {
            auto span = std::span<std::uint8_t const>(
                reinterpret_cast<std::uint8_t const*>(data.data()), data.size());
            auto d = crypto::digest(crypto::Hash::sha256, span);
            if (!d || d->size() != 32u) return std::unexpected("SHA-256 digest failed");
            return std::move(*d);
        }

        auto decode_hex_32(std::string_view hex) -> std::optional<std::array<std::uint8_t, 32>> {
            if (hex.size() != 64u) return std::nullopt;
            std::array<std::uint8_t, 32> out{};
            for (std::size_t i = 0; i < 32u; ++i) {
                int hi = encoding::hex_value(hex[i * 2u]);
                int lo = encoding::hex_value(hex[i * 2u + 1u]);
                if (hi < 0 || lo < 0) return std::nullopt;
                out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
            return out;
        }
    }

    auto seal_workspace_sync(
        std::string_view workspace_json,
        std::string_view passphrase,
        std::string_view device_label) -> WorkspaceSyncSealResult {
        WorkspaceSyncSealResult res{};
        if (workspace_json.size() > kMaxWorkspaceBytes) {
            res.errors.push_back("workspace.json exceeds 8 MiB limit");
            return res;
        }
        if (passphrase.empty() || passphrase.size() > kMaxPassphraseBytes) {
            res.errors.push_back("sync passphrase must be 1..4096 bytes");
            return res;
        }
        Workspace ws{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(ws, workspace_json)) {
            res.errors.push_back("invalid workspace.json: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, workspace_json));
            return res;
        }
        if (ws.schema_version != 1) {
            res.errors.push_back("unsupported workspace schema_version");
            return res;
        }
        // Re-serialize strictly through canonical Layer 1 schema so zero host/telemetry/cred keys leak.
        auto canonical_pt = glaze::write_json(ws);
        if (!canonical_pt) {
            res.errors.push_back("failed to canonicalize workspace.json");
            return res;
        }
        StringCleaner clean_pt{*canonical_pt};
        auto pt_hash = sha256_bytes(*canonical_pt);
        if (!pt_hash) {
            res.errors.push_back(pt_hash.error());
            return res;
        }

        std::array<std::uint8_t, 16> salt{};
        std::array<std::uint8_t, 24> nonce{};
        if (!crypto::random_bytes(salt) || !crypto::random_bytes(nonce)) {
            res.errors.push_back("random_bytes failed");
            return res;
        }

        SyncEnvelope env{};
        env.salt_b64 = encoding::encode_base64(salt, false, true);
        env.nonce_b64 = encoding::encode_base64(nonce, false, true);
        env.revision = ws.revision;
        env.updated_at_ms = ws.updated_at_ms;
        env.device_label = sanitize_device_label(device_label);
        env.plaintext_sha256 = encoding::hex_encode(*pt_hash);

        auto key_res = crypto::scrypt_derive_key(
            passphrase, salt, env.kdf_n, env.kdf_r, env.kdf_p, 32u, kScryptMaxMem);
        if (!key_res) {
            res.errors.push_back("scrypt key derivation failed");
            return res;
        }
        BytesCleaner clean_key{*key_res};

        auto aad = make_sync_aad(env);
        auto pt_span = std::span<std::uint8_t const>(
            reinterpret_cast<std::uint8_t const*>(canonical_pt->data()), canonical_pt->size());
        auto aad_span = std::span<std::uint8_t const>(
            reinterpret_cast<std::uint8_t const*>(aad.data()), aad.size());
        auto ct = crypto::seal(crypto::Aead::xchacha20_poly1305, *key_res, nonce, pt_span, aad_span);
        if (!ct) {
            res.errors.push_back("AEAD encryption failed");
            return res;
        }
        env.ciphertext_b64 = encoding::encode_base64(*ct, false, true);

        auto env_json = glaze::write_json(env);
        if (!env_json) {
            res.errors.push_back("failed to serialize sync envelope JSON");
            return res;
        }
        auto env_hash = sha256_bytes(*env_json);
        if (!env_hash) {
            res.errors.push_back(env_hash.error());
            return res;
        }

        res.ok = true;
        res.revision = env.revision;
        res.updated_at_ms = env.updated_at_ms;
        res.envelope_sha256 = encoding::hex_encode(*env_hash);
        res.envelope_json = std::move(*env_json);
        return res;
    }

    auto open_workspace_sync(
        std::string_view envelope_json,
        std::string_view passphrase) -> WorkspaceSyncOpenResult {
        WorkspaceSyncOpenResult res{};
        if (envelope_json.size() > kMaxEnvelopeBytes) {
            res.errors.push_back("sync envelope exceeds 16 MiB limit");
            return res;
        }
        if (passphrase.empty() || passphrase.size() > kMaxPassphraseBytes) {
            res.errors.push_back("sync passphrase must be 1..4096 bytes");
            return res;
        }
        SyncEnvelope env{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(env, envelope_json)) {
            res.errors.push_back("invalid sync envelope JSON: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, envelope_json));
            return res;
        }
        if (env.format != "nexus-sync-v1") {
            res.errors.push_back("unsupported sync envelope format");
            return res;
        }
        if (env.kdf != "scrypt" || env.kdf_n < 16384u || env.kdf_n > 131072u ||
            (env.kdf_n & (env.kdf_n - 1u)) != 0u || env.kdf_r < 1u || env.kdf_r > 16u ||
            env.kdf_p < 1u || env.kdf_p > 4u) {
            res.errors.push_back("unsupported or out-of-range scrypt parameters");
            return res;
        }
        if (env.aead != "xchacha20-poly1305") {
            res.errors.push_back("unsupported sync AEAD algorithm");
            return res;
        }
        auto expected_sha = decode_hex_32(env.plaintext_sha256);
        if (!expected_sha) {
            res.errors.push_back("invalid plaintext_sha256 in sync envelope");
            return res;
        }

        std::vector<std::uint8_t> salt, nonce, ct;
        if (!encoding::decode_base64_strict(env.salt_b64, salt) || salt.size() < 16u || salt.size() > 64u) {
            res.errors.push_back("invalid salt_b64 in sync envelope");
            return res;
        }
        if (!encoding::decode_base64_strict(env.nonce_b64, nonce) || nonce.size() != 24u) {
            res.errors.push_back("invalid nonce_b64 in sync envelope");
            return res;
        }
        if (!encoding::decode_base64_strict(env.ciphertext_b64, ct) || ct.size() < 16u) {
            res.errors.push_back("invalid ciphertext_b64 in sync envelope");
            return res;
        }

        auto key_res = crypto::scrypt_derive_key(
            passphrase, salt, env.kdf_n, env.kdf_r, env.kdf_p, 32u, kScryptMaxMem);
        if (!key_res) {
            res.errors.push_back("scrypt key derivation failed");
            return res;
        }
        BytesCleaner clean_key{*key_res};

        auto aad = make_sync_aad(env);
        auto aad_span = std::span<std::uint8_t const>(
            reinterpret_cast<std::uint8_t const*>(aad.data()), aad.size());
        auto pt = crypto::open(crypto::Aead::xchacha20_poly1305, *key_res, nonce, ct, aad_span);
        if (!pt) {
            res.errors.push_back("authentication failed: wrong passphrase or tampered envelope");
            return res;
        }
        BytesCleaner clean_pt{*pt};

        std::string_view pt_view(reinterpret_cast<char const*>(pt->data()), pt->size());
        auto actual_sha = sha256_bytes(pt_view);
        if (!actual_sha || !crypto::constant_time_equal(*actual_sha, *expected_sha)) {
            res.errors.push_back("plaintext_sha256 integrity mismatch");
            return res;
        }
        if (!is_valid_utf8(pt_view)) {
            res.errors.push_back("decrypted workspace payload is not valid UTF-8");
            return res;
        }

        Workspace ws{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(ws, pt_view)) {
            res.errors.push_back("decrypted payload is not valid workspace.json: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, pt_view));
            return res;
        }
        if (ws.schema_version != 1) {
            res.errors.push_back("unsupported decrypted workspace schema_version");
            return res;
        }
        auto sanitized = glaze::write_json(ws);
        if (!sanitized) {
            res.errors.push_back("failed to sanitize decrypted workspace.json");
            return res;
        }

        res.ok = true;
        res.revision = env.revision;
        res.updated_at_ms = env.updated_at_ms;
        res.device_label = sanitize_device_label(env.device_label);
        res.workspace_json = std::move(*sanitized);
        return res;
    }

    auto serialize_sync_seal_result_json(WorkspaceSyncSealResult const& r) -> std::string {
        std::string out = "{\"ok\":";
        out += r.ok ? "true" : "false";
        out += ",\"revision\":"; out += std::to_string(r.revision);
        out += ",\"updated_at_ms\":"; out += std::to_string(r.updated_at_ms);
        out += ",\"envelope_sha256\":"; out += json_quote(r.envelope_sha256);
        out += ",\"warnings\":"; append_json_string_array(out, r.warnings);
        out += ",\"errors\":"; append_json_string_array(out, r.errors);
        out += ",\"envelope_json\":"; out += json_quote(r.envelope_json);
        out += "}\n";
        return out;
    }

    auto serialize_sync_open_result_json(WorkspaceSyncOpenResult const& r) -> std::string {
        std::string out = "{\"ok\":";
        out += r.ok ? "true" : "false";
        out += ",\"revision\":"; out += std::to_string(r.revision);
        out += ",\"updated_at_ms\":"; out += std::to_string(r.updated_at_ms);
        out += ",\"device_label\":"; out += json_quote(r.device_label);
        out += ",\"warnings\":"; append_json_string_array(out, r.warnings);
        out += ",\"errors\":"; append_json_string_array(out, r.errors);
        out += ",\"workspace_json\":"; out += json_quote(r.workspace_json);
        out += "}\n";
        return out;
    }
}
