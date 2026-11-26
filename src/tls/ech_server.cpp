module;
#include <openssl/hpke.h>

module tls.ech_server;
import std;
import crypto;
import tls.handshake;
import tls.handshake_secrets;
import tls.schedule;
import tls.server_hello;
import tls.transcript;

namespace tls {
    struct EchServerContext::Impl {
        std::unique_ptr<EVP_HPKE_CTX, decltype(&EVP_HPKE_CTX_free)> ctx{nullptr, EVP_HPKE_CTX_free};
        std::uint8_t config_id = 0;
        std::uint16_t kdf_id = 0;
        std::uint16_t aead_id = 0;
    };

    auto EchServerContext::Deleter::operator()(Impl* p) const noexcept -> void { delete p; }

    namespace {
        using Bytes = std::span<std::uint8_t const>;
        constexpr std::uint16_t ech_ext_type = 0xfe0d;
        constexpr std::uint16_t outer_exts_type = 0xfd00;
        constexpr std::size_t max_hello_body = 65531;

        auto read16(Bytes s, std::size_t pos) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{s[pos]} << 8) | s[pos + 1]);
        }

        auto hpke_aead(std::uint16_t id) noexcept -> EVP_HPKE_AEAD const* {
            switch (id) {
                case 1: return EVP_hpke_aes_128_gcm();
                case 2: return EVP_hpke_aes_256_gcm();
                case 3: return EVP_hpke_chacha20_poly1305();
                default: return nullptr;
            }
        }

        struct OuterEchSlice {
            std::uint16_t kdf_id = 0;
            std::uint16_t aead_id = 0;
            std::uint8_t config_id = 0;
            Bytes enc;
            Bytes payload;
            crypto::Bytes aad;
        };

        auto parse_outer_ech_and_aad(Bytes outer_message) -> std::expected<OuterEchSlice, EchProcessStatus> {
            if (outer_message.size() < 4 + 39 || outer_message[0] != 1)
                return std::unexpected(EchProcessStatus::protocol_error);
            auto body = outer_message.subspan(4);
            std::size_t pos = 34; // version(2) + random(32)
            if (pos >= body.size()) return std::unexpected(EchProcessStatus::protocol_error);
            auto sid_len = std::size_t{body[pos++]};
            if (sid_len > body.size() - pos) return std::unexpected(EchProcessStatus::protocol_error);
            pos += sid_len;
            if (body.size() - pos < 2) return std::unexpected(EchProcessStatus::protocol_error);
            auto cs_len = std::size_t{read16(body, pos)}; pos += 2;
            if (cs_len > body.size() - pos) return std::unexpected(EchProcessStatus::protocol_error);
            pos += cs_len;
            if (pos >= body.size()) return std::unexpected(EchProcessStatus::protocol_error);
            auto comp_len = std::size_t{body[pos++]};
            if (comp_len > body.size() - pos) return std::unexpected(EchProcessStatus::protocol_error);
            pos += comp_len;
            if (body.size() - pos < 2) return std::unexpected(EchProcessStatus::protocol_error);
            auto ext_total = std::size_t{read16(body, pos)}; pos += 2;
            if (ext_total != body.size() - pos) return std::unexpected(EchProcessStatus::protocol_error);
            while (pos + 4 <= body.size()) {
                auto type = read16(body, pos);
                auto len = std::size_t{read16(body, pos + 2)};
                pos += 4;
                if (len > body.size() - pos) return std::unexpected(EchProcessStatus::protocol_error);
                if (type != ech_ext_type) { pos += len; continue; }
                auto ext = body.subspan(pos, len);
                if (ext.empty() || ext[0] != 0 || ext.size() < 10)
                    return std::unexpected(EchProcessStatus::protocol_error);
                OuterEchSlice slice;
                slice.kdf_id = read16(ext, 1);
                slice.aead_id = read16(ext, 3);
                slice.config_id = ext[5];
                auto enc_len = std::size_t{read16(ext, 6)};
                if (enc_len > ext.size() - 8 || ext.size() - (8 + enc_len) < 2)
                    return std::unexpected(EchProcessStatus::protocol_error);
                slice.enc = ext.subspan(8, enc_len);
                auto pay_off_in_ext = 8 + enc_len + 2;
                auto pay_len = std::size_t{read16(ext, 8 + enc_len)};
                if (pay_len == 0 || pay_off_in_ext + pay_len != ext.size())
                    return std::unexpected(EchProcessStatus::protocol_error);
                slice.payload = ext.subspan(pay_off_in_ext, pay_len);
                slice.aad.assign(body.begin(), body.end());
                std::fill_n(slice.aad.begin() + static_cast<std::ptrdiff_t>(pos + pay_off_in_ext), pay_len, std::uint8_t{0});
                return slice;
            }
            return std::unexpected(EchProcessStatus::not_offered);
        }

        auto measure_encoded_inner_length(Bytes pt) noexcept -> std::optional<std::size_t> {
            if (pt.size() < 39) return std::nullopt;
            std::size_t pos = 34;
            auto sid_len = std::size_t{pt[pos++]};
            if (sid_len != 0 || pos + 2 > pt.size()) return std::nullopt;
            auto cs_len = std::size_t{read16(pt, pos)}; pos += 2;
            if (cs_len == 0 || (cs_len % 2) != 0 || cs_len > pt.size() - pos) return std::nullopt;
            pos += cs_len;
            if (pos >= pt.size()) return std::nullopt;
            auto comp_len = std::size_t{pt[pos++]};
            if (comp_len == 0 || comp_len > pt.size() - pos) return std::nullopt;
            pos += comp_len;
            if (pt.size() - pos < 2) return std::nullopt;
            auto ext_len = std::size_t{read16(pt, pos)}; pos += 2;
            if (ext_len > pt.size() - pos) return std::nullopt;
            pos += ext_len;
            for (auto b : pt.subspan(pos)) if (b != 0) return std::nullopt;
            return pos;
        }

        auto reconstruct_inner_hello(ClientHello const& outer, Bytes plaintext)
            -> std::optional<std::pair<ClientHello, crypto::Bytes>> {
            auto body_len = measure_encoded_inner_length(plaintext);
            if (!body_len) return std::nullopt;
            auto parsed = ClientHello::parse(plaintext.first(*body_len), max_hello_body);
            if (!parsed || !parsed->session_id.empty()) return std::nullopt;
            auto* marker = parsed->extension(ech_ext_type);
            if (!marker || marker->data.size() != 1 || marker->data[0] != 1) return std::nullopt;

            ClientHello inner = std::move(*parsed);
            inner.session_id = outer.session_id;

            std::vector<Extension> expanded;
            expanded.reserve(inner.extensions.size() + outer.extensions.size());
            bool outer_exts_seen = false;
            for (auto& ext : inner.extensions) {
                if (ext.type != outer_exts_type) {
                    expanded.push_back(std::move(ext));
                    continue;
                }
                if (std::exchange(outer_exts_seen, true) || ext.data.size() < 3) return std::nullopt;
                auto list_bytes = std::size_t{ext.data[0]};
                if (list_bytes == 0 || (list_bytes % 2) != 0 || 1 + list_bytes != ext.data.size()) return std::nullopt;
                std::size_t outer_cursor = 0;
                for (std::size_t i = 1; i < ext.data.size(); i += 2) {
                    auto wanted = read16(ext.data, i);
                    if (wanted == ech_ext_type || wanted == outer_exts_type) return std::nullopt;
                    bool found = false;
                    while (outer_cursor < outer.extensions.size()) {
                        auto const& cand = outer.extensions[outer_cursor++];
                        if (cand.type == wanted) {
                            expanded.push_back(cand);
                            found = true;
                            break;
                        }
                    }
                    if (!found) return std::nullopt;
                }
            }
            inner.extensions = std::move(expanded);

            std::bitset<65536> seen;
            for (auto const& e : inner.extensions) {
                if (seen.test(e.type)) return std::nullopt;
                seen.set(e.type);
            }
            if (!inner.validate_tls13() || !inner.validate_encoding(max_hello_body)) return std::nullopt;
            auto encoded = inner.encode(max_hello_body);
            if (!encoded) return std::nullopt;
            auto wire = HandshakeDecoder::encode(1, *encoded, max_hello_body);
            if (!wire) return std::nullopt;
            return std::pair{std::move(inner), std::move(*wire)};
        }
    }

    auto extract_client_hello_sni_view(ClientHello const& hello) noexcept -> std::string_view {
        auto* ext = hello.extension(0);
        if (!ext || ext->data.size() < 5) return {};
        auto list_len = std::size_t{read16(ext->data, 0)};
        if (list_len + 2 != ext->data.size() || ext->data[2] != 0) return {};
        auto name_len = std::size_t{read16(ext->data, 3)};
        if (name_len == 0 || name_len + 5 > ext->data.size()) return {};
        return std::string_view(reinterpret_cast<char const*>(ext->data.data() + 5), name_len);
    }

    auto extract_client_hello_sni(ClientHello const& hello) -> std::string {
        return std::string(extract_client_hello_sni_view(hello));
    }

    auto EchServerContext::process_client_hello(ClientHello const& outer, Bytes outer_message, bool is_retry)
        -> EchProcessResult {
        EchProcessResult res;
        res.sni = extract_client_hello_sni(outer);
        auto* ext = outer.extension(ech_ext_type);
        if (!ext) {
            res.status = (is_retry && accepted_) ? EchProcessStatus::protocol_error : EchProcessStatus::not_offered;
            return res;
        }
        if (ext->data.size() == 1 && ext->data[0] == 1) {
            res.status = EchProcessStatus::protocol_error;
            return res;
        }
        auto parsed = parse_outer_ech_and_aad(outer_message);
        if (!parsed) { res.status = parsed.error(); return res; }
        if (!has_keys()) { res.status = EchProcessStatus::not_offered; return res; }

        if (is_retry) {
            if (!accepted_) { res.status = EchProcessStatus::not_offered; return res; }
            if (!impl_ || !impl_->ctx || !parsed->enc.empty() ||
                parsed->config_id != impl_->config_id ||
                parsed->kdf_id != impl_->kdf_id || parsed->aead_id != impl_->aead_id) {
                res.status = EchProcessStatus::protocol_error;
                return res;
            }
            crypto::Bytes pt(parsed->payload.size());
            std::size_t pt_len = 0;
            if (!EVP_HPKE_CTX_open(impl_->ctx.get(), pt.data(), &pt_len, pt.size(),
                                   parsed->payload.data(), parsed->payload.size(),
                                   parsed->aad.data(), parsed->aad.size())) {
                res.status = EchProcessStatus::protocol_error;
                return res;
            }
            pt.resize(pt_len);
            auto inner = reconstruct_inner_hello(outer, pt);
            if (!inner) { res.status = EchProcessStatus::protocol_error; return res; }
            res.status = EchProcessStatus::accepted;
            res.sni = extract_client_hello_sni(inner->first);
            res.inner_hello = std::move(inner->first);
            res.inner_message = std::move(inner->second);
            return res;
        }

        if (parsed->enc.size() != 32) {
            rejected_offered_ = true;
            res.status = EchProcessStatus::rejected_send_retry_configs;
            return res;
        }
        auto const* aead = hpke_aead(parsed->aead_id);
        if (parsed->kdf_id == 0x0001 && aead) {
            for (auto const& entry : keys_->entries()) {
                if (entry.config_id != parsed->config_id) continue;
                bool suite_ok = std::ranges::any_of(entry.suites, [&](auto const& s) {
                    return s.first == parsed->kdf_id && s.second == parsed->aead_id;
                });
                if (!suite_ok) continue;

                EVP_HPKE_KEY hpke_key;
                EVP_HPKE_KEY_zero(&hpke_key);
                struct KeyGuard { EVP_HPKE_KEY* k; ~KeyGuard() { EVP_HPKE_KEY_cleanup(k); } } kg{&hpke_key};
                if (!EVP_HPKE_KEY_init(&hpke_key, EVP_hpke_x25519_hkdf_sha256(),
                                       entry.private_key.data(), entry.private_key.size()))
                    continue;

                crypto::Bytes info{'t', 'l', 's', ' ', 'e', 'c', 'h', 0};
                info.insert(info.end(), entry.config_wire.begin(), entry.config_wire.end());
                std::unique_ptr<EVP_HPKE_CTX, decltype(&EVP_HPKE_CTX_free)> ctx(EVP_HPKE_CTX_new(), EVP_HPKE_CTX_free);
                if (!ctx) { res.status = EchProcessStatus::crypto_error; return res; }
                if (!EVP_HPKE_CTX_setup_recipient(ctx.get(), &hpke_key, EVP_hpke_hkdf_sha256(), aead,
                                                  parsed->enc.data(), parsed->enc.size(),
                                                  info.data(), info.size()))
                    continue;
                crypto::Bytes pt(parsed->payload.size());
                std::size_t pt_len = 0;
                if (!EVP_HPKE_CTX_open(ctx.get(), pt.data(), &pt_len, pt.size(),
                                       parsed->payload.data(), parsed->payload.size(),
                                       parsed->aad.data(), parsed->aad.size()))
                    continue;
                pt.resize(pt_len);
                auto inner = reconstruct_inner_hello(outer, pt);
                if (!inner) { res.status = EchProcessStatus::protocol_error; return res; }
                impl_.reset(new Impl{std::move(ctx), parsed->config_id, parsed->kdf_id, parsed->aead_id});
                accepted_ = true;
                rejected_offered_ = false;
                res.status = EchProcessStatus::accepted;
                res.sni = extract_client_hello_sni(inner->first);
                res.inner_hello = std::move(inner->first);
                res.inner_message = std::move(inner->second);
                return res;
            }
        }
        rejected_offered_ = true;
        res.status = EchProcessStatus::rejected_send_retry_configs;
        return res;
    }

    auto apply_ech_accept_confirmation(Bytes first_inner, Bytes retry_hello, Bytes second_inner, Bytes server_hello_wire)
        -> std::expected<crypto::Bytes, std::string> {
        if (first_inner.size() < 38 || server_hello_wire.size() < 4 || retry_hello.empty() != second_inner.empty())
            return std::unexpected("invalid ECH confirmation inputs");
        auto parsed = ServerHello::parse(server_hello_wire.subspan(4));
        if (!parsed || parsed->is_retry()) return std::unexpected("invalid ServerHello for ECH confirmation");
        auto spec = cipher_spec(parsed->cipher_suite);
        if (!spec) return std::unexpected("unsupported cipher suite for ECH confirmation");
        std::ranges::fill(std::span(parsed->random).last<8>(), std::uint8_t{0});
        auto zeroed_body = parsed->encode();
        if (!zeroed_body) return std::unexpected("cannot encode zeroed ServerHello");
        auto zeroed_wire = HandshakeDecoder::encode(2, *zeroed_body, max_hello_body);
        if (!zeroed_wire) return std::unexpected("cannot frame zeroed ServerHello");

        auto transcript = Transcript::create(spec->hash);
        if (!transcript || !transcript->append(first_inner)) return std::unexpected("transcript error");
        if (!retry_hello.empty() && (!transcript->hello_retry_request() ||
                                     !transcript->append(retry_hello) ||
                                     !transcript->append(second_inner)))
            return std::unexpected("retry transcript error");
        if (!transcript->append(*zeroed_wire)) return std::unexpected("transcript append error");
        auto hash = transcript->snapshot();
        auto prk = crypto::hkdf_extract(spec->hash, {}, first_inner.subspan(6, 32));
        if (!hash || !prk) return std::unexpected("ECH confirmation HKDF extract failed");
        Secret secret(std::move(*prk));
        auto conf = expand_label(spec->hash, secret.view(), "ech accept confirmation", *hash, 8);
        if (!conf) return std::unexpected("ECH confirmation HKDF expand failed");
        std::ranges::copy(conf->view(), std::span(parsed->random).last<8>().begin());
        auto final_body = parsed->encode();
        if (!final_body) return std::unexpected("cannot encode confirmed ServerHello");
        auto final_wire = HandshakeDecoder::encode(2, *final_body, max_hello_body);
        if (!final_wire) return std::unexpected("cannot frame confirmed ServerHello");
        return std::move(*final_wire);
    }

    auto apply_ech_hrr_confirmation(Bytes first_inner, Bytes hrr_wire) -> std::expected<crypto::Bytes, std::string> {
        if (first_inner.size() < 38 || hrr_wire.size() < 4)
            return std::unexpected("invalid ECH HRR confirmation inputs");
        auto parsed = ServerHello::parse(hrr_wire.subspan(4));
        if (!parsed || !parsed->is_retry()) return std::unexpected("invalid HRR for ECH confirmation");
        auto spec = cipher_spec(parsed->cipher_suite);
        if (!spec) return std::unexpected("unsupported cipher suite for ECH HRR confirmation");
        auto it = std::ranges::find(parsed->extensions, ech_ext_type, &Extension::type);
        if (it == parsed->extensions.end()) {
            parsed->extensions.push_back({ech_ext_type, crypto::Bytes(8, 0)});
            it = parsed->extensions.end() - 1;
        } else {
            it->data.assign(8, 0);
        }
        auto zeroed_body = parsed->encode();
        if (!zeroed_body) return std::unexpected("cannot encode zeroed HRR");
        auto zeroed_wire = HandshakeDecoder::encode(2, *zeroed_body, max_hello_body);
        if (!zeroed_wire) return std::unexpected("cannot frame zeroed HRR");

        auto transcript = Transcript::create(spec->hash);
        if (!transcript || !transcript->append(first_inner) || !transcript->hello_retry_request() ||
            !transcript->append(*zeroed_wire))
            return std::unexpected("HRR transcript error");
        auto hash = transcript->snapshot();
        auto prk = crypto::hkdf_extract(spec->hash, {}, first_inner.subspan(6, 32));
        if (!hash || !prk) return std::unexpected("ECH HRR confirmation HKDF extract failed");
        Secret secret(std::move(*prk));
        auto conf = expand_label(spec->hash, secret.view(), "hrr ech accept confirmation", *hash, 8);
        if (!conf) return std::unexpected("ECH HRR confirmation HKDF expand failed");
        std::ranges::copy(conf->view(), it->data.begin());
        auto final_body = parsed->encode();
        if (!final_body) return std::unexpected("cannot encode confirmed HRR");
        auto final_wire = HandshakeDecoder::encode(2, *final_body, max_hello_body);
        if (!final_wire) return std::unexpected("cannot frame confirmed HRR");
        return std::move(*final_wire);
    }
}
