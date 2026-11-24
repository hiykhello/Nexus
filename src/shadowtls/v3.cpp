module shadowtls.v3;
import std;
import crypto;

namespace shadowtls {
    namespace {
        constexpr std::size_t ch_session_id_len_off = 1 + 3 + 2 + tls_random_size; // 38 inside handshake body
        constexpr std::size_t ch_rec_session_id_len_off = tls_header_size + ch_session_id_len_off; // 43 inside record
        constexpr std::size_t sh_rec_random_off = tls_header_size + 1 + 3 + 2; // 11 inside record
        constexpr std::size_t sh_rec_session_id_len_off = sh_rec_random_off + tls_random_size; // 43 inside record

        auto as_bytes(std::string_view text) noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
        }
        auto hmac_sha1_chunked(
            std::string_view key,
            std::initializer_list<std::span<std::uint8_t const>> parts) -> std::expected<std::array<std::uint8_t, 20>, crypto::Error> {
            auto ctx = crypto::HmacSha1Context::create(as_bytes(key));
            if (!ctx) return std::unexpected(ctx.error());
            for (auto part : parts) {
                if (auto ok = ctx->update(part); !ok) return std::unexpected(ok.error());
            }
            return ctx->snapshot();
        }
        auto seed_hmac(std::string_view password, std::span<std::uint8_t const, tls_random_size> server_random,
                       std::span<std::uint8_t const> role = {})
            -> std::expected<crypto::HmacSha1Context, crypto::Error> {
            auto ctx = crypto::HmacSha1Context::create(as_bytes(password));
            if (!ctx) return std::unexpected(ctx.error());
            if (auto ok = ctx->update(server_random); !ok) return std::unexpected(ok.error());
            if (!role.empty()) {
                if (auto ok = ctx->update(role); !ok) return std::unexpected(ok.error());
            }
            return ctx;
        }
        auto verify_frame(crypto::HmacSha1Context& ctx, std::span<std::uint8_t const> record, bool chain_tag) -> bool {
            if (record.size() < tls_hmac_header_size || record[0] != tls_record_application_data ||
                record[1] != 3 || record[2] != 3) return false;
            auto payload = record.subspan(tls_hmac_header_size);
            auto tag = record.subspan(tls_header_size, hmac_tag_size);
            if (!ctx.update(payload)) return false;
            auto digest = ctx.snapshot();
            if (!digest) return false;
            if (!crypto::constant_time_equal(tag, std::span(*digest).first(hmac_tag_size))) return false;
            return !chain_tag || ctx.update(tag).has_value();
        }
    }

    auto TlsRecordReader::feed(std::span<std::uint8_t const> input) -> RecordStep {
        if (failed_) return {RecordStatus::malformed, 0, {}};
        if (header_bytes_ == tls_header_size && buffer_.size() == tls_header_size + payload_size_) {
            return {RecordStatus::complete, 0, buffer_};
        }
        std::size_t pos = 0;
        if (header_bytes_ < tls_header_size) {
            auto take = std::min(tls_header_size - header_bytes_, input.size());
            std::copy_n(input.begin(), take, header_.begin() + header_bytes_);
            header_bytes_ += take;
            pos += take;
            if (header_bytes_ < tls_header_size) return {RecordStatus::incomplete, pos, {}};
            payload_size_ = (static_cast<std::size_t>(header_[3]) << 8) | header_[4];
            if (payload_size_ > max_record_payload) {
                failed_ = true;
                return {RecordStatus::too_large, pos, {}};
            }
            buffer_.clear();
            buffer_.reserve(tls_header_size + payload_size_);
            buffer_.insert(buffer_.end(), header_.begin(), header_.end());
        }
        auto remaining = (tls_header_size + payload_size_) - buffer_.size();
        auto copy_len = std::min(remaining, input.size() - pos);
        buffer_.insert(buffer_.end(), input.begin() + pos, input.begin() + pos + copy_len);
        pos += copy_len;
        if (buffer_.size() < tls_header_size + payload_size_) return {RecordStatus::incomplete, pos, {}};
        return {RecordStatus::complete, pos, buffer_};
    }

    auto TlsRecordReader::consume() noexcept -> void {
        header_bytes_ = 0;
        payload_size_ = 0;
        buffer_.clear();
    }

    auto TlsRecordReader::pending() const noexcept -> bool {
        return header_bytes_ > 0 || !buffer_.empty();
    }

    auto stamp_client_hello_session_id(
        std::string_view password,
        std::span<std::uint8_t> handshake_body,
        std::span<std::uint8_t const, tls_session_id_size - hmac_tag_size> random28) -> bool {
        constexpr std::size_t min_body = ch_session_id_len_off + 1 + tls_session_id_size;
        if (handshake_body.size() < min_body || handshake_body[0] != tls_handshake_client_hello ||
            handshake_body[ch_session_id_len_off] != tls_session_id_size) return false;
        auto session_id = handshake_body.subspan(ch_session_id_len_off + 1, tls_session_id_size);
        std::ranges::copy(random28, session_id.begin());
        std::fill_n(session_id.begin() + (tls_session_id_size - hmac_tag_size), hmac_tag_size, std::uint8_t{0});
        auto mac = hmac_sha1_chunked(password, {handshake_body});
        if (!mac) return false;
        std::copy_n(mac->begin(), hmac_tag_size, session_id.begin() + (tls_session_id_size - hmac_tag_size));
        return true;
    }

    auto verify_client_hello(
        std::span<std::uint8_t const> record,
        std::span<std::string_view const> passwords) -> std::optional<std::size_t> {
        constexpr std::size_t min_len = ch_rec_session_id_len_off + 1 + tls_session_id_size;
        if (record.size() < min_len || record[0] != tls_record_handshake ||
            record[tls_header_size] != tls_handshake_client_hello ||
            record[ch_rec_session_id_len_off] != tls_session_id_size) return {};
        constexpr std::size_t tag_off = ch_rec_session_id_len_off + 1 + tls_session_id_size - hmac_tag_size;
        constexpr std::array<std::uint8_t, hmac_tag_size> zeros{};
        auto prefix = record.subspan(tls_header_size, tag_off - tls_header_size);
        auto observed = record.subspan(tag_off, hmac_tag_size);
        auto suffix = record.subspan(tag_off + hmac_tag_size);
        std::optional<std::size_t> matched;
        for (std::size_t i = 0; i < passwords.size(); ++i) {
            auto mac = hmac_sha1_chunked(passwords[i], {prefix, zeros, suffix});
            if (mac && crypto::constant_time_equal(observed, std::span(*mac).first(hmac_tag_size)) && !matched) matched = i;
        }
        return matched;
    }

    auto extract_server_random(
        std::span<std::uint8_t const> record) noexcept -> std::optional<std::array<std::uint8_t, tls_random_size>> {
        static constexpr std::array<std::uint8_t, tls_random_size> kHrrSentinel{
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
            0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
        };
        if (record.size() < sh_rec_random_off + tls_random_size ||
            record[0] != tls_record_handshake ||
            record[tls_header_size] != tls_handshake_server_hello) return {};
        std::array<std::uint8_t, tls_random_size> out{};
        std::copy_n(record.begin() + sh_rec_random_off, tls_random_size, out.begin());
        if (out == kHrrSentinel) return {};
        return out;
    }

    auto is_server_hello_tls13(std::span<std::uint8_t const> record) noexcept -> bool {
        if (record.size() <= sh_rec_session_id_len_off ||
            record[0] != tls_record_handshake ||
            record[tls_header_size] != tls_handshake_server_hello) return false;
        std::size_t pos = sh_rec_session_id_len_off;
        auto sid_len = static_cast<std::size_t>(record[pos++]);
        if (sid_len > 32 || pos + sid_len + 3 + 2 > record.size()) return false;
        pos += sid_len + 3; // session_id + cipher_suite(2) + compression_method(1)
        std::size_t ext_len = (static_cast<std::size_t>(record[pos]) << 8) | record[pos + 1];
        pos += 2;
        if (pos + ext_len > record.size()) return false;
        auto end = pos + ext_len;
        while (pos + 4 <= end) {
            std::uint16_t ext_type = (static_cast<std::uint16_t>(record[pos]) << 8) | record[pos + 1];
            std::uint16_t len = (static_cast<std::uint16_t>(record[pos + 2]) << 8) | record[pos + 3];
            pos += 4;
            if (pos + len > end) return false;
            if (ext_type == 43) {
                return len == 2 && record[pos] == 0x03 && record[pos + 1] == 0x04;
            }
            pos += len;
        }
        return false;
    }

    auto derive_mask_key(
        std::string_view password,
        std::span<std::uint8_t const, tls_random_size> server_random) -> std::expected<std::array<std::uint8_t, 32>, crypto::Error> {
        auto ctx = crypto::DigestContext::create(crypto::Hash::sha256);
        if (!ctx) return std::unexpected(ctx.error());
        if (auto ok = ctx->update(as_bytes(password)); !ok) return std::unexpected(ok.error());
        if (auto ok = ctx->update(server_random); !ok) return std::unexpected(ok.error());
        auto digest = ctx->snapshot();
        if (!digest) return std::unexpected(digest.error());
        if (digest->size() != 32) return std::unexpected(crypto::Error::backend_failure);
        std::array<std::uint8_t, 32> key{};
        std::copy_n(digest->begin(), 32, key.begin());
        crypto::cleanse(*digest);
        return key;
    }

    auto xor_mask(std::span<std::uint8_t> data, std::span<std::uint8_t const, 32> key) noexcept -> void {
        for (std::size_t i = 0; i < data.size(); ++i) data[i] ^= key[i & 31u];
    }

    auto encode_alert_record() -> std::expected<std::array<std::uint8_t, 31>, crypto::Error> {
        std::array<std::uint8_t, 31> record{tls_record_alert, 3, 3, 0, 26};
        if (auto ok = crypto::random_bytes(std::span(record).subspan(tls_header_size)); !ok)
            return std::unexpected(ok.error());
        return record;
    }

    ServerHandshakeMasker::ServerHandshakeMasker(crypto::HmacSha1Context hmac, std::array<std::uint8_t, 32> mask_key) noexcept
        : hmac_(std::move(hmac)), mask_key_(mask_key) {}
    ServerHandshakeMasker::~ServerHandshakeMasker() { crypto::cleanse(mask_key_); }

    auto ServerHandshakeMasker::create(
        std::string_view password,
        std::span<std::uint8_t const, tls_random_size> server_random) -> std::expected<ServerHandshakeMasker, crypto::Error> {
        auto hmac = seed_hmac(password, server_random); if (!hmac) return std::unexpected(hmac.error());
        auto key = derive_mask_key(password, server_random); if (!key) return std::unexpected(key.error());
        struct KeyWipe { std::array<std::uint8_t, 32>& k; ~KeyWipe() { crypto::cleanse(k); } } wipe{*key};
        return ServerHandshakeMasker(std::move(*hmac), *key);
    }

    auto ServerHandshakeMasker::mask_record(std::span<std::uint8_t const> record) -> std::expected<std::vector<std::uint8_t>, crypto::Error> {
        if (record.size() < tls_header_size) return std::unexpected(crypto::Error::invalid_length);
        if (record[0] != tls_record_application_data) return std::vector<std::uint8_t>(record.begin(), record.end());
        auto payload_len = record.size() - tls_header_size;
        if (payload_len > 65535 - hmac_tag_size) return std::unexpected(crypto::Error::invalid_length);
        std::vector<std::uint8_t> out(tls_hmac_header_size + payload_len);
        out[0] = tls_record_application_data;
        out[1] = record[1];
        out[2] = record[2];
        auto new_len = static_cast<std::uint16_t>(payload_len + hmac_tag_size);
        out[3] = static_cast<std::uint8_t>(new_len >> 8);
        out[4] = static_cast<std::uint8_t>(new_len);
        std::copy(record.begin() + tls_header_size, record.end(), out.begin() + tls_hmac_header_size);
        auto masked_payload = std::span(out).subspan(tls_hmac_header_size);
        xor_mask(masked_payload, mask_key_);
        if (auto ok = hmac_.update(masked_payload); !ok) return std::unexpected(ok.error());
        auto mac = hmac_.snapshot(); if (!mac) return std::unexpected(mac.error());
        std::copy_n(mac->begin(), hmac_tag_size, out.begin() + tls_header_size);
        return out;
    }

    ClientHandshakeUnmasker::ClientHandshakeUnmasker(crypto::HmacSha1Context hmac, std::array<std::uint8_t, 32> mask_key) noexcept
        : hmac_(std::move(hmac)), mask_key_(mask_key) {}
    ClientHandshakeUnmasker::~ClientHandshakeUnmasker() { crypto::cleanse(mask_key_); }

    auto ClientHandshakeUnmasker::create(
        std::string_view password,
        std::span<std::uint8_t const, tls_random_size> server_random) -> std::expected<ClientHandshakeUnmasker, crypto::Error> {
        auto hmac = seed_hmac(password, server_random); if (!hmac) return std::unexpected(hmac.error());
        auto key = derive_mask_key(password, server_random); if (!key) return std::unexpected(key.error());
        struct KeyWipe { std::array<std::uint8_t, 32>& k; ~KeyWipe() { crypto::cleanse(k); } } wipe{*key};
        return ClientHandshakeUnmasker(std::move(*hmac), *key);
    }

    auto ClientHandshakeUnmasker::unmask_record(std::span<std::uint8_t const> record) -> std::expected<std::vector<std::uint8_t>, crypto::Error> {
        if (record.size() < tls_header_size) return std::unexpected(crypto::Error::invalid_length);
        if (record[0] != tls_record_application_data) return std::vector<std::uint8_t>(record.begin(), record.end());
        if (record.size() <= tls_hmac_header_size) return std::unexpected(crypto::Error::invalid_length);
        auto masked_payload = record.subspan(tls_hmac_header_size);
        auto tag = record.subspan(tls_header_size, hmac_tag_size);
        if (auto ok = hmac_.update(masked_payload); !ok) return std::unexpected(ok.error());
        auto mac = hmac_.snapshot(); if (!mac) return std::unexpected(mac.error());
        if (!crypto::constant_time_equal(tag, std::span(*mac).first(hmac_tag_size)))
            return std::unexpected(crypto::Error::authentication_failed);
        std::vector<std::uint8_t> out(tls_header_size + masked_payload.size());
        out[0] = tls_record_application_data;
        out[1] = record[1];
        out[2] = record[2];
        out[3] = static_cast<std::uint8_t>(masked_payload.size() >> 8);
        out[4] = static_cast<std::uint8_t>(masked_payload.size());
        std::copy(masked_payload.begin(), masked_payload.end(), out.begin() + tls_header_size);
        xor_mask(std::span(out).subspan(tls_header_size), mask_key_);
        return out;
    }

    VerifiedStream::VerifiedStream(crypto::HmacSha1Context write, crypto::HmacSha1Context read,
                                   std::optional<crypto::HmacSha1Context> ignore,
                                   std::optional<crypto::HmacSha1Context> read_seed) noexcept
        : hmac_write_(std::move(write)), hmac_read_(std::move(read)), hmac_ignore_(std::move(ignore)), read_seed_(std::move(read_seed)) {}

    auto VerifiedStream::create(
        StreamRole role,
        std::string_view password,
        std::span<std::uint8_t const, tls_random_size> server_random,
        std::optional<crypto::HmacSha1Context> ignore_handshake_hmac,
        bool keep_read_seed) -> std::expected<VerifiedStream, crypto::Error> {
        static constexpr std::array<std::uint8_t, 1> client_tag{'C'};
        static constexpr std::array<std::uint8_t, 1> server_tag{'S'};
        auto write_tag = role == StreamRole::client ? std::span<std::uint8_t const>(client_tag) : std::span<std::uint8_t const>(server_tag);
        auto read_tag = role == StreamRole::client ? std::span<std::uint8_t const>(server_tag) : std::span<std::uint8_t const>(client_tag);
        auto write = seed_hmac(password, server_random, write_tag); if (!write) return std::unexpected(write.error());
        auto read = seed_hmac(password, server_random, read_tag); if (!read) return std::unexpected(read.error());
        std::optional<crypto::HmacSha1Context> seed;
        if (keep_read_seed) {
            auto copy = read->clone(); if (!copy) return std::unexpected(copy.error());
            seed = std::move(*copy);
        }
        return VerifiedStream(std::move(*write), std::move(*read), std::move(ignore_handshake_hmac), std::move(seed));
    }

    auto VerifiedStream::encode(std::span<std::uint8_t const> plaintext) -> std::expected<std::vector<std::uint8_t>, crypto::Error> {
        std::vector<std::uint8_t> out;
        if (plaintext.empty()) return out;
        std::size_t offset = 0;
        do {
            auto chunk = plaintext.subspan(offset, std::min(max_plaintext_chunk, plaintext.size() - offset));
            if (auto ok = hmac_write_.update(chunk); !ok) return std::unexpected(ok.error());
            auto mac = hmac_write_.snapshot(); if (!mac) return std::unexpected(mac.error());
            if (auto ok = hmac_write_.update(std::span(*mac).first(hmac_tag_size)); !ok) return std::unexpected(ok.error());
            auto len = static_cast<std::uint16_t>(hmac_tag_size + chunk.size());
            out.push_back(tls_record_application_data);
            out.push_back(3);
            out.push_back(3);
            out.push_back(static_cast<std::uint8_t>(len >> 8));
            out.push_back(static_cast<std::uint8_t>(len));
            out.insert(out.end(), mac->begin(), mac->begin() + hmac_tag_size);
            out.insert(out.end(), chunk.begin(), chunk.end());
            offset += chunk.size();
        } while (offset < plaintext.size());
        return out;
    }

    auto VerifiedStream::decode(std::span<std::uint8_t const> record) -> Decoded {
        if (record.size() < tls_header_size) return {DecodeStatus::malformed, {}};
        if (record[0] == tls_record_alert) return {DecodeStatus::alert_closed, {}};
        if (record[0] != tls_record_application_data || record.size() < tls_hmac_header_size ||
            record[1] != 3 || record[2] != 3) return {DecodeStatus::malformed, {}};
        if (hmac_ignore_) {
            if (verify_frame(*hmac_ignore_, record, false)) return {DecodeStatus::ignored_handshake, {}};
            hmac_ignore_.reset();
        }
        if (!verify_frame(hmac_read_, record, true)) return {DecodeStatus::auth_failed, {}};
        return {DecodeStatus::payload, record.subspan(tls_hmac_header_size)};
    }

    auto VerifiedStream::accept_cutover_record(std::span<std::uint8_t const> record) -> Decoded {
        if (!read_seed_ || record.size() <= tls_hmac_header_size || record[0] != tls_record_application_data ||
            record[1] != 3 || record[2] != 3) return {DecodeStatus::ignored_handshake, {}};
        auto probe = read_seed_->clone();
        if (!probe) return {DecodeStatus::auth_failed, {}};
        if (!verify_frame(*probe, record, true)) return {DecodeStatus::ignored_handshake, {}};
        hmac_read_ = std::move(*probe);
        read_seed_.reset();
        return {DecodeStatus::payload, record.subspan(tls_hmac_header_size)};
    }
}
