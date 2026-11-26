export module quic.tls_common;
import std;
import crypto;
import quic.packet_keys;
import quic.transport_parameters;
import ngtcp2;
import tls.ech_server;
import tls.handshake;
import tls.handshake_policy;
import tls.server_credential;
import tls.server_keys;

export namespace quic {
    inline constexpr std::array<std::uint16_t,3> tls_packet_ciphers{0x1301,0x1302,0x1303};
    inline auto tls_packet_suite(std::uint16_t cipher) noexcept -> std::optional<PacketSuite> {
        if (cipher==0x1301) return PacketSuite::aes128_gcm_sha256;
        if (cipher==0x1302) return PacketSuite::aes256_gcm_sha384;
        if (cipher==0x1303) return PacketSuite::chacha20_poly1305_sha256;
        return {};
    }
    inline auto parameter_block_status(std::span<std::uint8_t const> input) noexcept -> int {
        auto result=validate_parameter_block(input);
        if (result) return 0;
        switch (result.error()) {
        case ParameterBlockError::malformed: return ngtcp2::err_malformed_transport_param;
        case ParameterBlockError::duplicate: return ngtcp2::err_transport_param;
        case ParameterBlockError::allocation_failed: return ngtcp2::err_nomem;
        }
        return ngtcp2::err_callback_failure;
    }
    // The common TLS decoder bounds pending messages. It accepts at most one
    // record-sized input slice, but QUIC may deliver larger CRYPTO ranges.
    // Completed messages are recreated as exact raw Handshake wire messages;
    // there is no TLSPlaintext/TLSCiphertext record adaptation in this path.
    template<class Handler>
    auto feed_tls_messages(tls::HandshakeDecoder& decoder,std::span<std::uint8_t const> bytes,std::size_t message_limit,Handler&& handler) -> int {
        while (!bytes.empty()) {
            auto count=std::min<std::size_t>(bytes.size(),16384);
            auto messages=decoder.feed(bytes.first(count),message_limit);
            if (!messages) return ngtcp2::err_crypto;
            for (auto const& message:*messages) {
                auto wire=tls::HandshakeDecoder::encode(message.type,message.body,0x00ffffff);
                if (!wire) return ngtcp2::err_crypto;
                auto error=handler(message.type,std::span<std::uint8_t const>(*wire));
                if (error) return error;
            }
            bytes=bytes.subspan(count);
        }
        return 0;
    }
    template<class Connection>
    auto local_quic_parameters(Connection& connection) -> std::expected<crypto::Bytes,int> {
        auto size=connection.local_transport_parameters({}); if (!size) return std::unexpected(size.error());
        if (*size>65535) return std::unexpected(ngtcp2::err_crypto);
        crypto::Bytes result(*size);
        auto written=connection.local_transport_parameters(result);
        if (!written) return std::unexpected(written.error());
        if (*written!=result.size()) return std::unexpected(ngtcp2::err_crypto);
        return result;
    }

    struct QuicEchStep {
        tls::ClientHello client;
        crypto::Bytes inner_storage;
        std::string sni;
        bool accepted = false;
        [[nodiscard]] auto effective_wire(std::span<std::uint8_t const> outer_wire) const noexcept
            -> std::span<std::uint8_t const> {
            return inner_storage.empty() ? outer_wire : std::span<std::uint8_t const>(inner_storage);
        }
    };

    inline auto process_quic_client_hello_ech(tls::EchServerContext& ech,
        std::span<std::uint8_t const> wire, bool is_retry) -> std::expected<QuicEchStep, std::uint8_t> {
        auto parsed = tls::ClientHello::parse(wire.subspan(4), 65535);
        if (!parsed) return std::unexpected(std::uint8_t{50});
        std::string sni = tls::extract_client_hello_sni(*parsed);
        if (ech.has_keys()) {
            auto res = ech.process_client_hello(*parsed, wire, is_retry);
            if (res.status == tls::EchProcessStatus::protocol_error) return std::unexpected(std::uint8_t{50});
            if (res.status == tls::EchProcessStatus::crypto_error) return std::unexpected(std::uint8_t{80});
            if (res.status == tls::EchProcessStatus::accepted && res.inner_hello) {
                return QuicEchStep{std::move(*res.inner_hello), std::move(res.inner_message), std::move(res.sni), true};
            }
        }
        return QuicEchStep{std::move(*parsed), {}, std::move(sni), false};
    }

    template<class... Recovery>
    inline auto quic_server_handshake_secrets(std::span<std::uint8_t const> client,
        std::span<std::uint16_t const> schemes, bool ech_accepted, Recovery&... recovery)
        -> std::expected<tls::ServerHandshakeSecrets, tls::ServerKeyError> {
        if (ech_accepted)
            return tls::make_server_secrets<true>(client, schemes, {}, {},
                tls::PeerSignaturePolicy::require_offered, tls_packet_ciphers, tls::HandshakeTransport::quic, recovery...);
        return tls::server_handshake_secrets(client, schemes,
            tls::PeerSignaturePolicy::require_offered, tls_packet_ciphers, tls::HandshakeTransport::quic, recovery...);
    }

    template<class... Recovery>
    inline auto quic_server_retry_hello(std::span<std::uint8_t const> first,
        std::span<std::uint16_t const> schemes, bool ech_accepted, Recovery&... recovery)
        -> std::expected<crypto::Bytes, tls::ServerKeyError> {
        auto raw = tls::server_retry_hello(first, schemes, tls_packet_ciphers, tls::HandshakeTransport::quic, recovery...);
        if (!raw) return std::unexpected(raw.error());
        if (!ech_accepted) return raw;
        auto confirmed = tls::apply_ech_hrr_confirmation(first, *raw);
        if (!confirmed) return std::unexpected(tls::ServerKeyError::crypto_error);
        return std::move(*confirmed);
    }

    template<class... Recovery>
    inline auto quic_server_handshake_secrets_retry(std::span<std::uint8_t const> first,
        std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second,
        std::span<std::uint16_t const> schemes, bool ech_accepted, Recovery&... recovery)
        -> std::expected<tls::ServerHandshakeSecrets, tls::ServerKeyError> {
        if (first.empty() || retry.empty()) return std::unexpected(tls::ServerKeyError::invalid_hello);
        auto expected = quic_server_retry_hello(first, schemes, ech_accepted, recovery...);
        if (!expected) return std::unexpected(expected.error());
        if (!std::ranges::equal(*expected, retry)) return std::unexpected(tls::ServerKeyError::invalid_hello);
        if (ech_accepted)
            return tls::make_server_secrets<true>(second, schemes, first, retry,
                tls::PeerSignaturePolicy::require_offered, tls_packet_ciphers, tls::HandshakeTransport::quic, recovery...);
        return tls::make_server_secrets<false>(second, schemes, first, retry,
            tls::PeerSignaturePolicy::require_offered, tls_packet_ciphers, tls::HandshakeTransport::quic, recovery...);
    }

    inline auto encode_early_encrypted_extensions(std::span<std::uint8_t const> alpn,
        std::span<std::uint8_t const> quic_params) -> std::optional<crypto::Bytes> {
        if (alpn.empty() || alpn.size() > 255 || quic_params.size() > 65000) return {};
        std::size_t ext_len = (alpn.size() + 7) + (4 + quic_params.size()) + 4;
        crypto::Bytes msg(6 + ext_len);
        auto put16 = [&](std::size_t pos, std::size_t v) {
            msg[pos] = static_cast<std::uint8_t>(v >> 8);
            msg[pos + 1] = static_cast<std::uint8_t>(v);
        };
        std::size_t body = ext_len + 2;
        msg[0] = 8;
        msg[1] = static_cast<std::uint8_t>(body >> 16);
        msg[2] = static_cast<std::uint8_t>(body >> 8);
        msg[3] = static_cast<std::uint8_t>(body);
        put16(4, ext_len);
        std::size_t off = 6;
        put16(off, 16); put16(off + 2, alpn.size() + 3); put16(off + 4, alpn.size() + 1);
        msg[off + 6] = static_cast<std::uint8_t>(alpn.size());
        std::ranges::copy(alpn, msg.begin() + static_cast<std::ptrdiff_t>(off + 7));
        off += alpn.size() + 7;
        put16(off, 0x39); put16(off + 2, quic_params.size());
        std::ranges::copy(quic_params, msg.begin() + static_cast<std::ptrdiff_t>(off + 4));
        off += 4 + quic_params.size();
        put16(off, 42); put16(off + 2, 0);
        return msg;
    }
}
