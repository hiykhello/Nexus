export module quic.tls_common;
import std;
import crypto;
import quic.packet_keys;
import quic.transport_parameters;
import nexus.thirdparty.ngtcp2;
import tls.handshake;

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
        case ParameterBlockError::malformed: return nex::ngtcp2::err_malformed_transport_param;
        case ParameterBlockError::duplicate: return nex::ngtcp2::err_transport_param;
        case ParameterBlockError::allocation_failed: return nex::ngtcp2::err_nomem;
        }
        return nex::ngtcp2::err_callback_failure;
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
            if (!messages) return nex::ngtcp2::err_crypto;
            for (auto const& message:*messages) {
                auto wire=tls::HandshakeDecoder::encode(message.type,message.body,0x00ffffff);
                if (!wire) return nex::ngtcp2::err_crypto;
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
        if (*size>65535) return std::unexpected(nex::ngtcp2::err_crypto);
        crypto::Bytes result(*size);
        auto written=connection.local_transport_parameters(result);
        if (!written) return std::unexpected(written.error());
        if (*written!=result.size()) return std::unexpected(nex::ngtcp2::err_crypto);
        return result;
    }
}
