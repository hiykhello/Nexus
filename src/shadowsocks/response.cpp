module nexus.shadowsocks.response;
import std;
import nexus.shadowsocks.key;
import nexus.shadowsocks.chunk;
import nexus.shadowsocks.header;
namespace nexus::shadowsocks {
    namespace {
        auto chunk_error(ChunkError error) -> ResponseError {
            return error==ChunkError::authentication_failed ? ResponseError::authentication : ResponseError::crypto;
        }
    }
    auto encode_response(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> salt,
                         std::span<std::uint8_t const> request_salt, std::uint64_t timestamp,
                         std::span<std::uint8_t const> payload) -> std::expected<EncodedResponse,ResponseError> {
        if ((psk.size()!=16 && psk.size()!=32) || salt.size()!=psk.size() || request_salt.size()!=psk.size())
            return std::unexpected(ResponseError::invalid_key_or_salt);
        if (payload.empty() || payload.size()>65535) return std::unexpected(ResponseError::invalid_payload);
        auto key=SessionKey::derive(psk,salt);
        if (!key) return std::unexpected(ResponseError::invalid_key_or_salt);
        auto fixed=make_fixed_header(true,timestamp,static_cast<std::uint16_t>(payload.size()),request_salt);
        auto cipher=ChunkCipher::create(std::move(*key),true);
        if (!fixed || !cipher) return std::unexpected(ResponseError::crypto);
        auto first=cipher->process(*fixed); if (!first) return std::unexpected(chunk_error(first.error()));
        auto second=cipher->process(payload); if (!second) return std::unexpected(chunk_error(second.error()));
        std::vector<std::uint8_t> wire; wire.reserve(salt.size()+first->size()+second->size());
        wire.insert(wire.end(),salt.begin(),salt.end()); wire.insert(wire.end(),first->begin(),first->end());
        wire.insert(wire.end(),second->begin(),second->end());
        return EncodedResponse{std::move(wire),std::move(*cipher)};
    }
    auto decode_response_prefix(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> request_salt,
                                std::span<std::uint8_t const> input, std::uint64_t now)
        -> std::expected<ResponsePrefix,ResponseError> {
        if ((psk.size()!=16 && psk.size()!=32) || request_salt.size()!=psk.size())
            return std::unexpected(ResponseError::invalid_key_or_salt);
        auto consumed=2*psk.size()+27;
        if (input.size()<consumed) return std::unexpected(ResponseError::short_read);
        auto key=SessionKey::derive(psk,input.first(psk.size()));
        if (!key) return std::unexpected(ResponseError::invalid_key_or_salt);
        auto cipher=ChunkCipher::create(std::move(*key),false);
        if (!cipher) return std::unexpected(ResponseError::crypto);
        auto plaintext=cipher->process(input.subspan(psk.size(),psk.size()+27));
        if (!plaintext) return std::unexpected(chunk_error(plaintext.error()));
        auto fixed=parse_fixed_header(*plaintext,true,now,request_salt);
        if (!fixed || fixed->length==0) return std::unexpected(ResponseError::invalid_header);
        return ResponsePrefix{std::move(*cipher),fixed->length,consumed};
    }
    auto decode_response_payload(ResponsePrefix prefix, std::span<std::uint8_t const> ciphertext)
        -> std::expected<DecodedResponse,ResponseError> {
        if (ciphertext.size()!=prefix.payload_length+16) return std::unexpected(ResponseError::short_read);
        auto payload=prefix.cipher.process(ciphertext);
        if (!payload) return std::unexpected(chunk_error(payload.error()));
        return DecodedResponse{std::move(prefix.cipher),std::move(*payload)};
    }
}
