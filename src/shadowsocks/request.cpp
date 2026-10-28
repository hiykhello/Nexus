module nexus.shadowsocks.request;
import std;
import nexus.shadowsocks.key;
import nexus.shadowsocks.chunk;
import nexus.shadowsocks.header;
import nexus.shadowsocks.replay;
namespace nexus::shadowsocks {
    namespace {
        auto chunk_error(ChunkError error) -> RequestError {
            return error==ChunkError::authentication_failed ? RequestError::authentication : RequestError::crypto;
        }
    }
    auto encode_request(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> salt,
                        std::uint64_t timestamp, std::span<std::uint8_t const> address,
                        std::span<std::uint8_t const> padding, std::span<std::uint8_t const> payload)
        -> std::expected<EncodedRequest,RequestError> {
        auto key=SessionKey::derive(psk,salt);
        if (!key) return std::unexpected(RequestError::invalid_key_or_salt);
        auto variable=make_request_header(address,padding,payload);
        if (!variable) return std::unexpected(RequestError::invalid_header);
        auto fixed=make_fixed_header(false,timestamp,static_cast<std::uint16_t>(variable->size()));
        auto cipher=ChunkCipher::create(std::move(*key),true);
        if (!fixed || !cipher) return std::unexpected(RequestError::crypto);
        auto first=cipher->process(*fixed); if (!first) return std::unexpected(chunk_error(first.error()));
        auto second=cipher->process(*variable); if (!second) return std::unexpected(chunk_error(second.error()));
        std::vector<std::uint8_t> wire; wire.reserve(salt.size()+first->size()+second->size());
        wire.insert(wire.end(),salt.begin(),salt.end()); wire.insert(wire.end(),first->begin(),first->end());
        wire.insert(wire.end(),second->begin(),second->end());
        return EncodedRequest{std::move(wire),std::move(*cipher)};
    }
    namespace {
    auto decode_prefix(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> input,
                       std::uint64_t now, std::optional<std::chrono::steady_clock::time_point> monotonic_now, ReplayTable& replay)
        -> std::expected<RequestPrefix,RequestError> {
        if (psk.size()!=16 && psk.size()!=32) return std::unexpected(RequestError::invalid_key_or_salt);
        auto consumed=psk.size()+27;
        if (input.size()<consumed) return std::unexpected(RequestError::short_read);
        auto salt=input.first(psk.size());
        auto key=SessionKey::derive(psk,salt);
        if (!key) return std::unexpected(RequestError::invalid_key_or_salt);
        auto cipher=ChunkCipher::create(std::move(*key),false);
        if (!cipher) return std::unexpected(RequestError::crypto);
        auto plaintext=cipher->process(input.subspan(psk.size(),27));
        if (!plaintext) return std::unexpected(chunk_error(plaintext.error()));
        auto fixed=parse_fixed_header(*plaintext,false,now);
        if (!fixed) return std::unexpected(RequestError::invalid_header);
        auto admitted=monotonic_now ? replay.admit(salt,*monotonic_now,now) : replay.admit_current(salt,fixed->timestamp);
        if (!admitted) {
            switch (admitted.error()) {
                case ReplayError::duplicate: return std::unexpected(RequestError::replay);
                case ReplayError::full: return std::unexpected(RequestError::capacity);
                case ReplayError::time_reversed: return std::unexpected(RequestError::clock);
                case ReplayError::invalid_salt: return std::unexpected(RequestError::invalid_key_or_salt);
                case ReplayError::invalid_timestamp: return std::unexpected(RequestError::invalid_header);
            }
        }
        return RequestPrefix{std::move(*cipher),std::vector<std::uint8_t>(salt.begin(),salt.end()),fixed->length,consumed};
    }
    }
    auto decode_request_prefix(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> input,
                               std::uint64_t now, std::chrono::steady_clock::time_point monotonic_now, ReplayTable& replay)
        -> std::expected<RequestPrefix,RequestError> {
        return decode_prefix(psk,input,now,monotonic_now,replay);
    }
    auto decode_request_prefix_current(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> input, ReplayTable& replay)
        -> std::expected<RequestPrefix,RequestError> {
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (wall<0) return std::unexpected(RequestError::clock);
        return decode_prefix(psk,input,static_cast<std::uint64_t>(wall),std::nullopt,replay);
    }
    auto decode_request_header(RequestPrefix prefix, std::span<std::uint8_t const> ciphertext)
        -> std::expected<DecodedRequest,RequestError> {
        if (ciphertext.size()!=prefix.header_length+16) return std::unexpected(RequestError::short_read);
        auto plaintext=prefix.cipher.process(ciphertext);
        if (!plaintext) return std::unexpected(chunk_error(plaintext.error()));
        auto header=parse_request_header(*plaintext);
        if (!header) return std::unexpected(RequestError::invalid_header);
        return DecodedRequest{std::move(prefix.cipher),std::move(prefix.salt),std::move(*header)};
    }
}
