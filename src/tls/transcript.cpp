module nexus.tls.transcript;
import std;

namespace nexus::tls {
    auto Transcript::create(crypto::Hash hash) -> std::expected<Transcript,TranscriptError> {
        auto digest=crypto::DigestContext::create(hash);
        if (!digest) return std::unexpected(TranscriptError::crypto_error);
        return Transcript(hash,std::move(*digest));
    }
    auto Transcript::append(std::span<std::uint8_t const> message) -> std::expected<void,TranscriptError> {
        if (message.size()<4 || message[0]==254) return std::unexpected(TranscriptError::malformed_message);
        auto length=(std::size_t{message[1]}<<16)|(std::size_t{message[2]}<<8)|message[3];
        if (length!=message.size()-4) return std::unexpected(TranscriptError::malformed_message);
        if (!digest_.update(message)) return std::unexpected(TranscriptError::crypto_error);
        if (!messages_) first_is_client_hello_=message[0]==1;
        if (messages_<2) ++messages_;
        return {};
    }
    auto Transcript::snapshot() const -> std::expected<crypto::Bytes,TranscriptError> {
        auto digest=digest_.snapshot(); if (!digest) return std::unexpected(TranscriptError::crypto_error);
        return std::move(*digest);
    }
    auto Transcript::hello_retry_request() -> std::expected<void,TranscriptError> {
        if (retry_ || messages_!=1 || !first_is_client_hello_) return std::unexpected(TranscriptError::invalid_retry_state);
        auto hash=snapshot(); if (!hash) return std::unexpected(hash.error());
        auto replacement=crypto::DigestContext::create(hash_);
        if (!replacement) return std::unexpected(TranscriptError::crypto_error);
        std::array<std::uint8_t,4> header{254,0,0,static_cast<std::uint8_t>(hash->size())};
        if (!replacement->update(header) || !replacement->update(*hash)) return std::unexpected(TranscriptError::crypto_error);
        digest_=std::move(*replacement); retry_=true;
        return {};
    }
}
