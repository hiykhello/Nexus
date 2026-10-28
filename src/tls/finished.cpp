module nexus.tls.finished;
import std;

namespace nexus::tls {
    ClientFinished::ClientFinished(crypto::Hash hash, Transcript&& transcript, Secret&& client, Secret&& server) noexcept
        : hash_(hash), transcript_(std::move(transcript)), client_traffic_(std::move(client)), server_traffic_(std::move(server)) {}
    ClientFinished::ClientFinished(ClientFinished&& other) noexcept
        : hash_(other.hash_), transcript_(std::move(other.transcript_)), client_traffic_(std::move(other.client_traffic_)), server_traffic_(std::move(other.server_traffic_)), state_(other.state_) { other.state_=State::failed; }
    auto ClientFinished::operator=(ClientFinished&& other) noexcept -> ClientFinished& {
        if (this!=&other) { hash_=other.hash_; transcript_=std::move(other.transcript_); client_traffic_=std::move(other.client_traffic_); server_traffic_=std::move(other.server_traffic_); state_=other.state_; other.state_=State::failed; }
        return *this;
    }
    auto ClientFinished::verify_server(std::span<std::uint8_t const> message) -> std::expected<void,FinishedError> {
        if (state_!=State::await_server) return std::unexpected(FinishedError::invalid_state);
        state_=State::failed;
        auto len=hash_==crypto::Hash::sha256 ? 32u : hash_==crypto::Hash::sha384 ? 48u : 0u;
        if (!len || message.size()!=len+4 || message[0]!=20 || message[1]!=0 || message[2]!=0 || message[3]!=len)
            return std::unexpected(FinishedError::malformed_message);
        auto digest=transcript_.snapshot(); if (!digest) return std::unexpected(FinishedError::crypto_error);
        auto expected=finished_verify_data(hash_,server_traffic_.view(),*digest);
        if (!expected) return std::unexpected(FinishedError::crypto_error);
        if (!crypto::constant_time_equal(expected->view(),message.subspan(4))) return std::unexpected(FinishedError::verification_failed);
        if (!transcript_.append(message)) return std::unexpected(FinishedError::crypto_error);
        state_=State::await_client; return {};
    }
    auto ClientFinished::make_client() -> std::expected<crypto::Bytes,FinishedError> {
        if (state_!=State::await_client) return std::unexpected(FinishedError::invalid_state);
        state_=State::failed;
        auto digest=transcript_.snapshot(); if (!digest) return std::unexpected(FinishedError::crypto_error);
        auto verify=finished_verify_data(hash_,client_traffic_.view(),*digest); if (!verify) return std::unexpected(FinishedError::crypto_error);
        crypto::Bytes message{20,0,0,static_cast<std::uint8_t>(verify->view().size())}; message.insert(message.end(),verify->view().begin(),verify->view().end());
        if (!transcript_.append(message)) return std::unexpected(FinishedError::crypto_error);
        state_=State::complete; return message;
    }
    auto ClientFinished::transcript_hash() const -> std::expected<crypto::Bytes,FinishedError> {
        if (state_==State::failed) return std::unexpected(FinishedError::invalid_state);
        auto hash=transcript_.snapshot(); if (!hash) return std::unexpected(FinishedError::crypto_error); return std::move(*hash);
    }
}
