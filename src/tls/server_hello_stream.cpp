module nexus.tls.server_hello_stream;
import std;
namespace nexus::tls {
    ServerHelloStream::ServerHelloStream(HandshakeDecoder&& messages) noexcept : messages_(std::move(messages)) {}
    auto ServerHelloStream::create() -> std::expected<ServerHelloStream,ServerHelloStreamError> {
        auto messages=HandshakeDecoder::create(65535); if (!messages) return std::unexpected(ServerHelloStreamError::invalid_state);
        return ServerHelloStream(std::move(*messages));
    }
    ServerHelloStream::ServerHelloStream(ServerHelloStream&& other) noexcept : state_(other.state_), records_(std::move(other.records_)), messages_(std::move(other.messages_)) { other.state_=State::failed; }
    auto ServerHelloStream::operator=(ServerHelloStream&& other) noexcept -> ServerHelloStream& {
        if (this!=&other) { state_=other.state_; records_=std::move(other.records_); messages_=std::move(other.messages_); other.state_=State::failed; } return *this;
    }
    auto ServerHelloStream::feed(std::span<std::uint8_t const> input) -> std::expected<ServerHelloFeed,ServerHelloStreamError> {
        if (state_!=State::first && state_!=State::final) return std::unexpected(ServerHelloStreamError::invalid_state);
        try {
        auto record=records_.feed(input,RecordFraming::plaintext);
        if (!record) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_record); }
        ServerHelloFeed result{record->consumed,{},false}; if (!record->record) return result;
        auto const& bytes=record->record->bytes;
        if (bytes[1]!=3 || bytes[2]!=3) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_record); }
        if (bytes[0]==20) {
            if (bytes.size()!=6 || bytes[5]!=1 || messages_.pending_bytes()!=0) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_record); }
            return result;
        }
        if (bytes[0]!=22 || bytes.size()==5) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_record); }
        auto decoded=messages_.feed(std::span{bytes}.subspan(5),1);
        if (!decoded || decoded->size()>1 || (!decoded->empty() && messages_.pending_bytes()!=0)) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_message); }
        if (decoded->empty()) return result;
        auto& message=decoded->front();
        if (message.type!=2) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_message); }
        auto parsed=ServerHello::parse(message.body); if (!parsed) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_message); }
        auto retry=parsed->is_retry();
        if (retry && state_==State::final) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_retry); }
        auto encoded=HandshakeDecoder::encode(2,message.body,65535); if (!encoded) { state_=State::failed; return std::unexpected(ServerHelloStreamError::invalid_message); }
        state_=retry ? State::retry_pending : State::complete; result.message=std::move(*encoded); result.retry=retry; return result;
        } catch (...) { state_=State::failed; throw; }
    }
    auto ServerHelloStream::resume_retry() -> std::expected<void,ServerHelloStreamError> {
        if (state_!=State::retry_pending) return std::unexpected(ServerHelloStreamError::invalid_state);
        state_=State::final; return {};
    }
    auto ServerHelloStream::finish_input() -> std::expected<void,ServerHelloStreamError> {
        if (state_==State::failed || state_==State::complete) return std::unexpected(ServerHelloStreamError::invalid_state);
        state_=State::failed; return std::unexpected(ServerHelloStreamError::truncated);
    }
}
