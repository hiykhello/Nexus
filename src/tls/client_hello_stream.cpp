module nexus.tls.client_hello_stream;
import std;
namespace nexus::tls {
    ClientHelloStream::ClientHelloStream(HandshakeDecoder&& messages,bool allow_ccs) noexcept : messages_(std::move(messages)),allow_ccs_(allow_ccs) {}
    auto ClientHelloStream::create(std::size_t limit,bool allow_ccs) -> std::expected<ClientHelloStream,ClientHelloStreamError> {
        if (limit>65535) return std::unexpected(ClientHelloStreamError::invalid_state);
        auto messages=HandshakeDecoder::create(limit);
        if (!messages) return std::unexpected(ClientHelloStreamError::invalid_state);
        return ClientHelloStream(std::move(*messages),allow_ccs);
    }
    ClientHelloStream::ClientHelloStream(ClientHelloStream&& other) noexcept
        : state_(other.state_), records_(std::move(other.records_)), messages_(std::move(other.messages_)),allow_ccs_(other.allow_ccs_),ccs_seen_(other.ccs_seen_) { other.state_=State::failed; }
    auto ClientHelloStream::operator=(ClientHelloStream&& other) noexcept -> ClientHelloStream& {
        if (this!=&other) { state_=other.state_; records_=std::move(other.records_); messages_=std::move(other.messages_); allow_ccs_=other.allow_ccs_; ccs_seen_=other.ccs_seen_; other.state_=State::failed; }
        return *this;
    }
    auto ClientHelloStream::feed(std::span<std::uint8_t const> input, std::shared_ptr<memory::Budget> budget) -> std::expected<ClientHelloFeed,ClientHelloStreamError> {
        if (state_!=State::reading) return std::unexpected(ClientHelloStreamError::invalid_state);
        try {
        auto record=records_.feed(input,RecordFraming::plaintext);
        if (!record) { state_=State::failed; return std::unexpected(ClientHelloStreamError::invalid_record); }
        ClientHelloFeed result; result.consumed=record->consumed;
        if (!record->record) return result;
        auto const& bytes=record->record->bytes;
        if (bytes[0]==20 && allow_ccs_ && !ccs_seen_ && !messages_.pending_bytes() && bytes.size()==6 && bytes[1]==3 && bytes[2]==3 && bytes[5]==1) {
            ccs_seen_=true; result.compatibility_ccs=true; return result;
        }
        if (bytes[0]!=22 || bytes[1]!=3 || (bytes[2]!=1 && bytes[2]!=3) || bytes.size()==5) {
            state_=State::failed; return std::unexpected(ClientHelloStreamError::invalid_record);
        }
        auto decoded=messages_.feed(std::span{bytes}.subspan(5));
        if (!decoded || decoded->size()>1 || (!decoded->empty() && messages_.pending_bytes()!=0)) {
            state_=State::failed; return std::unexpected(ClientHelloStreamError::invalid_message);
        }
        if (decoded->empty()) return result;
        auto& message=decoded->front();
        if (budget && !message.body.empty()) {
            result.parsed_reservation=memory::Budget::reserve(std::move(budget),parsed_charge(message.body.size()));
            if (!result.parsed_reservation) { state_=State::failed; return std::unexpected(ClientHelloStreamError::budget_exceeded); }
        }
        auto hello=ClientHello::parse(message.body);
        if (message.type!=1 || !hello || !hello->validate_tls13()) {
            state_=State::failed; return std::unexpected(ClientHelloStreamError::invalid_message);
        }
        auto encoded=HandshakeDecoder::encode(1,message.body);
        if (!encoded) { state_=State::failed; return std::unexpected(ClientHelloStreamError::invalid_message); }
        state_=State::complete; result.hello=std::move(*hello); result.message=std::move(*encoded); return result;
        } catch (...) { state_=State::failed; throw; }
    }
    auto ClientHelloStream::finish_input() -> std::expected<void,ClientHelloStreamError> {
        if (state_!=State::reading) return std::unexpected(ClientHelloStreamError::invalid_state);
        state_=State::failed; return std::unexpected(ClientHelloStreamError::truncated);
    }
}
