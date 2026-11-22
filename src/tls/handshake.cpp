module tls.handshake;
import std;

namespace tls {
    HandshakeDecoder::HandshakeDecoder(std::size_t max_message_size) : max_message_size_(max_message_size) {
        pending_.reserve(std::min<std::size_t>(max_message_size_ + 4, 4096));
    }
    HandshakeDecoder::HandshakeDecoder(HandshakeDecoder&& other) noexcept
        : pending_(std::move(other.pending_)), expected_(other.expected_), max_message_size_(other.max_message_size_), failed_(other.failed_) {
        other.failed_=true; other.expected_=0;
    }
    auto HandshakeDecoder::operator=(HandshakeDecoder&& other) noexcept -> HandshakeDecoder& {
        if (this!=&other) {
            pending_=std::move(other.pending_); expected_=other.expected_;
            max_message_size_=other.max_message_size_; failed_=other.failed_;
            other.failed_=true; other.expected_=0;
        }
        return *this;
    }
    auto HandshakeDecoder::create(std::size_t max_message_size) -> std::expected<HandshakeDecoder, HandshakeError> {
        if (max_message_size == 0 || max_message_size > 0x00ffffffu)
            return std::unexpected(HandshakeError::message_too_large);
        return HandshakeDecoder(max_message_size);
    }
    auto HandshakeDecoder::fail(HandshakeError error) -> std::expected<std::vector<HandshakeMessage>, HandshakeError> {
        failed_ = true;
        std::vector<std::uint8_t>{}.swap(pending_);
        expected_ = 0;
        return std::unexpected(error);
    }
    auto HandshakeDecoder::feed(std::span<std::uint8_t const> input, std::size_t max_messages)
        -> std::expected<std::vector<HandshakeMessage>, HandshakeError> {
        if (failed_) return std::unexpected(HandshakeError::invalid_state);
        if (input.size() > 16384) return fail(HandshakeError::input_too_large);
        try {
        std::vector<HandshakeMessage> result;
        std::size_t offset = 0;
        while (offset < input.size()) {
            if (result.size()>=max_messages) return fail(HandshakeError::too_many_messages);
            if (pending_.size() < 4) {
                auto need = 4 - pending_.size();
                auto count = std::min(need, input.size() - offset);
                pending_.insert(pending_.end(), input.begin() + static_cast<std::ptrdiff_t>(offset),
                                input.begin() + static_cast<std::ptrdiff_t>(offset + count));
                offset += count;
                if (pending_.size() < 4) break;
                auto body_size = (std::size_t{pending_[1]} << 16) |
                                 (std::size_t{pending_[2]} << 8) | pending_[3];
                if (pending_[0] == 0xfe) return fail(HandshakeError::invalid_type);
                if (body_size > max_message_size_) return fail(HandshakeError::message_too_large);
                expected_ = body_size + 4;
                pending_.reserve(expected_);
            }
            auto need = expected_ - pending_.size();
            auto count = std::min(need, input.size() - offset);
            pending_.insert(pending_.end(), input.begin() + static_cast<std::ptrdiff_t>(offset),
                            input.begin() + static_cast<std::ptrdiff_t>(offset + count));
            offset += count;
            if (pending_.size() != expected_) continue;
            HandshakeMessage message;
            message.type = pending_[0];
            message.body.assign(pending_.begin() + 4, pending_.end());
            result.push_back(std::move(message));
            pending_.clear();
            expected_ = 0;
        }
        return result;
        } catch (...) { failed_=true; std::vector<std::uint8_t>{}.swap(pending_); expected_=0; throw; }
    }
    auto HandshakeDecoder::finish() -> std::expected<void, HandshakeError> {
        if (failed_) return std::unexpected(HandshakeError::invalid_state);
        if (!pending_.empty()) { failed_ = true; std::vector<std::uint8_t>{}.swap(pending_); expected_ = 0; return std::unexpected(HandshakeError::truncated); }
        return {};
    }
    auto HandshakeDecoder::encode(std::uint8_t type, std::span<std::uint8_t const> body,
                                  std::size_t max_message_size) -> std::expected<std::vector<std::uint8_t>, HandshakeError> {
        if (type == 0xfe) return std::unexpected(HandshakeError::invalid_type);
        if (max_message_size == 0 || max_message_size > 0x00ffffffu || body.size() > max_message_size)
            return std::unexpected(body.size() > max_message_size ? HandshakeError::message_too_large : HandshakeError::input_too_large);
        std::vector<std::uint8_t> result(4+body.size());
        result[0] = type;
        result[1] = static_cast<std::uint8_t>(body.size() >> 16);
        result[2] = static_cast<std::uint8_t>(body.size() >> 8);
        result[3] = static_cast<std::uint8_t>(body.size());
        std::ranges::copy(body,result.begin()+4);
        return result;
    }
}
