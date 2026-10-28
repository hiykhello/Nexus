module nexus.tcp.send;
import std;

namespace nexus::tcp {
    auto SendBuffer::create(std::uint32_t initial, std::size_t capacity) -> std::expected<SendBuffer, SendError> {
        if (!capacity || capacity >= 0x80000000ull) return std::unexpected(SendError::invalid_capacity);
        return SendBuffer(initial, capacity);
    }
    auto SendBuffer::enqueue(std::span<std::uint8_t const> bytes) -> std::expected<void, SendError> {
        if (bytes.size() > capacity_ - bytes_.size()) return std::unexpected(SendError::capacity);
        // Stage before mutation so allocation failure cannot leave a partially appended write.
        auto staged = bytes_;
        staged.insert(staged.end(), bytes.begin(), bytes.end());
        bytes_.swap(staged);
        return {};
    }
    auto SendBuffer::unsent(std::size_t maximum) const -> SendSlice {
        auto count = std::min(maximum, bytes_.size() - sent_);
        auto begin = bytes_.begin() + static_cast<std::ptrdiff_t>(sent_);
        return {next(), {begin, begin + static_cast<std::ptrdiff_t>(count)}};
    }
    auto SendBuffer::retransmit(std::size_t maximum) const -> SendSlice {
        auto count = std::min(maximum, sent_);
        return {una_, {bytes_.begin(), bytes_.begin() + static_cast<std::ptrdiff_t>(count)}};
    }
    auto SendBuffer::mark_sent(std::size_t count) noexcept -> std::expected<void, SendError> {
        if (count > bytes_.size() - sent_) return std::unexpected(SendError::invalid_count);
        sent_ += count;
        return {};
    }
    auto SendBuffer::acknowledge(std::uint32_t acknowledgement) noexcept -> std::expected<std::size_t, SendError> {
        auto count = static_cast<std::uint32_t>(acknowledgement - una_);
        if (count > sent_) return std::unexpected(SendError::invalid_ack);
        for (std::uint32_t i = 0; i < count; ++i) bytes_.pop_front();
        sent_ -= count; una_ = acknowledgement;
        return count;
    }
    auto TimedSend::create(std::uint32_t initial, std::size_t capacity) -> std::expected<TimedSend, SendError> {
        auto buffer = SendBuffer::create(initial, capacity);
        if (!buffer) return std::unexpected(buffer.error());
        return TimedSend(std::move(*buffer));
    }
    auto TimedSend::advance(std::uint64_t now) noexcept -> std::expected<void, SendError> {
        if (initialized_ && now < now_) return std::unexpected(SendError::time_reversed);
        now_ = now; initialized_ = true; return {};
    }
    auto TimedSend::arm(std::uint64_t now) noexcept -> void {
        deadline_ = now > std::numeric_limits<std::uint64_t>::max() - rto_
            ? std::numeric_limits<std::uint64_t>::max() : now + rto_;
    }
    auto TimedSend::sent(std::size_t count, std::uint64_t now) noexcept -> std::expected<void, SendError> {
        if (auto time = advance(now); !time) return time;
        auto was_empty = buffer_.in_flight() == 0;
        if (auto sent = buffer_.mark_sent(count); !sent) return sent;
        if (was_empty && count) arm(now);
        return {};
    }
    auto TimedSend::acknowledge(std::uint32_t ack, std::uint64_t now) noexcept -> std::expected<std::size_t, SendError> {
        if (auto time = advance(now); !time) return std::unexpected(time.error());
        auto count = buffer_.acknowledge(ack);
        if (!count) return count;
        if (*count) {
            if (buffer_.in_flight()) arm(now);
            else { deadline_.reset(); rto_ = 1000; }
        }
        return count;
    }
    auto TimedSend::due(std::uint64_t now, std::size_t maximum) -> std::expected<std::optional<SendSlice>, SendError> {
        if (auto time = advance(now); !time) return std::unexpected(time.error());
        if (!deadline_ || now < *deadline_ || !maximum) return std::optional<SendSlice>{};
        return std::optional<SendSlice>{buffer_.retransmit(maximum)};
    }
    auto TimedSend::retransmitted(std::uint64_t now) noexcept -> std::expected<void, SendError> {
        if (auto time = advance(now); !time) return time;
        if (!deadline_ || now < *deadline_) return std::unexpected(SendError::not_due);
        rto_ = std::min<std::uint64_t>(rto_ * 2, 60000);
        arm(now);
        return {};
    }
}
