module tcp.send;
import std;

namespace tcp {
    auto SendBuffer::copy_range(std::size_t offset, std::size_t length) const -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> out(length);
        if (!length) return out;
        auto pos = (head_ + offset) % capacity_;
        auto first = std::min(length, capacity_ - pos);
        std::copy_n(ring_.data() + pos, first, out.data());
        if (length > first) std::copy_n(ring_.data(), length - first, out.data() + first);
        return out;
    }
    auto SendBuffer::create(std::uint32_t initial, std::size_t capacity) -> std::expected<SendBuffer, SendError> {
        if (!capacity || capacity >= 0x80000000ull) return std::unexpected(SendError::invalid_capacity);
        return SendBuffer(initial, capacity);
    }
    auto SendBuffer::enqueue(std::span<std::uint8_t const> bytes) -> std::expected<void, SendError> {
        if (bytes.size() > capacity_ - count_) return std::unexpected(SendError::capacity);
        if (bytes.empty()) return {};
        auto tail = (head_ + count_) % capacity_;
        auto first = std::min(bytes.size(), capacity_ - tail);
        std::copy_n(bytes.data(), first, ring_.data() + tail);
        if (bytes.size() > first) std::copy_n(bytes.data() + first, bytes.size() - first, ring_.data());
        count_ += bytes.size();
        return {};
    }
    auto SendBuffer::unsent(std::size_t maximum) const -> SendSlice {
        auto length = std::min(maximum, count_ - sent_);
        return {next(), copy_range(sent_, length)};
    }
    auto SendBuffer::retransmit(std::size_t maximum) const -> SendSlice {
        auto length = std::min(maximum, sent_);
        return {una_, copy_range(0, length)};
    }
    auto SendBuffer::mark_sent(std::size_t count) noexcept -> std::expected<void, SendError> {
        if (count > count_ - sent_) return std::unexpected(SendError::invalid_count);
        sent_ += count;
        return {};
    }
    auto SendBuffer::acknowledge(std::uint32_t acknowledgement) noexcept -> std::expected<std::size_t, SendError> {
        auto acked = static_cast<std::uint32_t>(acknowledgement - una_);
        if (acked > sent_) return std::unexpected(SendError::invalid_ack);
        head_ = (head_ + acked) % capacity_;
        count_ -= acked;
        sent_ -= acked;
        una_ = acknowledgement;
        return acked;
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
    auto TimedSend::observe_rtt(std::uint64_t sample_ms) noexcept -> void {
        if (!rtt_valid_) {
            srtt_ms_ = sample_ms;
            rttvar_ms_ = sample_ms / 2;
            rtt_valid_ = true;
        } else {
            auto diff = (srtt_ms_ > sample_ms) ? (srtt_ms_ - sample_ms) : (sample_ms - srtt_ms_);
            rttvar_ms_ = (3 * rttvar_ms_ + diff) / 4;
            srtt_ms_ = (7 * srtt_ms_ + sample_ms) / 8;
        }
        auto candidate = srtt_ms_ + std::max<std::uint64_t>(10, 4 * rttvar_ms_);
        base_rto_ = std::clamp<std::uint64_t>(candidate, 200, 60000);
        rto_ = base_rto_;
    }
    auto TimedSend::sent(std::size_t count, std::uint64_t now) noexcept -> std::expected<void, SendError> {
        if (auto time = advance(now); !time) return time;
        auto was_empty = buffer_.in_flight() == 0;
        if (auto res = buffer_.mark_sent(count); !res) return res;
        if (count && !rtt_tracking_) {
            rtt_tracking_ = true;
            rtt_seq_ = buffer_.next();
            rtt_sent_at_ = now;
        }
        if (was_empty && count) arm(now);
        return {};
    }
    auto TimedSend::acknowledge(std::uint32_t ack, std::uint64_t now) noexcept -> std::expected<std::size_t, SendError> {
        if (auto time = advance(now); !time) return std::unexpected(time.error());
        auto count = buffer_.acknowledge(ack);
        if (!count) return count;
        if (*count) {
            dup_acks_ = 0;
            fast_retransmit_ = false;
            if (rtt_tracking_ && static_cast<std::int32_t>(ack - rtt_seq_) >= 0) {
                rtt_tracking_ = false;
                if (now >= rtt_sent_at_) observe_rtt(now - rtt_sent_at_);
            }
            if (buffer_.in_flight()) arm(now);
            else { rto_ = base_rto_; deadline_.reset(); }
        } else if (buffer_.in_flight() && ack == buffer_.una()) {
            ++dup_acks_;
            if (dup_acks_ == 3) fast_retransmit_ = true;
        }
        return count;
    }
    auto TimedSend::due(std::uint64_t now, std::size_t maximum) -> std::expected<std::optional<SendSlice>, SendError> {
        if (auto time = advance(now); !time) return std::unexpected(time.error());
        if (fast_retransmit_ && maximum && buffer_.in_flight())
            return std::optional<SendSlice>{buffer_.retransmit(maximum)};
        if (!deadline_ || now < *deadline_ || !maximum) return std::optional<SendSlice>{};
        return std::optional<SendSlice>{buffer_.retransmit(maximum)};
    }
    auto TimedSend::retransmitted(std::uint64_t now) noexcept -> std::expected<void, SendError> {
        if (auto time = advance(now); !time) return time;
        rtt_tracking_ = false; // Karn's algorithm: never sample RTT on retransmitted segments.
        if (fast_retransmit_) {
            fast_retransmit_ = false;
            if (buffer_.in_flight()) arm(now);
            return {};
        }
        if (!deadline_ || now < *deadline_) return std::unexpected(SendError::not_due);
        rto_ = std::min<std::uint64_t>(rto_ * 2, 60000);
        arm(now);
        return {};
    }
}
