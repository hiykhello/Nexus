module nexus.tcp.receive;
import std;

namespace nexus::tcp {
    ReceiveBuffer::ReceiveBuffer(std::uint32_t initial, std::size_t capacity) : slots_(capacity), base_(initial) {}
    auto ReceiveBuffer::create(std::uint32_t initial, std::size_t capacity) -> std::expected<ReceiveBuffer, ReceiveError> {
        // Keep all window offsets unambiguous in the 32-bit serial number space.
        if (!capacity || capacity >= 0x80000000ull) return std::unexpected(ReceiveError::invalid_capacity);
        return ReceiveBuffer(initial, capacity);
    }
    auto ReceiveBuffer::insert(std::uint32_t sequence, std::span<std::uint8_t const> data) -> ReceiveResult {
        ReceiveResult result;
        for (auto byte : data) {
            auto offset = static_cast<std::uint32_t>(sequence++ - base_);
            if (offset >= slots_.size() || (fin_ && offset >= static_cast<std::uint32_t>(*fin_ - base_))) {
                ++result.outside; continue;
            }
            auto& slot = slots_[(head_ + offset) % slots_.size()];
            if (slot) ++result.duplicate;
            else { slot = byte; ++result.accepted; }
        }
        while (ready_ < slots_.size() && slots_[(head_ + ready_) % slots_.size()]) ++ready_;
        return result;
    }
    auto ReceiveBuffer::insert_fin(std::uint32_t sequence) noexcept -> FinResult {
        if (fin_) return *fin_ == sequence ? FinResult::duplicate : FinResult::conflict;
        auto offset = static_cast<std::uint32_t>(sequence - base_);
        if (offset < ready_ || offset >= slots_.size()) return FinResult::outside;
        fin_ = sequence;
        // Bytes at or beyond FIN cannot belong to this stream.
        for (auto i = static_cast<std::size_t>(offset); i < slots_.size(); ++i)
            slots_[(head_ + i) % slots_.size()].reset();
        return FinResult::accepted;
    }
    auto ReceiveBuffer::read(std::span<std::uint8_t> output) noexcept -> std::size_t {
        auto count = std::min(output.size(), ready_);
        for (std::size_t i = 0; i < count; ++i) {
            output[i] = *slots_[head_]; slots_[head_].reset();
            head_ = (head_ + 1) % slots_.size();
        }
        base_ += static_cast<std::uint32_t>(count);
        ready_ -= count;
        return count;
    }
    auto ReceiveBuffer::finished() const noexcept -> bool {
        return fin_ && *fin_ == base_ + static_cast<std::uint32_t>(ready_);
    }
    auto ReceiveBuffer::next() const noexcept -> std::uint32_t {
        return base_ + static_cast<std::uint32_t>(ready_) + (finished() ? 1u : 0u);
    }
}
