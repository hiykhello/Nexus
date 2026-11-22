module tcp.receive;
import std;

namespace tcp {
    ReceiveBuffer::ReceiveBuffer(std::uint32_t initial, std::size_t capacity)
        : data_(capacity), present_(capacity, 0), base_(initial) {}
    auto ReceiveBuffer::create(std::uint32_t initial, std::size_t capacity) -> std::expected<ReceiveBuffer, ReceiveError> {
        if (!capacity || capacity >= 0x80000000ull) return std::unexpected(ReceiveError::invalid_capacity);
        return ReceiveBuffer(initial, capacity);
    }
    auto ReceiveBuffer::insert(std::uint32_t sequence, std::span<std::uint8_t const> data) -> ReceiveResult {
        ReceiveResult result;
        if (data.empty()) return result;
        auto const cap = data_.size();
        auto const start_off = static_cast<std::uint32_t>(sequence - base_);
        auto const limit = fin_ ? std::min<std::size_t>(cap, static_cast<std::uint32_t>(*fin_ - base_)) : cap;
        // Fast path: in-order contiguous segment when no out-of-order bytes overlap.
        if (ooo_count_ == 0 && start_off == ready_ && start_off < limit) {
            auto const take = std::min<std::size_t>(data.size(), limit - start_off);
            auto pos = (head_ + ready_) % cap;
            auto first = std::min(take, cap - pos);
            std::copy_n(data.data(), first, data_.data() + pos);
            std::fill_n(present_.data() + pos, first, std::uint8_t{1});
            if (take > first) {
                std::copy_n(data.data() + first, take - first, data_.data());
                std::fill_n(present_.data(), take - first, std::uint8_t{1});
            }
            ready_ += take;
            result.accepted = take;
            result.outside = data.size() - take;
            return result;
        }
        for (auto byte : data) {
            auto offset = static_cast<std::uint32_t>(sequence++ - base_);
            if (offset >= limit) {
                ++result.outside; continue;
            }
            auto idx = (head_ + offset) % cap;
            if (present_[idx]) ++result.duplicate;
            else {
                data_[idx] = byte;
                present_[idx] = 1;
                ++result.accepted;
                if (offset >= ready_) ++ooo_count_;
            }
        }
        while (ready_ < cap && present_[(head_ + ready_) % cap]) {
            ++ready_;
            if (ooo_count_) --ooo_count_;
        }
        return result;
    }
    auto ReceiveBuffer::insert_fin(std::uint32_t sequence) noexcept -> FinResult {
        if (fin_) return *fin_ == sequence ? FinResult::duplicate : FinResult::conflict;
        auto const cap = data_.size();
        auto offset = static_cast<std::uint32_t>(sequence - base_);
        if (offset < ready_ || offset >= cap) return FinResult::outside;
        fin_ = sequence;
        for (auto i = static_cast<std::size_t>(offset); i < cap; ++i) {
            auto idx = (head_ + i) % cap;
            if (present_[idx]) {
                present_[idx] = 0;
                if (ooo_count_) --ooo_count_;
            }
        }
        return FinResult::accepted;
    }
    auto ReceiveBuffer::read(std::span<std::uint8_t> output) noexcept -> std::size_t {
        auto count = std::min(output.size(), ready_);
        if (!count) return 0;
        auto const cap = data_.size();
        auto first = std::min(count, cap - head_);
        std::copy_n(data_.data() + head_, first, output.data());
        std::fill_n(present_.data() + head_, first, std::uint8_t{0});
        if (count > first) {
            std::copy_n(data_.data(), count - first, output.data() + first);
            std::fill_n(present_.data(), count - first, std::uint8_t{0});
        }
        head_ = (head_ + count) % cap;
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
    auto ReceiveBuffer::sack_blocks() const noexcept -> std::pair<std::array<SackBlock, 3>, std::size_t> {
        std::array<SackBlock, 3> blocks{};
        std::size_t count = 0;
        if (ooo_count_ == 0) return {blocks, 0};
        auto const cap = data_.size();
        std::size_t i = ready_;
        while (i < cap && count < blocks.size()) {
            while (i < cap && !present_[(head_ + i) % cap]) ++i;
            if (i >= cap) break;
            auto left = i;
            while (i < cap && present_[(head_ + i) % cap]) ++i;
            blocks[count++] = {base_ + static_cast<std::uint32_t>(left), base_ + static_cast<std::uint32_t>(i)};
        }
        return {blocks, count};
    }
}
