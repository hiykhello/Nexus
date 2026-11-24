module tcp.receive;
import std;

namespace tcp {
    ReceiveBuffer::ReceiveBuffer(std::uint32_t initial, std::size_t capacity)
        : data_(capacity), base_(initial) {}
    auto ReceiveBuffer::create(std::uint32_t initial, std::size_t capacity) -> std::expected<ReceiveBuffer, ReceiveError> {
        if (!capacity || capacity >= 0x80000000ull) return std::unexpected(ReceiveError::invalid_capacity);
        return ReceiveBuffer(initial, capacity);
    }
    auto ReceiveBuffer::write_ring(std::size_t offset, std::span<std::uint8_t const> bytes) noexcept -> void {
        if (bytes.empty()) return;
        auto const cap = data_.size();
        auto const pos = (head_ + offset) % cap;
        auto const first = std::min(bytes.size(), cap - pos);
        std::copy_n(bytes.data(), first, data_.data() + pos);
        if (bytes.size() > first) std::copy_n(bytes.data() + first, bytes.size() - first, data_.data());
    }
    auto ReceiveBuffer::insert(std::uint32_t sequence, std::span<std::uint8_t const> data) -> ReceiveResult {
        ReceiveResult result;
        if (data.empty()) return result;
        auto const cap = data_.size();
        if (cap == 0) { result.outside = data.size(); return result; }
        auto const start_off = static_cast<std::uint32_t>(sequence - base_);
        auto const limit = fin_ ? std::min<std::size_t>(cap, static_cast<std::uint32_t>(*fin_ - base_)) : cap;
        // Fast path: in-order contiguous segment when no out-of-order intervals are queued.
        if (ooo_len_ == 0 && start_off == ready_ && start_off < limit) {
            auto const take = std::min<std::size_t>(data.size(), limit - start_off);
            write_ring(ready_, data.first(take));
            ready_ += take;
            result.accepted = take;
            result.outside = data.size() - take;
            return result;
        }
        std::size_t data_off = 0, buf_off = 0, in_len = 0;
        if (start_off < limit) {
            buf_off = start_off;
            in_len = std::min<std::size_t>(data.size(), limit - start_off);
        } else {
            auto const wrap = std::uint64_t{0x100000000ull} - start_off;
            if (wrap >= data.size()) { result.outside = data.size(); return result; }
            data_off = static_cast<std::size_t>(wrap);
            in_len = std::min<std::size_t>(data.size() - data_off, limit);
        }
        result.outside = data.size() - in_len;
        if (in_len == 0) return result;
        auto buf_end = buf_off + in_len;
        if (buf_off < ready_) {
            auto const dup = std::min(buf_end, ready_) - buf_off;
            result.duplicate += dup;
            buf_off += dup;
            data_off += dup;
        }
        auto const rem_l = static_cast<std::uint32_t>(buf_off);
        auto const rem_r = static_cast<std::uint32_t>(buf_end);
        if (rem_l == rem_r) return result;

        auto cur = rem_l, merged_l = rem_l, merged_r = rem_r;
        std::size_t insert_at = ooo_len_, first_overlap = ooo_len_, overlap_count = 0;
        for (std::size_t i = 0; i < ooo_len_; ++i) {
            auto const& b = ooo_[i];
            if (b.right < rem_l) continue;
            if (b.left > rem_r) {
                if (insert_at == ooo_len_) insert_at = i;
                break;
            }
            if (first_overlap == ooo_len_) { first_overlap = i; insert_at = i; }
            ++overlap_count;
            if (b.left < merged_l) merged_l = b.left;
            if (b.right > merged_r) merged_r = b.right;
            if (cur < b.left) {
                auto const gap = static_cast<std::size_t>(b.left - cur);
                write_ring(cur, data.subspan(data_off + (cur - rem_l), gap));
                result.accepted += gap;
                cur = b.left;
            }
            auto const ov_end = std::min(rem_r, b.right);
            if (cur < ov_end) {
                result.duplicate += (ov_end - cur);
                cur = ov_end;
            }
        }
        if (overlap_count == 0 && rem_l > ready_ && ooo_len_ == ooo_.size()) {
            result.outside += (rem_r - rem_l);
            return result;
        }
        if (cur < rem_r) {
            auto const tail = static_cast<std::size_t>(rem_r - cur);
            write_ring(cur, data.subspan(data_off + (cur - rem_l), tail));
            result.accepted += tail;
        }
        if (merged_l == ready_) {
            ready_ = merged_r;
            if (overlap_count > 0) {
                for (std::size_t i = first_overlap + overlap_count; i < ooo_len_; ++i)
                    ooo_[i - overlap_count] = ooo_[i];
                ooo_len_ -= overlap_count;
            }
        } else if (overlap_count > 0) {
            ooo_[first_overlap] = {merged_l, merged_r};
            if (overlap_count > 1) {
                for (std::size_t i = first_overlap + overlap_count; i < ooo_len_; ++i)
                    ooo_[i - overlap_count + 1] = ooo_[i];
                ooo_len_ -= (overlap_count - 1);
            }
        } else {
            for (std::size_t i = ooo_len_; i > insert_at; --i) ooo_[i] = ooo_[i - 1];
            ooo_[insert_at] = {merged_l, merged_r};
            ++ooo_len_;
        }
        return result;
    }
    auto ReceiveBuffer::insert_fin(std::uint32_t sequence) noexcept -> FinResult {
        if (fin_) return *fin_ == sequence ? FinResult::duplicate : FinResult::conflict;
        auto const cap = data_.size();
        auto offset = static_cast<std::uint32_t>(sequence - base_);
        if (offset < ready_ || offset >= cap) return FinResult::outside;
        fin_ = sequence;
        for (std::size_t i = 0; i < ooo_len_; ++i) {
            if (ooo_[i].right <= offset) continue;
            if (ooo_[i].left < offset) { ooo_[i].right = offset; ooo_len_ = i + 1; }
            else ooo_len_ = i;
            break;
        }
        return FinResult::accepted;
    }
    auto ReceiveBuffer::read(std::span<std::uint8_t> output) noexcept -> std::size_t {
        auto count = std::min(output.size(), ready_);
        if (!count) return 0;
        auto const cap = data_.size();
        auto first = std::min(count, cap - head_);
        std::copy_n(data_.data() + head_, first, output.data());
        if (count > first) std::copy_n(data_.data(), count - first, output.data() + first);
        head_ = (head_ + count) % cap;
        base_ += static_cast<std::uint32_t>(count);
        ready_ -= count;
        for (std::size_t i = 0; i < ooo_len_; ++i) {
            ooo_[i].left -= static_cast<std::uint32_t>(count);
            ooo_[i].right -= static_cast<std::uint32_t>(count);
        }
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
        auto const count = std::min<std::size_t>(blocks.size(), ooo_len_);
        for (std::size_t i = 0; i < count; ++i)
            blocks[i] = {base_ + ooo_[i].left, base_ + ooo_[i].right};
        return {blocks, count};
    }
}
