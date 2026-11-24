// TUIC per-stream QUIC output buffer module.
export module tuic.stream_output;
import std;
import containers.byte_ring;

export namespace tuic::detail {
    // Retains submitted bytes in place until the QUIC acknowledgement.
    template<std::size_t Capacity>
    class StreamOutput {
        static constexpr auto max_offset = (std::uint64_t{1} << 62) - 1;
        std::unique_ptr<containers::ByteRing<Capacity>> storage_;
        std::uint64_t released_ = 0, sent_ = 0, end_ = 0;
    public:
        [[nodiscard]] auto empty(this StreamOutput const& self) noexcept -> bool { return self.released_ == self.end_; }
        [[nodiscard]] auto pending(this StreamOutput const& self) noexcept -> bool { return self.sent_ != self.end_; }
        [[nodiscard]] auto available(this StreamOutput const& self, std::size_t size) noexcept -> bool {
            return size <= Capacity - (self.end_ - self.released_) && size <= max_offset - self.end_;
        }
        auto append(this StreamOutput& self, std::span<std::uint8_t const> bytes) -> bool {
            if (!self.available(bytes.size())) return false;
            if (bytes.empty()) return true;
            if (!self.storage_) self.storage_ = std::make_unique<containers::ByteRing<Capacity>>();
            self.storage_->write(self.end_, bytes);
            self.end_ += bytes.size();
            return true;
        }
        [[nodiscard]] auto view(this StreamOutput const& self) noexcept -> std::array<std::span<std::uint8_t const>, 2> {
            if (!self.pending()) return {};
            return self.storage_->view(self.sent_, static_cast<std::size_t>(self.end_ - self.sent_));
        }
        auto submit(this StreamOutput& self, std::size_t size) noexcept -> void { self.sent_ += size; }
        auto acknowledge(this StreamOutput& self, std::uint64_t offset, std::uint64_t size) noexcept -> bool {
            if (offset != self.released_ || size > self.sent_ - self.released_) return false;
            self.released_ += size;
            return true;
        }
    };
}
