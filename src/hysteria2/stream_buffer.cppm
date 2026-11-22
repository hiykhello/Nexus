export module hysteria2.stream_buffer;
import std;
import containers.byte_ring;

export namespace hysteria2 {
    // Accepted bytes remain at their original addresses until QUIC ACKs them.
    // Ring offsets do not wrap: QUIC limits stream offsets to 62 bits.
    template<std::size_t Capacity=16384>
    class StreamBuffer {
        static_assert(Capacity && Capacity<=1048576);
        containers::ByteRing<Capacity> bytes_;
        std::uint64_t released_=0,accepted_=0,end_=0;
    public:
        auto size() const noexcept -> std::size_t { return static_cast<std::size_t>(end_-released_); }
        auto available() const noexcept -> std::size_t { return Capacity-size(); }
        auto pending() const noexcept -> std::size_t { return static_cast<std::size_t>(end_-accepted_); }
        auto offset() const noexcept -> std::uint64_t { return accepted_; }
        auto released() const noexcept -> std::uint64_t { return released_; }
        auto end() const noexcept -> std::uint64_t { return end_; }
        auto append(std::span<std::uint8_t const> input) noexcept -> bool {
            if (input.size()>available() || input.size()>((std::uint64_t{1}<<62)-1)-end_) return false;
            bytes_.write(end_,input);
            end_+=input.size();
            return true;
        }
        // Empty pending views may still carry the sender's FIN separately.
        auto view() const noexcept -> std::array<std::span<std::uint8_t const>,2> {
            return bytes_.view(accepted_,pending());
        }
        auto accept(std::size_t size) noexcept -> bool {
            if (size>pending()) return false;
            accepted_+=size; return true;
        }
        auto acknowledge(std::uint64_t offset,std::uint64_t size) noexcept -> bool {
            if (offset!=released_ || size>accepted_-released_) return false;
            released_+=size; return true;
        }
        // Receive windows never expose retained references after this call.
        auto pull(std::span<std::uint8_t> output) noexcept -> std::size_t {
            auto size=std::min(output.size(),this->size());
            bytes_.read(released_,output.first(size));
            released_+=size;
            accepted_=released_;
            return size;
        }
    };
}
