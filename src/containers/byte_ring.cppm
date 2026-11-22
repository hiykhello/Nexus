export module containers.byte_ring;
import std;

export namespace containers {
    // Owns fixed storage. The caller tracks occupied ranges and may overwrite
    // only positions whose views it no longer needs. A range spans at most
    // one wrap, and storage addresses remain stable for this object's lifetime.
    template<std::size_t Capacity>
    class ByteRing {
        static_assert(Capacity>0);
        std::array<std::uint8_t,Capacity> bytes_{};

        template<class Byte>
        static auto segments(std::span<Byte,Capacity> bytes,std::uint64_t offset,std::size_t size) noexcept
            -> std::array<std::span<Byte>,2> {
            auto index=static_cast<std::size_t>(offset%Capacity);
            auto first=std::min(size,Capacity-index);
            return {bytes.subspan(index,first),bytes.first(size-first)};
        }
    public:

        auto write(this ByteRing& self,std::uint64_t offset,std::span<std::uint8_t const> input) noexcept -> void {
            auto [first,second]=segments(std::span(self.bytes_),offset,input.size());
            std::ranges::copy(input.first(first.size()),first.begin());
            std::ranges::copy(input.last(second.size()),second.begin());
        }

        [[nodiscard]] auto view(this ByteRing const& self,std::uint64_t offset,std::size_t size) noexcept
            -> std::array<std::span<std::uint8_t const>,2> {
            return segments(std::span(self.bytes_),offset,size);
        }

        auto read(this ByteRing const& self,std::uint64_t offset,std::span<std::uint8_t> output) noexcept -> void {
            auto [first,second]=self.view(offset,output.size());
            std::ranges::copy(first,output.begin());
            std::ranges::copy(second,output.begin()+first.size());
        }
    };
}
