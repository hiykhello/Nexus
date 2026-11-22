export module quic.varint;
import std;

export namespace quic {
    inline constexpr std::uint64_t max_varint=(std::uint64_t{1}<<62)-1;
    enum class VarintStatus { incomplete,accepted,invalid,closed };
    struct VarintResult { VarintStatus status=VarintStatus::incomplete; std::size_t consumed=0; std::uint64_t value=0; };
    inline auto varint_size(std::uint64_t value) noexcept -> std::size_t {
        if (value<=63) return 1;
        if (value<=16383) return 2;
        if (value<=1073741823) return 4;
        return value<=max_varint ? 8 : 0;
    }
    // Legal QUIC integers may use a longer width than the shortest encoding.
    // The leading two bits always bound a decoded value to 62 bits.
    inline auto read_varint(std::span<std::uint8_t const> input) noexcept -> VarintResult {
        if (input.empty()) return {};
        auto width=std::size_t{1}<<(input[0]>>6);
        if (input.size()<width) return {};
        auto value=std::uint64_t(input[0]&63);
        for (std::size_t i=1;i<width;++i) value=(value<<8)|input[i];
        return {VarintStatus::accepted,width,value};
    }
    inline auto write_varint(std::span<std::uint8_t> output,std::uint64_t value,std::size_t width=0) noexcept -> std::optional<std::size_t> {
        auto minimum=varint_size(value);
        if (!minimum) return {};
        if (!width) width=minimum;
        if ((width!=1 && width!=2 && width!=4 && width!=8) || width<minimum || output.size()<width) return {};
        auto tag=width==1 ? 0u : width==2 ? 1u : width==4 ? 2u : 3u;
        for (std::size_t i=0;i<width;++i) output[width-i-1]=static_cast<std::uint8_t>(value>>(i*8));
        output[0]|=static_cast<std::uint8_t>(tag<<6);
        return width;
    }
    inline auto append_varint(std::vector<std::uint8_t>& output,std::uint64_t value) -> bool {
        auto size=varint_size(value);
        if (!size) return false;
        std::array<std::uint8_t,8> encoded{};
        (void)write_varint(encoded,value,size);
        output.insert(output.end(),encoded.begin(),encoded.begin()+size);
        return true;
    }
    class VarintDecoder {
        std::array<std::uint8_t,8> bytes_{};
        std::size_t size_=0,width_=0;
        VarintStatus status_=VarintStatus::incomplete;
        std::uint64_t value_=0;
    public:
        auto feed(std::span<std::uint8_t const> input) noexcept -> VarintResult {
            if (status_!=VarintStatus::incomplete) return {status_,0,value_};
            std::size_t consumed=0;
            if (!width_ && !input.empty()) {
                bytes_[0]=input[0]; size_=1; consumed=1;
                width_=std::size_t{1}<<(bytes_[0]>>6);
            }
            if (!width_) return {};
            auto count=std::min(width_-size_,input.size()-consumed);
            std::copy_n(input.begin()+consumed,count,bytes_.begin()+size_); size_+=count; consumed+=count;
            if (size_==width_) {
                value_=read_varint(std::span(bytes_).first(width_)).value;
                status_=VarintStatus::accepted;
            }
            return {status_,consumed,value_};
        }
        auto reset() noexcept -> void { size_=width_=0; value_=0; status_=VarintStatus::incomplete; }
        auto close() noexcept -> void { status_=VarintStatus::closed; }
        auto at_boundary() const noexcept -> bool { return status_==VarintStatus::incomplete && !size_; }
    };
}

