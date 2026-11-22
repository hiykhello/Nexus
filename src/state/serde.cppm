export module state.serde;
import std;
import state.core;

export namespace state {
    inline auto append_le(Bytes& bytes, std::uint64_t value, std::size_t width) -> void {
        for (std::size_t i=0; i<width; ++i) {
            bytes.push_back(static_cast<std::byte>(value & 255));
            value >>= 8;
        }
    }

    struct Reader {
        std::span<std::byte const> rest;
        bool invalid=false;

        auto take(std::size_t size) noexcept -> std::span<std::byte const> {
            if (size>rest.size()) {
                invalid=true;
                return {};
            }
            auto result=rest.first(size);
            rest=rest.subspan(size);
            return result;
        }

        auto number(std::size_t width) noexcept -> std::uint64_t {
            std::uint64_t value=0;
            for (auto byte:take(width) | std::views::reverse)
                value=(value<<8)|std::to_integer<unsigned>(byte);
            return value;
        }

        auto complete() const noexcept -> bool {return !invalid && rest.empty();}
    };
}
