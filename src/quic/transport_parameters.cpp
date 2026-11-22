module quic.transport_parameters;
import quic.varint;
import std;

namespace quic {
    namespace {
        template<class Sink>
        auto scan(std::span<std::uint8_t const> input,Sink sink) -> std::expected<std::size_t,ParameterBlockError> {
            if (input.size()>max_parameter_bytes) return std::unexpected(ParameterBlockError::malformed);
            std::size_t count=0;
            while (!input.empty()) {
                auto id=read_varint(input); if (id.status!=VarintStatus::accepted) return std::unexpected(ParameterBlockError::malformed);
                input=input.subspan(id.consumed);
                auto length=read_varint(input); if (length.status!=VarintStatus::accepted) return std::unexpected(ParameterBlockError::malformed);
                input=input.subspan(length.consumed);
                if (length.value>input.size()) return std::unexpected(ParameterBlockError::malformed);
                sink(id.value); ++count; input=input.subspan(static_cast<std::size_t>(length.value));
            }
            return count;
        }
    }
    auto validate_parameter_block(std::span<std::uint8_t const> input) noexcept -> std::expected<void,ParameterBlockError> {
        auto count=scan(input,[](auto) {}); if (!count) return std::unexpected(count.error());
        std::array<std::uint64_t,inline_parameter_ids> local{};
        std::vector<std::uint64_t> spill;
        try {
            if (*count>local.size()) spill.resize(*count);
            auto ids=*count<=local.size() ? std::span(local).first(*count) : std::span(spill);
            std::size_t offset=0;
            (void)scan(input,[&](auto id) { ids[offset++]=id; }); // Same immutable input as the successful count.
            std::ranges::sort(ids);
            if (std::adjacent_find(ids.begin(),ids.end())!=ids.end()) return std::unexpected(ParameterBlockError::duplicate);
            return {};
        } catch (std::bad_alloc const&) { return std::unexpected(ParameterBlockError::allocation_failed); }
    }
}
