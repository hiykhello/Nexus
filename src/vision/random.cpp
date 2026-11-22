module vision.random;
import std;
import vision;
import crypto;
namespace vision {
    auto secure_padding_random(std::size_t bound) -> std::expected<std::size_t,RandomError> {
        return uniform_padding_random(bound,[](std::span<std::uint8_t> output) { return crypto::random_bytes(output).has_value(); });
    }
    auto prepare_secure(Sender& sender,TrafficFilter const& filter,std::span<std::uint8_t const> bytes,bool initial)
        -> std::expected<SendBlock,SecureSendError> {
        auto bound=sender.random_bound(filter,bytes.size(),initial);
        std::size_t sample=0;
        if (bound) {
            auto value=secure_padding_random(bound);
            if (!value) return std::unexpected(SecureSendError{{},value.error()});
            sample=*value;
        }
        auto block=sender.prepare(filter,bytes,sample,initial);
        if (!block) return std::unexpected(SecureSendError{block.error(),{}});
        return std::move(*block);
    }
    auto prepare_large_secure(Sender& sender,TrafficFilter const& filter,std::span<std::uint8_t const> bytes)
        -> std::expected<SendBlock,SecureSendError> {
        auto plan=sender.plan_large(filter,bytes);
        if (!plan) return std::unexpected(SecureSendError{plan.error(),{}});
        std::array<std::size_t,2> random{};
        for (std::size_t i=0;i<random.size();++i) if (plan->random_bounds[i]) {
            auto value=secure_padding_random(plan->random_bounds[i]);
            if (!value) return std::unexpected(SecureSendError{{},value.error()});
            random[i]=*value;
        }
        auto block=sender.prepare_large(filter,bytes,random);
        if (!block) return std::unexpected(SecureSendError{block.error(),{}});
        return std::move(*block);
    }
}
