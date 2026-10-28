// Private implementation: import std, nexus.dns.message and nexus.dns.cache first.
#pragma once
#include "corosio_resolve.hpp"

namespace nexus::dns::detail {
    // One operation per object; cache and object live until the task completes.
    // All cache access and cancellation occur on the same owner/executor.
    class CachedAddressResolver {
        AddressCache& cache_;
        AddressResolver resolver_;
        bool started_=false, canceled_=false, disable_cache_=false;
        static auto now_ms() -> std::uint64_t {
            auto value=std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return value<0 ? 0 : static_cast<std::uint64_t>(value);
        }
    public:
        CachedAddressResolver(boost::corosio::io_context& context, AddressCache& cache, bool tcp_only=false, bool disable_cache=false, bool edns=false)
            : cache_(cache), resolver_(context,tcp_only,edns), disable_cache_(disable_cache) {}
        auto cancel() noexcept -> void { canceled_=true; resolver_.cancel(); }
        auto resolve(boost::corosio::endpoint upstream, std::uint64_t view, Question question,
                     std::chrono::steady_clock::time_point deadline)
            -> boost::capy::task<std::expected<AddressAnswer,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ResolveError::timeout);
            if (disable_cache_) {
                auto answer=co_await resolver_.resolve_random(upstream,std::move(question),deadline);
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                co_return answer;
            }
            CacheKey key{view,question.name,question.type};
            auto cached=cache_.lookup(key,now_ms());
            if (cached && *cached) co_return std::move(**cached);
            auto negative=cache_.lookup_negative(key,now_ms());
            if (negative && *negative) co_return std::unexpected(**negative==NegativeKind::name_not_found ?
                ResolveError::name_not_found : ResolveError::no_data);
            auto token=cache_.begin_query(key);
            struct Registration {
                AddressCache& cache;
                std::optional<CacheToken> token;
                ~Registration() { if (token) (void)cache.cancel_query(*token); }
            } registration{cache_,token ? std::optional<CacheToken>(*token) : std::nullopt};
            auto answer=co_await resolver_.resolve_random(upstream,std::move(question),deadline);
            // Registration is best effort; cache errors do not turn a successful
            // network resolution into a failure. A clear may invalidate the token.
            if (token && !canceled_) {
                if (answer) (void)cache_.publish(key,*answer,now_ms(),*token);
                else if (answer.error()==ResolveError::name_not_found || answer.error()==ResolveError::no_data) {
                    auto ttl=resolver_.negative_cache_ttl();
                    if (ttl) (void)cache_.publish_negative(key,answer.error()==ResolveError::name_not_found ?
                        NegativeKind::name_not_found : NegativeKind::no_data,*ttl,now_ms(),*token);
                    else (void)cache_.invalidate(key,now_ms(),*token);
                }
            }
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            co_return answer;
        }
    };
}
