// Private implementation: import std and nexus.dns.message first.
#pragma once
#include <cerrno>
#include <sys/random.h>
#include "corosio_tcp.hpp"

namespace nexus::dns::detail {
    enum class ResolveError {
        state, random, transport, timeout, canceled, protocol, alias_loop, limit,
        name_not_found, no_data, referral, indeterminate, server_failure, refused
    };
    // Linux kernel CSPRNG; never wait for initialization on the event loop.
    // A short or interrupted read is completed; errors fail closed.
    inline auto random_id() -> std::expected<std::uint16_t, ResolveError> {
        std::array<std::uint8_t,2> bytes{};
        std::size_t offset=0;
        while (offset<bytes.size()) {
            auto n=::getrandom(bytes.data()+offset,bytes.size()-offset,GRND_NONBLOCK);
            if (n<0 && errno==EINTR) continue;
            if (n<=0) return std::unexpected(ResolveError::random);
            offset+=static_cast<std::size_t>(n);
        }
        return static_cast<std::uint16_t>((std::uint16_t(bytes[0])<<8)|bytes[1]);
    }
    class AddressResolver {
        boost::corosio::io_context& context_;
        std::unique_ptr<FallbackQuery> active_;
        bool started_=false, canceled_=false, tcp_only_=false, edns_=false;
        std::optional<std::uint32_t> negative_ttl_;
    public:
        explicit AddressResolver(boost::corosio::io_context& context, bool tcp_only=false, bool edns=false)
            : context_(context), tcp_only_(tcp_only), edns_(edns) {}
        auto negative_cache_ttl() const noexcept -> std::optional<std::uint32_t> { return negative_ttl_; }
        auto cancel() noexcept -> void { canceled_=true; if (active_) active_->cancel(); }
        auto resolve_random(boost::corosio::endpoint upstream, Question question,
                            std::chrono::steady_clock::time_point deadline)
            -> boost::capy::task<std::expected<AddressAnswer,ResolveError>> {
            auto generator=[] { return random_id(); };
            co_return co_await resolve(upstream,std::move(question),deadline,generator);
        }
        // The generator is borrowed for the whole coroutine. Owner and generator
        // must outlive completion, including after cancellation.
        auto resolve(boost::corosio::endpoint upstream, Question question,
                     std::chrono::steady_clock::time_point deadline,
                     std::function_ref<std::expected<std::uint16_t,ResolveError>()> next_id)
            -> boost::capy::task<std::expected<AddressAnswer,ResolveError>> {
            using Clock=std::chrono::steady_clock;
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            auto start=Clock::now();
            std::vector<std::string> visited;
            std::optional<std::uint32_t> ttl;
            bool edns_active=edns_;
            for (;;) {
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                if (Clock::now()>=deadline) co_return std::unexpected(ResolveError::timeout);
                auto id=next_id();
                if (!id) co_return std::unexpected(id.error());
                active_=std::make_unique<FallbackQuery>(context_,tcp_only_);
                auto response=co_await active_->query(upstream,*id,question,deadline,edns_active);
                active_.reset();
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                if (!response) {
                    auto error=response.error();
                    co_return std::unexpected(error==UdpError::timeout ? ResolveError::timeout :
                        error==UdpError::canceled ? ResolveError::canceled :
                        error==UdpError::transport ? ResolveError::transport : ResolveError::protocol);
                }
                // Only a plain FORMERR without OPT indicates an unextended server.
                if (edns_active && response->rcode==1 && !response->edns) {
                    edns_active=false;
                    continue;
                }
                if (response->edns ? (!edns_active || response->edns->version || response->edns->flags || response->edns->option_count)
                                   : edns_active)
                    co_return std::unexpected(ResolveError::protocol);
                auto save_negative_ttl = [&](std::string_view name) {
                    auto value=negative_ttl(*response,name);
                    if (value) {
                        if (ttl) *value=std::min(*value,*ttl);
                        auto elapsed=std::chrono::ceil<std::chrono::seconds>(Clock::now()-start).count();
                        negative_ttl_=elapsed>=*value ? 0 : std::min<std::uint32_t>(*value-static_cast<std::uint32_t>(elapsed),600);
                    }
                };
                if (response->rcode!=0) {
                    if (response->rcode==3) {
                        auto negative=parse_nxdomain_alias(response->wire,*id,question,edns_active);
                        if (!negative) co_return std::unexpected(negative.error()==MessageError::alias_loop ? ResolveError::alias_loop :
                            negative.error()==MessageError::limit ? ResolveError::limit : ResolveError::protocol);
                        for (auto const& name:negative->chain) {
                            if (std::ranges::find(visited,name)!=visited.end()) co_return std::unexpected(ResolveError::alias_loop);
                            if (visited.size()==16) co_return std::unexpected(ResolveError::limit);
                            visited.push_back(name);
                        }
                        if (negative->ttl) ttl=ttl ? std::min(*ttl,*negative->ttl) : negative->ttl;
                        save_negative_ttl(negative->canonical_name);
                    }
                    co_return std::unexpected(response->rcode==3 ? ResolveError::name_not_found :
                        response->rcode==2 ? ResolveError::server_failure :
                        response->rcode==5 ? ResolveError::refused : ResolveError::protocol);
                }
                auto answer=parse_addresses(response->wire,*id,question,edns_active);
                if (!answer) co_return std::unexpected(answer.error()==MessageError::alias_loop ? ResolveError::alias_loop :
                                                       answer.error()==MessageError::limit ? ResolveError::limit : ResolveError::protocol);
                for (auto const& name : answer->chain) {
                    if (std::ranges::find(visited,name)!=visited.end()) co_return std::unexpected(ResolveError::alias_loop);
                    if (visited.size()==16) co_return std::unexpected(ResolveError::limit);
                    visited.push_back(name);
                }
                if (answer->ttl) ttl=ttl ? std::min(*ttl,*answer->ttl) : answer->ttl;
                // A negative answer must not hide unrelated or contradictory
                // answer records. DNSSEC and other answer types are not yet
                // supported for this conservative negative interpretation.
                auto valid_negative_answer = [&] {
                    for (auto const& record : response->records) {
                        if (record.section!=Section::answer) continue;
                        if (record.klass!=1 || record.type!=5 ||
                            std::ranges::find(answer->chain,record.name)==answer->chain.end() ||
                            record.name==answer->canonical_name) return false;
                    }
                    return true;
                };
                if (answer->addresses.empty() && answer->chain.size()>1 &&
                    negative_ttl(*response,answer->canonical_name)) {
                    if (!valid_negative_answer()) co_return std::unexpected(ResolveError::protocol);
                    save_negative_ttl(answer->canonical_name);
                    co_return std::unexpected(ResolveError::no_data);
                }
                if (answer->addresses.empty() && answer->chain.size()==1) {
                    auto in_zone = [&](std::string const& zone) {
                        auto const& name=answer->canonical_name;
                        return zone=="." || name==zone ||
                            (name.size()>zone.size() && name.ends_with(zone) && name[name.size()-zone.size()-1]=='.');
                    };
                    bool soa=negative_ttl(*response,answer->canonical_name).has_value(), ns=false;
                    for (auto const& record : response->records) {
                        if (record.section!=Section::authority || record.klass!=1 || !in_zone(record.name)) continue;
                        ns |= record.type==2;
                    }
                    if (soa && !valid_negative_answer()) co_return std::unexpected(ResolveError::protocol);
                    if (soa) save_negative_ttl(answer->canonical_name);
                    co_return std::unexpected(soa ? ResolveError::no_data : ns ? ResolveError::referral : ResolveError::indeterminate);
                }
                if (!answer->addresses.empty()) {
                    answer->chain=std::move(visited);
                    if (ttl) {
                        auto elapsed=std::chrono::ceil<std::chrono::seconds>(Clock::now()-start).count();
                        answer->ttl=elapsed>=*ttl ? 0 : *ttl-static_cast<std::uint32_t>(elapsed);
                    }
                    co_return std::move(*answer);
                }
                // The next response begins with the previous terminal name.
                question.name=answer->canonical_name;
                visited.pop_back();
            }
        }
    };
}
