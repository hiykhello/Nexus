// Experimental DNS cache model using the bounded table. Include after
// bounded_table.hpp and nexus.dns.cache/message imports. Not production code.
#pragma once
#include "actual_cache_types.hpp"

namespace dns_hp_experiment {
#ifdef DNS_SEMANTIC_TEST_HOOK
void after_advance_for_test();
#endif
class SemanticCache {
    using Key=dns::CacheKey;
    using Token=dns::CacheToken;
    using Error=dns::CacheError;
    using Answer=dns::AddressAnswer;
    using Negative=dns::NegativeKind;
    struct Entry {
        Key key;
        Answer answer;
        std::optional<Negative> negative;
        std::uint64_t expires,revision;
    };
    struct Indexed {
        Answer answer;
        std::optional<Negative> negative;
        std::uint64_t expires,generation;
    };
    struct Pending { Key key; std::uint64_t query; std::optional<std::uint64_t> refresh_revision; };
    using Index=BoundedTable<Key,Indexed,ActualKeyHash,ActualKeyEqual>;
    std::vector<Entry> entries_;
    std::vector<Pending> pending_;
    std::size_t capacity_;
    std::uint64_t stale_window_ms_,generation_=1,next_query_=0;
    std::atomic<std::uint64_t> visible_generation_{1},now_{0},sequence_{0};
    bool initialized_=false;
    mutable std::mutex mutex_;
    Index index_;
    struct Mutation {
        std::atomic<std::uint64_t>& sequence;
        explicit Mutation(std::atomic<std::uint64_t>& value) : sequence(value) { sequence.fetch_add(1); }
        Mutation(Mutation const&)=delete;
        ~Mutation() { sequence.fetch_add(1); }
    };
    auto sequence_exhausted() const noexcept -> bool {
        return sequence_.load()>=std::numeric_limits<std::uint64_t>::max()-1;
    }
    static_assert(std::is_nothrow_move_constructible_v<Entry> && std::is_nothrow_move_assignable_v<Entry>);
    static auto same(Key const& a,Key const& b) noexcept -> bool { return ActualKeyEqual{}(a,b); }
    static auto normalize(Key& key) -> bool {
        return (key.type==1 || key.type==28) && dns::canonicalize_name(key.name);
    }
    static auto valid_answer(Answer const& answer,std::uint16_t type) -> bool {
        if (answer.addresses.empty() || answer.addresses.size()>128 || answer.chain.size()>16 ||
            answer.canonical_name.size()>254 || !answer.ttl) return false;
        for (auto const& name:answer.chain) if (name.size()>254) return false;
        for (auto const& address:answer.addresses) if (address.size!=(type==1 ? 4 : 16)) return false;
        return true;
    }
    auto ordered(std::uint64_t now) const noexcept -> std::uint64_t {
        return initialized_ ? std::max(now,now_.load()) : now;
    }
    auto advance(std::uint64_t now,Index::Writer& writer) -> std::expected<void,Error> {
        if (initialized_ && now<now_.load()) return std::unexpected(Error::time_reversed);
        now_.store(now); initialized_=true;
        for (auto it=entries_.begin();it!=entries_.end();) {
            if (now>=it->expires && (it->negative || now-it->expires>=stale_window_ms_)) {
                if (!writer.erase(it->key)) std::terminate();
                it=entries_.erase(it);
            } else ++it;
        }
        return {};
    }
    auto refresh_current(Pending const& pending) const -> bool {
        if (!pending.refresh_revision) return true;
        auto entry=std::ranges::find_if(entries_,[&](auto const& item) { return same(item.key,pending.key); });
        return entry!=entries_.end() && !entry->negative && entry->revision==*pending.refresh_revision;
    }
    auto remove(Key const& key,Index::Writer& writer) -> void {
        auto existing=std::ranges::find_if(entries_,[&](auto const& entry) { return same(entry.key,key); });
        if (existing==entries_.end()) return;
        if (!writer.erase(existing->key)) std::terminate();
        entries_.erase(existing);
    }
    // All potentially throwing copies and allocations precede changes to an
    // existing key or eviction. entries_ was reserved at construction.
    auto install(Entry replacement,Index::Writer& writer) -> void {
        auto prepared=writer.prepare(replacement.key,Indexed{replacement.answer,replacement.negative,replacement.expires,generation_});
        auto existing=std::ranges::find_if(entries_,[&](auto const& entry) { return same(entry.key,replacement.key); });
        if (existing==entries_.end() && entries_.size()==capacity_) {
            existing=std::ranges::min_element(entries_,{},&Entry::expires);
            if (!writer.erase(existing->key)) std::terminate();
        }
        if (!writer.put(std::move(prepared))) std::terminate();
        if (existing!=entries_.end()) *existing=std::move(replacement);
        else entries_.push_back(std::move(replacement));
    }
public:
    using Reader=Index::Reader;
    explicit SemanticCache(std::size_t capacity,std::uint64_t stale_window_ms,std::size_t readers)
        : capacity_(std::min<std::size_t>(capacity,256)),stale_window_ms_(stale_window_ms),index_(readers) {
        entries_.reserve(capacity_);
    }
    [[nodiscard]] auto reader(std::size_t index) -> Reader { return index_.reader(index); }
    [[nodiscard]] auto size() const -> std::size_t { std::lock_guard lock(mutex_); return entries_.size(); }

    template<class Hook>
    [[nodiscard]] auto lookup_with_hook(Key key,std::uint64_t now,Reader& reader,Hook&& hook)
        -> std::expected<std::optional<Answer>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        for (;;) {
            auto sequence=sequence_.load();
            if (sequence&1) { std::this_thread::yield(); continue; }
            auto generation=visible_generation_.load();
            std::optional<Answer> result;
            (void)reader.visit(key,[&](Indexed const& entry) {
                if (entry.generation!=generation) return;
                hook();
                auto effective=std::max(now,now_.load());
                if (entry.negative || effective>=entry.expires || (entry.expires-effective)/1000==0) return;
                result=entry.answer;
                result->ttl=static_cast<std::uint32_t>((entry.expires-effective)/1000);
            });
            if (sequence_.load()==sequence && visible_generation_.load()==generation) return result;
        }
    }
    [[nodiscard]] auto lookup(Key key,std::uint64_t now,Reader& reader) -> std::expected<std::optional<Answer>,Error> {
        return lookup_with_hook(std::move(key),now,reader,[] {});
    }
    [[nodiscard]] auto lookup_negative(Key key,std::uint64_t now,Reader& reader) -> std::expected<std::optional<Negative>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        for (;;) {
            auto sequence=sequence_.load();
            if (sequence&1) { std::this_thread::yield(); continue; }
            auto generation=visible_generation_.load();
            std::optional<Negative> result;
            (void)reader.visit(key,[&](Indexed const& entry) {
                auto effective=std::max(now,now_.load());
                if (entry.generation==generation && entry.negative && effective<entry.expires &&
                    (entry.expires-effective)/1000) result=entry.negative;
            });
            if (sequence_.load()==sequence && visible_generation_.load()==generation) return result;
        }
    }
    [[nodiscard]] auto lookup_stale(Key key,std::uint64_t now)
        -> std::expected<std::optional<dns::StaleAddressAnswer>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_); auto writer=index_.writer(); now=ordered(now);
        if (sequence_exhausted()) return std::unexpected(Error::generation_exhausted);
        Mutation mutation(sequence_);
        if (auto result=advance(now,writer); !result) return std::unexpected(result.error());
        auto entry=std::ranges::find_if(entries_,[&](auto const& item) { return same(item.key,key); });
        if (entry==entries_.end() || entry->negative || now<entry->expires) return std::optional<dns::StaleAddressAnswer>{};
        auto age=now-entry->expires;
        if (stale_window_ms_-age<1000) return std::optional<dns::StaleAddressAnswer>{};
        auto answer=entry->answer; answer.ttl=1;
        return std::optional<dns::StaleAddressAnswer>{{std::move(answer),age}};
    }
    [[nodiscard]] auto begin_query(Key key) -> std::expected<Token,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_);
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        auto query=next_query_+1;
        pending_.push_back({std::move(key),query,{}}); next_query_=query;
        return Token{generation_,query};
    }
    [[nodiscard]] auto begin_refresh(Key key,std::uint64_t now,std::size_t maximum)
        -> std::expected<std::optional<Token>,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_); auto writer=index_.writer(); now=ordered(now);
        if (sequence_exhausted()) return std::unexpected(Error::generation_exhausted);
        Mutation mutation(sequence_);
        if (auto result=advance(now,writer); !result) return std::unexpected(result.error());
        auto entry=std::ranges::find_if(entries_,[&](auto const& item) { return same(item.key,key); });
        if (entry==entries_.end() || entry->negative || now<entry->expires ||
            stale_window_ms_-(now-entry->expires)<1000) return std::optional<Token>{};
        if (std::ranges::any_of(pending_,[&](auto const& item) { return same(item.key,key); })) return std::optional<Token>{};
        auto refreshes=std::ranges::count_if(pending_,[](auto const& item) { return item.refresh_revision.has_value(); });
        if (static_cast<std::size_t>(refreshes)>=maximum) return std::optional<Token>{};
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        auto query=next_query_+1;
        pending_.push_back({std::move(key),query,entry->revision}); next_query_=query;
        return std::optional<Token>{Token{generation_,query}};
    }
    [[nodiscard]] auto cancel_query(Token token) -> std::expected<void,Error> {
        std::lock_guard lock(mutex_);
        if (token.generation!=generation_) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end()) return std::unexpected(Error::stale_query);
        pending_.erase(pending); return {};
    }
    [[nodiscard]] auto publish(Key key,Answer answer,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        if (!valid_answer(answer,key.type)) return std::unexpected(Error::invalid_answer);
        std::lock_guard lock(mutex_); auto writer=index_.writer(); now=ordered(now);
        if (initialized_ && now<now_.load()) return std::unexpected(Error::time_reversed);
        if (token.generation!=generation_) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(Error::stale_query);
        if (!capacity_) return std::unexpected(Error::disabled);
        auto duration=std::uint64_t(*answer.ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(Error::invalid_answer);
        if (sequence_exhausted()) return std::unexpected(Error::generation_exhausted);
        Mutation mutation(sequence_);
        if (auto result=advance(now,writer); !result) return result;
#ifdef DNS_SEMANTIC_TEST_HOOK
        after_advance_for_test();
#endif
        if (!refresh_current(*pending)) return std::unexpected(Error::stale_query);
        if (!duration) remove(key,writer);
        else install(Entry{key,std::move(answer),{},now+duration,token.query},writer);
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    [[nodiscard]] auto publish_negative(Key key,Negative kind,std::uint32_t ttl,std::uint64_t now,Token token)
        -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_); auto writer=index_.writer(); now=ordered(now);
        if (initialized_ && now<now_.load()) return std::unexpected(Error::time_reversed);
        if (token.generation!=generation_) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(Error::stale_query);
        if (!capacity_) return std::unexpected(Error::disabled);
        auto duration=std::uint64_t(ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(Error::invalid_answer);
        if (sequence_exhausted()) return std::unexpected(Error::generation_exhausted);
        Mutation mutation(sequence_);
        if (auto result=advance(now,writer); !result) return result;
        if (!refresh_current(*pending)) return std::unexpected(Error::stale_query);
        if (!duration) remove(key,writer);
        else install(Entry{key,{},kind,now+duration,token.query},writer);
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    [[nodiscard]] auto invalidate(Key key,std::uint64_t now,Token token) -> std::expected<void,Error> {
        if (!normalize(key)) return std::unexpected(Error::invalid_key);
        std::lock_guard lock(mutex_); auto writer=index_.writer(); now=ordered(now);
        if (initialized_ && now<now_.load()) return std::unexpected(Error::time_reversed);
        if (token.generation!=generation_) return std::unexpected(Error::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(Error::stale_query);
        if (sequence_exhausted()) return std::unexpected(Error::generation_exhausted);
        Mutation mutation(sequence_);
        if (auto result=advance(now,writer); !result) return result;
        if (!refresh_current(*pending)) return std::unexpected(Error::stale_query);
        remove(key,writer);
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<void,Error> {
        std::lock_guard lock(mutex_); auto writer=index_.writer(); now=ordered(now);
        if (initialized_ && now<now_.load()) return std::unexpected(Error::time_reversed);
        if (generation_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(Error::generation_exhausted);
        if (sequence_exhausted()) return std::unexpected(Error::generation_exhausted);
        Mutation mutation(sequence_);
        now_.store(now); initialized_=true; ++generation_;
        visible_generation_.store(generation_);
        for (auto const& entry:entries_) if (!writer.erase(entry.key)) std::terminate();
        entries_.clear(); pending_.clear(); next_query_=0; return {};
    }
};
}
