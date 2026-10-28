module nexus.dns.cache;
import std;
import nexus.dns.message;

namespace nexus::dns {
    namespace {
        auto normalize(CacheKey& key) -> bool {
            if (key.type!=1 && key.type!=28) return false;
            auto wire=make_query(0,{key.name,key.type});
            if (!wire) return false;
            std::string name;
            for (std::size_t pos=12; (*wire)[pos];) {
                auto length=(*wire)[pos++];
                if (!name.empty()) name+='.';
                name.append(reinterpret_cast<char const*>(wire->data()+pos),length);
                pos+=length;
            }
            key.name=name.empty() ? "." : std::move(name);
            return true;
        }
        auto same(CacheKey const& a, CacheKey const& b) -> bool {
            return a.view==b.view && a.type==b.type && a.name==b.name;
        }
        auto valid_answer(AddressAnswer const& answer, std::uint16_t type) -> bool {
            if (answer.addresses.empty() || answer.addresses.size()>128 || answer.chain.size()>16 ||
                answer.canonical_name.size()>254 || !answer.ttl) return false;
            for (auto const& name : answer.chain) if (name.size()>254) return false;
            for (auto const& address : answer.addresses) if (address.size!=(type==1 ? 4 : 16)) return false;
            return true;
        }
    }
    auto AddressCache::advance(std::uint64_t now) -> std::expected<void,CacheError> {
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        now_=now; initialized_=true;
        std::erase_if(entries_,[now](Entry const& entry) { return entry.expires<=now; });
        return {};
    }
    auto AddressCache::lookup(CacheKey key, std::uint64_t now)
        -> std::expected<std::optional<AddressAnswer>,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (auto result=advance(now); !result) return std::unexpected(result.error());
        auto entry=std::ranges::find_if(entries_,[&](auto const& item) { return same(item.key,key); });
        if (entry==entries_.end()) return std::optional<AddressAnswer>{};
        auto remaining=(entry->expires-now)/1000;
        if (!remaining) { entries_.erase(entry); return std::optional<AddressAnswer>{}; }
        if (entry->negative) return std::optional<AddressAnswer>{};
        auto answer=entry->answer;
        answer.ttl=static_cast<std::uint32_t>(remaining);
        return std::optional<AddressAnswer>(std::move(answer));
    }
    auto AddressCache::lookup_negative(CacheKey key, std::uint64_t now)
        -> std::expected<std::optional<NegativeKind>,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (auto result=advance(now); !result) return std::unexpected(result.error());
        auto entry=std::ranges::find_if(entries_,[&](auto const& item) { return same(item.key,key); });
        if (entry==entries_.end()) return std::optional<NegativeKind>{};
        if ((entry->expires-now)/1000==0) { entries_.erase(entry); return std::optional<NegativeKind>{}; }
        return entry->negative;
    }
    auto AddressCache::begin_query(CacheKey key) -> std::expected<CacheToken,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (pending_.size()==4096) return std::unexpected(CacheError::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
        auto query=next_query_+1;
        pending_.push_back({std::move(key),query});
        next_query_=query;
        return CacheToken{generation_,query};
    }
    auto AddressCache::cancel_query(CacheToken token) -> std::expected<void,CacheError> {
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end()) return std::unexpected(CacheError::stale_query);
        pending_.erase(pending);
        return {};
    }
    auto AddressCache::publish(CacheKey key, AddressAnswer answer, std::uint64_t now, CacheToken token)
        -> std::expected<void,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (!valid_answer(answer,key.type)) return std::unexpected(CacheError::invalid_answer);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(CacheError::stale_query);
        if (!capacity_) return std::unexpected(CacheError::disabled);
        auto duration=std::uint64_t(*answer.ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(CacheError::invalid_answer);
        if (auto result=advance(now); !result) return result;
        auto existing=std::ranges::find_if(entries_,[&](auto const& entry) { return same(entry.key,key); });
        // Keep key intact until pending queries are invalidated.
        if (duration==0) {
            if (existing!=entries_.end()) entries_.erase(existing);
        } else {
            Entry replacement{key,std::move(answer),{},now+duration};
            if (existing!=entries_.end()) *existing=std::move(replacement);
            else if (entries_.size()==capacity_) {
                auto earliest=std::ranges::min_element(entries_,{},&Entry::expires);
                *earliest=std::move(replacement);
            } else entries_.push_back(std::move(replacement));
        }
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    auto AddressCache::publish_negative(CacheKey key, NegativeKind kind, std::uint32_t ttl,
                                        std::uint64_t now, CacheToken token) -> std::expected<void,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(CacheError::stale_query);
        if (!capacity_) return std::unexpected(CacheError::disabled);
        auto duration=std::uint64_t(ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(CacheError::invalid_answer);
        if (auto result=advance(now); !result) return result;
        auto existing=std::ranges::find_if(entries_,[&](auto const& entry) { return same(entry.key,key); });
        if (!duration) {
            if (existing!=entries_.end()) entries_.erase(existing);
        } else {
            Entry replacement{key,{},kind,now+duration};
            if (existing!=entries_.end()) *existing=std::move(replacement);
            else if (entries_.size()==capacity_) *std::ranges::min_element(entries_,{},&Entry::expires)=std::move(replacement);
            else entries_.push_back(std::move(replacement));
        }
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    auto AddressCache::invalidate(CacheKey key, std::uint64_t now, CacheToken token)
        -> std::expected<void,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || !same(pending->key,key)) return std::unexpected(CacheError::stale_query);
        if (auto result=advance(now); !result) return result;
        std::erase_if(entries_,[&](Entry const& entry) { return same(entry.key,key); });
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        return {};
    }
    auto AddressCache::clear(std::uint64_t now) -> std::expected<void,CacheError> {
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (generation_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
        now_=now; initialized_=true; ++generation_; next_query_=0; entries_.clear(); pending_.clear(); return {};
    }
}
