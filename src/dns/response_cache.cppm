export module dns.response_cache;
import std;
import containers.cache_index;
import dns.message;
import dns.cache;
import dns.response_match;

export namespace dns {
    // Distinct from the address cache: response conditions need original RR
    // sections and negative SOA, not a reconstructed AddressAnswer. `view`
    // must identify the endpoint/transport/EDNS and configuration epoch.
    class ResponseCache {
        struct Pending { CacheKey key; std::uint64_t query; bool sent_edns=false; };
        struct Entry { CacheKey key; Response response; std::uint64_t stored,expires; std::size_t cost=0; bool sent_edns=false; };
        mutable std::mutex mutex_;
        std::vector<Pending> pending_;
        containers::IntrusiveLruTable<Entry> entries_;
        std::size_t capacity_,byte_capacity_,total_bytes_=0;
        std::uint64_t generation_=1,next_=0,last_now_=0;
        static auto same(CacheKey const& a,CacheKey const& b) noexcept -> bool {
            return a.view==b.view && a.type==b.type && a.name==b.name;
        }
        static auto entry_hash(CacheKey const& k,bool sent_edns) noexcept -> std::size_t {
            auto h=detail::SnapshotKeyHash{}(k);
            return h^(std::size_t(sent_edns)*0x9e3779b97f4a7c15ull);
        }
        static auto normalize(CacheKey& key) -> bool {
            return (key.type==1 || key.type==28) && canonicalize_name(key.name) && detail::compact_key_storage(key);
        }
        // Account for retained buffers and record objects, including decoded names.
        static auto bytes(Entry const& entry) noexcept -> std::size_t {
            auto const& response=entry.response;
            auto result=sizeof(Entry)+entry.key.name.capacity()+response.wire.capacity()
                +response.records.capacity()*sizeof(Record);
            for (auto const& record:response.records) {
                result+=record.name.capacity();
                if (record.cname) result+=record.cname->capacity();
            }
            return result;
        }
        auto erase_idx(std::uint32_t idx) noexcept -> void {
            total_bytes_-=entries_.at(idx).cost;
            entries_.erase(idx);
        }
    public:
        static auto lifetime(Response const& response,Question const& question) -> std::optional<std::uint32_t> {
            if (response.rcode!=0 && response.rcode!=3) return {};
            auto name=question.name;if(!canonicalize_name(name))return {};
            bool answer=false;std::optional<std::uint32_t> ttl;
            for (auto const& record:response.records) {
                if (record.type==41) continue;
                ttl=ttl ? std::min(*ttl,record.ttl) : record.ttl;
            }
            std::vector<std::string> visited;
            for (;;) {
                if(visited.size()>=16 || std::ranges::find(visited,name)!=visited.end())return {};
                visited.push_back(name);std::optional<std::string> alias;
                for(auto const& record:response.records) {
                    if(record.section!=Section::answer || record.klass!=question.klass || record.name!=name)continue;
                    if(question.type==255 || record.type==question.type)answer=true;
                    if(record.type==5 && record.cname) {
                        if(alias && *alias!=*record.cname)return {};
                        alias=record.cname;
                    }
                }
                if(answer || !alias)break;
                name=std::move(*alias);
            }
            if (response.rcode==3 || !answer) {
                auto negative=negative_ttl(response,name);
                if (!negative) return {};
                ttl=ttl ? std::min(*ttl,*negative) : *negative;
            }
            if (!ttl || !*ttl) return {};
            return std::min(*ttl,std::uint32_t{600});
        }
        struct Cached { Response response;std::uint64_t expires; };
        explicit ResponseCache(std::size_t capacity,std::size_t byte_capacity=8*1024*1024)
            : capacity_(std::min<std::size_t>(capacity,4096)),byte_capacity_(byte_capacity) {}
        ResponseCache(ResponseCache const&)=delete;
        auto operator=(ResponseCache const&) -> ResponseCache& = delete;
        [[nodiscard]] auto begin(CacheKey key,bool sent_edns=false) -> std::expected<CacheToken,CacheError> {
            if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
            std::lock_guard lock(mutex_);
            if (pending_.size()>=4096) return std::unexpected(CacheError::query_limit);
            if (next_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
            auto next=next_+1;pending_.push_back({std::move(key),next,sent_edns});next_=next;
            return CacheToken{generation_,next};
        }
        auto cancel(CacheToken token) -> std::expected<void,CacheError> {
            std::lock_guard lock(mutex_);
            if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
            auto it=std::ranges::find(pending_,token.query,&Pending::query);
            if (it==pending_.end()) return std::unexpected(CacheError::stale_query);
            pending_.erase(it);return {};
        }
        auto publish(CacheKey key,Response const& source,std::uint64_t now,CacheToken token) -> std::expected<void,CacheError> {
            if (!normalize(key) || source.wire.size()<2) return std::unexpected(CacheError::invalid_key);
            auto id=static_cast<std::uint16_t>((std::uint16_t(source.wire[0])<<8)|source.wire[1]);
            auto response=parse_response(source.wire,id,{key.name,key.type});
            if (!response) return std::unexpected(CacheError::invalid_answer);
            auto ttl=lifetime(*response,{key.name,key.type});
            std::lock_guard lock(mutex_);
            if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
            auto it=std::ranges::find(pending_,token.query,&Pending::query);
            if (it==pending_.end() || !same(it->key,key)) return std::unexpected(CacheError::stale_query);
            now=std::max(now,last_now_);last_now_=now;
            if (!capacity_) return std::unexpected(CacheError::disabled);
            if (ttl && *ttl>(std::numeric_limits<std::uint64_t>::max()-now)/1000) return std::unexpected(CacheError::invalid_answer);
            auto sent_edns=it->sent_edns;
            auto h=entry_hash(key,sent_edns);
            auto existing=entries_.find(h,[&](Entry const& entry){return same(entry.key,key) && entry.sent_edns==sent_edns;});
            if (!ttl) { if (existing) erase_idx(*existing); }
            else {
                Entry replacement{key,std::move(*response),now,now+std::uint64_t(*ttl)*1000,0,sent_edns};
                replacement.cost=bytes(replacement);
                if (existing) erase_idx(*existing);
                if (replacement.cost<=byte_capacity_) {
                    while (!entries_.empty() && (entries_.size()>=capacity_ || total_bytes_>byte_capacity_-replacement.cost)) {
                        erase_idx(*entries_.lru());
                    }
                    total_bytes_+=replacement.cost;
                    (void)entries_.insert_front(h,std::move(replacement));
                }
            }
            std::erase_if(pending_,[&](Pending const& p){return p.query<=token.query && p.sent_edns==sent_edns && same(p.key,key);});
            return {};
        }
        auto lookup_entry(CacheKey key,std::uint64_t now,std::uint16_t id,bool sent_edns=false) -> std::expected<std::optional<Cached>,CacheError> {
            if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
            auto h=entry_hash(key,sent_edns);
            std::lock_guard lock(mutex_);now=std::max(now,last_now_);last_now_=now;
            auto found=entries_.find(h,[&](Entry const& entry){return same(entry.key,key) && entry.sent_edns==sent_edns;});
            if (!found) return std::optional<Cached>{};
            if (now>=entries_.at(*found).expires) { erase_idx(*found);return std::optional<Cached>{}; }
            entries_.promote(*found);
            auto const& entry=entries_.at(*found);
            auto result=entry.response;
            auto elapsed=(now-entry.stored+999)/1000;
            auto remaining=static_cast<std::uint32_t>((entry.expires-now)/1000);
            if (!age_response(result,elapsed,id,remaining)) return std::unexpected(CacheError::invalid_answer);
            return std::optional<Cached>{Cached{std::move(result),entry.expires}};
        }
        auto lookup(CacheKey key,std::uint64_t now,std::uint16_t id,bool sent_edns=false) -> std::expected<std::optional<Response>,CacheError> {
            auto cached=lookup_entry(std::move(key),now,id,sent_edns);
            if (!cached) return std::unexpected(cached.error());
            if (!*cached) return std::optional<Response>{};
            return std::optional<Response>{std::move((**cached).response)};
        }
        // Publication and slow waiters may consume time after the upstream
        // returned. Never restart the response's TTL at publication time.
        auto publish_from(CacheKey key,Response const& response,std::uint64_t received,std::uint64_t now,CacheToken token)
            -> std::expected<void,CacheError> {
            if (now<received) return std::unexpected(CacheError::time_reversed);
            auto copy=response;
            if (copy.wire.size()<2) return std::unexpected(CacheError::invalid_answer);
            auto id=static_cast<std::uint16_t>((std::uint16_t(copy.wire[0])<<8)|copy.wire[1]);
            auto elapsed=(now-received)/1000+bool((now-received)%1000);
            if (!age_response(copy,elapsed,id)) return std::unexpected(CacheError::invalid_answer);
            return publish(std::move(key),copy,now,token);
        }
        auto clear() -> std::expected<void,CacheError> {
            std::lock_guard lock(mutex_);
            if (generation_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
            ++generation_;pending_.clear();entries_.clear();total_bytes_=0;return {};
        }
    };
}
