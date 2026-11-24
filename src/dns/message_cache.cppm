export module dns.message_cache;
import std;
import functional;
import containers.cache_index;
import dns.message;
import dns.input_budget;
import dns.corosio_resolver;
import capy;
import dns.response_cache;
import dns.response_match;
import dns.local_config;
import corosio;

export namespace dns {
    // Executor-owned. The encoded query includes flags, class, case, EDNS
    // payload and DO; only its transaction ID is removed from the key.
    class MessageCache : public std::enable_shared_from_this<MessageCache> {
        using Clock=std::chrono::steady_clock;
    public:
        struct View {
            std::size_t upstream;std::array<std::uint8_t,16> address{};
            std::uint64_t policy_view;
            std::uint32_t scope=0;
            std::uint16_t port;bool ipv6,tcp,local;
            std::weak_ptr<LocalSnapshot const> snapshot;
            View(std::size_t index,corosio::endpoint endpoint,bool use_tcp,
                std::shared_ptr<LocalSnapshot const> const& source,std::uint64_t generation=0,std::uint32_t cache_scope=0)
                :upstream(index),policy_view(generation),scope(cache_scope),port(endpoint.port()),ipv6(endpoint.address().is_v6()),tcp(use_tcp),local(bool(source)),snapshot(source) {
                if(ipv6)address=endpoint.address().to_v6().to_bytes();
                else {auto bytes=endpoint.address().to_v4().to_bytes();std::ranges::copy(bytes,address.begin());}
            }
            auto matches(View const& other) const noexcept -> bool {
                return upstream==other.upstream && policy_view==other.policy_view && scope==other.scope &&
                    address==other.address && port==other.port && ipv6==other.ipv6 && tcp==other.tcp && local==other.local &&
                    (!local || (!snapshot.expired() && !other.snapshot.expired() &&
                        !snapshot.owner_before(other.snapshot) && !other.snapshot.owner_before(snapshot)));
            }
        };
        struct Ticket { std::uint64_t sequence; };

        class QueryFlight {
        public:
            using Result=std::expected<Bytes,detail::ResolveError>;
            Ticket ticket{};
            Clock::time_point deadline;
            capy::async_event changed;
            std::stop_source stop;
            std::optional<InputBudget::Lease> retained;
            std::optional<Result> result;
            std::size_t waiters=0;
            bool published=false;

            explicit QueryFlight(Clock::time_point until):deadline(until) {}

            auto complete(Result response) -> void {
                if (response) {
                    auto lease=default_upstream_receive_budget().acquire(response->capacity());
                    if (lease) retained.emplace(std::move(*lease));
                    else response=std::unexpected(detail::ResolveError::budget_exhausted);
                }
                result.emplace(std::move(response));
                changed.set();
            }
        };

        struct JoinedQuery { std::shared_ptr<QueryFlight> flight;bool launch; };

    private:
        struct Key { View view;Bytes query; };
        struct Entry { Key key;Response response;Clock::time_point stored,expires,refresh_after{};std::size_t cost=0; };
        struct Pending { Key key;std::uint64_t sequence;std::weak_ptr<QueryFlight> flight; };
        containers::IntrusiveLruTable<Entry> entries_;
        std::vector<Pending> pending_;
        std::uint64_t sequence_=0;
        std::size_t bytes_=0;
        std::size_t capacity_=1024;
        std::chrono::seconds stale_window_;
        std::stop_source refresh_stop_;

        auto stale_until(Entry const& entry) const noexcept -> Clock::time_point {
            return entry.expires+stale_window_;
        }
        static auto same(Key const& a,Key const& b) noexcept -> bool {
            return a.view.matches(b.view) && a.query==b.query;
        }
        static auto hash_key(Key const& k) noexcept -> std::size_t {
            std::size_t h=14695981039346656037ull;
            auto mix=[&](std::uint64_t v) noexcept { h^=v; h*=1099511628211ull; };
            mix(k.view.upstream);
            mix(k.view.policy_view);
            mix(k.view.scope);
            mix((std::uint64_t(k.view.port)<<3) | (std::uint64_t(k.view.ipv6)<<2) | (std::uint64_t(k.view.tcp)<<1) | std::uint64_t(k.view.local));
            for (auto b : k.view.address) mix(b);
            for (auto b : k.query) mix(b);
            return h;
        }
        static auto size(Entry const& entry) noexcept -> std::size_t {
            auto const& r=entry.response;
            auto result=sizeof(Entry)+entry.key.query.capacity()+r.wire.capacity()+r.records.capacity()*sizeof(Record);
            for(auto const& record:r.records) {result+=record.name.capacity();if(record.cname)result+=record.cname->capacity();}
            return result;
        }
        static auto key(View view,QueryMessage const& query) -> std::optional<Key> {
            // ECS is keyed by its exact source prefix; transaction-specific
            // options (e.g. COOKIE) are not reusable.
            if(query.edns && !query.edns->options.empty() &&
                (query.edns->options.size()!=1 || query.edns->options[0].code!=8 || !query_client_subnet(*query.edns)))return {};
            auto wire=encode_query(query);if(!wire)return {};
            (*wire)[0]=0;(*wire)[1]=0;
            return Key{std::move(view),std::move(*wire)};
        }
        auto erase_idx(std::uint32_t idx) noexcept -> void { bytes_-=entries_.at(idx).cost; entries_.erase(idx); }
    public:
        struct StaleReply { Bytes wire;std::optional<Ticket> refresh; };

        explicit MessageCache(std::chrono::seconds stale_window={},std::size_t capacity=1024)
            :capacity_(std::clamp<std::size_t>(capacity,1,4096)),
             stale_window_(std::clamp(stale_window,std::chrono::seconds::zero(),std::chrono::seconds(3600))),
             refresh_stop_(stale_window_.count()>0 ? std::stop_source{} : std::stop_source{std::nostopstate}) {}
        auto optimistic() const noexcept -> bool {return stale_window_.count()>0 && !refresh_stop_.stop_requested();}
        [[nodiscard]] auto entry_count() const noexcept -> std::size_t { return entries_.size(); }
        auto clear_entries() noexcept -> void { while (auto idx = entries_.lru()) erase_idx(*idx); }
        auto refresh_token() const noexcept -> std::stop_token {return refresh_stop_.get_token();}
        auto stop_refreshes() noexcept -> void {refresh_stop_.request_stop();}
        struct SavedAnswer {
            View view;
            Bytes query;
            Bytes response;
            std::uint32_t remaining;
        };

        auto checkpoint(this MessageCache const& self,std::span<View const> views,Clock::time_point now,
            std::size_t bytes_left) -> std::vector<SavedAnswer> {
            return self.checkpoint(now,bytes_left,8,[&](View const& view) {
                return view.upstream<views.size() && view.matches(views[view.upstream]);
            });
        }

        auto checkpoint(this MessageCache const& self,Clock::time_point now,std::size_t bytes_left,
            std::size_t overhead,functional::function_ref<bool(View const&)> include) -> std::vector<SavedAnswer> {
            std::vector<SavedAnswer> result;
            self.entries_.for_each([&](Entry const& entry) {
                if (!include(entry.key.view) || now>=entry.expires) return;
                auto cost=overhead+entry.key.query.size()+entry.response.wire.size();
                if (cost>bytes_left) return;
                auto remaining=std::chrono::duration_cast<std::chrono::seconds>(entry.expires-now);
                if (remaining.count()<=0) return;
                auto elapsed=std::chrono::ceil<std::chrono::seconds>(now-entry.stored);
                auto wire=entry.response.wire;
                auto ttl=static_cast<std::uint32_t>(remaining.count());
                if (age_response_wire(entry.response,wire,static_cast<std::uint64_t>(elapsed.count()),0,ttl)) {
                    result.push_back({entry.key.view,entry.key.query,std::move(wire),ttl});
                    bytes_left-=cost;
                }
            });
            return result;
        }

        auto restore(this MessageCache& self,View const& view,std::span<std::uint8_t const> question,
            Bytes answer,std::uint32_t remaining,std::uint32_t elapsed,Clock::time_point now) -> bool {
            auto query=parse_query(question);
            if (!query || query->id) return false;
            auto parsed=parse_owned_response(std::move(answer),0,query->question);
            if (!parsed || !validate_response_ecs(*query,*parsed)) return false;
            if (elapsed>=remaining) return true;
            auto wire=parsed->wire;
            if (!age_response_wire(*parsed,wire,elapsed,0,remaining-elapsed)) return false;
            parsed=parse_owned_response(std::move(wire),0,query->question);
            if (!parsed) return false;
            auto ticket=self.begin(view,*query);
            if (!ticket) return false;
            self.publish(*ticket,*query,std::move(*parsed),now);
            return true;
        }
        auto clear() noexcept -> void {entries_.clear();pending_.clear();bytes_=0;}
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        [[nodiscard]] auto lookup(View const& view,QueryMessage const& query,Clock::time_point now) -> std::optional<Bytes> {
            auto k=key(view,query);if(!k)return {};
            auto idx=entries_.find(hash_key(*k),[&](Entry const& entry){return same(entry.key,*k);});
            if(!idx)return {};
            if(now>=entries_.at(*idx).expires) {
                if (now>=stale_until(entries_.at(*idx))) erase_idx(*idx);
                return {};
            }
            entries_.promote(*idx);
            auto const& entry=entries_.at(*idx);
            auto wire=entry.response.wire;
            auto elapsed=std::chrono::ceil<std::chrono::seconds>(now-entry.stored).count();
            auto remaining=std::chrono::duration_cast<std::chrono::seconds>(entry.expires-now).count();
            if(!age_response_wire(entry.response,wire,static_cast<std::uint64_t>(std::max<std::int64_t>(elapsed,0)),query.id,
                static_cast<std::uint32_t>(std::max<std::int64_t>(remaining,0))))return {};
            return wire;
        }
        [[nodiscard]] auto lookup_stale(View const& view,QueryMessage const& query,Clock::time_point now)
            -> std::optional<StaleReply> {
            if (!optimistic() || !(query.flags&0x0100) || (query.edns && query.edns->dnssec_ok)) return {};
            auto k=key(view,query);
            if (!k) return {};
            auto idx=entries_.find(hash_key(*k),[&](Entry const& item) {return same(item.key,*k);});
            if (!idx) return {};
            auto& entry=entries_.at(*idx);
            if (now<entry.expires || entry.response.rcode) return {};
            auto remaining=std::chrono::duration_cast<std::chrono::seconds>(stale_until(entry)-now).count();
            if (remaining<1 || !std::ranges::any_of(entry.response.records,[&](auto const& record) {
                return record.section==Section::answer && record.type==query.question.type && record.klass==query.question.klass;
            })) return {};
            auto ttl=static_cast<std::uint32_t>(std::min<std::int64_t>(remaining,30));
            auto elapsed=static_cast<std::uint64_t>(std::chrono::ceil<std::chrono::seconds>(now-entry.stored).count());
            auto wire=entry.response.wire;
            if (!age_response_wire(entry.response,wire,elapsed,query.id,ttl)) return {};
            wire[3]&=static_cast<std::uint8_t>(~authenticated_data_flag);
            for (auto const& record : entry.response.records) {
                if (record.type!=41 && record.ttl && record.ttl<=elapsed)
                    wire[record.data_offset-3]=static_cast<std::uint8_t>(ttl);
            }
            std::optional<Ticket> refresh;
            if (now>=entry.refresh_after && !std::ranges::any_of(pending_,[&](auto const& item) {return same(item.key,*k);})) {
                refresh=begin(view,query);
                if (refresh) entry.refresh_after=now+std::chrono::seconds(1);
            }
            return StaleReply{std::move(wire),refresh};
        }

        [[nodiscard]] auto join(View const& view,QueryMessage const& query,Clock::time_point deadline)
            -> std::expected<std::optional<JoinedQuery>,detail::ResolveError> {
            auto k=key(view,query);
            if (!k) return std::optional<JoinedQuery>{};
            auto pending=std::ranges::find_if(pending_,[&](auto const& slot) {return same(slot.key,*k);});
            if (pending!=pending_.end()) {
                auto existing=pending->flight.lock();
                if (existing && !existing->result && existing->deadline>Clock::now() && !existing->stop.stop_requested()) {
                    if (existing->waiters>=64) return std::unexpected(detail::ResolveError::limit);
                    return JoinedQuery{std::move(existing),false};
                }
            }
            if (sequence_==std::numeric_limits<std::uint64_t>::max() || (pending==pending_.end() && pending_.size()>=256))
                return std::unexpected(detail::ResolveError::limit);
            auto flight=std::make_shared<QueryFlight>(deadline);
            flight->ticket=Ticket{++sequence_};
            if (pending==pending_.end()) pending_.push_back({std::move(*k),sequence_,flight});
            else {
                pending->sequence=sequence_;
                pending->flight=flight;
            }
            return JoinedQuery{std::move(flight),true};
        }

        [[nodiscard]] auto begin(View const& view,QueryMessage const& query) -> std::optional<Ticket> {
            auto k=key(view,query);if(!k || sequence_==std::numeric_limits<std::uint64_t>::max())return {};
            auto it=std::ranges::find_if(pending_,[&](auto const& pending){return same(pending.key,*k);});
            if(it==pending_.end() && pending_.size()>=256)return {};
            auto sequence=++sequence_;
            if(it==pending_.end()) pending_.push_back({std::move(*k),sequence,{}});
            else {it->sequence=sequence;it->flight.reset();}
            return Ticket{sequence};
        }
        auto cancel(Ticket const& ticket) noexcept -> void {
            std::erase_if(pending_,[&](auto const& pending){return pending.sequence==ticket.sequence;});
        }
        auto publish(Ticket const& ticket,QueryMessage const& query,Response response,Clock::time_point now) -> void {
            auto pending=std::ranges::find(pending_,ticket.sequence,&Pending::sequence);
            if(pending==pending_.end())return;
            Key k=std::move(pending->key);pending_.erase(pending);
            if(response.flags&0x0200 || !validate_response_ecs(query,response))return;
            bool ecs=query.edns && query.edns->options.size()==1 && query.edns->options[0].code==8;
            if(ecs) {
                if(!response.edns || response.edns->option_count!=1)return;
                auto opt=std::ranges::find(response.records,std::uint16_t{41},&Record::type);
                if(opt==response.records.end() || opt->data_length<4 || opt->data_offset>response.wire.size() ||
                    opt->data_length>response.wire.size()-opt->data_offset || response.wire[opt->data_offset]!=0 || response.wire[opt->data_offset+1]!=8)return;
            } else if(response.edns && response.edns->option_count)return;
            auto ttl=ResponseCache::lifetime(response,query.question);
            auto h=hash_key(k);
            if(auto old=entries_.find(h,[&](Entry const& value){return same(value.key,k);})) erase_idx(*old);
            if(!ttl)return;
            Entry entry{std::move(k),std::move(response),now,now+std::chrono::seconds(*ttl)};
            entry.cost=size(entry);
            if(entry.cost>8*1024*1024)return;
            while(!entries_.empty() && (entries_.size()>=capacity_ || bytes_>8*1024*1024-entry.cost)) {
                erase_idx(*entries_.lru());
            }
            bytes_+=entry.cost;
            (void)entries_.insert_front(h,std::move(entry));
        }
    };
}
