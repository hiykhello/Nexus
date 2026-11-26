export module packet.tun_default_policy;
import std;
import containers.inplace_vector;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.netlink_watch;
import platform.routing_rule;
import platform.socket_options;
import platform.ipv4_reverse_path;
import packet.tun_network;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_requests;
import packet.tun_network_view;

export namespace packet {
    namespace tun_policy_detail {
        namespace a=platform::netlink_abi;
        namespace n=platform::netlink;
        namespace r=platform::routing;
        namespace t=tun_network_detail;
        using Clock=std::chrono::steady_clock;
        inline constexpr std::uint8_t kRtnThrow=8;
        inline constexpr std::size_t kInlineRuleExcludeCap=64;
        template<class Record> struct Entry {Record value;bool attempted=false,owned=false;};
        template<class T,std::size_t InlineN> class SmallList {
            containers::inplace_vector<T,InlineN> head_;
            std::vector<T> tail_;
        public:
            [[nodiscard]] auto size() const noexcept -> std::size_t { return head_.size()+tail_.size(); }
            auto push_back(T value) -> void { if (head_.size()<InlineN) head_.push_back(std::move(value)); else tail_.push_back(std::move(value)); }
            auto sort_head(auto&& cmp) -> void { if (tail_.empty()) std::ranges::sort(head_,cmp); }
            auto for_each(auto&& fn) -> void { for (auto& v:head_) fn(v); for (auto& v:tail_) fn(v); }
            auto for_each(auto&& fn) const -> void { for (auto const& v:head_) fn(v); for (auto const& v:tail_) fn(v); }
            auto for_each_reverse(auto&& fn) -> void {
                for (auto it=tail_.rbegin();it!=tail_.rend();++it) fn(*it);
                for (auto it=head_.rbegin();it!=head_.rend();++it) fn(*it);
            }
            auto any_of(auto&& pred) const -> bool { return std::ranges::any_of(head_,pred) || std::ranges::any_of(tail_,pred); }
            auto erase_if(auto&& pred) -> void {
                std::size_t w=0;
                for (std::size_t i=0;i<head_.size();++i) if (!pred(head_[i])) { if (w!=i) head_[w]=std::move(head_[i]); ++w; }
                while (head_.size()>w) head_.pop_back();
                std::erase_if(tail_,pred);
            }
        };
        struct AddrHash {
            auto operator()(TunAddress const& v) const noexcept -> std::size_t {
                std::size_t h=(std::size_t(v.family)<<8)^v.prefix;
                for (auto b:v.bytes) h=(h^b)*1099511628211ull;
                return h;
            }
        };
        struct RouteKey { TunAddress destination{}; std::uint32_t table=0,priority=0,index=0; auto operator==(RouteKey const&) const -> bool = default; };
        struct RouteKeyHash { auto operator()(RouteKey const& k) const noexcept -> std::size_t { return AddrHash{}(k.destination)^(std::size_t(k.table)*2654435761ull)^(std::size_t(k.priority)<<16)^k.index; } };
        inline auto route_key(t::GatewayRouteRecord const& v) noexcept -> RouteKey { return {v.destination,v.table,v.priority,v.index}; }
        inline auto same_key(t::GatewayRouteRecord const& l,t::GatewayRouteRecord const& r) noexcept -> bool { return route_key(l)==route_key(r); }
        inline auto same_key(r::Rule const& l,r::Rule const& r) noexcept -> bool {return r::same_selector(l,r);}
        inline auto valid_ifname(std::array<char,16> const& name) noexcept -> bool {
            auto nul=std::ranges::find(name,'\0');
            return name[0]!='\0' && nul!=name.end() && std::ranges::all_of(std::span(name).subspan(static_cast<std::size_t>(nul-name.begin())),[](char c){return c=='\0';});
        }
        inline auto valid_policy_prefix(TunAddress const& p,bool allow_default) noexcept -> bool {
            if (allow_default && !p.prefix) return (p.family==4 || p.family==6) && std::ranges::all_of(p.bytes,[](auto b){return b==0;});
            return p.prefix && t::valid(p,true);
        }
    }
    inline constexpr std::size_t max_tun_excludes=65536;

    struct TunDefaultOptions {
        std::uint32_t capture_table=60000,bypass_table=60001,priority=10000,mark=0x6e780001;
        std::optional<platform::RoutingMarkFilter> include_mark, exclude_mark;
        std::uint32_t route_table=60002;
        bool dynamic_route_table=false;
    };
    enum class TunPolicyError { configuration,state,conflict,unsupported,netlink,ownership,readback,drift };
    struct TunPolicyFailure { TunPolicyError code; std::optional<platform::netlink::Failure> netlink; };
    struct TunPolicyCleanup {std::size_t removed=0,preserved=0,uncertain=0,settings_restored=0,settings_preserved=0;bool descriptors_closed=false;};
    template<class Hooks=platform::netlink::NoHooks> class TunDefaultPolicy {
        using Clock=tun_policy_detail::Clock;
        using Route=tun_network_detail::GatewayRouteRecord;
        using Rule=platform::routing::Rule;
        using Socket=platform::netlink::Socket<Hooks>;
        template<class Record> using Entry=tun_policy_detail::Entry<Record>;
        TunDefaultOptions options_;
        Socket socket_;
        platform::netlink::Watch watch_;
        platform::routing::IPv4ReversePathLease reverse_;
        tun_policy_detail::SmallList<Entry<Route>,66> routes_;
        tun_policy_detail::SmallList<Entry<Rule>,160> rules_;
        containers::inplace_vector<TunAddress,32> local_destinations_;
        std::array<bool,2> enabled_{};
        std::array<std::optional<std::array<std::uint8_t,16>>,2> tun_source_{};
        std::uint32_t capture_priority_=0,last_priority_=0;
        std::int32_t index_=0;
        bool starting_=false,started_=false,stopped_=false,drift_=false,uncertain_=false,watch_local_=false,use_route_table_=false;
        struct Pending {std::uint16_t type=0;std::uint32_t sequence=0;bool seen=false;};
        Pending pending_;
        TunPolicyCleanup cleanup_;
        static auto fail(TunPolicyError code) -> std::unexpected<TunPolicyFailure> {return std::unexpected(TunPolicyFailure{code,{}});}
        static auto failure(platform::netlink::Failure value) -> std::unexpected<TunPolicyFailure> {return std::unexpected(TunPolicyFailure{TunPolicyError::netlink,value});}
        auto invalidate() noexcept -> void {
            uncertain_=drift_=true;reverse_.invalidate();
            rules_.for_each([](auto& v){v.owned=false;});
            routes_.for_each([](auto& v){v.owned=false;});
        }
        template<class Record,class Entries>
        auto event(platform::netlink::Message message,Record const& value,Entries& entries) -> void {
            namespace d=tun_policy_detail;
            bool ours=message.header.nlmsg_pid==socket_.port_id() && message.header.nlmsg_seq==pending_.sequence && message.header.nlmsg_type==pending_.type;
            entries.for_each([&](auto& entry){
                if(d::same_key(entry.value,value)) {
                    if(ours && entry.value==value && !pending_.seen) {
                        pending_.seen=true;
                        entry.owned=message.header.nlmsg_type==d::a::RTM_NEWRULE || message.header.nlmsg_type==d::a::RTM_NEWROUTE;
                    } else {entry.owned=false;drift_=true;}
                }
            });
        }
        auto owns_table(std::uint32_t tbl) const noexcept -> bool {
            return tbl==options_.capture_table || tbl==options_.bypass_table || (use_route_table_ && tbl==options_.route_table);
        }
        auto observe() -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            auto drained=watch_.drain(socket_.receive_buffer(),[&](d::n::Message message)->std::expected<void,d::n::Failure> {
                auto copy=message;
                if(message.header.nlmsg_type==d::a::RTM_NEWRULE || message.header.nlmsg_type==d::a::RTM_DELRULE) {
                    copy.header.nlmsg_type=d::a::RTM_NEWRULE;
                    auto parsed=d::r::parse_rule(copy);if(!parsed)return std::unexpected(parsed.error());
                    event(message,*parsed,rules_);
                    if(message.header.nlmsg_pid!=socket_.port_id() &&
                       (parsed->priority<=last_priority_ || (parsed->mask && ((parsed->mark^options_.mark)&parsed->mask)==0) || owns_table(parsed->table)))drift_=true;
                } else if(message.header.nlmsg_type==d::a::RTM_NEWROUTE || message.header.nlmsg_type==d::a::RTM_DELROUTE) {
                    copy.header.nlmsg_type=d::a::RTM_NEWROUTE;
                    auto parsed=d::t::parse_route<Route>(copy);if(!parsed)return std::unexpected(parsed.error());
                    event(message,*parsed,routes_);
                    if(parsed->table==d::a::RT_TABLE_MAIN)drift_=true;
                    if(watch_local_ && parsed->table==d::a::RT_TABLE_LOCAL && parsed->type==d::a::RTN_LOCAL)drift_=true;
                    if(message.header.nlmsg_pid!=socket_.port_id() && owns_table(parsed->table))drift_=true;
                } else if(message.header.nlmsg_type==d::a::RTM_NEWNETCONF || message.header.nlmsg_type==d::a::RTM_DELNETCONF) {
                    auto observed=reverse_.observe(message);if(!observed)return observed;
                    drift_|=reverse_.drifted();
                } else if(message.header.nlmsg_type==d::a::RTM_NEWLINK || message.header.nlmsg_type==d::a::RTM_DELLINK) {
                    copy.header.nlmsg_type=d::a::RTM_NEWLINK;
                    auto parsed=d::t::parse_link(copy);if(!parsed)return std::unexpected(parsed.error());
                    if(parsed->index==index_ || routes_.any_of([&](auto const& route){return route.value.index==std::uint32_t(parsed->index);})) {
                        drift_=true;reverse_.changed_link(parsed->index);
                    }
                } else return d::n::fail(d::n::Error::protocol);
                return {};
            });
            if(!drained){invalidate();return failure(drained.error());}
            return {};
        }
        auto synchronize() -> std::expected<void,platform::netlink::Failure> {
            auto result=observe();if(!result)return std::unexpected(result.error().netlink.value_or(platform::netlink::Failure{platform::netlink::Error::uncertain,{}}));return {};
        }
        auto same_link(std::int32_t index,std::array<char,16> name,Clock::time_point deadline) -> bool {
            auto link=tun_network_detail::View(socket_,index,deadline).link();
            return link && *link && (**link).name==name && ((**link).flags&platform::netlink_abi::IFF_UP);
        }
        template<class Visitor> auto rules(std::uint8_t family,Clock::time_point deadline,Visitor&& visitor) -> std::expected<void,platform::netlink::Failure> {
            namespace d=tun_policy_detail;
            return socket_.dump(d::a::RTM_GETRULE,d::t::native_family(family),deadline,[&](d::n::Message message)->std::expected<void,d::n::Failure> {
                auto parsed=d::r::parse_rule(message);if(!parsed)return std::unexpected(parsed.error());return visitor(*parsed);
            });
        }
        template<class Record> auto count(Record const& desired,Clock::time_point deadline) -> std::expected<std::size_t,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            std::size_t found=0;bool exact=true;
            auto visit=[&](Record const& value)->std::expected<void,d::n::Failure> {
                if(d::same_key(value,desired)){++found;exact&=value==desired;}return {};
            };
            std::expected<void,d::n::Failure> scanned;
            if constexpr(std::same_as<Record,Rule>)scanned=rules(desired.family,deadline,visit);
            else scanned=d::t::View(socket_,index_,deadline).template routes<Route>(desired.destination.family,visit);
            if(!scanned)return failure(scanned.error());
            if(!exact)return fail(TunPolicyError::ownership);
            return found;
        }
        template<class Record> auto request(Record const& value,bool add) -> platform::netlink::Request {
            if constexpr(std::same_as<Record,Rule>)return platform::routing::rule_request(value,add);
            else {
                if(add && value.destination.family==6 && routes_.any_of([&](auto const& entry){
                    return entry.owned && entry.value.destination==value.destination && entry.value.table==value.table && entry.value.priority==value.priority;
                }))return tun_network_detail::route_record_request<false>(value,add);
                return tun_network_detail::route_record_request(value,add);
            }
        }
        template<class Record> auto mutate(Entry<Record>& entry,bool add,Clock::time_point deadline) -> std::expected<void,TunPolicyFailure> {
            auto obs=observe(); if(!obs)return obs;
            if((add && drift_) || (!add && !entry.owned))return fail(TunPolicyError::ownership);
            auto before=count(entry.value,deadline); if(!before)return std::unexpected(before.error());
            if(*before!=(add?0u:1u))return fail(TunPolicyError::conflict);
            obs=observe(); if(!obs)return obs;
            if((add && drift_) || (!add && !entry.owned))return fail(TunPolicyError::ownership);
            auto cmd=request(entry.value,add);
            pending_={cmd.header().nlmsg_type,socket_.sequence()+1,false}; entry.attempted=true;
            auto ack=socket_.acknowledge(std::move(cmd),deadline); obs=observe();
            if(!obs){pending_={};return obs;}
            bool confirmed=pending_.seen; pending_={};
            if(!ack && !ack.error().may_have_changed){if(add)entry.attempted=false;return failure(ack.error());}
            if(!ack && ack.error().rejected)return failure(ack.error());
            if(!confirmed){entry.owned=false;uncertain_=true;return fail(TunPolicyError::ownership);}
            auto after=count(entry.value,deadline); if(!after)return std::unexpected(after.error());
            if(*after!=(add?1u:0u))return fail(TunPolicyError::readback);
            obs=observe(); if(!obs)return obs;
            return (add && (!entry.owned || drift_)) ? std::expected<void,TunPolicyFailure>(fail(TunPolicyError::ownership)) : std::expected<void,TunPolicyFailure>{};
        }
        auto dump_route_table(Clock::time_point deadline) -> std::expected<std::unordered_map<tun_policy_detail::RouteKey,std::pair<Route,std::size_t>,tun_policy_detail::RouteKeyHash>,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            std::unordered_map<d::RouteKey,std::pair<Route,std::size_t>,d::RouteKeyHash> table;
            for (std::uint8_t fam:{4,6}) if (enabled_[fam==4?0:1]) {
                auto sc=d::t::View(socket_,index_,deadline).template routes<Route>(fam,[&](Route r)->std::expected<void,d::n::Failure> {
                    if (r.table==options_.route_table) { auto [it,ins]=table.try_emplace(d::route_key(r),std::move(r),std::size_t{1}); if (!ins) ++it->second.second; }
                    return {};
                });
                if (!sc) return failure(sc.error());
            }
            return table;
        }
        auto mutate_route_table_batch(std::span<Entry<Route>* const> batch,bool add,Clock::time_point deadline) -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            if (batch.empty()) return {};
            auto obs=observe(); if (!obs) return obs;
            if (add && drift_) return fail(TunPolicyError::ownership);
            auto before=dump_route_table(deadline); if (!before) return std::unexpected(before.error());
            for (auto* e : batch) {
                if (!add && !e->owned) return fail(TunPolicyError::ownership);
                auto it=before->find(d::route_key(e->value));
                if (add ? (it!=before->end()) : (it==before->end() || it->second.second!=1 || it->second.first!=e->value)) return fail(add ? TunPolicyError::conflict : TunPolicyError::ownership);
            }
            for (auto* e : batch) {
                auto cmd=tun_network_detail::route_record_request(e->value,add);
                pending_={cmd.header().nlmsg_type,socket_.sequence()+1,false}; e->attempted=true;
                auto ack=socket_.acknowledge(std::move(cmd),deadline); obs=observe();
                if (!obs) { pending_={}; return obs; }
                bool confirmed=pending_.seen; pending_={};
                if (!ack && !ack.error().may_have_changed) { if (add) e->attempted=false; return failure(ack.error()); }
                if (!ack && ack.error().rejected) return failure(ack.error());
                if (!confirmed) { e->owned=false; uncertain_=true; return fail(TunPolicyError::ownership); }
            }
            auto after=dump_route_table(deadline); if (!after) return std::unexpected(after.error());
            for (auto* e : batch) {
                auto it=after->find(d::route_key(e->value));
                if (add ? (it==after->end() || it->second.second!=1 || it->second.first!=e->value) : (it!=after->end())) return fail(TunPolicyError::readback);
            }
            obs=observe(); if (!obs) return obs;
            return (add && drift_) ? std::expected<void,TunPolicyFailure>(fail(TunPolicyError::ownership)) : std::expected<void,TunPolicyFailure>{};
        }
        auto make_tun_route(std::uint8_t family,std::uint32_t table,TunAddress dest={}) const noexcept -> Route {
            namespace d=tun_policy_detail;
            Route r{}; r.destination=dest; r.destination.family=family; r.table=table; r.index=static_cast<std::uint32_t>(index_);
            r.priority=1024; r.protocol=d::a::RTPROT_STATIC; r.scope=family==4?d::a::RT_SCOPE_LINK:d::a::RT_SCOPE_UNIVERSE; r.type=d::a::RTN_UNICAST; r.source=tun_source_[family==4?0:1]; return r;
        }
        auto make_throw_route(TunAddress const& dest) const noexcept -> Route {
            namespace d=tun_policy_detail;
            Route r{}; r.destination=dest; r.table=options_.route_table; r.priority=1024; r.protocol=d::a::RTPROT_STATIC; r.scope=d::a::RT_SCOPE_UNIVERSE; r.type=d::kRtnThrow; return r;
        }
        auto build_route_table_entries(std::span<TunAddress const> excludes,std::span<TunAddress const> includes,auto&& emit) const -> void {
            namespace d=tun_policy_detail;
            std::unordered_set<TunAddress,d::AddrHash> exc_set(excludes.begin(),excludes.end()), inc_seen;
            inc_seen.reserve(includes.size());
            for (std::uint8_t fam:{4,6}) if (enabled_[fam==4?0:1]) {
                if (includes.empty()) emit(make_tun_route(fam,options_.route_table));
                else for (auto const& inc : includes) if (inc.family==fam && !exc_set.contains(inc) && inc_seen.insert(inc).second) emit(make_tun_route(fam,options_.route_table,inc));
                for (auto const& exc : exc_set) if (exc.family==fam) emit(make_throw_route(exc));
            }
        }
        auto preflight(TunNetworkOptions const& network,Clock::time_point deadline,std::span<TunAddress const> excludes,
            std::array<char,16> const& device_name,TunRedirectOptions const& redirect,std::span<TunAddress const> includes={}) -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            for(std::size_t i=0;i<network.address_count;++i) {
                auto idx=network.addresses[i].family==4?0:1; enabled_[idx]=true;
                if (!tun_source_[idx]) tun_source_[idx]=network.addresses[i].bytes;
            }
            for (auto const& prefix : excludes)
                if (!d::valid_policy_prefix(prefix,false) || !enabled_[prefix.family==4 ? 0 : 1]) return fail(TunPolicyError::configuration);
            for(std::uint8_t family:{4,6}) {
                auto scanned=rules(family,deadline,[&](Rule const& rule)->std::expected<void,d::n::Failure> {
                    bool local=rule.priority==0 && rule.table==d::a::RT_TABLE_LOCAL && rule.action==d::a::FR_ACT_TO_TBL &&
                        !rule.destination && !rule.complex && !rule.flags && !rule.mask && !rule.mark &&
                        !rule.ip_protocol && !rule.destination_ports && !rule.uid_range && !rule.iifname;
                    if((rule.priority<=last_priority_ && !local) || (rule.mask && ((rule.mark^options_.mark)&rule.mask)==0) || owns_table(rule.table)) return d::n::fail(d::n::Error::configuration);
                    return {};
                });
                if(!scanned) return scanned.error().code==d::n::Error::configuration ? fail(TunPolicyError::conflict) : failure(scanned.error());
                TunPolicyError rejected=TunPolicyError::conflict;
                scanned=d::t::View(socket_,index_,deadline).template routes<Route>(family,[&](Route route)->std::expected<void,d::n::Failure> {
                    if(owns_table(route.table))return d::n::fail(d::n::Error::configuration);
                    if(watch_local_ && enabled_[family==4?0:1] && route.table==d::a::RT_TABLE_LOCAL && route.type==d::a::RTN_LOCAL &&
                        std::ranges::find(local_destinations_,route.destination)==local_destinations_.end()) {
                        if (local_destinations_.size()==local_destinations_.capacity() || !d::t::valid(route.destination,true)) { rejected=TunPolicyError::unsupported; return d::n::fail(d::n::Error::configuration); }
                        local_destinations_.push_back(route.destination);
                    }
                    if(!enabled_[family==4?0:1] || route.table!=d::a::RT_TABLE_MAIN)return {};
                    if(route.complex || !route.index || route.index==std::uint32_t(index_) || route.type!=d::a::RTN_UNICAST || route.flags || routes_.size()==64) { rejected=TunPolicyError::unsupported; return d::n::fail(d::n::Error::configuration); }
                    route.table=options_.bypass_table;route.protocol=d::a::RTPROT_STATIC; routes_.push_back({route}); return {};
                });
                if(!scanned) return scanned.error().code==d::n::Error::configuration ? fail(rejected) : failure(scanned.error());
            }
            std::expected<void,TunPolicyFailure> link_ok;
            routes_.for_each([&](auto const& entry) {
                if (!link_ok) return;
                auto link=d::t::View(socket_,entry.value.index,deadline).link();
                if(!link){link_ok=failure(link.error());return;}
                if(!*link || ((**link).flags&(d::a::IFF_UP|d::a::IFF_LOWER_UP))!=(d::a::IFF_UP|d::a::IFF_LOWER_UP) || (**link).type==d::a::ARPHRD_NONE || (**link).type==d::a::ARPHRD_LOOPBACK)
                    {link_ok=fail(TunPolicyError::unsupported);return;}
                if(entry.value.destination.family==4) if(auto added=reverse_.add(entry.value.index,(**link).name);!added) link_ok=failure(added.error());
            });
            if (!link_ok) return link_ok;
            bool has_selector_filters = options_.include_mark || options_.exclude_mark ||
                redirect.include_uid_count || redirect.exclude_uid_count || redirect.include_if_count || redirect.exclude_if_count;
            if (enabled_[0] && has_selector_filters) if (auto added=reverse_.add(index_,device_name); !added) return failure(added.error());
            if (auto reverse=reverse_.prepare(socket_,deadline); !reverse) return failure(reverse.error());
            routes_.sort_head([](auto const& left,auto const& right){return bool(left.value.gateway)<bool(right.value.gateway);});
            for(std::uint8_t family:{4,6})if(enabled_[family==4?0:1]) {
                routes_.push_back({make_tun_route(family,options_.capture_table)});
                Rule bypass{.family=family,.action=d::a::FR_ACT_TO_TBL,.protocol=d::a::RTPROT_STATIC,.table=options_.bypass_table,.priority=options_.priority,.mark=options_.mark,.mask=0xffffffffU};
                rules_.push_back({bypass});
                auto guard=bypass;guard.priority++;guard.table=0;guard.action=d::a::FR_ACT_UNREACHABLE;rules_.push_back({guard});
                auto priority=options_.priority+2;
                auto emit_bypass_pair=[&](Rule r) {
                    r.action=d::a::FR_ACT_TO_TBL; r.protocol=d::a::RTPROT_STATIC; r.table=options_.bypass_table; r.priority=priority++;
                    rules_.push_back({r});
                    r.priority=priority++; r.table=0; r.action=d::a::FR_ACT_UNREACHABLE;
                    rules_.push_back({r});
                };
                if (options_.exclude_mark) emit_bypass_pair(Rule{.family=family,.mark=options_.exclude_mark->mark,.mask=options_.exclude_mark->mask});
                for (auto const& u : std::span(redirect.exclude_uids).first(redirect.exclude_uid_count))
                    emit_bypass_pair(Rule{.family=family,.uid_range=d::r::UidRange{u.min,u.max}});
                for (auto const& ifn : std::span(redirect.exclude_interfaces).first(redirect.exclude_if_count))
                    emit_bypass_pair(Rule{.family=family,.iifname=ifn});
                auto capture_protected=[&](Rule take) {
                    take.priority=priority++; take.mask=options_.include_mark ? options_.include_mark->mask : 0;
                    take.mark=options_.include_mark ? options_.include_mark->mark : 0;
                    take.table=options_.capture_table; take.action=d::a::FR_ACT_TO_TBL;
                    rules_.push_back({take});
                };
                for (auto const& prefix:std::span(redirect.protected_destinations).first(redirect.protected_count))
                    if (prefix.family==family) capture_protected(Rule{.family=family,.protocol=d::a::RTPROT_STATIC,.destination=d::r::DestinationPrefix{prefix.bytes,prefix.prefix}});
                for (auto proto:{std::uint8_t{6},std::uint8_t{17}})
                    if (proto==6 ? redirect.tcp_dns : redirect.udp_dns) capture_protected(Rule{.family=family,.protocol=d::a::RTPROT_STATIC,.ip_protocol=proto,.destination_ports=std::array<std::uint16_t,2>{53,53}});
                if (!use_route_table_) {
                    containers::inplace_vector<TunAddress,d::kInlineRuleExcludeCap> seen_exc;
                    for (auto const& prefix : excludes) if (prefix.family==family && !std::ranges::contains(seen_exc,prefix)) {
                        seen_exc.push_back(prefix);
                        emit_bypass_pair(Rule{.family=family,.destination=d::r::DestinationPrefix{prefix.bytes,prefix.prefix}});
                    }
                }
                std::uint32_t target_table = use_route_table_ ? options_.route_table : options_.capture_table;
                auto cap_prio=capture_priority_;
                auto emit_capture=[&](std::optional<d::r::UidRange> uid,std::optional<std::array<char,16>> iif) {
                    Rule c{.family=family,.action=d::a::FR_ACT_TO_TBL,.protocol=d::a::RTPROT_STATIC,.table=target_table,.priority=cap_prio++,.uid_range=uid,.iifname=iif};
                    if (options_.include_mark) {
                        c.mark=options_.include_mark->mark; c.mask=options_.include_mark->mask; rules_.push_back({c});
                        if (!use_route_table_) { c.priority=cap_prio++; c.table=0; c.action=d::a::FR_ACT_UNREACHABLE; rules_.push_back({c}); }
                    } else if (!uid && !iif) {
                        c.mark=options_.mark; c.mask=0xffffffffU; c.flags=d::a::FIB_RULE_INVERT; rules_.push_back({c});
                    } else rules_.push_back({c});
                };
                if (!redirect.include_uid_count && !redirect.include_if_count) emit_capture(std::nullopt,std::nullopt);
                else {
                    for (auto const& u : std::span(redirect.include_uids).first(redirect.include_uid_count)) emit_capture(d::r::UidRange{u.min,u.max},std::nullopt);
                    for (auto const& ifn : std::span(redirect.include_interfaces).first(redirect.include_if_count)) emit_capture(std::nullopt,ifn);
                }
            }
            if (use_route_table_) build_route_table_entries(excludes,includes,[&](Route r){routes_.push_back({std::move(r)});});
            auto observed=observe();if(!observed)return observed;
            return drift_?std::expected<void,TunPolicyFailure>(fail(TunPolicyError::drift)):std::expected<void,TunPolicyFailure>{};
        }
      public:
        TunDefaultPolicy()=default;
        TunDefaultPolicy(TunDefaultPolicy const&)=delete;
        auto operator=(TunDefaultPolicy const&) -> TunDefaultPolicy& =delete;
        ~TunDefaultPolicy(){if(!stopped_)(void)stop(Clock::now()+std::chrono::seconds(2));}
        template<class LeaseHooks> [[nodiscard]] auto start(TunNetworkLease<LeaseHooks>& lease,TunDefaultOptions options,
            Clock::time_point deadline,Clock::time_point rollback_deadline,std::span<TunAddress const> excludes={},
            TunRedirectOptions const& redirect={},std::span<TunAddress const> includes={}) -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            if(starting_ || stopped_)return fail(TunPolicyError::state);
            starting_=true;options_=options;watch_local_=redirect.port!=0;auto const& network=lease.network_options();
            use_route_table_=options.dynamic_route_table || !includes.empty() || excludes.size()>d::kInlineRuleExcludeCap;
            auto valid_uids=[](std::span<TunUidRange const> s){return std::ranges::all_of(s,[](auto const& u){return u.min<=u.max;});};
            auto valid_ifs=[](std::span<std::array<char,16> const> s){return std::ranges::all_of(s,d::valid_ifname);};
            if (excludes.size()>max_tun_excludes || includes.size()>max_tun_excludes ||
                redirect.protected_count>redirect.protected_destinations.size() ||
                redirect.include_uid_count>redirect.include_uids.size() || redirect.exclude_uid_count>redirect.exclude_uids.size() ||
                redirect.include_if_count>redirect.include_interfaces.size() || redirect.exclude_if_count>redirect.exclude_interfaces.size() ||
                !valid_uids(std::span(redirect.include_uids).first(redirect.include_uid_count)) ||
                !valid_uids(std::span(redirect.exclude_uids).first(redirect.exclude_uid_count)) ||
                !valid_ifs(std::span(redirect.include_interfaces).first(redirect.include_if_count)) ||
                !valid_ifs(std::span(redirect.exclude_interfaces).first(redirect.exclude_if_count)) ||
                (options.include_mark && !options.include_mark->valid()) || (options.exclude_mark && !options.exclude_mark->valid()) ||
                options.capture_table<256 || options.bypass_table<256 || options.capture_table==options.bypass_table ||
                (use_route_table_ && (options.route_table<256 || options.route_table==options.capture_table || options.route_table==options.bypass_table)) ||
                !options.mark || !options.priority || network.route_count || !d::t::validate(network))
                return fail(TunPolicyError::configuration);
            for (auto const& prefix : includes)
                if (!d::valid_policy_prefix(prefix,true) || !std::ranges::any_of(std::span(network.addresses).first(network.address_count),
                    [&](auto const& addr){return addr.family==prefix.family;}))
                    return fail(TunPolicyError::configuration);
            std::size_t pre_slots = 2 + (options.exclude_mark ? 2u : 0u) + 2u*redirect.exclude_uid_count + 2u*redirect.exclude_if_count +
                redirect.protected_count + redirect.tcp_dns + redirect.udp_dns + (use_route_table_ ? 0u : 2u*excludes.size());
            std::size_t cap_selectors = (redirect.include_uid_count || redirect.include_if_count)
                ? (std::size_t(redirect.include_uid_count) + redirect.include_if_count) : std::size_t{1};
            std::size_t cap_slots = cap_selectors * ((options.include_mark && !use_route_table_) ? 2u : 1u);
            if (options.priority > 32765 || pre_slots + cap_slots > 32766u - options.priority) return fail(TunPolicyError::configuration);
            capture_priority_=static_cast<std::uint32_t>(options.priority+pre_slots);
            last_priority_=static_cast<std::uint32_t>(capture_priority_+cap_slots-1);
            auto device=lease.verified_device(deadline);if(!device)return fail(TunPolicyError::ownership);index_=device->index;
            if(auto opened=socket_.open();!opened)return failure(opened.error());
            std::array groups{d::a::RTNLGRP_IPV4_NETCONF,d::a::RTNLGRP_LINK,d::a::RTNLGRP_IPV4_ROUTE,d::a::RTNLGRP_IPV6_ROUTE,d::a::RTNLGRP_IPV4_RULE,d::a::RTNLGRP_IPV6_RULE};
            if(auto opened=watch_.open(groups);!opened)return failure(opened.error());
            auto result=preflight(network,deadline,excludes,device->name,redirect,includes);
            if(result) if(auto rev=reverse_.start([&]{return synchronize();},[&](auto index,auto name){return same_link(index,name,deadline);}); !rev) result=failure(rev.error());
            if(result) routes_.for_each([&](auto& e){if(result && (!use_route_table_ || e.value.table!=options_.route_table)) result=mutate(e,true,deadline);});
            if(result && use_route_table_) {
                std::vector<Entry<Route>*> bulk;
                routes_.for_each([&](auto& e){if(e.value.table==options_.route_table) bulk.push_back(&e);});
                result=mutate_route_table_batch(bulk,true,deadline);
            }
            if(result) rules_.for_each([&](auto& entry){if(result)result=mutate(entry,true,deadline);});
            if(result){auto still=lease.verified_device(deadline);if(!still || still->index!=index_)result=fail(TunPolicyError::ownership);}
            if(!result){(void)stop(rollback_deadline);return result;}
            started_=true;return {};
        }
        [[nodiscard]] auto update_routes(std::span<TunAddress const> excludes,std::span<TunAddress const> includes,Clock::time_point deadline)
            -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            if(!started_ || stopped_ || !use_route_table_) return fail(TunPolicyError::state);
            if(excludes.size()>max_tun_excludes || includes.size()>max_tun_excludes) return fail(TunPolicyError::configuration);
            for (auto const& prefix : excludes)
                if (!d::valid_policy_prefix(prefix,false) || !enabled_[prefix.family==4 ? 0 : 1]) return fail(TunPolicyError::configuration);
            for (auto const& prefix : includes)
                if (!d::valid_policy_prefix(prefix,true) || !enabled_[prefix.family==4 ? 0 : 1]) return fail(TunPolicyError::configuration);
            std::unordered_map<d::RouteKey,Route,d::RouteKeyHash> desired_map;
            build_route_table_entries(excludes,includes,[&](Route r){desired_map.emplace(d::route_key(r),std::move(r));});
            std::vector<Entry<Route>*> to_remove;
            routes_.for_each([&](auto& entry) {
                if (entry.value.table!=options_.route_table || !entry.owned) return;
                auto it=desired_map.find(d::route_key(entry.value));
                if (it==desired_map.end() || it->second!=entry.value) to_remove.push_back(&entry);
            });
            if (auto rm=mutate_route_table_batch(to_remove,false,deadline); !rm) return rm;
            routes_.erase_if([&](auto const& entry){return entry.value.table==options_.route_table && !entry.owned;});
            std::unordered_set<d::RouteKey,d::RouteKeyHash> existing;
            routes_.for_each([&](auto const& e){if(e.value.table==options_.route_table && e.owned) existing.insert(d::route_key(e.value));});
            for (auto& [k, wanted] : desired_map) if (!existing.contains(k)) routes_.push_back({std::move(wanted)});
            std::vector<Entry<Route>*> to_add;
            routes_.for_each([&](auto& e){if(e.value.table==options_.route_table && !e.owned) to_add.push_back(&e);});
            return mutate_route_table_batch(to_add,true,deadline);
        }
        [[nodiscard]] auto check() -> std::expected<void,TunPolicyFailure> {
            if(!started_ || stopped_)return fail(TunPolicyError::state);
            auto observed=observe();if(!observed)return observed;
            return drift_?std::expected<void,TunPolicyFailure>(fail(TunPolicyError::drift)):std::expected<void,TunPolicyFailure>{};
        }
        [[nodiscard]] auto stop(Clock::time_point deadline) noexcept -> TunPolicyCleanup {
            if(stopped_)return cleanup_;started_=false;
            if constexpr(Socket::cancellable)socket_.disable_cancellation();
            if(watch_.native_handle()>=0)(void)observe();
            auto remove=[&](auto& entry) {
                if(!entry.attempted)return;
                if(!entry.owned){++cleanup_.preserved;if(uncertain_)++cleanup_.uncertain;return;}
                auto removed=mutate(entry,false,deadline);if(removed)++cleanup_.removed;else ++cleanup_.uncertain;
            };
            rules_.for_each([&](auto& e){if(e.value.table==options_.capture_table || (use_route_table_ && e.value.table==options_.route_table) || e.value.priority>=capture_priority_)remove(e);});
            if (use_route_table_) {
                try {
                    std::vector<Entry<Route>*> rt;
                    routes_.for_each([&](auto& e){if(e.value.table==options_.route_table && e.attempted){if(e.owned)rt.push_back(&e);else remove(e);}});
                    if (!rt.empty()) {
                        if (mutate_route_table_batch(rt,false,deadline)) cleanup_.removed+=rt.size();
                        else for (auto* e : rt) { if (e->owned) remove(*e); else ++cleanup_.uncertain; }
                    }
                } catch (...) { routes_.for_each([&](auto& e){if(e.value.table==options_.route_table)remove(e);}); }
            }
            routes_.for_each([&](auto& e){if(e.value.table==options_.capture_table)remove(e);});
            rules_.for_each_reverse([&](auto& e){if(e.value.table!=options_.capture_table && (!use_route_table_ || e.value.table!=options_.route_table) && e.value.priority<capture_priority_)remove(e);});
            routes_.for_each_reverse([&](auto& e){if(e.value.table==options_.bypass_table)remove(e);});
            auto reverse=reverse_.stop([&]{return synchronize();},[&](auto index,auto name){return same_link(index,name,deadline);});
            cleanup_.settings_restored=reverse.restored;cleanup_.settings_preserved=reverse.preserved;cleanup_.uncertain+=reverse.uncertain;
            socket_.close();watch_.close();stopped_=true;cleanup_.descriptors_closed=true;return cleanup_;
        }
        [[nodiscard]] auto native_handle() const noexcept -> int{return watch_.native_handle();}
        [[nodiscard]] auto local_destinations() const noexcept -> std::span<TunAddress const> {return local_destinations_;}
        [[nodiscard]] auto cleanup() const noexcept -> TunPolicyCleanup{return cleanup_;}
        [[nodiscard]] auto drained() const noexcept -> bool{return stopped_ && cleanup_.descriptors_closed && !cleanup_.uncertain;}
    };
}
