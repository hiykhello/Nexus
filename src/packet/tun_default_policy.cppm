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
        template<class Record> struct Entry {Record value;bool attempted=false,owned=false;};
        inline auto same_key(t::GatewayRouteRecord const& left,t::GatewayRouteRecord const& right) noexcept -> bool {
            return left.destination==right.destination && left.table==right.table && left.priority==right.priority && left.index==right.index;
        }
        inline auto same_key(r::Rule const& left,r::Rule const& right) noexcept -> bool {return r::same_selector(left,right);}
    }
    inline constexpr std::size_t max_tun_excludes=64;

    struct TunDefaultOptions {
        std::uint32_t capture_table=60000,bypass_table=60001,priority=10000,mark=0x6e780001;
        std::optional<platform::RoutingMarkFilter> include_mark, exclude_mark;
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
        containers::inplace_vector<Entry<Route>,66> routes_;
        containers::inplace_vector<Entry<Rule>,2*(2+2+2+4)+2*max_tun_excludes> rules_;
        containers::inplace_vector<TunAddress,32> local_destinations_;
        std::uint32_t capture_priority_=0,last_priority_=0;
        std::int32_t index_=0;
        bool starting_=false,started_=false,stopped_=false,drift_=false,uncertain_=false,watch_local_=false;
        struct Pending {std::uint16_t type=0;std::uint32_t sequence=0;bool seen=false;};
        Pending pending_;
        TunPolicyCleanup cleanup_;
        static auto fail(TunPolicyError code) -> std::unexpected<TunPolicyFailure> {return std::unexpected(TunPolicyFailure{code,{}});}
        static auto failure(platform::netlink::Failure value) -> std::unexpected<TunPolicyFailure> {return std::unexpected(TunPolicyFailure{TunPolicyError::netlink,value});}
        auto invalidate() noexcept -> void {
            uncertain_=drift_=true;reverse_.invalidate();
            for(auto& value:rules_)value.owned=false;
            for(auto& value:routes_)value.owned=false;
        }
        template<class Record,class Entries>
        auto event(platform::netlink::Message message,Record const& value,Entries& entries) -> void {
            namespace d=tun_policy_detail;
            bool ours=message.header.nlmsg_pid==socket_.port_id() && message.header.nlmsg_seq==pending_.sequence && message.header.nlmsg_type==pending_.type;
            for(auto& entry:entries)if(d::same_key(entry.value,value)) {
                if(ours && entry.value==value && !pending_.seen) {
                    pending_.seen=true;
                    entry.owned=message.header.nlmsg_type==d::a::RTM_NEWRULE || message.header.nlmsg_type==d::a::RTM_NEWROUTE;
                } else {entry.owned=false;drift_=true;}
            }
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
                       (parsed->priority<=last_priority_ || (parsed->mask && ((parsed->mark^options_.mark)&parsed->mask)==0) || parsed->table==options_.capture_table || parsed->table==options_.bypass_table))drift_=true;
                } else if(message.header.nlmsg_type==d::a::RTM_NEWROUTE || message.header.nlmsg_type==d::a::RTM_DELROUTE) {
                    copy.header.nlmsg_type=d::a::RTM_NEWROUTE;
                    auto parsed=d::t::parse_route<Route>(copy);if(!parsed)return std::unexpected(parsed.error());
                    event(message,*parsed,routes_);
                    if(parsed->table==d::a::RT_TABLE_MAIN)drift_=true;
                    if(watch_local_ && parsed->table==d::a::RT_TABLE_LOCAL && parsed->type==d::a::RTN_LOCAL)drift_=true;
                    if(message.header.nlmsg_pid!=socket_.port_id() && (parsed->table==options_.capture_table || parsed->table==options_.bypass_table))drift_=true;
                } else if(message.header.nlmsg_type==d::a::RTM_NEWNETCONF || message.header.nlmsg_type==d::a::RTM_DELNETCONF) {
                    auto observed=reverse_.observe(message);if(!observed)return observed;
                    drift_|=reverse_.drifted();
                } else if(message.header.nlmsg_type==d::a::RTM_NEWLINK || message.header.nlmsg_type==d::a::RTM_DELLINK) {
                    copy.header.nlmsg_type=d::a::RTM_NEWLINK;
                    auto parsed=d::t::parse_link(copy);if(!parsed)return std::unexpected(parsed.error());
                    if(parsed->index==index_ || std::ranges::any_of(routes_,[&](auto const& route){return route.value.index==std::uint32_t(parsed->index);})) {
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
                // IPv6 on-link routes may share prefix/metric across physical
                // interfaces. Append only beside a concrete verified own route.
                if(add && value.destination.family==6 && std::ranges::any_of(routes_,[&](auto const& entry){
                    return entry.owned && entry.value.destination==value.destination && entry.value.table==value.table && entry.value.priority==value.priority;
                }))return tun_network_detail::route_record_request<false>(value,add);
                return tun_network_detail::route_record_request(value,add);
            }
        }
        template<class Record> auto mutate(Entry<Record>& entry,bool add,Clock::time_point deadline) -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            auto observed=observe();if(!observed)return observed;
            if((add && drift_) || (!add && !entry.owned))return fail(TunPolicyError::ownership);
            auto before=count(entry.value,deadline);if(!before)return std::unexpected(before.error());
            if(*before!=(add?0u:1u))return fail(TunPolicyError::conflict);
            // Reconcile the independent event stream before claiming/removing.
            observed=observe();if(!observed)return observed;
            if((add && drift_) || (!add && !entry.owned))return fail(TunPolicyError::ownership);
            auto command=request(entry.value,add);
            pending_={command.header().nlmsg_type,socket_.sequence()+1,false};
            entry.attempted=true;
            auto acknowledged=socket_.acknowledge(std::move(command),deadline);
            observed=observe();
            if(!observed){pending_={};return observed;}
            bool confirmed=pending_.seen;pending_={};
            if(!acknowledged && !acknowledged.error().may_have_changed) {
                if(add)entry.attempted=false;
                return failure(acknowledged.error());
            }
            if(!acknowledged && acknowledged.error().rejected)return failure(acknowledged.error());
            if(!confirmed){entry.owned=false;uncertain_=true;return fail(TunPolicyError::ownership);}
            auto after=count(entry.value,deadline);if(!after)return std::unexpected(after.error());
            if(*after!=(add?1u:0u))return fail(TunPolicyError::readback);
            observed=observe();if(!observed)return observed;
            if(add && (!entry.owned || drift_))return fail(TunPolicyError::ownership);
            return {};
        }
        auto preflight(TunNetworkOptions const& network,Clock::time_point deadline,std::span<TunAddress const> excludes,
            std::array<char,16> const& device_name,TunRedirectOptions const& redirect) -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            std::array<bool,2> enabled{};
            for(std::size_t i=0;i<network.address_count;++i)enabled[network.addresses[i].family==4?0:1]=true;
            for (auto const& prefix : excludes)
                if (!prefix.prefix || !d::t::valid(prefix,true) || !enabled[prefix.family==4 ? 0 : 1])
                    return fail(TunPolicyError::configuration);
            for(std::uint8_t family:{4,6}) {
                auto scanned=rules(family,deadline,[&](Rule const& rule)->std::expected<void,d::n::Failure> {
                    bool local=rule.priority==0 && rule.table==d::a::RT_TABLE_LOCAL && rule.action==d::a::FR_ACT_TO_TBL && !rule.destination && !rule.complex && !rule.flags && !rule.mask && !rule.mark && !rule.ip_protocol && !rule.destination_ports;
                    if((rule.priority<=last_priority_ && !local) || (rule.mask && ((rule.mark^options_.mark)&rule.mask)==0) || rule.table==options_.capture_table || rule.table==options_.bypass_table)return d::n::fail(d::n::Error::configuration);
                    return {};
                });
                if(!scanned) {
                    if(scanned.error().code==d::n::Error::configuration)return fail(TunPolicyError::conflict);
                    return failure(scanned.error());
                }
                TunPolicyError rejected=TunPolicyError::conflict;
                scanned=d::t::View(socket_,index_,deadline).template routes<Route>(family,[&](Route route)->std::expected<void,d::n::Failure> {
                    if(route.table==options_.capture_table || route.table==options_.bypass_table)return d::n::fail(d::n::Error::configuration);
                    if(watch_local_ && enabled[family==4?0:1] && route.table==d::a::RT_TABLE_LOCAL && route.type==d::a::RTN_LOCAL &&
                        std::ranges::find(local_destinations_,route.destination)==local_destinations_.end()) {
                        if (local_destinations_.size()==local_destinations_.capacity() || !d::t::valid(route.destination,true)) {
                            rejected=TunPolicyError::unsupported;
                            return d::n::fail(d::n::Error::configuration);
                        }
                        local_destinations_.push_back(route.destination);
                    }
                    if(!enabled[family==4?0:1] || route.table!=d::a::RT_TABLE_MAIN)return {};
                    // Every main-table route must be faithfully reproducible.
                    if(route.complex || !route.index || route.index==std::uint32_t(index_) || route.type!=d::a::RTN_UNICAST || route.flags || routes_.size()==64) {
                        rejected=TunPolicyError::unsupported;return d::n::fail(d::n::Error::configuration);
                    }
                    route.table=options_.bypass_table;route.protocol=d::a::RTPROT_STATIC;
                    routes_.push_back({route});return {};
                });
                if(!scanned) {
                    if(scanned.error().code==d::n::Error::configuration)return fail(rejected);
                    return failure(scanned.error());
                }
            }
            // Validate each concrete output link before any policy mutation.
            for(auto const& entry:routes_) {
                auto link=d::t::View(socket_,entry.value.index,deadline).link();if(!link)return failure(link.error());
                if(!*link || ((**link).flags&(d::a::IFF_UP|d::a::IFF_LOWER_UP))!=(d::a::IFF_UP|d::a::IFF_LOWER_UP) || (**link).type==d::a::ARPHRD_NONE || (**link).type==d::a::ARPHRD_LOOPBACK)return fail(TunPolicyError::unsupported);
                if(entry.value.destination.family==4) {
                    auto added=reverse_.add(entry.value.index,(**link).name);if(!added)return failure(added.error());
                }
            }
            // TUN replies are reinjected without the application's socket mark.
            if (enabled[0] && (options_.include_mark || options_.exclude_mark)) {
                auto added=reverse_.add(index_,device_name);
                if (!added) return failure(added.error());
            }
            auto reverse=reverse_.prepare(socket_,deadline);if(!reverse)return failure(reverse.error());
            std::ranges::sort(routes_,[](auto const& left,auto const& right){return bool(left.value.gateway)<bool(right.value.gateway);});
            for(std::uint8_t family:{4,6})if(enabled[family==4?0:1]) {
                Route capture;capture.destination.family=family;capture.index=index_;capture.table=options_.capture_table;capture.priority=1024;
                capture.protocol=d::a::RTPROT_STATIC;capture.scope=family==4?d::a::RT_SCOPE_LINK:d::a::RT_SCOPE_UNIVERSE;capture.type=d::a::RTN_UNICAST;
                for(std::size_t i=0;i<network.address_count;++i)if(network.addresses[i].family==family){capture.source=network.addresses[i].bytes;break;}
                routes_.push_back({capture});
                Rule bypass{.family=family,.action=d::a::FR_ACT_TO_TBL,.protocol=d::a::RTPROT_STATIC,.table=options_.bypass_table,.priority=options_.priority,.mark=options_.mark,.mask=0xffffffffU};
                rules_.push_back({bypass});
                auto guard=bypass;guard.priority++;guard.table=0;guard.action=d::a::FR_ACT_UNREACHABLE;rules_.push_back({guard});
                auto priority=options_.priority+2;
                if (options_.exclude_mark) {
                    auto exclude=bypass;
                    exclude.priority=priority++;
                    exclude.mark=options_.exclude_mark->mark;
                    exclude.mask=options_.exclude_mark->mask;
                    rules_.push_back({exclude});
                    exclude.priority=priority++;
                    exclude.table=0;
                    exclude.action=d::a::FR_ACT_UNREACHABLE;
                    rules_.push_back({exclude});
                }
                auto capture_protected=[&](Rule take) {
                    take.priority=priority++;
                    take.mask=options_.include_mark ? options_.include_mark->mask : 0;
                    take.mark=options_.include_mark ? options_.include_mark->mark : 0;
                    take.table=options_.capture_table;
                    take.action=d::a::FR_ACT_TO_TBL;
                    rules_.push_back({take});
                };
                for (auto const& prefix:std::span(redirect.protected_destinations).first(redirect.protected_count))
                    if (prefix.family==family)
                        capture_protected(Rule{.family=family,.protocol=d::a::RTPROT_STATIC,
                            .destination=d::r::DestinationPrefix{prefix.bytes,prefix.prefix}});
                for (auto proto:{std::uint8_t{6},std::uint8_t{17}})
                    if (proto==6 ? redirect.tcp_dns : redirect.udp_dns)
                        capture_protected(Rule{.family=family,.protocol=d::a::RTPROT_STATIC,.ip_protocol=proto,
                            .destination_ports=std::array<std::uint16_t,2>{53,53}});
                for (auto const& prefix : excludes) {
                    if (prefix.family!=family) continue;
                    Rule let_through{.family=family,.action=d::a::FR_ACT_TO_TBL,.protocol=d::a::RTPROT_STATIC,
                        .table=options_.bypass_table,.priority=priority++,.destination=d::r::DestinationPrefix{prefix.bytes,prefix.prefix}};
                    rules_.push_back({let_through});
                    let_through.priority=priority++;
                    let_through.table=0;
                    let_through.action=d::a::FR_ACT_UNREACHABLE;
                    rules_.push_back({let_through});
                }
                auto capture_rule=bypass;
                capture_rule.priority=capture_priority_;
                capture_rule.table=options_.capture_table;
                if (options_.include_mark) {
                    capture_rule.mark=options_.include_mark->mark;
                    capture_rule.mask=options_.include_mark->mask;
                    rules_.push_back({capture_rule});
                    capture_rule.priority++;
                    capture_rule.table=0;
                    capture_rule.action=d::a::FR_ACT_UNREACHABLE;
                } else {
                    capture_rule.flags=d::a::FIB_RULE_INVERT;
                }
                rules_.push_back({capture_rule});
            }
            auto observed=observe();if(!observed)return observed;
            return drift_?std::expected<void,TunPolicyFailure>(fail(TunPolicyError::drift)):std::expected<void,TunPolicyFailure>{};
        }
      public:
        TunDefaultPolicy()=default;
        TunDefaultPolicy(TunDefaultPolicy const&)=delete;
        auto operator=(TunDefaultPolicy const&) -> TunDefaultPolicy& =delete;
        ~TunDefaultPolicy(){if(!stopped_)(void)stop(Clock::now()+std::chrono::seconds(2));}
        template<class LeaseHooks> [[nodiscard]] auto start(TunNetworkLease<LeaseHooks>& lease,TunDefaultOptions options,
            Clock::time_point deadline,Clock::time_point rollback_deadline,std::span<TunAddress const> excludes={},TunRedirectOptions const& redirect={})
            -> std::expected<void,TunPolicyFailure> {
            namespace d=tun_policy_detail;
            if(starting_ || stopped_)return fail(TunPolicyError::state);
            starting_=true;options_=options;watch_local_=redirect.port!=0;auto const& network=lease.network_options();
            if (excludes.size()>max_tun_excludes || options.priority>32759-2*excludes.size() ||
                redirect.protected_count>redirect.protected_destinations.size() ||
                (options.include_mark && !options.include_mark->valid()) ||
                (options.exclude_mark && !options.exclude_mark->valid()) ||
                options.capture_table<256 ||
                options.bypass_table<256 || options.capture_table==options.bypass_table || !options.mark ||
                !options.priority || network.route_count || !d::t::validate(network)) return fail(TunPolicyError::configuration);
            capture_priority_=static_cast<std::uint32_t>(options.priority+2+2*excludes.size()+
                (options.exclude_mark ? 2 : 0)+redirect.protected_count+redirect.tcp_dns+redirect.udp_dns);
            last_priority_=capture_priority_+(options.include_mark ? 1 : 0);
            auto device=lease.verified_device(deadline);if(!device)return fail(TunPolicyError::ownership);index_=device->index;
            auto opened=socket_.open();if(!opened)return failure(opened.error());
            std::array groups{d::a::RTNLGRP_IPV4_NETCONF,d::a::RTNLGRP_LINK,d::a::RTNLGRP_IPV4_ROUTE,d::a::RTNLGRP_IPV6_ROUTE,d::a::RTNLGRP_IPV4_RULE,d::a::RTNLGRP_IPV6_RULE};
            opened=watch_.open(groups);if(!opened)return failure(opened.error());
            auto result=preflight(network,deadline,excludes,device->name,redirect);
            if(result) {
                auto reverse=reverse_.start([&]{return synchronize();},[&](auto index,auto name){return same_link(index,name,deadline);});
                if(!reverse)result=failure(reverse.error());
            }
            if(result)for(auto& entry:routes_){result=mutate(entry,true,deadline);if(!result)break;}
            if(result)for(auto& entry:rules_){result=mutate(entry,true,deadline);if(!result)break;}
            if(result){auto still=lease.verified_device(deadline);if(!still || still->index!=index_)result=fail(TunPolicyError::ownership);}
            if(!result){(void)stop(rollback_deadline);return result;}
            started_=true;return {};
        }
        [[nodiscard]] auto check() -> std::expected<void,TunPolicyFailure> {
            if(!started_ || stopped_)return fail(TunPolicyError::state);
            auto observed=observe();if(!observed)return observed;
            return drift_?std::expected<void,TunPolicyFailure>(fail(TunPolicyError::drift)):std::expected<void,TunPolicyFailure>{};
        }
        // The caller quiesces both TUN and marked outer traffic before cleanup.
        [[nodiscard]] auto stop(Clock::time_point deadline) noexcept -> TunPolicyCleanup {
            if(stopped_)return cleanup_;started_=false;
            if constexpr(Socket::cancellable)socket_.disable_cancellation();
            if(watch_.native_handle()>=0)(void)observe();
            auto remove=[&](auto& entry) {
                if(!entry.attempted)return;
                if(!entry.owned){++cleanup_.preserved;if(uncertain_)++cleanup_.uncertain;return;}
                auto removed=mutate(entry,false,deadline);if(removed)++cleanup_.removed;else ++cleanup_.uncertain;
            };
            // Remove all capture selectors before either family's bypass chain.
            for(auto& entry:rules_)if(entry.value.table==options_.capture_table || entry.value.priority>=capture_priority_)remove(entry);
            for(auto& entry:routes_)if(entry.value.table==options_.capture_table)remove(entry);
            for(auto it=rules_.rbegin();it!=rules_.rend();++it)if(it->value.table!=options_.capture_table && it->value.priority<capture_priority_)remove(*it);
            for(auto it=routes_.rbegin();it!=routes_.rend();++it)if(it->value.table==options_.bypass_table)remove(*it);
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
