module;
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <cstring>

module platform.nftables;
import std;
import platform.socket_options;

namespace platform::nftables {
    namespace {
        constexpr auto reg=NFT_REG_1;
        constexpr std::size_t kMaxCidrs=65536, kInlineExcludeLimit=64, kSetElemChunk=256;

        struct V4Interval { std::uint32_t start=0, end=0; };
        struct V6Interval { std::array<std::uint8_t,16> start{}, end{}; };

        auto load_be32(std::array<std::uint8_t,16> const& a) noexcept -> std::uint32_t {
            return (std::uint32_t(a[0])<<24)|(std::uint32_t(a[1])<<16)|(std::uint32_t(a[2])<<8)|a[3];
        }
        auto store_be32(std::uint32_t v) noexcept -> std::array<std::uint8_t,4> {
            return {static_cast<std::uint8_t>(v>>24),static_cast<std::uint8_t>(v>>16),
                    static_cast<std::uint8_t>(v>>8),static_cast<std::uint8_t>(v&0xffu)};
        }
        auto inc_v6(std::array<std::uint8_t,16> a) noexcept -> std::optional<std::array<std::uint8_t,16>> {
            for (int i=15;i>=0;--i) if (++a[static_cast<std::size_t>(i)]!=0) return a;
            return std::nullopt;
        }
        auto merge_v4(std::span<Prefix const> prefixes) -> std::vector<V4Interval> {
            std::vector<V4Interval> raw, merged;
            for (auto const& p : prefixes) {
                if (p.family!=4) continue;
                std::uint32_t mask = p.length==0 ? 0u : p.length==32 ? 0xffffffffu : (~0u<<(32u-p.length));
                std::uint32_t start = load_be32(p.address) & mask;
                raw.push_back({start, start | ~mask});
            }
            if (raw.empty()) return merged;
            std::ranges::sort(raw,[](auto const& a,auto const& b){return a.start<b.start||(a.start==b.start&&a.end<b.end);});
            merged.push_back(raw.front());
            for (std::size_t i=1;i<raw.size();++i) {
                auto& b=merged.back();
                if (b.end==0xffffffffu || raw[i].start<=b.end+1u) b.end=std::max(b.end,raw[i].end);
                else merged.push_back(raw[i]);
            }
            return merged;
        }
        auto merge_v6(std::span<Prefix const> prefixes) -> std::vector<V6Interval> {
            std::vector<V6Interval> raw, merged;
            for (auto const& p : prefixes) {
                if (p.family!=6) continue;
                auto start=p.address, end=p.address;
                for (unsigned bit=p.length;bit<128;++bit) {
                    start[bit/8]&=static_cast<std::uint8_t>(~(128u>>(bit%8)));
                    end[bit/8]|=static_cast<std::uint8_t>(128u>>(bit%8));
                }
                raw.push_back({start,end});
            }
            if (raw.empty()) return merged;
            std::ranges::sort(raw,[](auto const& a,auto const& b){return a.start<b.start||(a.start==b.start&&a.end<b.end);});
            merged.push_back(raw.front());
            for (std::size_t i=1;i<raw.size();++i) {
                auto& b=merged.back();
                auto next=inc_v6(b.end);
                if (!next || raw[i].start<=*next) { if (raw[i].end>b.end) b.end=raw[i].end; }
                else merged.push_back(raw[i]);
            }
            return merged;
        }
        auto u16_bytes(std::uint16_t const& value) noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(&value), sizeof value};
        }
        auto u32_bytes(std::uint32_t const& value) noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(&value), sizeof value};
        }

        class Writer {
            Transaction message_;
            std::size_t current_=0;
            template<class T> auto append(T const& value) -> void {
                auto offset=message_.bytes.size();
                message_.bytes.resize(offset+sizeof(T));
                std::memcpy(message_.bytes.data()+offset,&value,sizeof(T));
            }
            template<class T> auto fill(std::size_t offset,T value) -> void {
                std::memcpy(message_.bytes.data()+offset,&value,sizeof(T));
            }
        public:
            explicit Writer(std::uint32_t first) {message_.end=first;}
            auto header(std::uint16_t type,std::uint16_t flags,std::uint8_t family,std::uint16_t id=0) -> void {
                current_=message_.bytes.size();
                append(nlmsghdr{.nlmsg_type=type,.nlmsg_flags=flags,.nlmsg_seq=message_.end++});
                append(nfgenmsg{family,NFNETLINK_V0,htons(id)});
            }
            auto end() -> void {fill(current_,static_cast<std::uint32_t>(message_.bytes.size()-current_));}
            auto fence(std::uint16_t type) -> void { header(type,NLM_F_REQUEST,AF_UNSPEC,NFNL_SUBSYS_NFTABLES); end(); }
            auto raw(std::uint16_t id,std::span<std::uint8_t const> bytes) -> void {
                append(nlattr{static_cast<std::uint16_t>(sizeof(nlattr)+bytes.size()),id});
                message_.bytes.insert(message_.bytes.end(),bytes.begin(),bytes.end());
                message_.bytes.resize(NLA_ALIGN(message_.bytes.size()));
            }
            auto text(std::uint16_t id,std::string_view value) -> void {
                std::string terminated(value);
                raw(id,{reinterpret_cast<std::uint8_t const*>(terminated.c_str()),terminated.size()+1});
            }
            auto u8(std::uint16_t id,std::uint8_t value) -> void { raw(id,{&value,sizeof(value)}); }
            auto u32(std::uint16_t id,std::uint32_t value) -> void { value=htonl(value); raw(id,u32_bytes(value)); }
            auto nest(std::uint16_t id,auto&& write) -> void {
                auto pos=message_.bytes.size();
                append(nlattr{0,static_cast<std::uint16_t>(id|NLA_F_NESTED)});
                write();
                fill(pos,static_cast<std::uint16_t>(message_.bytes.size()-pos));
            }
            auto expr(std::string_view name,auto&& write) -> void {
                nest(NFTA_LIST_ELEM,[&]{text(NFTA_EXPR_NAME,name); nest(NFTA_EXPR_DATA,write);});
            }
            auto meta(std::uint32_t key) -> void { expr("meta",[&]{u32(NFTA_META_KEY,key);u32(NFTA_META_DREG,reg);}); }
            auto set_meta_mark(std::uint32_t mark) -> void {
                expr("immediate",[&]{u32(NFTA_IMMEDIATE_DREG,reg);nest(NFTA_IMMEDIATE_DATA,[&]{raw(NFTA_DATA_VALUE,u32_bytes(mark));});});
                expr("meta",[&]{u32(NFTA_META_KEY,NFT_META_MARK);u32(NFTA_META_SREG,reg);});
            }
            auto compare(std::span<std::uint8_t const> data,int op=NFT_CMP_EQ) -> void {
                expr("cmp",[&]{u32(NFTA_CMP_SREG,reg);u32(NFTA_CMP_OP,op);nest(NFTA_CMP_DATA,[&]{raw(NFTA_DATA_VALUE,data);});});
            }
            auto payload(std::uint32_t base,std::uint32_t offset,std::size_t length) -> void {
                expr("payload",[&]{u32(NFTA_PAYLOAD_DREG,reg);u32(NFTA_PAYLOAD_BASE,base);u32(NFTA_PAYLOAD_OFFSET,offset);u32(NFTA_PAYLOAD_LEN,length);});
            }
            auto bitwise(std::span<std::uint8_t const> mask) -> void {
                expr("bitwise",[&]{
                    u32(NFTA_BITWISE_SREG,reg);u32(NFTA_BITWISE_DREG,reg);u32(NFTA_BITWISE_LEN,mask.size());
                    nest(NFTA_BITWISE_MASK,[&]{raw(NFTA_DATA_VALUE,mask);});
                    nest(NFTA_BITWISE_XOR,[&]{raw(NFTA_DATA_VALUE,std::span<std::uint8_t const>(std::array<std::uint8_t,16>{}).first(mask.size()));});
                });
            }
            auto matches_mark(RoutingMarkFilter filter,int op=NFT_CMP_EQ) -> void {
                meta(NFT_META_MARK);
                if (filter.mask!=0xffffffffU) bitwise(u32_bytes(filter.mask));
                compare(u32_bytes(filter.mark),op);
            }
            auto uid_range(UidRange const& range) -> void {
                meta(NFT_META_SKUID);
                if (range.min==range.max) compare(u32_bytes(range.min),NFT_CMP_EQ);
                else { compare(u32_bytes(range.min),NFT_CMP_GTE); meta(NFT_META_SKUID); compare(u32_bytes(range.max),NFT_CMP_LTE); }
            }
            auto destination(Prefix const& prefix) -> void {
                meta(NFT_META_NFPROTO); compare(std::array{std::uint8_t(prefix.family==4 ? NFPROTO_IPV4 : NFPROTO_IPV6)});
                auto size=prefix.family==4 ? 4u : 16u;
                payload(NFT_PAYLOAD_NETWORK_HEADER,prefix.family==4 ? 16 : 24,size);
                if (prefix.length!=size*8) {
                    std::array<std::uint8_t,16> mask{};
                    for (unsigned i=0;i<prefix.length;++i) mask[i/8]|=std::uint8_t(128u>>(i%8));
                    bitwise(std::span(mask).first(size));
                }
                compare(std::span(prefix.address).first(size));
            }
            auto lookup_daddr_set(bool ipv6,std::string_view set_name,bool invert) -> void {
                meta(NFT_META_NFPROTO); compare(std::array{std::uint8_t(ipv6 ? NFPROTO_IPV6 : NFPROTO_IPV4)});
                payload(NFT_PAYLOAD_NETWORK_HEADER,ipv6 ? 24 : 16,ipv6 ? 16 : 4);
                expr("lookup",[&]{
                    text(NFTA_LOOKUP_SET,set_name); u32(NFTA_LOOKUP_SREG,reg);
                    if (invert) u32(NFTA_LOOKUP_FLAGS,NFT_LOOKUP_F_INV);
                });
            }
            auto verdict(std::uint32_t code) -> void {
                expr("immediate",[&]{
                    u32(NFTA_IMMEDIATE_DREG,NFT_REG_VERDICT);
                    nest(NFTA_IMMEDIATE_DATA,[&]{nest(NFTA_DATA_VERDICT,[&]{u32(NFTA_VERDICT_CODE,code);});});
                });
            }
            auto leave() -> void { verdict(static_cast<std::uint32_t>(NFT_RETURN)); }
            auto accept() -> void { verdict(static_cast<std::uint32_t>(NF_ACCEPT)); }
            auto redirect(std::uint16_t port) -> void {
                auto value=std::array{std::uint8_t(port>>8),std::uint8_t(port)};
                expr("immediate",[&]{u32(NFTA_IMMEDIATE_DREG,reg);nest(NFTA_IMMEDIATE_DATA,[&]{raw(NFTA_DATA_VALUE,value);});});
                expr("redir",[&]{u32(NFTA_REDIR_REG_PROTO_MIN,reg);});
            }
            auto tproxy(std::uint8_t family,std::uint16_t port) -> void {
                auto value=std::array{std::uint8_t(port>>8),std::uint8_t(port)};
                expr("immediate",[&]{u32(NFTA_IMMEDIATE_DREG,reg);nest(NFTA_IMMEDIATE_DATA,[&]{raw(NFTA_DATA_VALUE,value);});});
                expr("tproxy",[&]{u32(NFTA_TPROXY_FAMILY,family);u32(NFTA_TPROXY_REG_PORT,reg);});
            }
            auto command(std::uint16_t op,bool create) -> void {
                std::uint16_t extra = !create ? 0 : op==NFT_MSG_NEWRULE ? (NLM_F_CREATE|NLM_F_APPEND)
                    : op==NFT_MSG_NEWSETELEM ? NLM_F_CREATE : (NLM_F_CREATE|NLM_F_EXCL);
                header((NFNL_SUBSYS_NFTABLES<<8)|op,NLM_F_REQUEST|NLM_F_ACK|extra,NFPROTO_INET);
            }
            auto open_chain(std::string_view table,std::string_view name,std::string_view type,std::uint32_t hook,std::int32_t prio) -> void {
                command(NFT_MSG_NEWCHAIN,true);
                text(NFTA_CHAIN_TABLE,table); text(NFTA_CHAIN_NAME,name); text(NFTA_CHAIN_TYPE,type);
                nest(NFTA_CHAIN_HOOK,[&]{u32(NFTA_HOOK_HOOKNUM,hook);u32(NFTA_HOOK_PRIORITY,static_cast<std::uint32_t>(prio));});
                end();
            }
            auto emit_rule(std::string_view table,std::string_view chain_name,auto&& match,auto&& action) -> void {
                command(NFT_MSG_NEWRULE,true);
                text(NFTA_RULE_TABLE,table); text(NFTA_RULE_CHAIN,chain_name);
                nest(NFTA_RULE_EXPRESSIONS,[&]{match();action();});
                end();
            }
            auto emit_bypass(std::string_view table,std::string_view chain_name,auto&& match) -> void {
                emit_rule(table,chain_name,match,[&]{leave();});
            }
            template<class Interval>
            auto define_interval_set(std::string_view table,std::string_view name,std::uint32_t id,
                bool ipv6,std::span<Interval const> intervals) -> void {
                command(NFT_MSG_NEWSET,true);
                text(NFTA_SET_TABLE,table); text(NFTA_SET_NAME,name);
                u32(NFTA_SET_FLAGS,NFT_SET_INTERVAL);
                u32(NFTA_SET_KEY_TYPE,ipv6 ? 8u : 7u); u32(NFTA_SET_KEY_LEN,ipv6 ? 16u : 4u); u32(NFTA_SET_ID,id);
                end();
                for (std::size_t off=0; off<intervals.size(); off+=kSetElemChunk) {
                    command(NFT_MSG_NEWSETELEM,true);
                    text(NFTA_SET_ELEM_LIST_TABLE,table); text(NFTA_SET_ELEM_LIST_SET,name);
                    nest(NFTA_SET_ELEM_LIST_ELEMENTS,[&]{
                        for (std::size_t i=off;i<std::min(off+kSetElemChunk,intervals.size());++i) {
                            if constexpr (std::same_as<Interval,V4Interval>) {
                                auto lo=store_be32(intervals[i].start);
                                nest(NFTA_LIST_ELEM,[&]{nest(NFTA_SET_ELEM_KEY,[&]{raw(NFTA_DATA_VALUE,lo);});});
                                if (intervals[i].end!=0xffffffffu) {
                                    auto hi=store_be32(intervals[i].end+1u);
                                    nest(NFTA_LIST_ELEM,[&]{nest(NFTA_SET_ELEM_KEY,[&]{raw(NFTA_DATA_VALUE,hi);});u32(NFTA_SET_ELEM_FLAGS,NFT_SET_ELEM_INTERVAL_END);});
                                }
                            } else {
                                nest(NFTA_LIST_ELEM,[&]{nest(NFTA_SET_ELEM_KEY,[&]{raw(NFTA_DATA_VALUE,intervals[i].start);});});
                                if (auto hi=inc_v6(intervals[i].end)) {
                                    nest(NFTA_LIST_ELEM,[&]{nest(NFTA_SET_ELEM_KEY,[&]{raw(NFTA_DATA_VALUE,*hi);});u32(NFTA_SET_ELEM_FLAGS,NFT_SET_ELEM_INTERVAL_END);});
                                }
                            }
                        }
                    });
                    end();
                }
            }
            auto release() -> Transaction {return std::move(message_);}
        };

        struct SetFlags { bool excl_v4=false, excl_v6=false, incl_v4=false, incl_v6=false, use_excl_sets=false; };

        auto emit_common_filters(Writer& w,std::string_view tbl,std::string_view ch,bool output,Redirect const& o) -> void {
            auto bypass=[&](auto&& m){w.emit_bypass(tbl,ch,m);};
            if (o.ipv4!=o.ipv6) bypass([&]{w.meta(NFT_META_NFPROTO);w.compare(std::array{std::uint8_t(o.ipv4 ? NFPROTO_IPV6 : NFPROTO_IPV4)});});
            bypass([&]{w.matches_mark({o.socket_mark});});
            if (o.reset_mark) bypass([&]{w.matches_mark({o.reset_mark});});
            bypass([&]{constexpr std::array<std::uint8_t,16> lo{'l','o'}; w.meta(output ? NFT_META_OIFNAME : NFT_META_IIFNAME); w.compare(lo);});
            for (auto const& iface : o.exclude_interfaces) bypass([&]{
                w.meta(output ? NFT_META_OIFNAME : NFT_META_IIFNAME);
                w.compare({reinterpret_cast<std::uint8_t const*>(iface.data()),iface.size()});
            });
            if (!o.include_interfaces.empty()) bypass([&]{
                for (auto const& iface : o.include_interfaces) {
                    w.meta(output ? NFT_META_OIFNAME : NFT_META_IIFNAME);
                    w.compare({reinterpret_cast<std::uint8_t const*>(iface.data()),iface.size()},NFT_CMP_NEQ);
                }
            });
            if (!output) {
                static constexpr std::uint16_t kEther = ARPHRD_ETHER;
                for (auto const& mac : o.exclude_macs) bypass([&]{
                    w.meta(NFT_META_IIFTYPE); w.compare(u16_bytes(kEther));
                    w.payload(NFT_PAYLOAD_LL_HEADER,6,6); w.compare(mac);
                });
                if (!o.include_macs.empty()) {
                    bypass([&]{ w.meta(NFT_META_IIFTYPE); w.compare(u16_bytes(kEther),NFT_CMP_NEQ); });
                    bypass([&]{
                        w.meta(NFT_META_IIFTYPE); w.compare(u16_bytes(kEther));
                        for (auto const& mac : o.include_macs) { w.payload(NFT_PAYLOAD_LL_HEADER,6,6); w.compare(mac,NFT_CMP_NEQ); }
                    });
                }
            }
            if (o.exclude_mark) bypass([&]{w.matches_mark(*o.exclude_mark);});
            if (o.include_mark) bypass([&]{w.matches_mark(*o.include_mark,NFT_CMP_NEQ);});
            if (output) for (auto const& range : o.exclude_uids) bypass([&]{w.uid_range(range);});
        }

        auto emit_dest_filters(Writer& w,std::string_view tbl,std::string_view ch,Redirect const& o,SetFlags const& s) -> void {
            auto bypass=[&](auto&& m){w.emit_bypass(tbl,ch,m);};
            if (s.use_excl_sets) {
                if (s.excl_v4) bypass([&]{w.lookup_daddr_set(false,"excl_v4",false);});
                if (s.excl_v6) bypass([&]{w.lookup_daddr_set(true,"excl_v6",false);});
            } else {
                for (auto const& prefix : o.excludes) bypass([&]{w.destination(prefix);});
            }
            if (!o.includes.empty()) {
                if (o.ipv4) {
                    if (s.incl_v4) bypass([&]{w.lookup_daddr_set(false,"incl_v4",true);});
                    else bypass([&]{w.meta(NFT_META_NFPROTO);w.compare(std::array{std::uint8_t(NFPROTO_IPV4)});});
                }
                if (o.ipv6) {
                    if (s.incl_v6) bypass([&]{w.lookup_daddr_set(true,"incl_v6",true);});
                    else bypass([&]{w.meta(NFT_META_NFPROTO);w.compare(std::array{std::uint8_t(NFPROTO_IPV6)});});
                }
            }
        }

        auto chain(Writer& w,std::string_view tbl,std::string_view name,bool output,Redirect const& o,SetFlags const& s) -> void {
            w.open_chain(tbl,name,"nat",output ? NF_INET_LOCAL_OUT : NF_INET_PRE_ROUTING,-101);
            auto rule=[&](auto&& m,auto&& a){w.emit_rule(tbl,name,m,a);};
            auto bypass=[&](auto&& m){w.emit_bypass(tbl,name,m);};
            auto tcp=[&]{w.meta(NFT_META_L4PROTO);w.compare(std::array{std::uint8_t(IPPROTO_TCP)});};
            auto active_mark = output ? o.output_mark : o.input_mark;
            auto divert=[&]{ if (active_mark) w.set_meta_mark(active_mark); w.redirect(o.port); };
            bypass([&]{w.meta(NFT_META_L4PROTO);w.compare(std::array{std::uint8_t(IPPROTO_TCP)},NFT_CMP_NEQ);});
            if (o.exclude_mptcp) bypass([&]{
                w.expr("exthdr",[&]{
                    w.u32(NFTA_EXTHDR_DREG,reg);w.u8(NFTA_EXTHDR_TYPE,30);
                    w.u32(NFTA_EXTHDR_OFFSET,0);w.u32(NFTA_EXTHDR_LEN,1);
                    w.u32(NFTA_EXTHDR_FLAGS,NFT_EXTHDR_F_PRESENT);w.u32(NFTA_EXTHDR_OP,NFT_EXTHDR_OP_TCPOPT);
                });
                w.compare(std::array{std::uint8_t(1)});
            });
            emit_common_filters(w,tbl,name,output,o);
            if (!output && (!o.protected_destinations.empty() || o.port==53))
                for (auto const& prefix : o.local_destinations)
                    bypass([&]{
                        tcp();w.destination(prefix);w.payload(NFT_PAYLOAD_TRANSPORT_HEADER,2,2);
                        w.compare(std::array{static_cast<std::uint8_t>(o.port>>8),static_cast<std::uint8_t>(o.port)});
                    });
            for (auto const& prefix : o.protected_destinations) rule([&]{tcp();w.destination(prefix);},divert);
            if (o.intercept_dns && o.port!=53)
                rule([&]{tcp();w.payload(NFT_PAYLOAD_TRANSPORT_HEADER,2,2);w.compare(std::array<std::uint8_t,2>{0,53});},divert);
            if (!output) for (auto const& prefix : o.local_destinations) bypass([&]{w.destination(prefix);});
            emit_dest_filters(w,tbl,name,o,s);
            if (output && !o.include_uids.empty())
                for (auto const& range : o.include_uids) rule([&]{tcp();w.uid_range(range);},divert);
            else rule(tcp,divert);
        }

        auto tproxy_chain(Writer& w,std::string_view tbl,std::string_view name,bool output,Redirect const& o,SetFlags const& s) -> void {
            w.open_chain(tbl,name,output ? "route" : "filter",output ? NF_INET_LOCAL_OUT : NF_INET_PRE_ROUTING,-150);
            auto rule=[&](auto&& m,auto&& a){w.emit_rule(tbl,name,m,a);};
            auto udp=[&]{w.meta(NFT_META_L4PROTO);w.compare(std::array{std::uint8_t(IPPROTO_UDP)});};
            std::uint16_t port = o.tproxy_port ? o.tproxy_port : o.port;
            w.emit_bypass(tbl,name,[&]{w.meta(NFT_META_L4PROTO);w.compare(std::array{std::uint8_t(IPPROTO_UDP)},NFT_CMP_NEQ);});
            if (!output) {
                // Locally-originated UDP marked in tproxy_output re-enters prerouting on "lo":
                // divert before emit_common_filters's iifname=="lo" bypass!
                constexpr std::array<std::uint8_t,16> lo{'l','o'};
                auto emit_lo_tp=[&](std::uint8_t fam){
                    rule([&]{w.meta(NFT_META_IIFNAME);w.compare(lo);w.matches_mark({o.tproxy_mark});
                             w.meta(NFT_META_NFPROTO);w.compare(std::array{fam});udp();},
                         [&]{w.tproxy(fam,port);w.accept();});
                };
                if (o.ipv4) emit_lo_tp(NFPROTO_IPV4);
                if (o.ipv6) emit_lo_tp(NFPROTO_IPV6);
            }
            emit_common_filters(w,tbl,name,output,o);
            if (!output && (!o.protected_destinations.empty() || port==53))
                for (auto const& prefix : o.local_destinations)
                    w.emit_bypass(tbl,name,[&]{
                        udp();w.destination(prefix);w.payload(NFT_PAYLOAD_TRANSPORT_HEADER,2,2);
                        w.compare(std::array{static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)});
                    });
            for (auto const& prefix : o.protected_destinations) {
                if ((prefix.family==4 && o.ipv4) || (prefix.family==6 && o.ipv6)) {
                    std::uint8_t fam = prefix.family==4 ? NFPROTO_IPV4 : NFPROTO_IPV6;
                    if (output) rule([&]{udp();w.destination(prefix);},[&]{w.set_meta_mark(o.tproxy_mark);});
                    else rule([&]{udp();w.destination(prefix);},[&]{w.set_meta_mark(o.tproxy_mark);w.tproxy(fam,port);w.accept();});
                }
            }
            if (o.intercept_udp_dns && port!=53) {
                auto dns53=[&]{w.payload(NFT_PAYLOAD_TRANSPORT_HEADER,2,2);w.compare(std::array<std::uint8_t,2>{0,53});};
                if (output) rule([&]{udp();dns53();},[&]{w.set_meta_mark(o.tproxy_mark);});
                else {
                    auto divert_dns=[&](std::uint8_t fam){
                        rule([&]{w.meta(NFT_META_NFPROTO);w.compare(std::array{fam});udp();dns53();},
                             [&]{w.set_meta_mark(o.tproxy_mark);w.tproxy(fam,port);w.accept();});
                    };
                    if (o.ipv4) divert_dns(NFPROTO_IPV4);
                    if (o.ipv6) divert_dns(NFPROTO_IPV6);
                }
            }
            if (!output) for (auto const& prefix : o.local_destinations) w.emit_bypass(tbl,name,[&]{w.destination(prefix);});
            emit_dest_filters(w,tbl,name,o,s);
            if (output) {
                auto mark_udp=[&]{w.set_meta_mark(o.tproxy_mark);};
                if (!o.include_uids.empty()) for (auto const& r : o.include_uids) rule([&]{udp();w.uid_range(r);},mark_udp);
                else rule(udp,mark_udp);
            } else {
                auto emit_tp=[&](std::uint8_t fam){
                    rule([&]{w.meta(NFT_META_NFPROTO);w.compare(std::array{fam});udp();},
                         [&]{w.set_meta_mark(o.tproxy_mark);w.tproxy(fam,port);w.accept();});
                };
                if (o.ipv4) emit_tp(NFPROTO_IPV4);
                if (o.ipv6) emit_tp(NFPROTO_IPV6);
            }
        }
    }

    auto encode(std::string_view table,Redirect const* redirect,std::uint32_t first,bool replace_existing)
        -> std::expected<Transaction,std::error_code> {
        auto valid_prefix=[](Prefix const& p, bool allow_default = false) {
            if ((!allow_default && !p.length) || (p.family!=4 && p.family!=6) || p.length>(p.family==4 ? 32 : 128)) return false;
            for (unsigned bit=p.length;bit<128;++bit) if (p.address[bit/8]&(128u>>(bit%8))) return false;
            return true;
        };
        auto valid_ifname=[](std::array<char,16> const& name) {
            auto nul=std::ranges::find(name,'\0');
            return name[0]!='\0' && nul!=name.end() &&
                std::ranges::all_of(std::span(name).subspan(static_cast<std::size_t>(nul-name.begin())),[](char c){return c=='\0';});
        };
        auto valid_uid=[](UidRange const& r){return r.min<=r.max;};
        if (!table.starts_with("nexus_auto_redirect_") || table.size()>63 ||
            !std::ranges::all_of(table,[](char c){return c=='_'||(c>='0'&&c<='9')||(c>='a'&&c<='z');}) ||
            !first || first>std::numeric_limits<std::uint32_t>::max()-65536 ||
            (redirect && (!redirect->port || !redirect->socket_mark || (!redirect->ipv4 && !redirect->ipv6) ||
                (redirect->include_mark && !redirect->include_mark->valid()) ||
                (redirect->exclude_mark && !redirect->exclude_mark->valid()) ||
                redirect->excludes.size()>kMaxCidrs || redirect->includes.size()>kMaxCidrs ||
                redirect->protected_destinations.size()>2 || redirect->local_destinations.size()>32 ||
                redirect->include_uids.size()>16 || redirect->exclude_uids.size()>16 ||
                redirect->include_interfaces.size()>8 || redirect->exclude_interfaces.size()>8 ||
                redirect->include_macs.size()>16 || redirect->exclude_macs.size()>16 ||
                !std::ranges::all_of(redirect->excludes,[&](auto const& p){return valid_prefix(p,false);}) ||
                !std::ranges::all_of(redirect->includes,[&](auto const& p){return valid_prefix(p,true);}) ||
                !std::ranges::all_of(redirect->local_destinations,[&](auto const& p){return valid_prefix(p,false);}) ||
                !std::ranges::all_of(redirect->protected_destinations,[&](auto const& p){return valid_prefix(p,false);}) ||
                !std::ranges::all_of(redirect->include_uids,valid_uid) ||
                !std::ranges::all_of(redirect->exclude_uids,valid_uid) ||
                !std::ranges::all_of(redirect->include_interfaces,valid_ifname) ||
                !std::ranges::all_of(redirect->exclude_interfaces,valid_ifname))))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        Writer writer(first);
        writer.fence(NFNL_MSG_BATCH_BEGIN);
        if (replace_existing && redirect) {
            writer.command(NFT_MSG_DELTABLE,false); writer.text(NFTA_TABLE_NAME,table); writer.end();
        }
        writer.command(redirect ? NFT_MSG_NEWTABLE : NFT_MSG_DELTABLE,redirect!=nullptr);
        writer.text(NFTA_TABLE_NAME,table);
        if (redirect) writer.u32(NFTA_TABLE_FLAGS,NFT_TABLE_F_OWNER);
        writer.end();
        if (redirect) {
            SetFlags sets{.use_excl_sets=redirect->excludes.size()>kInlineExcludeLimit};
            std::uint32_t sid=1;
            if (sets.use_excl_sets) {
                auto v4=redirect->ipv4 ? merge_v4(redirect->excludes) : std::vector<V4Interval>{};
                auto v6=redirect->ipv6 ? merge_v6(redirect->excludes) : std::vector<V6Interval>{};
                if (!v4.empty()) { sets.excl_v4=true; writer.define_interval_set<V4Interval>(table,"excl_v4",sid++,false,v4); }
                if (!v6.empty()) { sets.excl_v6=true; writer.define_interval_set<V6Interval>(table,"excl_v6",sid++,true,v6); }
            }
            if (!redirect->includes.empty()) {
                auto v4=redirect->ipv4 ? merge_v4(redirect->includes) : std::vector<V4Interval>{};
                auto v6=redirect->ipv6 ? merge_v6(redirect->includes) : std::vector<V6Interval>{};
                if (!v4.empty()) { sets.incl_v4=true; writer.define_interval_set<V4Interval>(table,"incl_v4",sid++,false,v4); }
                if (!v6.empty()) { sets.incl_v6=true; writer.define_interval_set<V6Interval>(table,"incl_v6",sid++,true,v6); }
            }
            chain(writer,table,"output",true,*redirect,sets);
            chain(writer,table,"prerouting",false,*redirect,sets);
            if (redirect->tproxy_mark) {
                tproxy_chain(writer,table,"tproxy_output",true,*redirect,sets);
                tproxy_chain(writer,table,"tproxy_prerouting",false,*redirect,sets);
            }
        }
        writer.fence(NFNL_MSG_BATCH_END);
        return writer.release();
    }
}
