import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.netlink_watch;
import platform.routing_rule;
import nexus.test.lease_support;
namespace {
    namespace a = ::platform::netlink_abi;
    namespace n = ::platform::netlink;
    namespace r = ::platform::routing;
    namespace t=nexus::test::lease;
    using Clock=std::chrono::steady_clock;
    struct Event {std::uint16_t type;std::uint32_t port,sequence;r::Rule rule;};
    auto events(n::Watch& watch) -> std::inplace_vector<Event,16> {
        std::inplace_vector<Event,16> values;
        std::array<std::uint8_t,65536> input;
        auto drained=watch.drain(input,[&](n::Message message) -> std::expected<void,n::Failure> {
            if(message.header.nlmsg_type!=a::RTM_NEWRULE && message.header.nlmsg_type!=a::RTM_DELRULE)return n::fail(n::Error::protocol);
            auto copy=message;copy.header.nlmsg_type=a::RTM_NEWRULE;
            auto parsed=r::parse_rule(copy);if(!parsed)return std::unexpected(parsed.error());
            if(values.size()==values.capacity())return n::fail(n::Error::limit);
            values.push_back({message.header.nlmsg_type,message.header.nlmsg_pid,message.header.nlmsg_seq,*parsed});return {};
        });t::require(drained.has_value());return values;
    }
    auto count(n::Socket<>& socket,r::Rule const& rule) -> unsigned {
        unsigned found=0;
        auto result=socket.dump(a::RTM_GETRULE,rule.family==4?a::AF_INET:a::AF_INET6,Clock::now()+std::chrono::seconds(2),[&](n::Message message)->std::expected<void,n::Failure> {
            auto value=r::parse_rule(message);if(!value){
                std::println("rule parse rejected native payload bytes={} type={}",message.payload.size(),message.header.nlmsg_type);
                for(auto byte:message.payload)std::print("{:02x}",byte);std::println("");
                return std::unexpected(value.error());
            }
            if(r::same_selector(*value,rule)){t::require(*value==rule);++found;}return {};
        });t::require(result.has_value());return found;
    }
}
auto main(int argc,char**argv) -> int {
    try {
        t::isolation(argc,argv);n::Watch watch;std::array groups{a::RTNLGRP_IPV4_RULE,a::RTNLGRP_IPV6_RULE};t::require(watch.open(groups).has_value());
        n::Socket<> first,second;t::require(first.open().has_value()&&second.open().has_value()&&first.port_id()!=second.port_id());
        for(auto family:{4,6}) {
            r::Rule rule{.family=static_cast<std::uint8_t>(family),.action=a::FR_ACT_TO_TBL,.protocol=186,.table=60000,.priority=10000,.mark=0x6e780001,.mask=0xffffffffU,.flags=a::FIB_RULE_INVERT};
            t::require(!count(first,rule));auto sequence=first.sequence()+1;
            t::require(first.acknowledge(r::rule_request(rule,true),Clock::now()+std::chrono::seconds(2)).has_value());
            auto own=events(watch);t::require(own.size()==1&&own[0].type==a::RTM_NEWRULE&&own[0].rule==rule);
            std::println("own rule IPv{} notification port={} expected={} seq={} expected={}",family,own[0].port,first.port_id(),own[0].sequence,sequence);
            t::require(own[0].port==first.port_id()&&own[0].sequence==sequence&&count(first,rule)==1);
            auto duplicate=first.acknowledge(r::rule_request(rule,true),Clock::now()+std::chrono::seconds(2));
            t::require(!duplicate&&duplicate.error().rejected&&duplicate.error().system==std::errc::file_exists&&count(first,rule)==1&&events(watch).empty());
            auto foreign_sequence=second.sequence()+1;
            t::require(second.acknowledge(r::rule_request(rule,false),Clock::now()+std::chrono::seconds(2)).has_value());
            t::require(second.acknowledge(r::rule_request(rule,true),Clock::now()+std::chrono::seconds(2)).has_value());
            auto replacement=events(watch);t::require(replacement.size()==2&&replacement[0].type==a::RTM_DELRULE&&replacement[1].type==a::RTM_NEWRULE&&count(first,rule)==1);
            t::require(replacement[0].port==second.port_id()&&replacement[1].port==second.port_id()&&replacement[0].sequence==foreign_sequence&&replacement[1].sequence==foreign_sequence+1);
            t::require(second.acknowledge(r::rule_request(rule,false),Clock::now()+std::chrono::seconds(2)).has_value());(void)events(watch);t::require(!count(first,rule));
        }
        std::println("native dual-family rules: exact ACK/readback, EXCL duplicate reject, multicast origin port/sequence and externally identical delete+recreate observable; Watch={} Socket={}",sizeof(n::Watch),sizeof(n::Socket<>));
    }catch(int code){return code;}
}
