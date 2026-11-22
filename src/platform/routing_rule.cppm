export module platform.routing_rule;
import std;
import platform.netlink_abi;
import platform.netlink_codec;

export namespace platform::routing {
    namespace a=netlink_abi;
    namespace n=netlink;
    struct DestinationPrefix {
        std::array<std::uint8_t,16> address{};
        std::uint8_t length=0;
        auto operator==(DestinationPrefix const&) const -> bool = default;
    };
    struct Rule {
        std::uint8_t family=0,action=0,protocol=0;
        std::uint32_t table=0,priority=0,mark=0,mask=0,flags=0;
        std::optional<std::uint32_t> suppress_prefix;
        bool complex=false;
        std::optional<DestinationPrefix> destination;
        std::optional<std::uint8_t> ip_protocol;
        std::optional<std::array<std::uint16_t,2>> destination_ports;
        auto operator==(Rule const&) const -> bool = default;
    };
    [[nodiscard]] inline auto parse_rule(n::Message message) -> std::expected<Rule,n::Failure> {
        auto header=n::native<a::fib_rule_hdr>(message.payload);
        if(message.header.nlmsg_type!=a::RTM_NEWRULE || !header || (header->family!=a::AF_INET && header->family!=a::AF_INET6))return n::fail(n::Error::protocol);
        auto width=header->family==a::AF_INET ? 32u:128u;
        if(header->dst_len>width || header->src_len>width)return n::fail(n::Error::protocol);
        Rule result{.family=header->family==a::AF_INET?std::uint8_t{4}:std::uint8_t{6},.action=header->action,.table=header->table,.flags=header->flags,
                    .complex=bool(header->src_len || header->tos || header->res1 || header->res2)};
        bool table=false,priority=false,mark=false,mask=false,protocol=false,suppress=false,port_mask=false;
        auto parsed=n::attributes(message.payload.subspan(sizeof(*header)),[&](n::Attribute attribute) -> std::expected<void,n::Failure> {
            if(attribute.type==a::FRA_TABLE || attribute.type==a::FRA_PRIORITY || attribute.type==a::FRA_FWMARK || attribute.type==a::FRA_FWMASK || attribute.type==a::FRA_SUPPRESS_PREFIXLEN) {
                auto value=n::scalar<std::uint32_t>(attribute);if(!value)return std::unexpected(value.error());
                if(attribute.type==a::FRA_TABLE) {
                    if(table || (header->table && header->table!=*value && !(header->table==a::RT_TABLE_COMPAT && *value>255)))return n::fail(n::Error::protocol);
                    table=true;result.table=*value;
                } else if(attribute.type==a::FRA_PRIORITY) {
                    if(priority)return n::fail(n::Error::protocol);priority=true;result.priority=*value;
                } else if(attribute.type==a::FRA_FWMARK) {
                    if(mark)return n::fail(n::Error::protocol);mark=true;result.mark=*value;
                } else if(attribute.type==a::FRA_FWMASK) {
                    if(mask)return n::fail(n::Error::protocol);mask=true;result.mask=*value;
                } else {
                    if(suppress || (*value>width && *value!=std::numeric_limits<std::uint32_t>::max()))return n::fail(n::Error::protocol);
                    suppress=true;
                    // Native dumps encode disabled suppression as UINT_MAX.
                    if(*value!=std::numeric_limits<std::uint32_t>::max())result.suppress_prefix=*value;
                }
            } else if(attribute.type==a::FRA_PROTOCOL) {
                auto value=n::scalar<std::uint8_t>(attribute);if(protocol || !value)return n::fail(n::Error::protocol);
                protocol=true;result.protocol=*value;
            } else if (attribute.type==a::FRA_DST) {
                if (result.destination || attribute.flags || attribute.bytes.size()!=width/8 || !header->dst_len)
                    return n::fail(n::Error::protocol);
                result.destination.emplace();
                result.destination->length=header->dst_len;
                std::ranges::copy(attribute.bytes,result.destination->address.begin());
            } else if (attribute.type==a::FRA_IP_PROTO) {
                auto value=n::scalar<std::uint8_t>(attribute);
                if (!value || result.ip_protocol) return n::fail(n::Error::protocol);
                if (*value) result.ip_protocol=*value;
            } else if (attribute.type==a::FRA_DPORT_RANGE) {
                auto range=n::scalar<std::array<std::uint16_t,2>>(attribute);
                if (!range || result.destination_ports) return n::fail(n::Error::protocol);
                if ((*range)[0] || (*range)[1]) result.destination_ports=*range;
            } else if (attribute.type==a::FRA_DPORT_MASK) {
                auto value=n::scalar<std::uint16_t>(attribute);
                if (!value || port_mask) return n::fail(n::Error::protocol);
                port_mask=true;
                // Newer kernels report the implicit exact-match mask.
                result.complex|=*value!=std::numeric_limits<std::uint16_t>::max();
            } else result.complex=true;
            return {};
        });
        if(!parsed)return std::unexpected(parsed.error());
        if (header->dst_len && !result.destination) return n::fail(n::Error::protocol);
        if (port_mask && (!result.destination_ports || (*result.destination_ports)[0]!=(*result.destination_ports)[1]))
            result.complex=true;
        // Kernel defaults a nonzero mark's absent mask to all bits.
        if(mark && result.mark && !mask)result.mask=std::numeric_limits<std::uint32_t>::max();
        return result;
    }
    [[nodiscard]] inline auto rule_request(Rule const& rule,bool add) -> n::Request {
        a::fib_rule_hdr header{.family=rule.family==4?std::uint8_t(a::AF_INET):std::uint8_t(a::AF_INET6),
            .dst_len=rule.destination ? rule.destination->length : std::uint8_t{},
            .table=rule.table<256?static_cast<std::uint8_t>(rule.table):std::uint8_t(a::RT_TABLE_UNSPEC),.action=rule.action,.flags=rule.flags};
        n::Request request(add?a::RTM_NEWRULE:a::RTM_DELRULE,a::NLM_F_REQUEST|a::NLM_F_ACK|(add?a::NLM_F_CREATE|a::NLM_F_EXCL:0),header);
        request.scalar(a::FRA_PRIORITY,rule.priority);
        request.scalar(a::FRA_TABLE,rule.table);
        request.scalar(a::FRA_PROTOCOL,rule.protocol);
        if (rule.destination)
            request.append(a::FRA_DST,std::span(rule.destination->address).first(rule.family==4 ? 4 : 16));
        if(rule.mask || rule.mark) {request.scalar(a::FRA_FWMARK,rule.mark);request.scalar(a::FRA_FWMASK,rule.mask);}
        if(rule.ip_protocol)request.scalar(a::FRA_IP_PROTO,*rule.ip_protocol);
        if(rule.destination_ports)request.scalar(a::FRA_DPORT_RANGE,*rule.destination_ports);
        if(rule.suppress_prefix)request.scalar(a::FRA_SUPPRESS_PREFIXLEN,*rule.suppress_prefix);
        return request;
    }
    [[nodiscard]] inline auto same_selector(Rule const& left,Rule const& right) noexcept -> bool {
        return left.family==right.family && left.priority==right.priority;
    }
    [[nodiscard]] inline auto selects_mark(Rule const& rule,std::uint32_t mark) noexcept -> bool {
        auto matched=((rule.mark^mark)&rule.mask)==0;
        return rule.flags&a::FIB_RULE_INVERT ? !matched:matched;
    }
}
