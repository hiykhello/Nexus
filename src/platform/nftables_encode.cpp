module;
#include <netinet/in.h>
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
            auto fence(std::uint16_t type) -> void {
                header(type,NLM_F_REQUEST,AF_UNSPEC,NFNL_SUBSYS_NFTABLES);
                end();
            }
            auto raw(std::uint16_t id,std::span<std::uint8_t const> bytes) -> void {
                append(nlattr{static_cast<std::uint16_t>(sizeof(nlattr)+bytes.size()),id});
                message_.bytes.insert(message_.bytes.end(),bytes.begin(),bytes.end());
                message_.bytes.resize(NLA_ALIGN(message_.bytes.size()));
            }
            auto text(std::uint16_t id,std::string_view value) -> void {
                std::string terminated(value);
                raw(id,{reinterpret_cast<std::uint8_t const*>(terminated.c_str()),terminated.size()+1});
            }
            auto u8(std::uint16_t id,std::uint8_t value) -> void {
                raw(id,{&value,sizeof(value)});
            }
            auto u32(std::uint16_t id,std::uint32_t value) -> void {
                value=htonl(value);
                raw(id,{reinterpret_cast<std::uint8_t const*>(&value),sizeof(value)});
            }
            auto nest(std::uint16_t id,auto&& write) -> void {
                auto pos=message_.bytes.size();
                append(nlattr{0,static_cast<std::uint16_t>(id|NLA_F_NESTED)});
                write();
                fill(pos,static_cast<std::uint16_t>(message_.bytes.size()-pos));
            }
            auto expr(std::string_view name,auto&& write) -> void {
                nest(NFTA_LIST_ELEM,[&] {
                    text(NFTA_EXPR_NAME,name);
                    nest(NFTA_EXPR_DATA,write);
                });
            }
            auto meta(std::uint32_t key) -> void {
                expr("meta",[&] {u32(NFTA_META_KEY,key);u32(NFTA_META_DREG,reg);});
            }
            auto compare(std::span<std::uint8_t const> data,int op=NFT_CMP_EQ) -> void {
                expr("cmp",[&] {
                    u32(NFTA_CMP_SREG,reg);u32(NFTA_CMP_OP,op);
                    nest(NFTA_CMP_DATA,[&] {raw(NFTA_DATA_VALUE,data);});
                });
            }
            auto payload(std::uint32_t base,std::uint32_t offset,std::size_t length) -> void {
                expr("payload",[&] {
                    u32(NFTA_PAYLOAD_DREG,reg);u32(NFTA_PAYLOAD_BASE,base);
                    u32(NFTA_PAYLOAD_OFFSET,offset);u32(NFTA_PAYLOAD_LEN,length);
                });
            }
            auto bitwise(std::span<std::uint8_t const> mask) -> void {
                expr("bitwise",[&] {
                    u32(NFTA_BITWISE_SREG,reg);u32(NFTA_BITWISE_DREG,reg);u32(NFTA_BITWISE_LEN,mask.size());
                    nest(NFTA_BITWISE_MASK,[&] {raw(NFTA_DATA_VALUE,mask);});
                    nest(NFTA_BITWISE_XOR,[&] {raw(NFTA_DATA_VALUE,std::span<std::uint8_t const>(std::array<std::uint8_t,16>{}).first(mask.size()));});
                });
            }
            auto matches_mark(RoutingMarkFilter filter,int op=NFT_CMP_EQ) -> void {
                auto bytes=[](std::uint32_t const& value) {
                    return std::span(reinterpret_cast<std::uint8_t const*>(&value),sizeof value);
                };
                meta(NFT_META_MARK);
                if (filter.mask!=0xffffffffU) bitwise(bytes(filter.mask));
                compare(bytes(filter.mark),op);
            }
            auto destination(Prefix const& prefix) -> void {
                auto family=std::array{std::uint8_t(prefix.family==4 ? NFPROTO_IPV4 : NFPROTO_IPV6)};
                meta(NFT_META_NFPROTO);compare(family);
                auto size=prefix.family==4 ? 4u : 16u;
                payload(NFT_PAYLOAD_NETWORK_HEADER,prefix.family==4 ? 16 : 24,size);
                if (prefix.length!=size*8) {
                    std::array<std::uint8_t,16> mask{};
                    for (unsigned i=0;i<prefix.length;++i) mask[i/8]|=std::uint8_t(128u>>(i%8));
                    bitwise(std::span(mask).first(size));
                }
                compare(std::span(prefix.address).first(size));
            }
            auto leave() -> void {
                expr("immediate",[&] {
                    u32(NFTA_IMMEDIATE_DREG,NFT_REG_VERDICT);
                    nest(NFTA_IMMEDIATE_DATA,[&] {
                        nest(NFTA_DATA_VERDICT,[&] {u32(NFTA_VERDICT_CODE,static_cast<std::uint32_t>(NFT_RETURN));});
                    });
                });
            }
            auto redirect(std::uint16_t port) -> void {
                auto value=std::array{std::uint8_t(port>>8),std::uint8_t(port)};
                expr("immediate",[&] {
                    u32(NFTA_IMMEDIATE_DREG,reg);
                    nest(NFTA_IMMEDIATE_DATA,[&] {raw(NFTA_DATA_VALUE,value);});
                });
                expr("redir",[&] {u32(NFTA_REDIR_REG_PROTO_MIN,reg);});
            }
            auto command(std::uint16_t op,bool create) -> void {
                header((NFNL_SUBSYS_NFTABLES<<8)|op,NLM_F_REQUEST|NLM_F_ACK|
                    (create ? NLM_F_CREATE|(op==NFT_MSG_NEWRULE ? NLM_F_APPEND : NLM_F_EXCL) : 0),NFPROTO_INET);
            }
            auto release() -> Transaction {return std::move(message_);}
        };
        auto chain(Writer& writer,std::string_view table,std::string_view name,bool output,Redirect const& options) -> void {
            writer.command(NFT_MSG_NEWCHAIN,true);
            writer.text(NFTA_CHAIN_TABLE,table);
            writer.text(NFTA_CHAIN_NAME,name);
            writer.text(NFTA_CHAIN_TYPE,"nat");
            writer.nest(NFTA_CHAIN_HOOK,[&] {
                writer.u32(NFTA_HOOK_HOOKNUM,output ? NF_INET_LOCAL_OUT : NF_INET_PRE_ROUTING);
                writer.u32(NFTA_HOOK_PRIORITY,static_cast<std::uint32_t>(-101));
            });
            writer.end();
            auto rule=[&](auto&& match,auto&& action) {
                writer.command(NFT_MSG_NEWRULE,true);
                writer.text(NFTA_RULE_TABLE,table);writer.text(NFTA_RULE_CHAIN,name);
                writer.nest(NFTA_RULE_EXPRESSIONS,[&] {match();action();});
                writer.end();
            };
            auto bypass=[&](auto&& match) {rule(match,[&] {writer.leave();});};
            auto tcp=[&] {writer.meta(NFT_META_L4PROTO);writer.compare(std::array{std::uint8_t(IPPROTO_TCP)});};
            auto divert=[&] {writer.redirect(options.port);};
            bypass([&] {writer.meta(NFT_META_L4PROTO);writer.compare(std::array{std::uint8_t(IPPROTO_TCP)},NFT_CMP_NEQ);});
            if (options.exclude_mptcp) bypass([&] {
                writer.expr("exthdr",[&] {
                    writer.u32(NFTA_EXTHDR_DREG,reg);
                    writer.u8(NFTA_EXTHDR_TYPE,30); // RFC 8684 TCPOPT_MPTCP
                    writer.u32(NFTA_EXTHDR_OFFSET,0);
                    writer.u32(NFTA_EXTHDR_LEN,1);
                    writer.u32(NFTA_EXTHDR_FLAGS,NFT_EXTHDR_F_PRESENT);
                    writer.u32(NFTA_EXTHDR_OP,NFT_EXTHDR_OP_TCPOPT);
                });
                writer.compare(std::array{std::uint8_t(1)});
            });
            if (options.ipv4!=options.ipv6) bypass([&] {
                writer.meta(NFT_META_NFPROTO);
                writer.compare(std::array{std::uint8_t(options.ipv4 ? NFPROTO_IPV6 : NFPROTO_IPV4)});
            });
            bypass([&] {writer.matches_mark({options.socket_mark});});
            bypass([&] {
                constexpr std::array<std::uint8_t,16> loopback{'l','o'};
                writer.meta(output ? NFT_META_OIFNAME : NFT_META_IIFNAME);
                writer.compare(loopback);
            });
            if (!output) for (auto const& prefix:options.local_destinations)
                bypass([&] {writer.destination(prefix);});
            if (options.exclude_mark) bypass([&] {writer.matches_mark(*options.exclude_mark);});
            if (options.include_mark) bypass([&] {writer.matches_mark(*options.include_mark,NFT_CMP_NEQ);});
            for (auto const& prefix:options.protected_destinations)
                rule([&] {tcp();writer.destination(prefix);},divert);
            if (options.intercept_dns) rule([&] {
                tcp();writer.payload(NFT_PAYLOAD_TRANSPORT_HEADER,2,2);
                writer.compare(std::array<std::uint8_t,2>{0,53});
            },divert);
            for (auto const& prefix:options.excludes) bypass([&] {writer.destination(prefix);});
            rule(tcp,divert);
        }
    }

    auto encode(std::string_view table,Redirect const* redirect,std::uint32_t first)
        -> std::expected<Transaction,std::error_code> {
        auto valid_prefix=[](Prefix const& prefix) {
            if (!prefix.length || (prefix.family!=4 && prefix.family!=6) ||
                prefix.length>(prefix.family==4 ? 32 : 128)) return false;
            for (unsigned bit=prefix.length;bit<128;++bit)
                if (prefix.address[bit/8]&(128u>>(bit%8))) return false;
            return true;
        };
        if (!table.starts_with("nexus_auto_redirect_") || table.size()>63 ||
            !std::ranges::all_of(table,[](char c) {return c=='_' || (c>='0' && c<='9') || (c>='a' && c<='z');}) ||
            !first || first>std::numeric_limits<std::uint32_t>::max()-128 ||
            (redirect && (!redirect->port || !redirect->socket_mark || (!redirect->ipv4 && !redirect->ipv6) ||
                (redirect->include_mark && !redirect->include_mark->valid()) ||
                (redirect->exclude_mark && !redirect->exclude_mark->valid()) ||
                redirect->excludes.size()>32 || redirect->protected_destinations.size()>2 ||
                redirect->local_destinations.size()>32 ||
                !std::ranges::all_of(redirect->excludes,valid_prefix) ||
                !std::ranges::all_of(redirect->local_destinations,valid_prefix) ||
                !std::ranges::all_of(redirect->protected_destinations,valid_prefix))))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        Writer writer(first);
        writer.fence(NFNL_MSG_BATCH_BEGIN);
        writer.command(redirect ? NFT_MSG_NEWTABLE : NFT_MSG_DELTABLE,redirect!=nullptr);
        writer.text(NFTA_TABLE_NAME,table);
        if (redirect) writer.u32(NFTA_TABLE_FLAGS,NFT_TABLE_F_OWNER);
        writer.end();
        if (redirect) {
            chain(writer,table,"output",true,*redirect);
            chain(writer,table,"prerouting",false,*redirect);
        }
        writer.fence(NFNL_MSG_BATCH_END);
        return writer.release();
    }
}
