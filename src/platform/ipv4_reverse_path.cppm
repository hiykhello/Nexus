export module platform.ipv4_reverse_path;
import std;
import containers.inplace_vector;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;

export namespace platform::routing {
    namespace reverse_path_detail {
        namespace a=netlink_abi;
        namespace n=netlink;
        struct Config {std::int32_t index=0;std::optional<std::int32_t> filter;};
        inline auto parse(n::Message message) -> std::expected<Config,n::Failure> {
            auto header=n::native<a::netconfmsg>(message.payload);
            auto offset=n::aligned(sizeof(a::netconfmsg));
            if(!header || header->ncm_family!=a::AF_INET || message.payload.size()<offset ||
               (message.header.nlmsg_type!=a::RTM_NEWNETCONF && message.header.nlmsg_type!=a::RTM_DELNETCONF))return n::fail(n::Error::protocol);
            Config result;bool index=false;
            auto parsed=n::attributes(message.payload.subspan(offset),[&](n::Attribute attribute)->std::expected<void,n::Failure> {
                if(attribute.type!=a::NETCONFA_IFINDEX && attribute.type!=a::NETCONFA_RP_FILTER)return {};
                auto value=n::scalar<std::int32_t>(attribute);if(!value)return std::unexpected(value.error());
                if(attribute.type==a::NETCONFA_IFINDEX){if(index || !*value || *value<a::NETCONFA_IFINDEX_DEFAULT)return n::fail(n::Error::protocol);index=true;result.index=*value;}
                else {if(result.filter || *value<0 || *value>2)return n::fail(n::Error::protocol);result.filter=*value;}
                return {};
            });
            if(!parsed)return std::unexpected(parsed.error());if(!index)return n::fail(n::Error::protocol);return result;
        }
        struct Entry {
            std::int32_t index=0,original=0;
            std::array<char,16> name{};
            bool attempted=false,owned=false;
        };
        inline auto access(Entry const& entry,std::optional<std::int32_t> write={}) -> std::expected<std::int32_t,n::Failure> {
            auto end=std::ranges::find(entry.name,'\0');
            std::string_view name(entry.name.data(),std::size_t(end-entry.name.begin()));
            if((write && (*write<0 || *write>2)) || name.empty() || name.size()>15 || name=="." || name==".." || name.contains('/'))return n::fail(n::Error::configuration);
            std::array<char,80> path{};constexpr std::string_view prefix="/proc/sys/net/ipv4/conf/",suffix="/rp_filter";
            auto position=std::ranges::copy(prefix,path.begin()).out;position=std::ranges::copy(name,position).out;std::ranges::copy(suffix,position);
            auto fd=a::open(path.data(),(write?a::O_WRONLY:a::O_RDONLY)|a::O_CLOEXEC|a::O_NOFOLLOW);
            auto error=[](){return std::error_code(*a::__errno_location(),std::generic_category());};
            if(fd<0)return n::fail(n::Error::system,error());
            std::array<char,8> buffer{};std::ptrdiff_t size;
            if(write){buffer[0]=char('0'+*write);buffer[1]='\n';size=a::write(fd,buffer.data(),2);}
            else size=a::read(fd,buffer.data(),buffer.size());
            auto code=error();a::close(fd);
            if(size<0)return n::fail(n::Error::system,code);
            if(size!=2 || buffer[1]!='\n' || buffer[0]<'0' || buffer[0]>'2')return n::fail(n::Error::protocol);
            return buffer[0]-'0';
        }
    }
    // Native policy composition supplies its existing control socket and watch.
    // Only specified interfaces whose effective setting is strict change.
    class IPv4ReversePathLease {
        using Entry=reverse_path_detail::Entry;
        containers::inplace_vector<Entry,65> entries_;
        std::optional<std::int32_t> all_;
        std::int32_t pending_=0,expected_=0;
        bool seen_=false,drift_=false,uncertain_=false;
      public:
        [[nodiscard]] auto add(std::int32_t index,std::array<char,16> name) -> std::expected<void,netlink::Failure> {
            if(std::ranges::any_of(entries_,[&](auto const& entry){return entry.index==index;}))return {};
            if(entries_.size()==entries_.capacity())return netlink::fail(netlink::Error::limit);
            entries_.push_back({.index=index,.name=name});return {};
        }
        template<class Socket> [[nodiscard]] auto prepare(Socket& socket,netlink::Clock::time_point deadline) -> std::expected<void,netlink::Failure> {
            namespace d=reverse_path_detail;
            std::array<bool,65> found{};
            auto dumped=socket.dump(d::a::RTM_GETNETCONF,d::a::AF_INET,deadline,[&](d::n::Message message)->std::expected<void,d::n::Failure> {
                auto value=d::parse(message);if(!value || !value->filter)return value?d::n::fail(d::n::Error::protocol):std::unexpected(value.error());
                if(value->index==d::a::NETCONFA_IFINDEX_ALL){if(all_)return d::n::fail(d::n::Error::protocol);all_=*value->filter;}
                for(std::size_t i=0;i<entries_.size();++i)if(entries_[i].index==value->index){if(found[i])return d::n::fail(d::n::Error::protocol);found[i]=true;entries_[i].original=*value->filter;}
                return {};
            });
            if(!dumped)return dumped;
            if(!all_ || !std::ranges::all_of(std::span(found).first(entries_.size()),[](bool value){return value;}))return d::n::fail(d::n::Error::protocol);
            return {};
        }
        [[nodiscard]] auto observe(netlink::Message message) -> std::expected<void,netlink::Failure> {
            namespace d=reverse_path_detail;
            auto value=d::parse(message);if(!value){invalidate();return std::unexpected(value.error());}
            if(value->index==d::a::NETCONFA_IFINDEX_ALL && value->filter)drift_=true;
            for(auto& entry:entries_)if(entry.index==value->index) {
                if(!value->filter && message.header.nlmsg_type!=d::a::RTM_DELNETCONF)continue;
                if(pending_==entry.index && !seen_ && value->filter==expected_ && message.header.nlmsg_type==d::a::RTM_NEWNETCONF){seen_=true;entry.owned=expected_==2;}
                else {entry.owned=false;drift_=true;}
            }
            return {};
        }
        auto changed_link(std::int32_t index) noexcept -> void {
            for(auto& entry:entries_)if(entry.index==index){entry.owned=false;drift_=true;}
        }
        auto invalidate() noexcept -> void {uncertain_=drift_=true;for(auto& entry:entries_)entry.owned=false;}
        [[nodiscard]] auto drifted() const noexcept -> bool{return drift_;}
        template<class Observe,class Verify> [[nodiscard]] auto start(Observe&& observe,Verify&& verify) -> std::expected<void,netlink::Failure> {
            namespace d=reverse_path_detail;
            for(auto& entry:entries_) {
                if(std::max(*all_,entry.original)!=1)continue;
                auto drained=observe();if(!drained)return drained;
                if(drift_ || !verify(entry.index,entry.name))return d::n::fail(d::n::Error::uncertain);
                auto before=d::access(entry);if(!before)return std::unexpected(before.error());if(*before!=entry.original)return d::n::fail(d::n::Error::uncertain);
                entry.attempted=true;pending_=entry.index;expected_=2;seen_=false;
                auto changed=d::access(entry,2);auto after=d::access(entry);drained=observe();pending_=0;
                if(!changed || !after || !drained || !seen_ || *after!=2 || !entry.owned || drift_) {
                    // An independently unchanged scalar needs no restoration.
                    // A confirmed own event retains its proof for rollback even
                    // when the separate scalar readback or write result failed.
                    if(!changed && after && *after==entry.original && drained && !seen_)entry.attempted=false;
                    if(entry.attempted && !entry.owned)uncertain_=true;
                    if(!changed)return std::unexpected(changed.error());
                    if(!after)return std::unexpected(after.error());
                    if(!drained)return drained;
                    return d::n::fail(d::n::Error::uncertain);
                }
            }
            return {};
        }
        struct Cleanup {std::size_t restored=0,preserved=0,uncertain=0;};
        template<class Observe,class Verify> [[nodiscard]] auto stop(Observe&& observe,Verify&& verify) -> Cleanup {
            namespace d=reverse_path_detail;Cleanup report;
            for(auto& entry:entries_)if(entry.attempted) {
                auto drained=observe();
                if(!drained || !entry.owned){++report.preserved;if(uncertain_)++report.uncertain;continue;}
                if(!verify(entry.index,entry.name)){++report.preserved;continue;}
                auto before=d::access(entry);
                if(!before){++report.uncertain;continue;}
                if(*before!=2){entry.owned=false;++report.preserved;continue;}
                pending_=entry.index;expected_=entry.original;seen_=false;
                auto changed=d::access(entry,entry.original);auto after=d::access(entry);drained=observe();pending_=0;
                if(!changed || !after || !drained || !seen_ || *after!=entry.original)++report.uncertain;
                else {entry.owned=false;++report.restored;}
            }
            return report;
        }
    };
}
