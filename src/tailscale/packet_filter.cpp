module tailscale.packet_filter;
import std;
import containers.inplace_vector;
import glaze;
import corosio;

namespace tailscale::packet_filter {
    namespace detail {
        using Raw=glaze::raw_json_view;
        struct RuleJson {Raw SrcIPs,SrcBits,DstPorts,IPProto,CapGrant;};
        struct DestinationJson {Raw IP,Bits,Ports;};
        struct PortJson {Raw First,Last;};
    }
    namespace {
        using detail::Raw;
        using detail::RuleJson;
        using detail::DestinationJson;
        using detail::PortJson;
        struct Options : glaze::opts {bool validate_trailing_whitespace=true,validate_skipped=true;};
        inline constexpr auto options=[] {Options value;value.null_terminated=false;value.error_on_unknown_keys=true;return value;}();
        template<class T> auto read(T& value,std::string_view json) -> bool {return !glaze::read<options>(value,json);}
        auto trim(std::string_view text) noexcept -> std::string_view {
            auto space=[](char c){return c==' ' || c=='\n' || c=='\r' || c=='\t';};
            while(!text.empty() && space(text.front()))text.remove_prefix(1);
            while(!text.empty() && space(text.back()))text.remove_suffix(1);
            return text;
        }
        auto present(Raw const& raw) noexcept -> bool {auto text=trim(raw.str);return !text.empty() && text!="null";}
        auto array(std::string_view json) noexcept -> bool {json=trim(json);return json.size()>=2 && json.front()=='[' && json.back()==']';}
        auto fail(Error error) noexcept -> std::unexpected<Error> {return std::unexpected(error);}
        auto object(std::string_view json,std::vector<std::pair<std::string_view,Raw>>& fields,std::size_t max_fields) -> std::expected<void,Error> {
            auto trimmed=trim(json);if(trimmed.size()<2 || trimmed.front()!='{' || trimmed.back()!='}')return fail(Error::schema);
            if(!read(fields,json))return fail(Error::json);
            if(fields.size()>max_fields)return fail(Error::limit);
            std::unordered_set<std::string_view> seen;
            seen.reserve(fields.size());
            for(auto const& [k,v]:fields) {
                (void)v;
                if(k.contains('\\'))return fail(Error::unsupported);
                if(!seen.insert(k).second)return fail(Error::duplicate);
            }
            return {};
        }
        auto raw_string(Raw const& raw,std::size_t limit) -> std::expected<std::string_view,Error> {
            std::string_view value;
            if(!present(raw) || !read(value,raw.str))return fail(Error::schema);
            if(value.size()>limit)return fail(Error::limit);
            // Borrowed string views are not decoded. Reject escaped values,
            // so a field cannot silently acquire a different interpretation.
            if(value.contains('\\'))return fail(Error::unsupported);
            return value;
        }
        auto address(std::string_view text) -> std::expected<Address,Error> {
            if(text.empty() || text.contains('%') || text.contains('[') || text.contains(']'))return fail(Error::address);
            auto format=corosio::detect_endpoint_format(text);
            if(format!=corosio::endpoint_format::ipv4_no_port && format!=corosio::endpoint_format::ipv6_no_port)return fail(Error::address);
            auto [error,endpoint]=corosio::make_endpoint(text);
            if(error)return fail(Error::address);
            Address result;result.family=endpoint.is_v4() ? 4 : 6;
            if(result.family==4)std::ranges::copy(endpoint.address().to_v4().to_bytes(),result.bytes.begin());
            else std::ranges::copy(endpoint.address().to_v6().to_bytes(),result.bytes.begin());
            return result;
        }
        auto order(Address const& a,Address const& b) noexcept -> int {
            auto count=a.family==4 ? 4u : 16u;
            for(unsigned i=0;i<count;++i)if(a.bytes[i]!=b.bytes[i])return a.bytes[i]<b.bytes[i] ? -1 : 1;
            return 0;
        }
        auto ip_ranges(Raw const& raw) -> std::expected<containers::inplace_vector<Range,2>,Error> {
            auto parsed=raw_string(raw,128);if(!parsed)return std::unexpected(parsed.error());
            auto text=*parsed;
            if(text.starts_with("cap:"))return fail(Error::unsupported);
            containers::inplace_vector<Range,2> result;
            if(text=="*") {
                Address first4{},last4{},first6{},last6{};
                first4.family=last4.family=4;first6.family=last6.family=6;
                std::fill_n(last4.bytes.begin(),4,255);last6.bytes.fill(255);
                result.push_back({first4,last4});result.push_back({first6,last6});return result;
            }
            auto slash=text.find('/'),dash=text.find('-');
            if(slash!=text.npos && dash!=text.npos)return fail(Error::address);
            if(dash!=text.npos) {
                if(!dash || text.find('-',dash+1)!=text.npos)return fail(Error::address);
                auto first=address(text.substr(0,dash)),last=address(text.substr(dash+1));
                if(!first || !last || first->family!=last->family || order(*first,*last)>0)return fail(Error::address);
                result.push_back({*first,*last});return result;
            }
            auto first=address(slash==text.npos ? text : text.substr(0,slash));if(!first)return std::unexpected(first.error());
            auto last=*first;
            if(slash!=text.npos) {
                auto bits_text=text.substr(slash+1);unsigned bits=0;
                auto converted=std::from_chars(bits_text.data(),bits_text.data()+bits_text.size(),bits);
                auto count=first->family==4 ? 4u : 16u;
                if(bits_text.empty() || converted.ec!=std::errc{} || converted.ptr!=bits_text.data()+bits_text.size() || bits>count*8)return fail(Error::address);
                for(unsigned i=0;i<count;++i) {
                    auto remain=bits>i*8 ? std::min(bits-i*8,8u) : 0u;
                    auto mask=static_cast<std::uint8_t>(remain ? 255u<<(8-remain) : 0u);
                    if(first->bytes[i]&static_cast<std::uint8_t>(~mask))return fail(Error::address);
                    last.bytes[i]|=static_cast<std::uint8_t>(~mask);
                }
            }
            result.push_back({*first,last});return result;
        }
        template<class T> auto fields_unique(std::string_view json) -> std::expected<T,Error> {
            std::vector<std::pair<std::string_view,Raw>> fields;
            if(auto result=object(json,fields,64);!result)return std::unexpected(result.error());
            T value;if(!read(value,json))return fail(Error::schema);return value;
        }
        auto ports(Raw const& raw) -> std::expected<std::pair<std::uint16_t,std::uint16_t>,Error> {
            if(!present(raw))return std::pair<std::uint16_t,std::uint16_t>{0,0};
            auto parsed=fields_unique<PortJson>(raw.str);if(!parsed)return std::unexpected(parsed.error());
            unsigned first=0,last=0;
            if((present(parsed->First) && !read(first,parsed->First.str)) || (present(parsed->Last) && !read(last,parsed->Last.str)) || first>65535 || last>65535)return fail(Error::schema);
            return std::pair{static_cast<std::uint16_t>(first),static_cast<std::uint16_t>(last)};
        }
        auto empty_array(Raw const& raw) -> std::expected<bool,Error> {
            if(!present(raw))return true;
            if(!array(raw.str))return fail(Error::schema);
            containers::inplace_vector<Raw,1> items;
            if(!read(items,raw.str))return fail(Error::unsupported);
            return items.empty();
        }
        auto merge_ranges(std::vector<Range>& ranges) -> void {
            if(ranges.size()<2)return;
            std::ranges::sort(ranges,[](Range const& a,Range const& b) noexcept {
                if(a.first.family!=b.first.family)return a.first.family<b.first.family;
                int c=order(a.first,b.first);
                return c!=0 ? c<0 : order(a.last,b.last)<0;
            });
            std::vector<Range> merged;
            merged.reserve(ranges.size());
            for(auto const& r:ranges) {
                if(!merged.empty() && merged.back().first.family==r.first.family && order(r.first,merged.back().last)<=0) {
                    if(order(merged.back().last,r.last)<0)merged.back().last=r.last;
                } else merged.push_back(r);
            }
            ranges=std::move(merged);
        }
        auto rules(std::string_view json) -> std::expected<std::vector<Rule>,Error> {
            if(!array(json))return fail(Error::schema);
            std::vector<Raw> entries;
            if(!read(entries,json))return fail(Error::json);
            if(entries.size()>max_rules)return fail(Error::limit);
            std::vector<Rule> result;result.reserve(entries.size());std::size_t address_count=0;
            for(auto const& entry:entries) {
                auto input=fields_unique<RuleJson>(entry.str);if(!input)return std::unexpected(input.error());
                auto bits_empty=empty_array(input->SrcBits),caps_empty=empty_array(input->CapGrant);
                if(!bits_empty || !caps_empty || !*bits_empty || !*caps_empty)return fail(Error::unsupported);
                Rule rule;
                if(present(input->SrcIPs)) {
                    std::vector<Raw> src;
                    if(!array(input->SrcIPs.str) || !read(src,input->SrcIPs.str))return fail(Error::schema);
                    if(src.size()>max_addresses)return fail(Error::limit);
                    rule.sources.reserve(src.size());
                    for(auto const& value:src) {
                        auto ranges=ip_ranges(value);if(!ranges)return std::unexpected(ranges.error());
                        address_count+=ranges->size();if(address_count>max_addresses)return fail(Error::limit);
                        for(auto const& range:*ranges)rule.sources.push_back(range);
                    }
                    merge_ranges(rule.sources);
                }
                if(present(input->DstPorts)) {
                    std::vector<Raw> dst;
                    if(!array(input->DstPorts.str) || !read(dst,input->DstPorts.str))return fail(Error::schema);
                    if(dst.size()>max_addresses)return fail(Error::limit);
                    rule.destinations.reserve(dst.size());
                    for(auto const& value:dst) {
                        auto destination=fields_unique<DestinationJson>(value.str);if(!destination)return std::unexpected(destination.error());
                        if(present(destination->Bits))return fail(Error::unsupported);
                        auto ranges=ip_ranges(destination->IP);if(!ranges)return std::unexpected(ranges.error());
                        auto port=ports(destination->Ports);if(!port)return std::unexpected(port.error());
                        address_count+=ranges->size();if(address_count>max_addresses)return fail(Error::limit);
                        for(auto const& range:*ranges)rule.destinations.push_back({range,port->first,port->second});
                    }
                }
                std::vector<std::int64_t> protocols;
                if(present(input->IPProto) && (!array(input->IPProto.str) || !read(protocols,input->IPProto.str)))return fail(Error::schema);
                if(protocols.size()>max_protocols)return fail(Error::limit);
                if(protocols.empty())for(auto n:{1u,6u,17u,58u})rule.protocols[n/64]|=std::uint64_t{1}<<(n%64);
                else for(auto n:protocols)if(n>=0 && n<256)rule.protocols[static_cast<unsigned>(n)/64]|=std::uint64_t{1}<<(static_cast<unsigned>(n)%64);
                result.push_back(std::move(rule));
            }
            return result;
        }
        auto within_limits(std::vector<Chunk> const& chunks) noexcept -> bool {
            if(chunks.size()>max_chunks)return false;
            std::size_t count=0,addresses=0;
            for(auto const& chunk:chunks) {
                count+=chunk.rules.size();if(count>max_rules)return false;
                for(auto const& rule:chunk.rules) {
                    addresses+=rule.sources.size()+rule.destinations.size();if(addresses>max_addresses)return false;
                }
            }
            return true;
        }
        auto replace(std::vector<Chunk>& chunks,std::string_view name,std::vector<Rule>&& value) -> std::expected<void,Error> {
            auto it=std::ranges::find(chunks,name,&Chunk::name);
            if(it!=chunks.end())it->rules=std::move(value);
            else {if(chunks.size()==max_chunks)return fail(Error::limit);chunks.push_back({std::string(name),std::move(value)});}
            if(!within_limits(chunks))return fail(Error::limit);return {};
        }
    }
    auto Range::contains(Address const& value) const noexcept -> bool {
        return (value.family==4 || value.family==6) && first.family==value.family && last.family==value.family && order(first,value)<=0 && order(value,last)<=0;
    }
    auto Rule::matches(Address const& source,Address const& destination,std::uint8_t protocol,std::uint16_t port) const noexcept -> bool {
        if(source.family!=destination.family || sources.empty())return false;
        if(!(protocols[protocol/64] & (std::uint64_t{1}<<(protocol%64))))return false;
        auto it=std::upper_bound(sources.begin(),sources.end(),source,[](Address const& target,Range const& r) noexcept {
            if(target.family!=r.first.family)return target.family<r.first.family;
            return order(target,r.first)<0;
        });
        if(it==sources.begin() || !std::prev(it)->contains(source))return false;
        return std::ranges::any_of(destinations,[&](auto const& value){return value.range.contains(destination) && value.first<=port && port<=value.last;});
    }
    auto Filter::matches(Address const& source,Address const& destination,std::uint8_t protocol,std::uint16_t port) const noexcept -> bool {
        for(auto const& chunk:chunks_)for(auto const& rule:chunk.rules)if(rule.matches(source,destination,protocol,port))return true;
        return false;
    }
    auto Filter::update(std::optional<std::string_view> legacy,std::optional<std::string_view> named) noexcept -> std::expected<void,Error> {
        try {
            if((legacy && legacy->size()>max_json_bytes) || (named && named->size()>max_json_bytes) ||
               (legacy && named && legacy->size()>max_json_bytes-named->size()))return fail(Error::limit);
            bool has_legacy=legacy && trim(*legacy)!="null",has_named=named && trim(*named)!="null";
            if(!has_legacy && !has_named)return {};
            auto next=chunks_;
            std::optional<std::vector<Rule>> base;
            if(has_legacy) {
                auto parsed=rules(*legacy);if(!parsed)return std::unexpected(parsed.error());
                base=std::move(*parsed);
            }
            std::vector<std::pair<std::string_view,Raw>> entries;
            bool clear_all=false,base_overridden=false;
            if(has_named) {
                if(auto parsed=object(*named,entries,max_chunks+1);!parsed)return parsed;
                for(auto const& [key,value]:entries) {
                    if(key.size()>max_name_bytes)return fail(Error::limit);
                    if(key=="*" && trim(value.str)=="null")clear_all=true;
                    if(key=="base")base_overridden=true;
                }
                if(clear_all)next.clear();
                for(auto const& [key,value]:entries) {
                    if(key=="*") {
                        if(trim(value.str)!="null") {auto parsed=rules(value.str);if(!parsed)return std::unexpected(parsed.error());}
                        continue;
                    }
                    auto it=std::ranges::find(next,key,&Chunk::name);if(it!=next.end())next.erase(it);
                }
            }
            if(base && !clear_all && !base_overridden) {
                auto it=std::ranges::find(next,std::string_view("base"),&Chunk::name);if(it!=next.end())next.erase(it);
            }
            // Named deletion and reset happen before additions so an update
            // that fits after replacement is not rejected due to ordering.
            if(base && !clear_all && !base_overridden) {
                if(auto applied=replace(next,"base",std::move(*base));!applied)return applied;
            }
            if(has_named) {
                for(auto const& [key,value]:entries) {
                    if(key=="*" || trim(value.str)=="null")continue;
                    auto parsed=rules(value.str);if(!parsed)return std::unexpected(parsed.error());
                    if(auto applied=replace(next,key,std::move(*parsed));!applied)return applied;
                }
            }
            std::ranges::sort(next,{},&Chunk::name);chunks_=std::move(next);received_=true;return {};
        } catch(std::bad_alloc const&) {return fail(Error::allocation);} catch(...) {return fail(Error::schema);}
    }
}
