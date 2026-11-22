export module masque.ip_control;
import std;
import quic.varint;
import masque.capsule;

export namespace masque {
    inline constexpr std::uint64_t address_assign_capsule=1,address_request_capsule=2,route_advertisement_capsule=3;
    enum class IpControlError { incomplete,malformed,buffer_too_small };
    struct AddressEntry {
        std::uint64_t request_id=0;
        std::uint8_t version=0,prefix_length=0;
        std::array<std::uint8_t,16> address{};
    };
    struct RouteEntry {
        std::uint8_t version=0,protocol=0;
        std::array<std::uint8_t,16> first{},last{};
    };
    template<class T>struct IpControlRead {T value;std::size_t consumed;};
    inline auto ip_address_bytes(std::uint8_t version) noexcept -> std::size_t {return version==4 ? 4 : version==6 ? 16 : 0;}
    // A response with a matching nonzero request ID and a zero host address
    // at full prefix length rejects that request; it is not an assigned IP.
    inline auto address_rejection(AddressEntry const& entry) noexcept -> bool {
        auto size=ip_address_bytes(entry.version);
        return entry.request_id && size && entry.prefix_length==size*8 &&
            std::ranges::all_of(std::span(entry.address).first(size),[](std::uint8_t value){return value==0;});
    }
    inline auto valid_prefix(std::span<std::uint8_t const> bytes,std::uint8_t prefix) noexcept -> bool {
        if(prefix>bytes.size()*8)return false;
        auto whole=prefix/8,partial=prefix%8;
        if(partial && (bytes[whole]&static_cast<std::uint8_t>(0xffu>>partial)))return false;
        auto remaining=static_cast<std::size_t>(whole)+(partial ? 1 : 0);
        return std::ranges::all_of(bytes.subspan(remaining),[](std::uint8_t value){return value==0;});
    }
    // Returns one record without advancing caller state; retain incomplete
    // fragments until the capsule boundary and reject a truncated final one.
    // For a request, the caller also checks nonempty and never-reused IDs.
    inline auto read_address_entry(std::span<std::uint8_t const> input,bool request) noexcept -> std::expected<IpControlRead<AddressEntry>,IpControlError> {
        auto id=quic::read_varint(input);
        if(id.status!=quic::VarintStatus::accepted)return std::unexpected(IpControlError::incomplete);
        if(request && !id.value)return std::unexpected(IpControlError::malformed);
        auto tail=input.subspan(id.consumed);
        if(tail.empty())return std::unexpected(IpControlError::incomplete);
        auto size=ip_address_bytes(tail[0]);
        if(!size)return std::unexpected(IpControlError::malformed);
        if(tail.size()<size+2)return std::unexpected(IpControlError::incomplete);
        auto prefix=tail[size+1];auto address=tail.subspan(1,size);
        if(!valid_prefix(address,prefix))return std::unexpected(IpControlError::malformed);
        AddressEntry entry{id.value,tail[0],prefix,{}};
        std::ranges::copy(address,entry.address.begin());
        return IpControlRead<AddressEntry>{entry,id.consumed+size+2};
    }
    inline auto write_address_entry(std::span<std::uint8_t> output,AddressEntry const& entry,bool request) noexcept -> std::expected<std::size_t,IpControlError> {
        auto size=ip_address_bytes(entry.version),id_size=quic::varint_size(entry.request_id);
        if(!size || !id_size || (request && !entry.request_id) || !valid_prefix(std::span(entry.address).first(size),entry.prefix_length))
            return std::unexpected(IpControlError::malformed);
        auto length=id_size+size+2;
        if(output.size()<length)return std::unexpected(IpControlError::buffer_too_small);
        (void)quic::write_varint(output,entry.request_id,id_size);output[id_size]=entry.version;
        std::ranges::copy(std::span(entry.address).first(size),output.begin()+id_size+1);output[length-1]=entry.prefix_length;
        return length;
    }
    inline auto read_route_entry(std::span<std::uint8_t const> input) noexcept -> std::expected<IpControlRead<RouteEntry>,IpControlError> {
        if(input.empty())return std::unexpected(IpControlError::incomplete);
        auto size=ip_address_bytes(input[0]);
        if(!size)return std::unexpected(IpControlError::malformed);
        auto length=2+2*size;
        if(input.size()<length)return std::unexpected(IpControlError::incomplete);
        auto first=input.subspan(1,size),last=input.subspan(size+1,size);
        if(std::lexicographical_compare(last.begin(),last.end(),first.begin(),first.end()))return std::unexpected(IpControlError::malformed);
        RouteEntry entry{input[0],input[length-1],{}, {}};
        std::ranges::copy(first,entry.first.begin());std::ranges::copy(last,entry.last.begin());
        return IpControlRead<RouteEntry>{entry,length};
    }
    inline auto write_route_entry(std::span<std::uint8_t> output,RouteEntry const& entry) noexcept -> std::expected<std::size_t,IpControlError> {
        auto size=ip_address_bytes(entry.version);
        if(!size)return std::unexpected(IpControlError::malformed);
        auto first=std::span(entry.first).first(size),last=std::span(entry.last).first(size);
        if(std::lexicographical_compare(last.begin(),last.end(),first.begin(),first.end()))return std::unexpected(IpControlError::malformed);
        auto length=2+2*size;
        if(output.size()<length)return std::unexpected(IpControlError::buffer_too_small);
        output[0]=entry.version;std::ranges::copy(first,output.begin()+1);std::ranges::copy(last,output.begin()+1+size);output[length-1]=entry.protocol;
        return length;
    }
    // One instance per complete ROUTE_ADVERTISEMENT. Call before staging each
    // record and discard the staged list on failure; publish only after the
    // whole capsule succeeds. This is the mandatory receive-side ordering
    // check only. RFC 9484 also forbids a sender from emitting overlaps
    // between wildcard and specific protocols; the send-side caller must
    // check those separately. Receivers may additionally detect and reject.
    class RouteOrder {
        RouteEntry previous_{};bool have_previous_=false;
    public:
        auto accept(RouteEntry const& next) noexcept -> bool {
            auto size=ip_address_bytes(next.version);
            if(!size || std::lexicographical_compare(next.last.begin(),next.last.begin()+size,next.first.begin(),next.first.begin()+size))return false;
            if(have_previous_) {
                if(next.version<previous_.version)return false;
                if(next.version==previous_.version) {
                    if(next.protocol<previous_.protocol)return false;
                    if(next.protocol==previous_.protocol && !std::lexicographical_compare(previous_.last.begin(),previous_.last.begin()+size,next.first.begin(),next.first.begin()+size))return false;
                }
            }
            previous_=next;have_previous_=true;return true;
        }
    };

    enum class IpSnapshotError { malformed, limit, reused_request_id };

    enum class IpCapsuleEvent { need_more, complete, limit, malformed, truncated, closed };
    struct IpCapsuleResult {
        IpCapsuleEvent event=IpCapsuleEvent::need_more;
        std::size_t consumed=0;
        std::uint64_t type=0;
        // Complete body is borrowed until the next feed or finish call.
        std::span<std::uint8_t const> body;
    };
    // Unknown capsule types are skipped without buffering. Known control
    // bodies are bounded and emitted only at their complete TLV boundary.
    // The optional DATAGRAM consumer drops oversized packets rather than
    // treating an IP forwarding limit as a malformed control capsule.
    template<std::size_t Limit> class IpControlCapsules {
        CapsuleDecoder decoder_;
        quic::VarintDecoder datagram_context_;
        std::array<std::uint8_t,Limit> body_{};
        std::size_t size_=0;
        std::uint64_t type_=0;
        bool known_=false,closed_=false,failed_=false,datagrams_=false,dropping_=false,context_done_=false;
        auto complete(std::size_t consumed) const noexcept -> IpCapsuleResult {
            return {IpCapsuleEvent::complete,consumed,type_,std::span(body_).first(size_)};
        }
    public:
        explicit IpControlCapsules(bool datagrams=false) noexcept:datagrams_(datagrams) {}
        auto feed(std::span<std::uint8_t const> input) noexcept -> IpCapsuleResult {
            if(failed_)return {IpCapsuleEvent::limit};
            if(closed_)return {IpCapsuleEvent::closed};
            std::size_t consumed=0;
            while(true) {
                auto result=decoder_.feed(input.subspan(consumed));consumed+=result.consumed;
                switch(result.event) {
                case CapsuleEvent::need_more:return {IpCapsuleEvent::need_more,consumed};
                case CapsuleEvent::begin:
                    type_=result.type;size_=0;
                    known_=type_==address_assign_capsule || type_==address_request_capsule || type_==route_advertisement_capsule || (datagrams_ && type_==datagram_capsule_type);
                    dropping_=datagrams_ && type_==datagram_capsule_type && result.length>Limit;
                    context_done_=false;datagram_context_.reset();
                    if(dropping_)known_=false;
                    if(known_ && result.length>Limit) {failed_=true;return {IpCapsuleEvent::limit,consumed};}
                    break;
                case CapsuleEvent::data:
                    if(known_) {std::ranges::copy(result.data,body_.begin()+size_);size_+=result.data.size();}
                    else if(dropping_ && !context_done_)context_done_=datagram_context_.feed(result.data).status==quic::VarintStatus::accepted;
                    break;
                case CapsuleEvent::end:
                    if(dropping_ && !context_done_) {closed_=true;return {IpCapsuleEvent::malformed,consumed};}
                    if(known_)return complete(consumed);break;
                default:failed_=true;return {IpCapsuleEvent::limit,consumed};
                }
            }
        }
        auto finish() noexcept -> IpCapsuleResult {
            if(failed_)return {IpCapsuleEvent::limit};
            if(closed_)return {IpCapsuleEvent::closed};
            closed_=true;
            auto result=decoder_.finish();
            if(result==CapsuleEvent::end && dropping_ && !context_done_)return {IpCapsuleEvent::malformed};
            if(result==CapsuleEvent::end && known_)return complete(0);
            if(result==CapsuleEvent::closed || result==CapsuleEvent::end)return {IpCapsuleEvent::closed};
            return {IpCapsuleEvent::truncated};
        }
    };

    // Complete capsule bodies only. A failed replacement leaves both the
    // published list and the request-ID history untouched. Capacities are
    // per request stream; callers must close it on a resource limit rather
    // than forget IDs and permit reuse. This does not install or authorize IPs.
    template<std::size_t Addresses,std::size_t Routes,std::size_t Requests>
    class IpControlState {
        std::array<AddressEntry,Addresses> addresses_{};
        std::array<RouteEntry,Routes> routes_{};
        std::array<std::uint64_t,Requests> request_ids_{};
        std::size_t address_count_=0,route_count_=0,request_count_=0;
    public:
        auto addresses() const noexcept -> std::span<AddressEntry const> {return {addresses_.data(),address_count_};}
        auto routes() const noexcept -> std::span<RouteEntry const> {return {routes_.data(),route_count_};}

        auto assign(std::span<std::uint8_t const> body) noexcept -> std::expected<void,IpSnapshotError> {
            std::array<AddressEntry,Addresses> next{};std::size_t count=0;
            while(!body.empty()) {
                auto entry=read_address_entry(body,false);
                if(!entry)return std::unexpected(IpSnapshotError::malformed);
                if(count==Addresses)return std::unexpected(IpSnapshotError::limit);
                next[count++]=entry->value;body=body.subspan(entry->consumed);
            }
            addresses_=next;address_count_=count;return {};
        }

        auto advertise(std::span<std::uint8_t const> body) noexcept -> std::expected<void,IpSnapshotError> {
            std::array<RouteEntry,Routes> next{};std::size_t count=0;RouteOrder order;
            while(!body.empty()) {
                auto entry=read_route_entry(body);
                if(!entry || !order.accept(entry->value))return std::unexpected(IpSnapshotError::malformed);
                if(count==Routes)return std::unexpected(IpSnapshotError::limit);
                // Reject wildcard/specific overlaps as allowed by RFC 9484.
                auto const& value=entry->value;auto size=ip_address_bytes(value.version);
                for(std::size_t i=0;i<count;++i) {
                    auto const& prior=next[i];
                    if(prior.version!=value.version || (prior.protocol!=0 && value.protocol!=0))continue;
                    if(!std::lexicographical_compare(prior.last.begin(),prior.last.begin()+size,value.first.begin(),value.first.begin()+size) &&
                       !std::lexicographical_compare(value.last.begin(),value.last.begin()+size,prior.first.begin(),prior.first.begin()+size))
                        return std::unexpected(IpSnapshotError::malformed);
                }
                next[count++]=value;body=body.subspan(entry->consumed);
            }
            routes_=next;route_count_=count;return {};
        }

        // The caller receives the newly accepted records in its own buffer;
        // no records or IDs are published on a malformed or oversized body.
        auto request(std::span<std::uint8_t const> body,std::span<AddressEntry> output) noexcept -> std::expected<std::size_t,IpSnapshotError> {
            if(body.empty())return std::unexpected(IpSnapshotError::malformed);
            std::array<AddressEntry,Requests> next{};std::size_t count=0;
            while(!body.empty()) {
                auto entry=read_address_entry(body,true);
                if(!entry)return std::unexpected(IpSnapshotError::malformed);
                if(count==Requests || count==output.size() || count>=Requests-request_count_)
                    return std::unexpected(IpSnapshotError::limit);
                auto id=entry->value.request_id;
                for(std::size_t i=0;i<request_count_;++i)if(request_ids_[i]==id)return std::unexpected(IpSnapshotError::reused_request_id);
                for(std::size_t i=0;i<count;++i)if(next[i].request_id==id)return std::unexpected(IpSnapshotError::reused_request_id);
                next[count++]=entry->value;body=body.subspan(entry->consumed);
            }
            for(std::size_t i=0;i<count;++i) {request_ids_[request_count_++]=next[i].request_id;output[i]=next[i];}
            return count;
        }
    };
}
