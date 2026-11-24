export module sniff.quic;
import std;
import quic.packet_keys;
import quic.varint;
import sniff.tls;

export namespace sniff {
    enum class QuicSniffStatus { need_more,matched,not_initial,unsupported,malformed,too_large,authentication_failed };
    struct QuicSniffResult {
        QuicSniffStatus status=QuicSniffStatus::need_more;
        // A visible outer SNI with ECH is not an authenticated inner name.
        std::optional<std::string_view> server_name;
        bool ech_offered=false;
        std::optional<std::string_view> client{};
    };
    // One client Initial packet-number space. Callers bound the number and
    // lifetime of these objects and retain any datagrams needed for replay.
    // The object authenticates before accepting CRYPTO bytes; it does not
    // authenticate the client or make the visible name a trusted identity.
    class QuicSniffer {
        static constexpr std::size_t max_crypto=16384;
        std::array<std::uint8_t,max_crypto> bytes_{};
        std::bitset<max_crypto> received_{};
        std::array<std::uint8_t,20> dcid_{};
        std::size_t dcid_size_=0,contiguous_=0;
        std::uint32_t version_=0;
        std::optional<std::uint64_t> largest_;
        std::optional<std::string> name_,client_;
        bool ech_=false,finished_=false,conflicted_=false;
        struct Fragment {std::size_t offset;std::span<std::uint8_t const> data;};
        struct Extent {std::size_t size;bool initial;};

        static auto number(std::uint64_t truncated,unsigned width,std::optional<std::uint64_t> largest) noexcept -> std::uint64_t;
        auto inspect() -> QuicSniffResult;
        [[nodiscard]] auto feed_initial(std::span<std::uint8_t const> datagram) -> QuicSniffResult;
        static auto extent(std::span<std::uint8_t const> data) noexcept -> std::expected<Extent,QuicSniffStatus>;
    public:
        QuicSniffer()=default;
        QuicSniffer(QuicSniffer const&)=delete;
        auto operator=(QuicSniffer const&) -> QuicSniffer& = delete;
        // Accept a bounded UDP datagram, including multiple long-header
        // packets. Unsupported or unauthenticated input remains unknown.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> datagram) -> QuicSniffResult;
    };
}

module :private;

namespace sniff {
    auto QuicSniffer::number(std::uint64_t truncated,unsigned width,std::optional<std::uint64_t> largest) noexcept -> std::uint64_t {
        auto expected=largest ? *largest+1 : 0;
        auto window=std::uint64_t{1}<<(width*8),half=window/2,mask=window-1;
        auto candidate=(expected & ~mask)|truncated;
        if(candidate+half<=expected && candidate<=quic::max_varint-window)candidate+=window;
        else if(candidate>expected+half && candidate>=window)candidate-=window;
        return candidate;
    }

    auto QuicSniffer::inspect() -> QuicSniffResult {
        while(contiguous_<max_crypto && received_.test(contiguous_))++contiguous_;
        if(contiguous_<4)return {};
        auto body=(std::size_t(bytes_[1])<<16)|(std::size_t(bytes_[2])<<8)|bytes_[3];
        if(bytes_[0]!=1 || !body)return {QuicSniffStatus::malformed};
        if(body>max_crypto-4)return {QuicSniffStatus::too_large};
        if(contiguous_<body+4)return {};
        std::array<std::uint8_t,max_crypto+5> record{};
        auto length=body+4;record[0]=22;record[1]=3;record[2]=3;
        record[3]=static_cast<std::uint8_t>(length>>8);record[4]=static_cast<std::uint8_t>(length);
        std::copy_n(bytes_.begin(),length,record.begin()+5);
        std::array<std::uint8_t,max_crypto> scratch{};
        TlsSniffer parser;auto result=parser.feed(std::span(record).first(length+5),scratch);
        if(result.status!=TlsStatus::matched)return {QuicSniffStatus::malformed};
        if(result.server_name)name_=std::string(*result.server_name);
        if(result.client)client_=std::string(*result.client);
        ech_=result.ech_offered;finished_=true;
        return {QuicSniffStatus::matched,name_ ? std::optional<std::string_view>{*name_} : std::nullopt,ech_,
            client_ ? std::optional<std::string_view>{*client_} : std::nullopt};
    }

    auto QuicSniffer::feed_initial(std::span<std::uint8_t const> datagram) -> QuicSniffResult {
        if(datagram.size()>65535)return {QuicSniffStatus::too_large};
        if(datagram.size()<7 || (datagram[0]&0xc0)!=0xc0)return {QuicSniffStatus::not_initial};
        auto version=(std::uint32_t(datagram[1])<<24)|(std::uint32_t(datagram[2])<<16)|(std::uint32_t(datagram[3])<<8)|datagram[4];
        constexpr std::uint32_t v2=0x6b3343cf;
        if(version!=1 && version!=v2)return {QuicSniffStatus::unsupported};
        if((datagram[0]&0x30)!=(version==1 ? 0 : 0x10))return {QuicSniffStatus::not_initial};
        std::size_t offset=5;
        auto dcid_size=std::size_t(datagram[offset++]);
        if(!dcid_size || dcid_size>20 || dcid_size>datagram.size()-offset)return {QuicSniffStatus::malformed};
        auto dcid=datagram.subspan(offset,dcid_size);offset+=dcid_size;
        if(offset>=datagram.size())return {QuicSniffStatus::malformed};
        auto scid_size=std::size_t(datagram[offset++]);
        if(scid_size>20 || scid_size>datagram.size()-offset)return {QuicSniffStatus::malformed};
        offset+=scid_size;
        auto read=[&](std::uint64_t& value) -> bool {
            auto result=quic::read_varint(datagram.subspan(offset));
            if(result.status!=quic::VarintStatus::accepted)return false;
            offset+=result.consumed;value=result.value;return true;
        };
        std::uint64_t token=0,length=0;
        if(!read(token) || token>datagram.size()-offset)return {QuicSniffStatus::malformed};
        offset+=static_cast<std::size_t>(token);
        if(!read(length) || length>datagram.size()-offset || length<20)return {QuicSniffStatus::malformed};
        auto pn_offset=offset;auto end=offset+static_cast<std::size_t>(length);
        if(end-pn_offset<20)return {QuicSniffStatus::malformed};
        if(dcid_size_ && (version_!=version || dcid_size_!=dcid_size || !std::equal(dcid.begin(),dcid.end(),dcid_.begin())))
            return {QuicSniffStatus::not_initial};
        quic::InitialSecrets secrets;quic::PacketKeys keys;
        auto initialized=version==1 ? secrets.reset(version,dcid) : secrets.reset_v2(dcid);
        if(!initialized)return {QuicSniffStatus::malformed};
        auto keyed=version==1 ? keys.reset(quic::PacketSuite::aes128_gcm_sha256,secrets.client()) :
            keys.reset_v2(quic::PacketSuite::aes128_gcm_sha256,secrets.client());
        if(!keyed)
            return {QuicSniffStatus::malformed};
        std::array<std::uint8_t,16> mask{};
        if(!keys.mask_to(mask,std::span<std::uint8_t const,16>(datagram.data()+pn_offset+4,16)))return {QuicSniffStatus::malformed};
        auto flags=std::uint8_t(datagram[0]^(mask[0]&0x0f));
        if(flags&0x0c)return {QuicSniffStatus::malformed};
        auto pn_size=unsigned((flags&3)+1);
        if(length<pn_size+16)return {QuicSniffStatus::malformed};
        std::vector<std::uint8_t> header(datagram.begin(),datagram.begin()+pn_offset+pn_size);
        header[0]=flags;std::uint64_t truncated=0;
        for(unsigned i=0;i<pn_size;++i){header[pn_offset+i]^=mask[i+1];truncated=(truncated<<8)|header[pn_offset+i];}
        auto packet=number(truncated,pn_size,largest_);
        auto nonce=quic::packet_nonce(keys.iv(),packet);if(!nonce)return {QuicSniffStatus::malformed};
        auto ciphertext=datagram.subspan(pn_offset+pn_size,end-pn_offset-pn_size);
        std::vector<std::uint8_t> plain(ciphertext.size()-16);
        if(!keys.open_to(plain,*nonce,ciphertext,header))return {QuicSniffStatus::authentication_failed};
        std::size_t pos=0;std::vector<Fragment> fragments;fragments.reserve(8);
        auto value=[&](std::uint64_t& output) -> bool {
            auto result=quic::read_varint(std::span(plain).subspan(pos));
            if(result.status!=quic::VarintStatus::accepted)return false;
            pos+=result.consumed;output=result.value;return true;
        };
        while(pos<plain.size()) {
            std::uint64_t type=0;if(!value(type))return {QuicSniffStatus::malformed};
            if(type==0 || type==1)continue;
            if(type==6) {
                std::uint64_t start=0,size=0;
                if(!value(start) || !value(size) || size>plain.size()-pos)return {QuicSniffStatus::malformed};
                if(start>max_crypto || size>max_crypto-start || fragments.size()>=128)return {QuicSniffStatus::too_large};
                fragments.push_back({static_cast<std::size_t>(start),std::span(plain).subspan(pos,static_cast<std::size_t>(size))});
                pos+=static_cast<std::size_t>(size);continue;
            }
            if(type==2 || type==3) {
                std::uint64_t largest=0,ignored=0,count=0,range=0;
                if(!value(largest) || !value(ignored) || !value(count) || !value(range) || range>largest)
                    return {QuicSniffStatus::malformed};
                if(count>256)return {QuicSniffStatus::too_large};
                auto smallest=largest-range;
                for(std::uint64_t i=0;i<count;++i) {
                    std::uint64_t gap=0;
                    if(!value(gap) || !value(range) || smallest<2 || gap>smallest-2)return {QuicSniffStatus::malformed};
                    largest=smallest-gap-2;
                    if(range>largest)return {QuicSniffStatus::malformed};
                    smallest=largest-range;
                }
                if(type==3 && (!value(ignored) || !value(ignored) || !value(ignored)))return {QuicSniffStatus::malformed};
                continue;
            }
            if(type==0x1c) {
                // RFC 9000 Section 19.19: transport CONNECTION_CLOSE is legal in Initial packets.
                std::uint64_t error_code=0,frame_type=0,reason_len=0;
                if(!value(error_code) || !value(frame_type) || !value(reason_len) || reason_len>plain.size()-pos)
                    return {QuicSniffStatus::malformed};
                pos+=static_cast<std::size_t>(reason_len);
                continue;
            }
            return {QuicSniffStatus::unsupported};
        }
        // Validate overlaps against both earlier packets and this packet
        // before publishing any byte, including conflicting retransmits.
        auto next_bytes=bytes_;auto next_received=received_;
        for(auto const& fragment:fragments)for(std::size_t i=0;i<fragment.data.size();++i) {
            auto index=fragment.offset+i;auto byte=fragment.data[i];
            if(next_received.test(index) && next_bytes[index]!=byte) {conflicted_=true;return {QuicSniffStatus::malformed};}
            next_bytes[index]=byte;next_received.set(index);
        }
        bytes_=next_bytes;received_=next_received;
        if(!dcid_size_){dcid_size_=dcid_size;version_=version;std::copy(dcid.begin(),dcid.end(),dcid_.begin());}
        if(!largest_ || packet>*largest_)largest_=packet;
        return inspect();
    }

    // Only Initial, 0-RTT and Handshake have a usable length field. A
    // short header or Retry terminates inspection of this datagram.
    auto QuicSniffer::extent(std::span<std::uint8_t const> data) noexcept -> std::expected<Extent,QuicSniffStatus> {
        if(data.size()<7 || (data[0]&0xc0)!=0xc0)return std::unexpected(QuicSniffStatus::not_initial);
        auto version=(std::uint32_t(data[1])<<24)|(std::uint32_t(data[2])<<16)|(std::uint32_t(data[3])<<8)|data[4];
        constexpr std::uint32_t v2=0x6b3343cf;
        if(version!=1 && version!=v2)return std::unexpected(QuicSniffStatus::unsupported);
        auto type=(data[0]>>4)&3;
        auto initial=type==(version==1 ? 0 : 1);
        if(type==(version==1 ? 3 : 0))return std::unexpected(QuicSniffStatus::unsupported);
        std::size_t offset=5;auto dcid=std::size_t(data[offset++]);
        if(dcid>20 || dcid>data.size()-offset)return std::unexpected(QuicSniffStatus::malformed);
        offset+=dcid;if(offset>=data.size())return std::unexpected(QuicSniffStatus::malformed);
        auto scid=std::size_t(data[offset++]);
        if(scid>20 || scid>data.size()-offset)return std::unexpected(QuicSniffStatus::malformed);
        offset+=scid;
        auto read=[&](std::uint64_t& value) -> bool {
            auto result=quic::read_varint(data.subspan(offset));
            if(result.status!=quic::VarintStatus::accepted)return false;
            offset+=result.consumed;value=result.value;return true;
        };
        std::uint64_t length=0;
        if(initial) {
            std::uint64_t token=0;
            if(!read(token) || token>data.size()-offset)return std::unexpected(QuicSniffStatus::malformed);
            offset+=static_cast<std::size_t>(token);
        }
        if(!read(length) || !length || length>data.size()-offset)return std::unexpected(QuicSniffStatus::malformed);
        return Extent{offset+static_cast<std::size_t>(length),initial};
    }

    auto QuicSniffer::feed(std::span<std::uint8_t const> datagram) -> QuicSniffResult {
        if(conflicted_)return {QuicSniffStatus::malformed};
        if(finished_)return {QuicSniffStatus::matched,name_ ? std::optional<std::string_view>{*name_} : std::nullopt,ech_,
            client_ ? std::optional<std::string_view>{*client_} : std::nullopt};
        if(datagram.size()>65535)return {QuicSniffStatus::too_large};
        QuicSniffResult result{QuicSniffStatus::not_initial};
        std::size_t offset=0,count=0;
        while(offset<datagram.size()) {
            if(++count>64)return {QuicSniffStatus::too_large};
            auto packet=extent(datagram.subspan(offset));
            if(!packet) {
                if(result.status==QuicSniffStatus::need_more || result.status==QuicSniffStatus::matched)return result;
                return {packet.error()};
            }
            if(packet->initial) {
                auto current=feed_initial(datagram.subspan(offset,packet->size));
                if(conflicted_)return current;
                if(current.status==QuicSniffStatus::matched)result=current;
                else if(result.status!=QuicSniffStatus::matched &&
                        (current.status==QuicSniffStatus::need_more || result.status!=QuicSniffStatus::need_more))result=current;
            }
            offset+=packet->size;
        }
        return result;
    }
}
