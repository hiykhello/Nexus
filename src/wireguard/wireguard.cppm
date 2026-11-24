export module wireguard;
import std;
import encoding.endian;

export namespace wireguard {
    using Key=std::array<std::uint8_t,32>;
    using Mac=std::array<std::uint8_t,16>;
    using Timestamp=std::array<std::uint8_t,12>;
    enum class Error { invalid_type,invalid_length,invalid_reserved,invalid_key,invalid_state,invalid_timestamp,
        authentication,replay,expired,too_old,counter_exhausted,not_confirmed,source,backend };
    enum class MessageType : std::uint8_t { initiation=1,response=2,cookie=3,transport=4 };
    inline constexpr std::size_t initiation_size=148,response_size=92,cookie_size=64,transport_header_size=16,transport_overhead=32;
    inline constexpr std::size_t max_datagram_size=65535;
    inline constexpr std::uint64_t rekey_after_messages=std::uint64_t{1}<<60;
    inline constexpr std::uint64_t reject_after_messages=std::numeric_limits<std::uint64_t>::max()-8192;
    inline constexpr auto rekey_after_time=std::chrono::seconds(120),reject_after_time=std::chrono::seconds(180);
    inline constexpr auto cookie_refresh_time=std::chrono::seconds(120);
    inline auto load_le32(std::span<std::uint8_t const,4> bytes) noexcept -> std::uint32_t {
        return encoding::read_le32(bytes);
    }
    inline auto load_le64(std::span<std::uint8_t const,8> bytes) noexcept -> std::uint64_t {
        return encoding::read_le64(bytes);
    }
    inline auto store_le32(std::span<std::uint8_t,4> bytes,std::uint32_t value) noexcept -> void {
        encoding::write_le32(bytes, value);
    }
    inline auto store_le64(std::span<std::uint8_t,8> bytes,std::uint64_t value) noexcept -> void {
        encoding::write_le64(bytes, value);
    }
    inline auto message_type(std::span<std::uint8_t const> wire) noexcept -> std::expected<MessageType,Error> {
        if (wire.size()<4) return std::unexpected(Error::invalid_length);
        if (wire[1] || wire[2] || wire[3]) return std::unexpected(Error::invalid_reserved);
        auto type=static_cast<MessageType>(wire[0]);
        if (type<MessageType::initiation || type>MessageType::transport) return std::unexpected(Error::invalid_type);
        auto size=type==MessageType::initiation ? initiation_size : type==MessageType::response ? response_size : cookie_size;
        if (type==MessageType::transport ? wire.size()<transport_overhead || wire.size()>max_datagram_size : wire.size()!=size)
            return std::unexpected(Error::invalid_length);
        return type;
    }
    struct Initiation {
        std::uint32_t sender=0; Key ephemeral{}; std::array<std::uint8_t,48> encrypted_static{};
        std::array<std::uint8_t,28> encrypted_timestamp{}; Mac mac1{},mac2{};
    };
    struct Response {
        std::uint32_t sender=0,receiver=0; Key ephemeral{}; Mac encrypted_empty{},mac1{},mac2{};
    };
    struct CookieReply { std::uint32_t receiver=0; std::array<std::uint8_t,24> nonce{}; Key encrypted_cookie{}; };
    struct TransportView { std::uint32_t receiver; std::uint64_t counter; std::span<std::uint8_t const> ciphertext; };
    inline auto encode(Initiation const& message) noexcept -> std::array<std::uint8_t,initiation_size> {
        std::array<std::uint8_t,initiation_size> result{}; result[0]=1;
        store_le32(std::span(result).subspan<4,4>(),message.sender);
        std::ranges::copy(message.ephemeral,result.begin()+8); std::ranges::copy(message.encrypted_static,result.begin()+40);
        std::ranges::copy(message.encrypted_timestamp,result.begin()+88); std::ranges::copy(message.mac1,result.begin()+116);
        std::ranges::copy(message.mac2,result.begin()+132); return result;
    }
    inline auto encode(Response const& message) noexcept -> std::array<std::uint8_t,response_size> {
        std::array<std::uint8_t,response_size> result{}; result[0]=2;
        store_le32(std::span(result).subspan<4,4>(),message.sender); store_le32(std::span(result).subspan<8,4>(),message.receiver);
        std::ranges::copy(message.ephemeral,result.begin()+12); std::ranges::copy(message.encrypted_empty,result.begin()+44);
        std::ranges::copy(message.mac1,result.begin()+60); std::ranges::copy(message.mac2,result.begin()+76); return result;
    }
    inline auto encode(CookieReply const& message) noexcept -> std::array<std::uint8_t,cookie_size> {
        std::array<std::uint8_t,cookie_size> result{}; result[0]=3;
        store_le32(std::span(result).subspan<4,4>(),message.receiver);
        std::ranges::copy(message.nonce,result.begin()+8); std::ranges::copy(message.encrypted_cookie,result.begin()+32); return result;
    }
    inline auto parse_initiation(std::span<std::uint8_t const> wire) noexcept -> std::expected<Initiation,Error> {
        auto type=message_type(wire); if (!type) return std::unexpected(type.error());
        if (*type!=MessageType::initiation) return std::unexpected(Error::invalid_type);
        Initiation message; message.sender=load_le32(wire.subspan<4,4>());
        std::copy_n(wire.begin()+8,32,message.ephemeral.begin()); std::copy_n(wire.begin()+40,48,message.encrypted_static.begin());
        std::copy_n(wire.begin()+88,28,message.encrypted_timestamp.begin()); std::copy_n(wire.begin()+116,16,message.mac1.begin());
        std::copy_n(wire.begin()+132,16,message.mac2.begin()); return message;
    }
    inline auto parse_response(std::span<std::uint8_t const> wire) noexcept -> std::expected<Response,Error> {
        auto type=message_type(wire); if (!type) return std::unexpected(type.error());
        if (*type!=MessageType::response) return std::unexpected(Error::invalid_type);
        Response message; message.sender=load_le32(wire.subspan<4,4>()); message.receiver=load_le32(wire.subspan<8,4>());
        std::copy_n(wire.begin()+12,32,message.ephemeral.begin()); std::copy_n(wire.begin()+44,16,message.encrypted_empty.begin());
        std::copy_n(wire.begin()+60,16,message.mac1.begin()); std::copy_n(wire.begin()+76,16,message.mac2.begin()); return message;
    }
    inline auto parse_cookie(std::span<std::uint8_t const> wire) noexcept -> std::expected<CookieReply,Error> {
        auto type=message_type(wire); if (!type) return std::unexpected(type.error());
        if (*type!=MessageType::cookie) return std::unexpected(Error::invalid_type);
        CookieReply message; message.receiver=load_le32(wire.subspan<4,4>());
        std::copy_n(wire.begin()+8,24,message.nonce.begin()); std::copy_n(wire.begin()+32,32,message.encrypted_cookie.begin()); return message;
    }
    inline auto parse_transport(std::span<std::uint8_t const> wire) noexcept -> std::expected<TransportView,Error> {
        auto type=message_type(wire); if (!type) return std::unexpected(type.error());
        if (*type!=MessageType::transport) return std::unexpected(Error::invalid_type);
        return TransportView{load_le32(wire.subspan<4,4>()),load_le64(wire.subspan<8,8>()),wire.subspan(16)};
    }
    inline auto transport_header(std::uint32_t receiver,std::uint64_t counter) noexcept -> std::array<std::uint8_t,16> {
        std::array<std::uint8_t,16> result{}; result[0]=4;
        store_le32(std::span(result).subspan<4,4>(),receiver); store_le64(std::span(result).subspan<8,8>(),counter); return result;
    }
    inline auto transport_nonce(std::uint64_t counter) noexcept -> std::array<std::uint8_t,12> {
        std::array<std::uint8_t,12> result{}; store_le64(std::span(result).subspan<4,8>(),counter); return result;
    }
    inline auto make_timestamp(std::uint64_t seconds,std::uint32_t nanoseconds,bool coarse=true) noexcept -> std::expected<Timestamp,Error> {
        constexpr std::uint64_t base=0x400000000000000a;
        if (seconds>std::numeric_limits<std::uint64_t>::max()-base || nanoseconds>=1000000000) return std::unexpected(Error::invalid_timestamp);
        Timestamp result{}; seconds+=base;
        if (coarse) nanoseconds&=~std::uint32_t{0xffffff};
        for (std::size_t i=0;i<8;++i) result[i]=static_cast<std::uint8_t>(seconds>>(56-8*i));
        for (std::size_t i=0;i<4;++i) result[8+i]=static_cast<std::uint8_t>(nanoseconds>>(24-8*i));
        return result;
    }
    // One executor owns this RFC 6479 window. Only authenticated ciphertext
    // may be committed; preflight never mutates the window or peer endpoint.
    class ReplayWindow {
        std::array<std::uint64_t,128> ring_{};
        std::uint64_t last_=0;
    public:
        inline static constexpr std::uint64_t window_size=8128;
        auto check(this ReplayWindow const& self,std::uint64_t counter) noexcept -> std::expected<void,Error> {
            if (counter>=reject_after_messages) return std::unexpected(Error::counter_exhausted);
            if (counter>self.last_) return {};
            if (self.last_-counter>window_size) return std::unexpected(Error::too_old);
            if (self.ring_[(counter>>6)&127]&(std::uint64_t{1}<<(counter&63))) return std::unexpected(Error::replay);
            return {};
        }
        auto commit_authenticated(this ReplayWindow& self,std::uint64_t counter) noexcept -> std::expected<void,Error> {
            auto checked=self.check(counter); if (!checked) return checked;
            if (counter>self.last_) {
                auto current=self.last_>>6,blocks=std::min((counter>>6)-current,std::uint64_t{128});
                for (std::uint64_t i=1;i<=blocks;++i) self.ring_[(current+i)&127]=0;
                self.last_=counter;
            }
            self.ring_[(counter>>6)&127]|=std::uint64_t{1}<<(counter&63); return {};
        }
        auto last(this ReplayWindow const& self) noexcept -> std::uint64_t { return self.last_; }
    };
    class SendCounter {
        std::uint64_t next_=0;
    public:
        explicit SendCounter(std::uint64_t next=0) noexcept : next_(next) {}
        auto take(this SendCounter& self) noexcept -> std::expected<std::uint64_t,Error> {
            if (self.next_>=reject_after_messages) return std::unexpected(Error::counter_exhausted);
            return self.next_++;
        }
        auto next(this SendCounter const& self) noexcept -> std::uint64_t { return self.next_; }
    };
    enum class Provider { standard,warp };
    class ReservedProfile {
        Provider provider_=Provider::standard;
        std::array<std::uint8_t,3> bytes_{};
        ReservedProfile(Provider provider,std::array<std::uint8_t,3> bytes) noexcept : provider_(provider),bytes_(bytes) {}
    public:
        ReservedProfile()=default;
        auto operator==(ReservedProfile const&) const noexcept -> bool = default;
        static auto create(Provider provider,std::span<std::uint8_t const> bytes) noexcept -> std::expected<ReservedProfile,Error> {
            if (bytes.size()!=3 || (provider!=Provider::standard && provider!=Provider::warp) ||
                (provider==Provider::standard && std::ranges::any_of(bytes,[](auto c) { return c!=0; }))) return std::unexpected(Error::invalid_reserved);
            std::array<std::uint8_t,3> result; std::ranges::copy(bytes,result.begin()); return ReservedProfile(provider,result);
        }
        // The standard codec and MAC always see zero reserved bytes. The
        // provider value overwrites outbound bytes only after MAC generation;
        // replies need not echo it. Source authorization precedes restore.
        auto apply(this ReservedProfile const& self,std::span<std::uint8_t> wire) noexcept -> std::expected<void,Error> {
            auto type=message_type(wire); if (!type) return std::unexpected(type.error());
            std::ranges::copy(self.bytes_,wire.begin()+1); return {};
        }
        auto restore(this ReservedProfile const& self,std::span<std::uint8_t> wire,bool source_authorized) noexcept -> std::expected<MessageType,Error> {
            if (!source_authorized) return std::unexpected(Error::source);
            if (wire.size()<4) return std::unexpected(Error::invalid_length);
            if (self.provider_==Provider::standard && std::ranges::any_of(wire.subspan(1,3),[](auto c) { return c!=0; }))
                return std::unexpected(Error::invalid_reserved);
            auto original=std::array<std::uint8_t,3>{wire[1],wire[2],wire[3]};
            std::fill_n(wire.begin()+1,3,0);
            auto type=message_type(wire);
            if (!type) { std::ranges::copy(original,wire.begin()+1); return std::unexpected(type.error()); }
            return *type;
        }
    };
}
