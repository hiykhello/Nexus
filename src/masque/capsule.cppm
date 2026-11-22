export module masque.capsule;
import std;
import quic.varint;

export namespace masque {
    inline constexpr std::uint64_t datagram_capsule_type=0;
    enum class CapsuleEvent { need_more,begin,data,end,limit,truncated,closed };
    struct CapsuleResult {
        CapsuleEvent event=CapsuleEvent::need_more;
        std::size_t consumed=0;
        std::uint64_t type=0,length=0;
        // Borrows feed() input only until the caller releases that input.
        std::span<std::uint8_t const> data;
    };
    // Pull-based framing: never stores payload or invokes a consumer; caller
    // handles begin, consumes each data span, then accepts end. Unknown types
    // can be skipped without allocating. A finite max_length is a caller's
    // policy and applies to every type; to silently skip arbitrary unknown or
    // oversized datagram types, use the default and consume without storing.
    // EOF must be reported via finish().
    class CapsuleDecoder {
        enum class State { type,length,value,end,closed,limit,truncated };
        State state_=State::type;
        quic::VarintDecoder integer_;
        std::uint64_t type_=0,length_=0,remaining_=0,limit_;
    public:
        explicit CapsuleDecoder(std::uint64_t max_length=quic::max_varint) noexcept:limit_(max_length) {}
        auto feed(std::span<std::uint8_t const> input) noexcept -> CapsuleResult {
            std::size_t consumed=0;
            while(true) {
                switch(state_) {
                case State::type:
                case State::length: {
                    auto value=integer_.feed(input.subspan(consumed));
                    consumed+=value.consumed;
                    if(value.status!=quic::VarintStatus::accepted)return {CapsuleEvent::need_more,consumed};
                    integer_.reset();
                    if(state_==State::type) {type_=value.value;state_=State::length;continue;}
                    length_=remaining_=value.value;
                    if(length_>limit_) {state_=State::limit;return {CapsuleEvent::limit,consumed,type_,length_};}
                    state_=remaining_ ? State::value : State::end;
                    return {CapsuleEvent::begin,consumed,type_,length_};
                }
                case State::value: {
                    auto count=static_cast<std::size_t>(std::min<std::uint64_t>(remaining_,input.size()-consumed));
                    if(!count)return {CapsuleEvent::need_more,consumed,type_,length_};
                    auto payload=input.subspan(consumed,count);consumed+=count;remaining_-=count;
                    if(!remaining_)state_=State::end;
                    return {CapsuleEvent::data,consumed,type_,length_,payload};
                }
                case State::end:
                    state_=State::type;
                    return {CapsuleEvent::end,consumed,type_,length_};
                case State::closed:return {CapsuleEvent::closed,consumed};
                case State::limit:return {CapsuleEvent::limit,consumed,type_,length_};
                case State::truncated:return {CapsuleEvent::truncated,consumed,type_,length_};
                }
            }
        }
        // A completed value still has an outstanding end event. Return it
        // first so the caller can finalize the capsule before closing.
        auto finish() noexcept -> CapsuleEvent {
            if(state_==State::closed)return CapsuleEvent::closed;
            if(state_==State::limit)return CapsuleEvent::limit;
            if(state_==State::truncated)return CapsuleEvent::truncated;
            if(state_==State::end) {state_=State::closed;return CapsuleEvent::end;}
            if(state_==State::type && integer_.at_boundary()) {state_=State::closed;return CapsuleEvent::closed;}
            state_=State::truncated;return CapsuleEvent::truncated;
        }
    };
    // Produces the TLV header only, with no partial writes on invalid inputs.
    inline auto write_capsule_prefix(std::span<std::uint8_t> output,std::uint64_t type,std::uint64_t length) noexcept -> std::optional<std::size_t> {
        auto a=quic::varint_size(type),b=quic::varint_size(length);
        if(!a || !b || output.size()<a+b)return {};
        (void)quic::write_varint(output,type,a);
        (void)quic::write_varint(output.subspan(a),length,b);
        return a+b;
    }
}
