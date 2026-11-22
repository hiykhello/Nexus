export module hysteria2.dispatch;
import std;
import quic.varint;

export namespace hysteria2 {
    enum class StreamRoute { pending,http3,tcp,rejected };
    enum class DispatchError { none,unauthenticated,truncated };
    struct DispatchResult { StreamRoute route=StreamRoute::pending; std::size_t consumed=0; DispatchError error=DispatchError::none; };
    // One instance per incoming client bidirectional stream. The caller keeps
    // the instance until that stream closes and bounds the number of streams.
    // No HTTP3 bytes may be submitted before classification. On transition,
    // submit prefix() once, then the unconsumed input, to the chosen consumer.
    class StreamDispatch {
        std::array<std::uint8_t,8> prefix_{};
        std::size_t size_=0,width_=0;
        StreamRoute route_=StreamRoute::pending;
        DispatchError error_=DispatchError::none;
        bool eligible_=false;
    public:
        auto route() const noexcept -> StreamRoute { return route_; }
        auto prefix() const noexcept -> std::span<std::uint8_t const> { return std::span(prefix_).first(size_); }
        // Authentication is captured at the first byte. Completing auth on
        // another stream cannot authorize an already-started business stream.
        auto feed(std::span<std::uint8_t const> input,bool authenticated,bool fin=false) noexcept -> DispatchResult {
            if (route_!=StreamRoute::pending) return {route_,0,error_};
            if (!width_ && !input.empty()) { width_=std::size_t{1}<<(input[0]>>6); eligible_=authenticated; }
            auto count=std::min(width_-size_,input.size());
            std::copy_n(input.begin(),count,prefix_.begin()+size_); size_+=count;
            if (width_ && size_==width_) {
                auto type=quic::read_varint(prefix()).value;
                route_=type==0x401 ? (eligible_ ? StreamRoute::tcp : StreamRoute::rejected) : StreamRoute::http3;
                if (route_==StreamRoute::rejected) error_=DispatchError::unauthenticated;
            } else if (fin) { route_=StreamRoute::rejected; error_=DispatchError::truncated; }
            return {route_,count,error_};
        }
    };
}
