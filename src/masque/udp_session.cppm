export module masque.udp_session;
import std;
import masque.datagram;
import masque.capsule;
import quic.varint;

export namespace masque {
    enum class UdpPhase { opening,authorizing,ready,rejected,closed };
    enum class UdpInput { accepted,dropped,malformed,too_large,closed };
    struct UdpHandle {
        std::uint16_t slot=0;
        std::uint64_t generation=0;
        auto operator==(UdpHandle const&) const noexcept -> bool = default;
    };
    // Single-executor request table. The server transitions to ready only
    // after its caller has authenticated and bound a UDP association. A stale
    // handle cannot reopen a stream after close, even when the slot is reused.
    template<std::size_t Streams=16> class UdpRequests {
        static_assert(Streams && Streams<=65535);
        struct Entry { std::uint64_t stream=0,generation=0; UdpPhase phase=UdpPhase::opening; bool rx=true,tx=true; };
        std::array<std::optional<Entry>,Streams> entries_;
        std::uint64_t generation_=1;
        auto get(UdpHandle h) noexcept -> Entry* {
            if(h.slot>=Streams || !entries_[h.slot] || entries_[h.slot]->generation!=h.generation)return nullptr;
            return &*entries_[h.slot];
        }
    public:
        auto open(std::uint64_t stream,bool server) noexcept -> std::optional<UdpHandle> {
            if(!generation_ || stream>max_quarter_stream_id*4 || (stream&3) || find(stream))return {};
            for(std::size_t i=0;i<Streams;++i)if(!entries_[i]) {
                auto generation=generation_++;
                entries_[i].emplace(Entry{stream,generation,server ? UdpPhase::authorizing : UdpPhase::opening});
                return UdpHandle{static_cast<std::uint16_t>(i),generation};
            }
            return {};
        }
        auto find(std::uint64_t stream) const noexcept -> std::optional<UdpHandle> {
            for(std::size_t i=0;i<Streams;++i)if(entries_[i] && entries_[i]->stream==stream)return UdpHandle{static_cast<std::uint16_t>(i),entries_[i]->generation};
            return {};
        }
        auto approve(UdpHandle h) noexcept -> bool {
            auto* entry=get(h);
            if(!entry || (entry->phase!=UdpPhase::authorizing && entry->phase!=UdpPhase::opening) || (!entry->rx || !entry->tx))return false;
            entry->phase=UdpPhase::ready; return true;
        }
        auto reject(UdpHandle h) noexcept -> bool { auto* entry=get(h); if(!entry || entry->phase==UdpPhase::closed)return false;entry->phase=UdpPhase::rejected;return true; }
        auto receive_close(UdpHandle h) noexcept -> void {if(auto* e=get(h))e->rx=false;}
        auto send_close(UdpHandle h) noexcept -> void {if(auto* e=get(h))e->tx=false;}
        auto close(UdpHandle h) noexcept -> bool { auto* entry=get(h); if(!entry)return false;entries_[h.slot].reset();return true; }
        auto phase(UdpHandle h) noexcept -> std::optional<UdpPhase> {auto* e=get(h);return e ? std::optional(e->phase) : std::nullopt;}
        auto stream(UdpHandle h) noexcept -> std::optional<std::uint64_t> {auto* e=get(h);return e ? std::optional(e->stream) : std::nullopt;}
        auto can_receive(UdpHandle h) noexcept -> bool {auto* e=get(h);return e && e->rx && e->phase==UdpPhase::ready;}
        auto can_send(UdpHandle h) noexcept -> bool {auto* e=get(h);return e && e->tx && e->phase==UdpPhase::ready;}
    };

    // Stage only an admitted context-zero payload. Context and lengths are
    // decoded before allocation/copy, including across arbitrary fragments.
    // emit borrows the view until it returns and may not retain it.
    template<std::size_t Limit=65527> class UdpCapsules {
        static_assert(Limit<=max_udp_payload);
        CapsuleDecoder decoder_;
        quic::VarintDecoder context_;
        std::array<std::uint8_t,Limit> data_{};
        std::size_t size_=0,context_bytes_=0;
        std::uint64_t length_=0;
        bool datagram_=false,context_done_=false,skip_=false,finished_=false;
        std::optional<UdpInput> failure_;
        template<class Emit> auto complete(Emit&& emit) -> UdpInput {
            if(!datagram_)return UdpInput::dropped;
            if(!context_done_)return UdpInput::malformed;
            if(skip_)return UdpInput::dropped;
            std::invoke(std::forward<Emit>(emit),std::span(data_).first(size_));return UdpInput::accepted;
        }
    public:
        template<class Emit> auto feed(std::span<std::uint8_t const> bytes,Emit&& emit) -> UdpInput {
            if(failure_)return *failure_;
            if(finished_)return UdpInput::closed;
            UdpInput last=UdpInput::dropped;
            while(true) {
                auto result=decoder_.feed(bytes);bytes=bytes.subspan(result.consumed);
                switch(result.event) {
                case CapsuleEvent::need_more:return last;
                case CapsuleEvent::begin:
                    datagram_=result.type==datagram_capsule_type;size_=context_bytes_=0;length_=result.length;
                    context_done_=skip_=false;context_.reset();break;
                case CapsuleEvent::data: {
                    auto value=result.data;
                    if(!datagram_)break;
                    if(!context_done_) {
                        auto parsed=context_.feed(value);context_bytes_+=parsed.consumed;value=value.subspan(parsed.consumed);
                        if(parsed.status!=quic::VarintStatus::accepted)break;
                        context_done_=true;
                        if(parsed.value)skip_=true;
                        else if(length_-context_bytes_>max_udp_payload) {failure_=UdpInput::too_large;return *failure_;}
                        else if(length_-context_bytes_>Limit)skip_=true;
                    }
                    if(!skip_) {std::ranges::copy(value,data_.begin()+size_);size_+=value.size();}
                    break;
                }
                case CapsuleEvent::end:last=complete(emit);if(last==UdpInput::malformed) {failure_=last;return last;}break;
                default:failure_=UdpInput::malformed;return *failure_;
                }
            }
        }
        template<class Emit> auto finish(Emit&& emit) -> UdpInput {
            if(failure_)return *failure_;
            if(finished_)return UdpInput::closed;finished_=true;
            auto result=decoder_.finish();
            if(result==CapsuleEvent::end) {auto status=complete(emit);if(status==UdpInput::malformed)failure_=status;return status;}
            if(result==CapsuleEvent::closed)return UdpInput::accepted;
            failure_=UdpInput::malformed;return *failure_;
        }
    };
}
