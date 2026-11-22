export module masque.http3;
import std;
import quic.varint;
import masque.datagram;

export namespace masque {
    enum class SettingsError { invalid,duplicate,offset,closed };
    // Tracks the actual local control stream bytes accepted by QUIC. It parses
    // the stream type and first SETTINGS frame without retaining their bytes.
    // The owner feeds only the prefix accepted by ngtcp2, then reports native
    // contiguous ACK offsets for this same stream. Waiting for ACK is stricter
    // than RFC 9297's sent requirement but handles delayed/local failed sends.
    class LocalSettings {
        enum class State { stream_type,frame_type,frame_length,key,value,done,error,closed };
        State state_=State::stream_type;
        quic::VarintDecoder integer_;
        std::uint64_t key_=0,remaining_=0,accepted_=0,acked_=0,end_=0;
        bool seen_datagram_=false,datagram_=false,seen_connect_=false,connect_=false;
        auto failure() noexcept -> std::unexpected<SettingsError> {state_=State::error;return std::unexpected(SettingsError::invalid);}
        auto read(std::span<std::uint8_t const>& bytes,std::uint64_t max) noexcept -> quic::VarintResult {
            auto count=static_cast<std::size_t>(std::min<std::uint64_t>(max,bytes.size()));
            auto result=integer_.feed(bytes.first(count));bytes=bytes.subspan(result.consumed);accepted_+=result.consumed;
            return result;
        }
    public:
        auto accepted(std::span<std::uint8_t const> bytes) noexcept -> std::expected<void,SettingsError> {
            if(state_==State::closed)return std::unexpected(SettingsError::closed);
            if(state_==State::error || bytes.size()>quic::max_varint-accepted_)return failure();
            while(state_!=State::done) {
                auto before=bytes.size();
                auto result=read(bytes,(state_==State::key || state_==State::value) ? remaining_ : quic::max_varint);
                auto consumed=before-bytes.size();
                if(state_==State::key || state_==State::value)remaining_-=consumed;
                if(result.status!=quic::VarintStatus::accepted) {
                    if((state_==State::key || state_==State::value) && !remaining_)return failure();
                    return {};
                }
                integer_.reset();
                switch(state_) {
                case State::stream_type:if(result.value)return failure();state_=State::frame_type;break;
                case State::frame_type:if(result.value!=4)return failure();state_=State::frame_length;break;
                case State::frame_length:
                    remaining_=result.value;
                    if(!remaining_) {state_=State::done;end_=accepted_;} else state_=State::key;
                    break;
                case State::key:
                    key_=result.value;
                    if(!remaining_)return failure();
                    state_=State::value;break;
                case State::value:
                    if(key_==0x33) {if(seen_datagram_ || result.value>1)return failure();seen_datagram_=true;datagram_=bool(result.value);}
                    else if(key_==0x08) {if(seen_connect_ || result.value>1)return failure();seen_connect_=true;connect_=bool(result.value);}
                    if(!remaining_) {state_=State::done;end_=accepted_;} else state_=State::key;
                    break;
                default:return failure();
                }
                if(bytes.empty())break;
            }
            if(state_==State::done)accepted_+=bytes.size();
            return {};
        }
        // ngtcp2 reports ACK ranges in increasing, contiguous stream order.
        auto acknowledged(std::uint64_t offset,std::uint64_t length) noexcept -> std::expected<void,SettingsError> {
            if(state_==State::closed)return std::unexpected(SettingsError::closed);
            if(state_==State::error)return std::unexpected(SettingsError::invalid);
            if(offset!=acked_ || length>accepted_-acked_)return std::unexpected(SettingsError::offset);
            acked_+=length;return {};
        }
        auto complete() const noexcept -> bool {return state_==State::done;}
        auto sent_and_acked() const noexcept -> bool {return complete() && acked_>=end_;}
        auto datagram() const noexcept -> bool {return complete() && datagram_;}
        auto extended_connect() const noexcept -> bool {return complete() && connect_;}
        auto close() noexcept -> void {state_=State::closed;}
    };

    enum class Http3StreamKind { unknown,no_datagram,datagram };
    struct Http3StreamState {Http3StreamKind kind=Http3StreamKind::unknown;bool receive_open=false,send_open=false;};
    enum class Http3DatagramAction { deliver,drop,connection_error,stream_error };
    struct ReceivedHttp3Datagram {
        Http3DatagramAction action=Http3DatagramAction::drop;
        std::uint64_t stream_id=0;
        // Borrowed from the input packet; never retained by this owner.
        std::span<std::uint8_t const> payload;
    };
    enum class SendError { stopped,not_negotiated,closed,unsupported,invalid_stream,too_large };
    struct Http3DatagramPrefix { std::array<std::uint8_t,8> bytes{};std::size_t size=0; };

    // Single-executor boundary. The owning H3 application supplies its live
    // request classification synchronously and rechecks it on every send;
    // this object does not own streams, queue packets or permit 0-RTT.
    class Http3DatagramBoundary {
        LocalSettings local_;
        std::uint64_t control_stream_=0,peer_max_frame_=0;
        bool server_=false,peer_settings_=false,peer_datagram_=false,peer_connect_=false,peer_transport_=false,stopped_=false;
        Http3DatagramBoundary(bool server,std::uint64_t control) noexcept:control_stream_(control),server_(server) {}
    public:
        // The local H3 control stream is unidirectional and owned by this
        // endpoint. Store its ID to avoid accepting unrelated stream events.
        static auto create(bool server,std::uint64_t control) noexcept -> std::expected<Http3DatagramBoundary,SettingsError> {
            if(control>quic::max_varint || (control&3)!=(server ? 3u : 2u))return std::unexpected(SettingsError::invalid);
            return Http3DatagramBoundary(server,control);
        }
        auto accepted_stream(std::uint64_t stream,std::span<std::uint8_t const> bytes) noexcept -> std::expected<void,SettingsError> {
            if(stopped_)return std::unexpected(SettingsError::closed);
            return stream==control_stream_ ? local_.accepted(bytes) : std::expected<void,SettingsError>{};
        }
        auto acknowledged_stream(std::uint64_t stream,std::uint64_t offset,std::uint64_t length) noexcept -> std::expected<void,SettingsError> {
            if(stopped_)return std::unexpected(SettingsError::closed);
            return stream==control_stream_ ? local_.acknowledged(offset,length) : std::expected<void,SettingsError>{};
        }
        auto peer_settings(std::uint64_t datagram,std::uint64_t connect) noexcept -> std::expected<void,SettingsError> {
            if(stopped_)return std::unexpected(SettingsError::closed);
            if(peer_settings_)return std::unexpected(SettingsError::duplicate);
            if(datagram>1 || connect>1)return std::unexpected(SettingsError::invalid);
            peer_settings_=true;peer_datagram_=bool(datagram);peer_connect_=bool(connect);return {};
        }
        auto peer_transport(std::uint64_t max_frame) noexcept -> std::expected<void,SettingsError> {
            if(stopped_)return std::unexpected(SettingsError::closed);
            if(peer_transport_)return std::unexpected(SettingsError::duplicate);
            if(max_frame>quic::max_varint)return std::unexpected(SettingsError::invalid);
            peer_max_frame_=max_frame;peer_transport_=true;return {};
        }
        // Extended CONNECT may be requested after server SETTINGS are received.
        auto can_open_extended_connect() const noexcept -> bool {return !server_ && !stopped_ && peer_settings_ && peer_connect_;}
        auto can_send_datagram() const noexcept -> bool {
            return !stopped_ && local_.sent_and_acked() && local_.datagram() && peer_settings_ && peer_datagram_ && peer_transport_ && peer_max_frame_;
        }
        // payload_budget is the actual HTTP Datagram byte budget derived from
        // peer QUIC limit and path capacity, including this stream prefix.
        // ngtcp2 remains the final admission point and may reject the packet.
        auto send_prefix(std::uint64_t stream_id,Http3StreamState state,std::size_t payload_size,std::size_t payload_budget) const noexcept -> std::expected<Http3DatagramPrefix,SendError> {
            if(stopped_)return std::unexpected(SendError::stopped);
            if(!can_send_datagram())return std::unexpected(SendError::not_negotiated);
            if(!state.send_open || state.kind==Http3StreamKind::unknown)return std::unexpected(SendError::closed);
            if(state.kind!=Http3StreamKind::datagram)return std::unexpected(SendError::unsupported);
            Http3DatagramPrefix prefix;auto length=write_http3_datagram_prefix(prefix.bytes,stream_id);
            if(!length)return std::unexpected(SendError::invalid_stream);
            if(*length>payload_budget || payload_size>payload_budget-*length)return std::unexpected(SendError::too_large);
            if(payload_size>quic::max_varint-*length)return std::unexpected(SendError::too_large);
            auto datagram_size=static_cast<std::uint64_t>(payload_size)+*length;
            auto frame_header=1+quic::varint_size(datagram_size); // ngtcp2 uses the length-bearing frame.
            if(frame_header>peer_max_frame_ || datagram_size>peer_max_frame_-frame_header)return std::unexpected(SendError::too_large);
            prefix.size=*length;return prefix;
        }
        template<class Resolve> auto receive(std::span<std::uint8_t const> bytes,Resolve&& resolve) -> ReceivedHttp3Datagram {
            if(stopped_)return {};
            auto parsed=parse_http3_datagram(bytes);
            if(!parsed)return {Http3DatagramAction::connection_error};
            if(!local_.datagram())return {};
            auto state=std::invoke(std::forward<Resolve>(resolve),parsed->stream_id);
            if(!state.receive_open)return {};
            switch(state.kind) {
            case Http3StreamKind::unknown:return {};
            case Http3StreamKind::no_datagram:return {Http3DatagramAction::stream_error,parsed->stream_id};
            case Http3StreamKind::datagram:return {Http3DatagramAction::deliver,parsed->stream_id,parsed->payload};
            }
            return {};
        }
        auto stop() noexcept -> void {stopped_=true;local_.close();}
    };
}
