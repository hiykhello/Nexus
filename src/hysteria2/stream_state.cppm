export module hysteria2.stream_state;
import std;
import hysteria2.dispatch;
import hysteria2.wire;
import hysteria2.stream_buffer;
import hysteria2.receive_buffer;
import quic.http3_headers;
import nghttp3;

export namespace hysteria2 {
    enum class StreamPhase { opening,request,routing,ready,rejected,reset,closed,masquerade };
    enum class ApplicationError { state,capacity,header,authentication,flow_control,protocol,unsupported,exhausted };
    struct StreamHandle {
        std::uint16_t slot=0;
        std::uint64_t generation=0;
        auto operator==(StreamHandle const&) const noexcept -> bool = default;
    };
    struct StreamRead { std::size_t size=0; bool eof=false; };
    struct Http3ResponseBody {
        std::vector<std::uint8_t> bytes;
        std::size_t sent=0,acked=0;
    };
    template<std::size_t Window> struct StreamState {
        std::int64_t id=-1;
        std::uint64_t generation=0,received=0;
        StreamDispatch dispatch;
        std::variant<TcpRequestDecoder,TcpResponseDecoder> decoder;
        quic::Http3Headers<> headers;
        std::optional<Http3ResponseBody> http3_body;
        ReceiveBuffer input;
        StreamBuffer<Window> output;
        StreamPhase phase=StreamPhase::opening;
        bool tcp=false,header_done=false,input_fin=false,output_fin=false,output_stopped=false,fin_accepted=false,transport_closed=false,abandoned=false,business_owned=false,masquerade_pending=false;
        std::uint64_t reset_code=0;
        StreamState(std::int64_t id,std::uint64_t generation,bool server,nghttp3::nghttp3_mem memory,std::size_t input_limit)
            :id(id),generation(generation),input(memory,input_limit) {
            if (!server) decoder.template emplace<TcpResponseDecoder>();
        }
        auto complete_header() const noexcept -> bool { return header_done; }
        auto address() const noexcept -> std::string_view {
            if (auto* decoder=std::get_if<TcpRequestDecoder>(&this->decoder)) {
                if (auto request=decoder->request()) return request->address;
            }
            return {};
        }
    };
}
