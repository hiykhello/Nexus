export module net.packet_stream_socket;
import std;
import net.datagram_frame;
import uot;
import xudp;
import xudp.client_io;
import xudp.client_sessions;
import capy;
import corosio;

export namespace net {
    // A single peer over an already-connected packet-capable proxy stream.
    // One reader and one writer may run concurrently on the same executor;
    // the owner cancels and joins both before destroying this socket or stream.
    inline auto packet_peer_address(corosio::endpoint const& peer) -> ProxyAddress {
        ProxyAddress result;result.port=peer.port();
        if(peer.is_v6()) {
            result.family=ProxyAddressFamily::ipv6;result.length=16;
            auto bytes=peer.address().to_v6().to_bytes();std::ranges::copy(bytes,result.bytes.begin());
        } else {
            result.family=ProxyAddressFamily::ipv4;result.length=4;
            auto bytes=peer.address().to_v4().to_bytes();std::ranges::copy(bytes,result.bytes.begin());
        }
        return result;
    }

    template<class Stream>
    class PacketStreamSocket {
        using Clock=std::chrono::steady_clock;
        using Io=corosio::io_context;
        using Endpoint=corosio::endpoint;
        struct Adapter {
            PacketStreamSocket& owner;
            auto write(std::span<std::uint8_t const> bytes) {return owner.stream_->send(bytes);}
            auto read(std::span<std::uint8_t> bytes) {return owner.stream_->read(bytes);}
            auto cancel() noexcept -> void {if(owner.stream_)owner.stream_->cancel();}
        };
        struct Guard {
            PacketStreamSocket& owner;bool completed=false;
            ~Guard(){if(!completed)owner.close();}
        };
        Io& context_;
        Stream* stream_=nullptr;
        Endpoint peer_,local_;
        PacketTransport transport_;
        ProxyAddress target_;
        std::optional<DatagramDecoder> decoder_;
        Adapter adapter_{*this};
        std::optional<xudp::ClientIo<Adapter>> xudp_;
        std::uint16_t session_=0;
        capy::async_event session_ready_;
        std::array<std::uint8_t,16384> input_{};
        std::size_t begin_=0,end_=0;
        bool closed_=false,prepared_=false,reading_=false,writing_=false;
        static auto failure(std::errc code) noexcept -> std::error_code {return std::make_error_code(code);}
        auto send_request(std::span<std::uint8_t const> bytes) -> capy::task<capy::results<>> {
            auto sent=co_await stream_->send(bytes);
            co_return capy::results<>{sent ? std::error_code{} : failure(std::errc::io_error)};
        }
        auto xaddress() const noexcept -> xudp::Address {
            xudp::Address result;result.family=peer_.is_v6() ? xudp::Family::ipv6 : xudp::Family::ipv4;
            result.length=target_.length;result.port=target_.port;std::copy_n(target_.bytes.begin(),target_.length,result.bytes.begin());return result;
        }
    public:
        explicit PacketStreamSocket(Io& context) noexcept:context_(context) {}
        PacketStreamSocket(PacketStreamSocket const&)=delete;
        auto operator=(PacketStreamSocket const&) -> PacketStreamSocket& = delete;
        ~PacketStreamSocket(){close();}
        auto context() noexcept -> Io& {return context_;}
        // A lower packet transport is connected before this call. The peer is
        // resolved once by the caller, not through the business route again.
        auto attach(Stream& stream,PacketTransport transport,Endpoint peer) -> bool {
            if(stream_ || closed_ || !peer.port() || transport.kind==PacketTransportKind::none)return false;
            stream_=&stream;peer_=peer;transport_=transport;target_=packet_peer_address(peer);
            local_=peer.is_v6() ? Endpoint(corosio::ipv6_address{},0) : Endpoint(corosio::ipv4_address{},0);
            if(transport.kind==PacketTransportKind::framed)decoder_.emplace(transport.framing,target_);
            else if(transport.kind==PacketTransportKind::xudp)xudp_.emplace(adapter_,1);
            else {stream_=nullptr;return false;}
            return true;
        }
        // UoT's request precedes every framed packet. The caller supplies the
        // same connection deadline already used to establish the lower stream.
        auto prepare(Clock::time_point deadline) -> capy::task<bool> {
            if(!stream_ || closed_ || prepared_ || Clock::now()>=deadline)co_return false;
            Guard guard{*this};
            if(transport_.needs_uot_request) {
                if(transport_.kind!=PacketTransportKind::framed)co_return false;
                auto request=uot::encode_request({transport_.framing.connected,target_});
                if(!request)co_return false;
                auto [error]=co_await corosio::timeout(send_request(*request),deadline);
                if(error || closed_ || Clock::now()>=deadline)co_return false;
            }
            prepared_=true;guard.completed=true;co_return true;
        }
        auto close() noexcept -> void {
            if(std::exchange(closed_,true))return;
            session_ready_.set();if(decoder_)decoder_->close();
            if(xudp_)xudp_->cancel();else if(stream_)stream_->cancel();
        }
        auto local_endpoint() const noexcept -> Endpoint {return local_;}
        auto send_to(capy::const_buffer buffer,Endpoint destination) -> capy::task<capy::results<std::size_t>> {
            if(!prepared_ || closed_ || writing_ || destination!=peer_)co_return capy::results<std::size_t>{failure(std::errc::invalid_argument),0};
            if(buffer.size()>65535)co_return capy::results<std::size_t>{failure(std::errc::message_size),0};
            writing_=true;struct Active{bool& value;~Active(){value=false;}} active{writing_};Guard guard{*this};
            auto bytes=std::span(static_cast<std::uint8_t const*>(buffer.data()),buffer.size());
            if(xudp_) {
                if(!session_) {
                    auto opened=co_await xudp_->open(xaddress(),bytes);
                    if(!opened || closed_)co_return capy::results<std::size_t>{failure(std::errc::io_error),0};
                    session_=*opened;session_ready_.set();
                } else {
                    auto sent=co_await xudp_->send(session_,{},bytes);
                    if(!sent || closed_)co_return capy::results<std::size_t>{failure(std::errc::io_error),0};
                }
            } else {
                auto frame=encode_datagram(transport_.framing,target_,bytes);
                if(!frame || !co_await stream_->send(*frame) || closed_)co_return capy::results<std::size_t>{failure(std::errc::io_error),0};
            }
            guard.completed=true;co_return capy::results<std::size_t>{std::error_code{},buffer.size()};
        }
        auto recv_from(capy::mutable_buffer buffer,Endpoint& source) -> capy::task<capy::results<std::size_t>> {
            if(!prepared_ || closed_ || reading_)co_return capy::results<std::size_t>{failure(std::errc::invalid_argument),0};
            reading_=true;struct Active{bool& value;~Active(){value=false;}} active{reading_};Guard guard{*this};
            auto output=std::span(static_cast<std::uint8_t*>(buffer.data()),buffer.size());
            if(xudp_) {
                while(!closed_ && !session_) {
                    session_ready_.clear();auto [error]=co_await session_ready_.wait();
                    if(error)co_return capy::results<std::size_t>{error,0};
                }
                while(!closed_) {
                    auto event=co_await xudp_->read();
                    if(!event || closed_ || event->action==xudp::Incoming::ended)break;
                    if(event->action!=xudp::Incoming::datagram || event->session!=session_ || !event->source || *event->source!=xaddress())continue;
                    if(event->payload.size()>output.size())co_return capy::results<std::size_t>{failure(std::errc::message_size),0};
                    std::ranges::copy(event->payload,output.begin());source=peer_;guard.completed=true;
                    co_return capy::results<std::size_t>{std::error_code{},event->payload.size()};
                }
            } else while(!closed_) {
                if(begin_==end_) {
                    auto result=co_await stream_->read(input_);
                    if(!result || !*result || *result>input_.size() || closed_)break;
                    begin_=0;end_=*result;
                }
                auto fed=decoder_->feed(std::span(input_).subspan(begin_,end_-begin_));begin_+=fed.consumed;
                if(fed.status==DatagramStatus::incomplete && fed.consumed)continue;
                if(fed.status!=DatagramStatus::accepted)break;
                auto packet=decoder_->packet();if(!packet)break;
                if(packet->destination!=target_) {(void)decoder_->consume();continue;}
                if(packet->payload.size()>output.size())co_return capy::results<std::size_t>{failure(std::errc::message_size),0};
                auto size=packet->payload.size();std::ranges::copy(packet->payload,output.begin());
                (void)decoder_->consume();source=peer_;guard.completed=true;
                co_return capy::results<std::size_t>{std::error_code{},size};
            }
            co_return capy::results<std::size_t>{failure(closed_ ? std::errc::operation_canceled : std::errc::io_error),0};
        }
    };
}
