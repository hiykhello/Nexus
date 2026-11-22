export module vless.vision_server;
import std;
import vless;
import vless.tls_server;
import vision;
import vision.corosio_reader;
import vision.corosio_writer;
import tls.corosio_application;
import nexus.thirdparty.capy;

export namespace vless::detail {
    // Vision-only authenticated inbound. The same executor owns the socket,
    // TLS connection, this object and both directions until calls are drained.
    template<class Socket>
    class VisionInbound {
        Socket& socket_;
        tls::detail::ApplicationConnection<Socket>& connection_;
        TlsInbound<Socket,true> inbound_;
        vision::TrafficFilter filter_;
        std::optional<vision::UserId> user_;
        std::optional<vision::detail::Writer<Socket>> writer_;
        std::optional<vision::detail::Reader<Socket>> reader_;
        bool failed_=false;
    public:
        VisionInbound(Socket& socket,tls::detail::ApplicationConnection<Socket>& connection,ServerHandshake handshake)
            : socket_(socket),connection_(connection),inbound_(connection,std::move(handshake)) {}
        VisionInbound(VisionInbound const&)=delete;
        auto operator=(VisionInbound const&) -> VisionInbound& = delete;
        [[nodiscard]] auto send_status() const noexcept -> std::optional<vision::SendStatus> { return writer_ ? std::optional{writer_->status()} : std::nullopt; }
        [[nodiscard]] auto receive_direct() const noexcept -> bool { return reader_ && reader_->direct(); }
        auto cancel() noexcept -> void { failed_=true; inbound_.cancel(); if (writer_) writer_->cancel(); }
        [[nodiscard]] auto allow_mux() noexcept -> bool { return !failed_ && inbound_.allow_mux(); }
        auto read_header() -> nex::capy::task<std::expected<InboundRequest,TlsInboundError>> {
            if (failed_ || user_ || !inbound_.vision_enabled()) co_return std::unexpected(TlsInboundError::state);
            auto result=co_await inbound_.read_header();
            if (!result || failed_) { cancel(); co_return std::unexpected(TlsInboundError::rejected); }
            if (auto request=std::get_if<TcpRequest>(&*result)) user_=request->user;
            else user_=std::get<UserId>(*result);
            co_return std::move(*result);
        }
        auto read_request() -> nex::capy::task<std::expected<TcpRequest,TlsInboundError>> {
            auto result=co_await read_header();
            if (!result) co_return std::unexpected(result.error());
            if (auto request=std::get_if<TcpRequest>(&*result)) co_return std::move(*request);
            cancel(); co_return std::unexpected(TlsInboundError::rejected);
        }
        auto complete_dial(bool connected) -> nex::capy::task<std::expected<void,TlsInboundError>> {
            if (failed_ || !user_ || writer_) co_return std::unexpected(TlsInboundError::state);
            auto result=co_await inbound_.complete_dial(connected);
            if (!result || failed_) { cancel(); co_return std::unexpected(TlsInboundError::io); }
            auto handoff=inbound_.handoff_vision();
            if (!handoff) { cancel(); co_return std::unexpected(TlsInboundError::state); }
            writer_.emplace(socket_,connection_,filter_,*user_);
            reader_.emplace(socket_,*handoff->reader,*writer_,filter_,*user_,handoff->initial);
            co_return std::expected<void,TlsInboundError>{};
        }
        auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t,TlsInboundError>> {
            if (failed_ || !reader_) co_return std::unexpected(TlsInboundError::state);
            auto result=co_await reader_->read(bytes);
            if (!result || failed_) { cancel(); co_return std::unexpected(TlsInboundError::io); }
            co_return *result;
        }
        auto send(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
            if (failed_ || !writer_) co_return false;
            if (!co_await writer_->write(bytes) || failed_) { cancel(); co_return false; }
            co_return true;
        }
        auto close_output() -> nex::capy::task<bool> {
            if (failed_ || !writer_) co_return false;
            if (!co_await writer_->close_output() || failed_) { cancel(); co_return false; }
            co_return true;
        }
    };
}
