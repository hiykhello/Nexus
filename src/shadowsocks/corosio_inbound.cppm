export module nexus.shadowsocks.corosio_inbound;
import std;
import nexus.crypto;
import nexus.shadowsocks.frame;
import nexus.shadowsocks.corosio_client;
import nexus.shadowsocks.corosio_server;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace nexus::shadowsocks::detail {
    // Single executor; owner drains pending operations before destroying this object.
    template<class Socket>
    class InboundStream {
        Socket& socket_;
        std::vector<std::uint8_t> address_,psk_,salt_;
        FrameReader<Socket> reader_;
        std::optional<FrameEncoder> writer_;
        nex::capy::async_mutex mutex_;
        bool canceled_=false,output_closed_=false;
    public:
        InboundStream(Socket& socket,std::span<std::uint8_t const> psk,AcceptedRequest request)
            : socket_(socket),address_(std::move(request.header.address)),psk_(psk.begin(),psk.end()),salt_(std::move(request.salt)),
              reader_(socket,StartedResponse{std::move(request.cipher),std::move(request.header.payload),std::move(request.unread)}) {}
        ~InboundStream() { crypto::cleanse(psk_); }
        InboundStream(InboundStream const&)=delete;
        auto operator=(InboundStream const&) -> InboundStream& = delete;
        [[nodiscard]] auto address() const noexcept -> std::span<std::uint8_t const> { return address_; }
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true; if (writer_) writer_->close(); reader_.cancel();
        }
        auto read(std::span<std::uint8_t> output,std::chrono::steady_clock::time_point deadline)
            -> nex::capy::task<std::expected<std::size_t,ReadError>> {
            if (canceled_) co_return std::unexpected(ReadError::state);
            struct Guard { InboundStream& self; bool done=false; ~Guard() { if (!done) self.cancel(); } } guard{*this};
            auto result=co_await reader_.read(output,deadline);
            if (!result || canceled_) co_return std::unexpected(result ? ReadError::state : result.error());
            guard.done=true;
            co_return *result;
        }
        auto send(std::span<std::uint8_t const> input,std::chrono::steady_clock::time_point deadline) -> nex::capy::task<bool> {
            auto [error,lock]=co_await mutex_.scoped_lock();
            if (error || canceled_ || output_closed_) co_return false;
            struct Guard { InboundStream& self; bool done=false; ~Guard() { if (!done) self.cancel(); } } guard{*this};
            while (!input.empty()) {
                auto part=input.first(std::min(input.size(),std::size_t{65535}));
                if (!writer_) {
                    auto response=co_await send_response(socket_,psk_,salt_,part,deadline);
                    if (!response || canceled_) co_return false;
                    writer_.emplace(std::move(*response)); crypto::cleanse(psk_); psk_.clear();
                } else {
                    auto sent=co_await send_frame(socket_,*writer_,part,deadline);
                    if (!sent || canceled_) co_return false;
                }
                input=input.subspan(part.size());
            }
            guard.done=true; co_return true;
        }
        auto close_output() -> nex::capy::task<bool> {
            auto [error,lock]=co_await mutex_.scoped_lock();
            if (error || canceled_ || output_closed_) co_return false;
            output_closed_=true;
            if (socket_.shutdown(nex::corosio::shutdown_send)) { cancel(); co_return false; }
            co_return true;
        }
    };
}
