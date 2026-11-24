export module shadowsocks.corosio_inbound;
import std;
import crypto;
import shadowsocks.frame;
import shadowsocks.key;
import shadowsocks.corosio_client;
import shadowsocks.corosio_server;
import capy;
import corosio;

export namespace shadowsocks::detail {
    // Single executor; owner drains pending operations before destroying this object.
    template<class Socket>
    class InboundStream {
        Socket& socket_;
        std::vector<std::uint8_t> address_,psk_,salt_;
        CipherMethod method_;
        FrameReader<Socket> reader_;
        std::optional<FrameEncoder> writer_;
        capy::async_mutex mutex_;
        bool canceled_=false,output_closed_=false;
    public:
        InboundStream(Socket& socket,std::span<std::uint8_t const> psk,AcceptedRequest request)
            : socket_(socket),address_(std::move(request.header.address)),psk_(psk.begin(),psk.end()),salt_(std::move(request.salt)),
              method_(request.cipher.method()),
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
            -> capy::task<std::expected<std::size_t,ReadError>> {
            if (canceled_) co_return std::unexpected(ReadError::state);
            struct Guard { InboundStream& self; bool done=false; ~Guard() { if (!done) self.cancel(); } } guard{*this};
            auto result=co_await reader_.read(output,deadline);
            if (!result || canceled_) co_return std::unexpected(result ? ReadError::state : result.error());
            guard.done=true;
            co_return *result;
        }
        // A sniff timeout leaves frame and cipher state available for relay.
        auto read_sniff(std::span<std::uint8_t> output,std::chrono::steady_clock::time_point deadline)
            -> capy::task<std::expected<std::size_t,ReadError>> {
            if(canceled_)co_return std::unexpected(ReadError::state);
            struct Guard {InboundStream& self;bool done=false;~Guard(){if(!done)self.cancel();}} guard{*this};
            auto result=co_await reader_.read(output,deadline,true);
            if(!result) {
                if(result.error()==ReadError::timeout && !canceled_)guard.done=true;
                co_return std::unexpected(result.error());
            }
            if(canceled_)co_return std::unexpected(ReadError::state);
            guard.done=true;co_return *result;
        }
        auto send(std::span<std::uint8_t const> input,std::chrono::steady_clock::time_point deadline) -> capy::task<bool> {
            auto [error,lock]=co_await mutex_.scoped_lock();
            if (error || canceled_ || output_closed_) co_return false;
            struct Guard { InboundStream& self; bool done=false; ~Guard() { if (!done) self.cancel(); } } guard{*this};
            while (!input.empty()) {
                auto part=input.first(std::min(input.size(),std::size_t{65535}));
                if (!writer_) {
                    auto response=co_await send_response(socket_,psk_,salt_,part,deadline,method_);
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
        auto close_output() -> capy::task<bool> {
            auto [error,lock]=co_await mutex_.scoped_lock();
            if (error || canceled_ || output_closed_) co_return false;
            output_closed_=true;
            if (socket_.shutdown(corosio::shutdown_send)) { cancel(); co_return false; }
            co_return true;
        }
    };
}
