export module vless.corosio_server;
import std;
import capy;
import corosio;
import vless;

export namespace vless::detail {
    enum class ServerError { state, rejected, io };
    // Stream is an already established transport. Its owner must cancel and
    // drain all operations before destroying this adapter or the stream.
    template<class Stream>
    class TcpServer {
        Stream& stream_;
        ServerHandshake handshake_;
        std::array<std::uint8_t,4096> buffer_{};
        std::size_t begin_=0, end_=0;
        bool busy_=false, accepted_=false, failed_=false;
        struct BusyGuard { bool& flag; ~BusyGuard() { flag=false; } };
        auto fail(ServerError error) -> std::unexpected<ServerError> {
            failed_=true;
            stream_.cancel();
            return std::unexpected(error);
        }
    public:
        TcpServer(Stream& stream, ServerHandshake handshake) : stream_(stream),handshake_(std::move(handshake)) {}
        TcpServer(TcpServer const&)=delete;
        auto operator=(TcpServer const&) -> TcpServer& = delete;
        auto cancel() noexcept -> void { failed_=true; stream_.cancel(); }
        auto read_request() -> capy::task<std::expected<TcpRequest,ServerError>> {
            if (busy_ || failed_ || handshake_.status()!=ServerStatus::reading) co_return std::unexpected(ServerError::state);
            busy_=true; BusyGuard guard{busy_};
            for (;;) {
                auto [error,n]=co_await stream_.read_some(capy::mutable_buffer(buffer_.data(),buffer_.size()));
                if (error || !n || n>buffer_.size() || failed_) co_return fail(ServerError::io);
                auto step=handshake_.feed(std::span(buffer_).first(n));
                if (step.status==ServerStatus::rejected) co_return fail(ServerError::rejected);
                if (step.status==ServerStatus::dialing) {
                    auto const* req=handshake_.request();
                    if (!req) co_return fail(ServerError::rejected);
                    begin_=step.consumed; end_=n;
                    co_return *req;
                }
            }
        }
        // A failed dial produces no response. The owner closes the transport.
        auto complete_dial(bool connected) -> capy::task<std::expected<void,ServerError>> {
            if (busy_ || failed_ || handshake_.status()!=ServerStatus::dialing) co_return std::unexpected(ServerError::state);
            busy_=true; BusyGuard guard{busy_};
            auto reply=handshake_.complete_dial(connected);
            if (!reply) co_return fail(ServerError::rejected);
            std::size_t sent=0;
            while (sent<reply->size()) {
                auto [error,n]=co_await stream_.write_some(capy::const_buffer(reply->data()+sent,reply->size()-sent));
                if (error || !n || n>reply->size()-sent || failed_) co_return fail(ServerError::io);
                sent+=n;
            }
            accepted_=true;
            co_return std::expected<void,ServerError>{};
        }
        // Returns zero only for transport EOF; the output buffer must be nonempty.
        auto read(std::span<std::uint8_t> output) -> capy::task<std::expected<std::size_t,ServerError>> {
            if (busy_ || failed_ || !accepted_ || output.empty()) co_return std::unexpected(ServerError::state);
            if (begin_<end_) {
                auto n=std::min(output.size(),end_-begin_);
                std::copy_n(buffer_.begin()+begin_,n,output.begin()); begin_+=n;
                co_return n;
            }
            busy_=true; BusyGuard guard{busy_};
            auto [error,n]=co_await stream_.read_some(capy::mutable_buffer(output.data(),output.size()));
            if (failed_) co_return fail(ServerError::io);
            if (capy::is_eof(error)) co_return 0;
            if (error || !n || n>output.size()) co_return fail(ServerError::io);
            co_return n;
        }
    };
}

export namespace vless::detail {
    // Both directions run on one executor. The owner retains the relay and
    // both sockets until both tasks have completed, including after cancel().
    template<class Incoming, class Target>
    class ServerRelay {
        TcpServer<Incoming>& server_;
        Incoming& incoming_;
        Target& target_;
        bool canceled_=false, uploading_=false, downloading_=false;
        auto fail() noexcept -> void { cancel(); }
    public:
        ServerRelay(TcpServer<Incoming>& server, Incoming& incoming, Target& target)
            : server_(server),incoming_(incoming),target_(target) {}
        ServerRelay(ServerRelay const&)=delete;
        auto operator=(ServerRelay const&) -> ServerRelay& = delete;
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true; server_.cancel(); target_.cancel();
        }
        auto upload() -> capy::task<bool> {
            if (uploading_ || canceled_) co_return false;
            uploading_=true;
            struct Guard { bool& f; ~Guard() { f=false; } } g{uploading_};
            std::array<std::uint8_t,16640> buffer{};
            for (;;) {
                auto result=co_await server_.read(buffer);
                if (!result || canceled_) { fail(); co_return false; }
                if (!*result) {
                    if (target_.shutdown(corosio::shutdown_send)) { fail(); co_return false; }
                    co_return true;
                }
                std::size_t sent=0;
                while (sent<*result) {
                    auto [error,n]=co_await target_.write_some(capy::const_buffer(buffer.data()+sent,*result-sent));
                    if (error || !n || n>*result-sent || canceled_) { fail(); co_return false; }
                    sent+=n;
                }
            }
        }
        auto download() -> capy::task<bool> {
            if (downloading_ || canceled_) co_return false;
            downloading_=true;
            struct Guard { bool& f; ~Guard() { f=false; } } g{downloading_};
            std::array<std::uint8_t,16640> buffer{};
            for (;;) {
                auto [error,n]=co_await target_.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                if (capy::is_eof(error) && !canceled_) {
                    if (incoming_.shutdown(corosio::shutdown_send)) { fail(); co_return false; }
                    co_return true;
                }
                if (error || !n || n>buffer.size() || canceled_) { fail(); co_return false; }
                std::size_t sent=0;
                while (sent<n) {
                    auto [write_error,count]=co_await incoming_.write_some(capy::const_buffer(buffer.data()+sent,n-sent));
                    if (write_error || !count || count>n-sent || canceled_) { fail(); co_return false; }
                    sent+=count;
                }
            }
        }
    };
}
