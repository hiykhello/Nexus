export module nexus.vless.corosio_server;
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.vless;

export namespace nexus::vless::detail {
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
        auto read_request() -> nex::capy::task<std::expected<TcpRequest,ServerError>> {
            if (busy_ || failed_ || handshake_.status()!=ServerStatus::reading) co_return std::unexpected(ServerError::state);
            busy_=true;
            for (;;) {
                auto [error,n]=co_await stream_.read_some(nex::capy::mutable_buffer(buffer_.data(),buffer_.size()));
                if (error || !n || failed_) { busy_=false; co_return fail(ServerError::io); }
                auto step=handshake_.feed(std::span(buffer_).first(n));
                if (step.status==ServerStatus::rejected) { busy_=false; co_return fail(ServerError::rejected); }
                if (step.status==ServerStatus::dialing) {
                    begin_=step.consumed; end_=n; busy_=false;
                    co_return *handshake_.request();
                }
            }
        }
        // A failed dial produces no response. The owner closes the transport.
        auto complete_dial(bool connected) -> nex::capy::task<std::expected<void,ServerError>> {
            if (busy_ || failed_ || handshake_.status()!=ServerStatus::dialing) co_return std::unexpected(ServerError::state);
            busy_=true;
            auto reply=handshake_.complete_dial(connected);
            if (!reply) { busy_=false; co_return fail(ServerError::rejected); }
            std::size_t sent=0;
            while (sent<reply->size()) {
                auto [error,n]=co_await stream_.write_some(nex::capy::const_buffer(reply->data()+sent,reply->size()-sent));
                if (error || !n || failed_) { busy_=false; co_return fail(ServerError::io); }
                sent+=n;
            }
            busy_=false; accepted_=true;
            co_return std::expected<void,ServerError>{};
        }
        // Returns zero only for transport EOF; the output buffer must be nonempty.
        auto read(std::span<std::uint8_t> output) -> nex::capy::task<std::expected<std::size_t,ServerError>> {
            if (busy_ || failed_ || !accepted_ || output.empty()) co_return std::unexpected(ServerError::state);
            if (begin_<end_) {
                auto n=std::min(output.size(),end_-begin_);
                std::copy_n(buffer_.begin()+begin_,n,output.begin()); begin_+=n;
                co_return n;
            }
            busy_=true;
            auto [error,n]=co_await stream_.read_some(nex::capy::mutable_buffer(output.data(),output.size()));
            busy_=false;
            if (failed_) co_return fail(ServerError::io);
            if (nex::capy::is_eof(error)) co_return 0;
            if (error || !n) co_return fail(ServerError::io);
            co_return n;
        }
    };
}

export namespace nexus::vless::detail {
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
        auto upload() -> nex::capy::task<bool> {
            if (uploading_ || canceled_) co_return false;
            uploading_=true;
            std::array<std::uint8_t,16384> buffer{};
            for (;;) {
                auto result=co_await server_.read(buffer);
                if (!result || canceled_) { fail(); co_return false; }
                if (!*result) {
                    if (target_.shutdown(nex::corosio::shutdown_send)) { fail(); co_return false; }
                    co_return true;
                }
                std::size_t sent=0;
                while (sent<*result) {
                    auto [error,n]=co_await target_.write_some(nex::capy::const_buffer(buffer.data()+sent,*result-sent));
                    if (error || !n || canceled_) { fail(); co_return false; }
                    sent+=n;
                }
            }
        }
        auto download() -> nex::capy::task<bool> {
            if (downloading_ || canceled_) co_return false;
            downloading_=true;
            std::array<std::uint8_t,16384> buffer{};
            for (;;) {
                auto [error,n]=co_await target_.read_some(nex::capy::mutable_buffer(buffer.data(),buffer.size()));
                if (nex::capy::is_eof(error) && !canceled_) {
                    if (incoming_.shutdown(nex::corosio::shutdown_send)) { fail(); co_return false; }
                    co_return true;
                }
                if (error || !n || canceled_) { fail(); co_return false; }
                std::size_t sent=0;
                while (sent<n) {
                    auto [write_error,count]=co_await incoming_.write_some(nex::capy::const_buffer(buffer.data()+sent,n-sent));
                    if (write_error || !count || canceled_) { fail(); co_return false; }
                    sent+=count;
                }
            }
        }
    };
}
