export module vless.vision_client;
import std;
export import functional;
import vless;
import vless.corosio_client;
import vision;
import vision.corosio_reader;
import vision.corosio_writer;
import tls.corosio_application;
import net.stream_relay;
import capy;
import corosio;

export namespace vless::detail {
    // Authenticated TLS/Reality connection, socket and this owner must outlive
    // all operations. One reader and one writer run on the same executor.
    template<class Socket>
    class VisionClient {
        Socket& socket_;
        TcpClient<Socket,true> client_;
        vision::TrafficFilter filter_;
        vision::UserId user_;
        vision::detail::Writer<Socket> writer_;
        std::optional<vision::detail::Reader<Socket>> reader_;
        bool starting_=false, started_=false, reading_=false, failed_=false;
    public:
        VisionClient(Socket& socket,tls::detail::ApplicationConnection<Socket>& connection,vision::UserId user)
            : socket_(socket),client_(connection),user_(user),writer_(socket,connection,filter_,user) {}
        VisionClient(VisionClient const&)=delete;
        auto operator=(VisionClient const&) -> VisionClient& = delete;
        [[nodiscard]] auto send_status() const noexcept -> vision::SendStatus { return writer_.status(); }
        [[nodiscard]] auto receive_direct() const noexcept -> bool { return reader_ && reader_->direct(); }
        auto cancel() noexcept -> void { failed_=true; client_.cancel(); writer_.cancel(); if (reader_) reader_->cancel(); }
        auto start(TcpRequest const& request,tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if (starting_ || started_ || failed_ || request.user!=user_) co_return false;
            starting_=true;
            struct Guard { bool& f; ~Guard() { f=false; } } g{starting_};
            try {
                auto result=co_await client_.start_vision(request,deadline);
                if (!result || failed_) { cancel(); co_return false; }
                started_=true; co_return true;
            } catch (...) { cancel(); throw; }
        }
        // Used only by an owner implementing the Mux/XUDP frame protocol.
        auto start_mux(tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if (starting_ || started_ || failed_) co_return false;
            starting_=true;
            struct Guard { bool& f; ~Guard() { f=false; } } g{starting_};
            try {
                auto result=co_await client_.start_mux(user_,true,deadline);
                if (!result || failed_) { cancel(); co_return false; }
                started_=true; co_return true;
            } catch (...) { cancel(); throw; }
        }
        // Upload may begin before the peer sends its VLESS response.
        auto write(std::span<std::uint8_t const> data,tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if (!started_ || failed_) co_return false;
            if (!co_await writer_.write(data,deadline)) { cancel(); co_return false; }
            co_return true;
        }
        auto close_output(tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if (!started_ || failed_) co_return false;
            if (!co_await writer_.close_output(deadline)) { cancel(); co_return false; }
            co_return true;
        }
        auto read(std::span<std::uint8_t> output,tls::detail::ApplicationDeadline deadline={})
            -> capy::task<std::expected<std::size_t,ClientError>> {
            if (!started_ || failed_ || reading_ || output.empty()) co_return std::unexpected(ClientError::state);
            reading_=true;
            struct Guard { bool& f; ~Guard() { f=false; } } g{reading_};
            try {
                if (!reader_) {
                    for (;;) {
                        auto response=co_await client_.receive_response(deadline);
                        if (failed_) { cancel(); co_return std::unexpected(ClientError::response); }
                        if (response) break;
                        if (response.error()!=ClientError::backpressure || !co_await writer_.flush_control(deadline) || failed_) {
                            cancel(); co_return std::unexpected(ClientError::response);
                        }
                    }
                    auto stream=client_.reader();
                    if (!stream || failed_) { cancel(); co_return std::unexpected(ClientError::state); }
                    reader_.emplace(socket_,*stream,writer_,filter_,user_);
                }
                auto result=co_await reader_->read(output,deadline);
                if (!result || failed_) { cancel(); co_return std::unexpected(ClientError::tls); }
                co_return *result;
            } catch (...) { cancel(); throw; }
        }
    };
}

export namespace vless::detail {
    // Both directions run on one executor. The owner retains and drains this
    // relay, the client and sockets after cancellation or failure.
    template<class LocalSocket,class RemoteSocket>
    class VisionRelay {
        LocalSocket& local_;
        VisionClient<RemoteSocket>& client_;
        functional::move_only_function<void()> touch_;
        bool canceled_=false, uploading_=false, downloading_=false;
        bool cancel_local_=true;
    public:
        VisionRelay(LocalSocket& local,VisionClient<RemoteSocket>& client,functional::move_only_function<void()> touch={},bool cancel_local=true)
            : local_(local),client_(client),touch_(std::move(touch)),cancel_local_(cancel_local) {}
        VisionRelay(VisionRelay const&)=delete;
        auto operator=(VisionRelay const&) -> VisionRelay& = delete;
        auto cancel() noexcept -> void { if (!canceled_) { canceled_=true; if (cancel_local_) local_.cancel(); client_.cancel(); } }
        auto write(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if (canceled_ || bytes.empty()) co_return false;
            if (!co_await client_.write(bytes,deadline) || canceled_) { cancel(); co_return false; }
            if (touch_) touch_(); co_return true;
        }
        auto read(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline={})
            -> capy::task<std::expected<std::size_t,ClientError>> {
            if (canceled_ || bytes.empty()) co_return std::unexpected(ClientError::state);
            auto result=co_await client_.read(bytes,deadline);
            if (!result || canceled_) { cancel(); co_return std::unexpected(ClientError::tls); }
            if (*result && touch_) touch_(); co_return *result;
        }
        auto close_output(tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if (canceled_ || !co_await client_.close_output(deadline)) { cancel(); co_return false; }
            co_return true;
        }
    private:
        struct RelayAdapter {
            VisionRelay& relay;
            tls::detail::ApplicationDeadline deadline;
            net::stream_relay::Delivery delivery;
            static constexpr bool locked_upload=false;
            auto local() const -> LocalSocket& { return relay.local_; }
            auto start_upload() -> bool {
                if (relay.canceled_ || relay.uploading_) return false;
                relay.uploading_=true; return true;
            }
            auto start_download() -> bool {
                if (relay.canceled_ || relay.downloading_) return false;
                relay.downloading_=true; return true;
            }
            template<class Error> auto upload_eof(Error const& error,std::size_t) const -> bool {
                return capy::is_eof(error) && !relay.canceled_;
            }
            template<class Error> auto invalid_upload(Error const& error,std::size_t n,std::size_t size) const -> bool {
                return error || !n || n>size || relay.canceled_;
            }
            template<class Error> auto invalid_download(Error const& error,std::size_t n,std::size_t size) const -> bool {
                return error || !n || n>size || relay.canceled_;
            }
            auto after_local_read() const -> void {}
            auto after_local_write() const -> void {}
            auto cancel() const noexcept -> void { relay.cancel(); }
            auto close_upload() const { return relay.close_output(deadline); }
            auto send_upload(std::span<std::uint8_t const> bytes) const { return relay.write(bytes,deadline); }
            auto receive(std::span<std::uint8_t> bytes) const { return relay.read(bytes,deadline); }
            auto shutdown_local() const -> bool {
                if (relay.local_.shutdown(corosio::shutdown_send)) { relay.cancel(); return false; }
                return true;
            }
        };
    public:
        auto upload(tls::detail::ApplicationDeadline deadline={},net::stream_relay::Delivery delivery={}) -> capy::task<bool> {
            return net::stream_relay::upload(RelayAdapter{*this,deadline,delivery});
        }
        auto download(tls::detail::ApplicationDeadline deadline={},net::stream_relay::Delivery delivery={}) -> capy::task<bool> {
            return net::stream_relay::download(RelayAdapter{*this,deadline,delivery});
        }
    };
}
