export module shadowsocks.corosio_relay;
import std;
export import nexus.compat;
import crypto;
import shadowsocks.frame;
import shadowsocks.key;
import shadowsocks.corosio_client;
import net.stream_relay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace shadowsocks::detail {
    // One executor owns both sockets. The owner must drain both directions after cancellation.
    template<class LocalSocket,class RemoteSocket>
    class DuplexRelay {
        LocalSocket& local_; RemoteSocket& remote_;
        std::vector<std::uint8_t> psk_,salt_;
        CipherMethod method_;
        FrameEncoder encoder_;
        std::unique_ptr<FrameReader<RemoteSocket>> reader_;
        nex::capy::async_mutex writer_;
        nexus::move_only_function<void()> touch_;
        bool canceled_=false, upload_started_=false, download_started_=false, output_closed_=false, reading_=false;
        bool cancel_local_=true;
    public:
        DuplexRelay(LocalSocket& local,RemoteSocket& remote,std::span<std::uint8_t const> psk,
                    StartedRequest started,nexus::move_only_function<void()> touch={},bool cancel_local=true)
            : local_(local),remote_(remote),psk_(psk.begin(),psk.end()),salt_(std::move(started.salt)),
              method_(started.cipher.method()),encoder_(std::move(started.cipher)),touch_(std::move(touch)),cancel_local_(cancel_local) {}
        ~DuplexRelay() { crypto::cleanse(psk_); }
        DuplexRelay(DuplexRelay const&)=delete;
        auto operator=(DuplexRelay const&) -> DuplexRelay& = delete;
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true; encoder_.close(); if (reader_) reader_->cancel();
            if (cancel_local_) local_.cancel(); remote_.cancel();
        }
        auto write(std::span<std::uint8_t const> bytes, std::chrono::steady_clock::time_point deadline) -> nex::capy::task<bool> {
            auto [error,guard]=co_await writer_.scoped_lock();
            if (error || canceled_ || output_closed_) co_return false;
            while (!bytes.empty()) {
                auto part=bytes.first(std::min(bytes.size(),std::size_t{65535}));
                auto result=co_await send_frame(remote_,encoder_,part,deadline);
                if (!result || canceled_) { cancel(); co_return false; }
                if (touch_) touch_(); bytes=bytes.subspan(part.size());
            }
            co_return true;
        }
        auto read(std::span<std::uint8_t> bytes,std::chrono::steady_clock::time_point deadline)
            -> nex::capy::task<std::expected<std::size_t,ReadError>> {
            if (canceled_ || reading_ || bytes.empty()) co_return std::unexpected(ReadError::state);
            reading_=true;
            struct Guard { DuplexRelay& self; bool done=false; ~Guard() { self.reading_=false; if (!done) self.cancel(); } } guard{*this};
            if (!reader_) {
                auto response=co_await receive_response(remote_,psk_,salt_,deadline,method_);
                if (!response || canceled_) co_return std::unexpected(ReadError::transport);
                reader_=std::make_unique<FrameReader<RemoteSocket>>(remote_,std::move(*response));
                crypto::cleanse(psk_); psk_.clear();
            }
            auto result=co_await reader_->read(bytes,deadline);
            if (!result || canceled_) co_return std::unexpected(result ? ReadError::state : result.error());
            if (*result && touch_) touch_();
            guard.done=true; co_return *result;
        }
        auto close_output() -> nex::capy::task<bool> {
            auto [error,guard]=co_await writer_.scoped_lock();
            if (error || canceled_ || output_closed_) co_return false;
            output_closed_=true;
            if constexpr (requires { remote_.close_output(); }) {
                if (!co_await remote_.close_output()) { cancel(); co_return false; }
            } else {
                auto result=remote_.shutdown(nex::corosio::shutdown_send);
                if (result) { cancel(); co_return false; }
            }
            co_return true;
        }
    private:
        struct RelayAdapter {
            DuplexRelay& relay;
            net::stream_relay::Delivery delivery;
            static constexpr bool locked_upload=false;
            auto local() const -> LocalSocket& { return relay.local_; }
            auto start_upload() -> bool {
                if (relay.canceled_ || relay.upload_started_) return false;
                relay.upload_started_=true; return true;
            }
            auto start_download() -> bool {
                if (relay.canceled_ || relay.download_started_) return false;
                relay.download_started_=true; return true;
            }
            template<class Error> auto upload_eof(Error const& error,std::size_t n) const -> bool {
                return nex::capy::is_eof(error) || (!error && !n);
            }
            template<class Error> auto invalid_upload(Error const& error,std::size_t n,std::size_t size) const -> bool {
                return error || relay.canceled_ || n>size;
            }
            template<class Error> auto invalid_download(Error const& error,std::size_t n,std::size_t size) const -> bool {
                return error || relay.canceled_ || !n || n>size;
            }
            auto after_local_read() const -> void {}
            auto after_local_write() const -> void { if (relay.touch_) relay.touch_(); }
            auto cancel() const noexcept -> void { relay.cancel(); }
            auto close_upload() const -> nex::capy::task<bool> { return relay.close_output(); }
            auto send_upload(std::span<std::uint8_t const> bytes) const -> nex::capy::task<bool> {
                return relay.write(bytes,std::chrono::steady_clock::now()+std::chrono::seconds(300));
            }
            auto receive(std::span<std::uint8_t> bytes) const -> nex::capy::task<std::expected<std::size_t,ReadError>> {
                return relay.read(bytes,std::chrono::steady_clock::now()+std::chrono::seconds(300));
            }
            auto shutdown_local() const -> bool {
                if (relay.local_.shutdown(nex::corosio::shutdown_send)) { relay.cancel(); return false; }
                return true;
            }
        };
    public:
        auto upload(net::stream_relay::Delivery delivery={}) -> nex::capy::task<bool> {
            return net::stream_relay::upload(RelayAdapter{*this,delivery});
        }
        auto download(net::stream_relay::Delivery delivery={}) -> nex::capy::task<bool> {
            return net::stream_relay::download(RelayAdapter{*this,delivery});
        }
    };
}
