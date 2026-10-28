export module nexus.shadowsocks.corosio_relay;
import std;
import nexus.crypto;
import nexus.shadowsocks.frame;
import nexus.shadowsocks.corosio_client;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace nexus::shadowsocks::detail {
    // One executor owns both sockets. The owner must drain both directions after cancellation.
    template<class LocalSocket,class RemoteSocket>
    class DuplexRelay {
        LocalSocket& local_; RemoteSocket& remote_;
        std::vector<std::uint8_t> psk_,salt_;
        FrameEncoder encoder_;
        std::unique_ptr<FrameReader<RemoteSocket>> reader_;
        nex::capy::async_mutex writer_;
        std::move_only_function<void()> touch_;
        bool canceled_=false, upload_started_=false, download_started_=false, output_closed_=false, reading_=false;
    public:
        DuplexRelay(LocalSocket& local,RemoteSocket& remote,std::span<std::uint8_t const> psk,
                    StartedRequest started,std::move_only_function<void()> touch={})
            : local_(local),remote_(remote),psk_(psk.begin(),psk.end()),salt_(std::move(started.salt)),
              encoder_(std::move(started.cipher)),touch_(std::move(touch)) {}
        ~DuplexRelay() { crypto::cleanse(psk_); }
        DuplexRelay(DuplexRelay const&)=delete;
        auto operator=(DuplexRelay const&) -> DuplexRelay& = delete;
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true; encoder_.close(); if (reader_) reader_->cancel();
            local_.cancel(); remote_.cancel();
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
                auto response=co_await receive_response(remote_,psk_,salt_,deadline);
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
            output_closed_=true; auto result=remote_.shutdown(nex::corosio::shutdown_send);
            if (result) { cancel(); co_return false; }
            co_return true;
        }
        auto upload() -> nex::capy::task<bool> {
            if (canceled_ || upload_started_) co_return false;
            upload_started_=true; std::array<std::uint8_t,16384> bytes{};
            for (;;) {
                auto [error,n]=co_await local_.read_some(nex::capy::mutable_buffer(bytes.data(),bytes.size()));
                if (nex::capy::is_eof(error) || (!error && !n)) co_return co_await close_output();
                if (error || canceled_ || n>bytes.size()) { cancel(); co_return false; }
                if (!co_await write(std::span{bytes}.first(n),std::chrono::steady_clock::now()+std::chrono::seconds(300))) co_return false;
            }
        }
        auto download() -> nex::capy::task<bool> {
            if (canceled_ || download_started_) co_return false;
            download_started_=true; std::array<std::uint8_t,16384> bytes{};
            for (;;) {
                auto result=co_await read(bytes,std::chrono::steady_clock::now()+std::chrono::seconds(300));
                if (!result) co_return false;
                if (!*result) { if (local_.shutdown(nex::corosio::shutdown_send)) { cancel(); co_return false; } co_return true; }
                auto pending=std::span{bytes}.first(*result);
                while (!pending.empty()) {
                    auto [error,n]=co_await local_.write_some(nex::capy::const_buffer(pending.data(),pending.size()));
                    if (error || canceled_ || !n || n>pending.size()) { cancel(); co_return false; }
                    if (touch_) touch_(); pending=pending.subspan(n);
                }
            }
        }
    };
}
