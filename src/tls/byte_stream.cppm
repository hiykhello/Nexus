export module tls.byte_stream;
import std;
import tls.corosio_application;
import tls.application_io;
import tls.ktls;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace tls::detail {
    enum class ByteStreamError { state,io,protocol,timeout };
    // One reader and one serialized writer per authenticated TLS connection.
    // No proxy protocol is known here. The owner cancels and drains before
    // destroying this object or any borrowed prefetched plaintext.
    template<class Socket>
    class ByteStream {
        ApplicationConnection<Socket>& connection_;
        ApplicationStreamReader<Socket> reader_;
        nex::capy::async_mutex writer_;
        std::span<std::uint8_t const> prefetched_;
        bool failed_=false,reading_=false,eof_=false,released_read_=false;
        auto fail(ByteStreamError error) -> std::unexpected<ByteStreamError> {
            failed_=true; connection_.cancel(); return std::unexpected(error);
        }
    public:
        explicit ByteStream(ApplicationConnection<Socket>& connection) : connection_(connection),reader_(connection) {}
        ByteStream(ByteStream const&)=delete;
        auto operator=(ByteStream const&) -> ByteStream& = delete;
        auto prepend(std::span<std::uint8_t const> plaintext) noexcept -> bool {
            if (reading_ || failed_ || released_read_ || !prefetched_.empty()) return false;
            prefetched_=plaintext; return true;
        }
        auto prepend_owned(std::vector<std::uint8_t>&& plaintext) -> bool {
            if (reading_ || failed_ || released_read_ || !prefetched_.empty()) return false;
            return reader_.prepend_owned(std::move(plaintext));
        }
        // Explicitly hand out the sole read direction. Repeated inspection is
        // allowed while it is idle. The serialized write direction remains.
        auto release_reader() noexcept -> ApplicationStreamReader<Socket>* {
            if (reading_ || failed_ || !prefetched_.empty() || !reader_.idle()) return nullptr;
            released_read_=true; return &reader_;
        }
        auto cancel() noexcept -> void { failed_=true; connection_.cancel(); }
        [[nodiscard]] auto ktls_active() const noexcept -> bool { return connection_.ktls_active(); }
        auto try_enable_ktls(ApplicationRole role = ApplicationRole::client) noexcept -> bool {
#ifdef NEXUS_ENABLE_KTLS
            if (reading_ || failed_ || released_read_ || !prefetched_.empty() || reader_.pending_plaintext())
                return false;
            return connection_.try_enable_ktls(role) == KtlsStatus::ok;
#else
            (void)role;
            return false;
#endif
        }
        auto read(std::span<std::uint8_t> output,ApplicationDeadline deadline={},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection)
            -> nex::capy::task<std::expected<std::size_t,ByteStreamError>> {
            if (failed_ || reading_ || released_read_) co_return std::unexpected(ByteStreamError::state);
            if (output.empty() || eof_) co_return 0;
            if (!prefetched_.empty()) {
                auto size=std::min(output.size(),prefetched_.size());
                std::copy_n(prefetched_.begin(),size,output.begin()); prefetched_=prefetched_.subspan(size); co_return size;
            }
            reading_=true;
            struct Guard { bool& reading; ~Guard() { reading=false; } } guard{reading_};
            for (;;) {
                auto result=co_await reader_.read_some(output,deadline,policy);
                if(!result && policy==ReadTimeoutPolicy::preserve_connection && result.error()==AsyncApplicationError::timeout && !failed_)
                    co_return std::unexpected(ByteStreamError::timeout);
                if (!result || failed_) co_return fail(ByteStreamError::io);
                if (result->kind==AsyncStreamReadKind::data) co_return result->size;
                if (result->kind==AsyncStreamReadKind::eof || (result->event && result->event->kind==ApplicationEventKind::close_notify)) {
                    eof_=true; co_return 0;
                }
                if (result->event && (result->event->kind==ApplicationEventKind::fatal_alert || result->event->kind==ApplicationEventKind::user_canceled))
                    co_return fail(ByteStreamError::protocol);
                if (result->kind==AsyncStreamReadKind::backpressure || (result->event && result->event->kind==ApplicationEventKind::key_update_requested)) {
                    auto operation=writer_.scoped_lock();
                    auto [error,lock]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                    if (error || failed_ || !co_await connection_.flush(deadline)) co_return fail(ByteStreamError::io);
                }
            }
        }
        auto send(std::span<std::uint8_t const> input,ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            auto operation=writer_.scoped_lock();
            auto [error,lock]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || failed_) co_return false;
            while (connection_.pending_output()) {
                if (!co_await connection_.flush(deadline) || failed_) { (void)fail(ByteStreamError::io); co_return false; }
            }
            auto sent=co_await connection_.send_all(input,deadline);
            if (!sent || failed_) { (void)fail(ByteStreamError::io); co_return false; }
            co_return true;
        }
        auto key_update(bool request,ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            auto operation=writer_.scoped_lock();
            auto [error,lock]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || failed_) co_return false;
            while (connection_.pending_output()) {
                if (!co_await connection_.flush(deadline) || failed_) { (void)fail(ByteStreamError::io); co_return false; }
            }
            auto updated=co_await connection_.key_update(request,deadline);
            if (!updated || failed_) { (void)fail(ByteStreamError::io); co_return false; }
            co_return true;
        }
        auto close_output(ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            auto operation=writer_.scoped_lock();
            auto [error,lock]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || failed_) co_return false;
            while (connection_.pending_output()) {
                if (!co_await connection_.flush(deadline) || failed_) { (void)fail(ByteStreamError::io); co_return false; }
            }
            auto closed=co_await connection_.close_notify(deadline);
            if (!closed || failed_) { (void)fail(ByteStreamError::io); co_return false; }
            co_return true;
        }
    };
}
