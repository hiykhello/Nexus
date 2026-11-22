module;
#include <cerrno>
#include <boost/corosio/wait_type.hpp>
export module tls.corosio_application;
import std;
import tls.application_io;
import tls.ktls;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace tls::detail {
    enum class AsyncApplicationError { transport, state, truncated, protocol, timeout, key_update_required, record_overflow };
    using ApplicationDeadline = std::optional<std::chrono::steady_clock::time_point>;
    inline auto expired(ApplicationDeadline deadline) noexcept -> bool { return deadline && std::chrono::steady_clock::now() >= *deadline; }
    enum class ReadTimeoutPolicy { cancel_connection, preserve_connection };
    enum class AsyncReadKind { event, backpressure, eof };
    struct AsyncReadResult { AsyncReadKind kind; std::optional<ApplicationEvent> event; };
    // One reader owns the buffered transport suffix, including any bytes read during handshake.
    class ApplicationInput {
        std::array<std::uint8_t,4096> buffered_{};
        std::size_t offset_=0, size_=0;
        bool valid_=true;
    public:
        // Handshake drivers read at most one 4096-byte transport block. Reject a
        // larger externally supplied suffix and do not retain its allocation.
        explicit ApplicationInput(crypto::Bytes&& unread) : valid_(unread.size()<=buffered_.size()) {
            if (valid_) { size_=unread.size(); std::copy(unread.begin(),unread.end(),buffered_.begin()); }
            crypto::Bytes{}.swap(unread);
        }
        [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }
        [[nodiscard]] auto unread() const noexcept -> std::span<std::uint8_t const> { return std::span(buffered_).subspan(offset_,size_-offset_); }
        auto detach() noexcept -> void { valid_=false; offset_=size_=0; }
        ApplicationInput(ApplicationInput const&)=delete;
        auto operator=(ApplicationInput const&) -> ApplicationInput& = delete;
        // A backpressure result means the single writer must flush pending output first.
        template<class Socket>
        auto read(Socket& socket, ApplicationIo& app, ApplicationDeadline deadline = {},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) -> nex::capy::task<std::expected<AsyncReadResult,AsyncApplicationError>> {
            if (!valid_) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
            while (true) {
                if (expired(deadline)) { if(policy==ReadTimeoutPolicy::cancel_connection)app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                if (app.input_blocked()) co_return AsyncReadResult{AsyncReadKind::backpressure,{}};
                if (offset_==size_) {
                    offset_=size_=0;
                    auto operation=socket.read_some(nex::capy::mutable_buffer(buffered_.data(),buffered_.size()));
                    auto [error,n]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                    if (n>buffered_.size()) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    if (nex::capy::is_timeout(error) || (!error && expired(deadline))) {
                        if(policy==ReadTimeoutPolicy::cancel_connection)app.cancel();
                        else if(!error)size_=n; // A completed read at the deadline remains owned here.
                        co_return std::unexpected(AsyncApplicationError::timeout);
                    }
                    if (nex::capy::is_eof(error) || (!error && !n)) {
                        if (!app.finish_input()) co_return std::unexpected(AsyncApplicationError::truncated);
                        co_return AsyncReadResult{AsyncReadKind::eof,{}};
                    }
                    if (error) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    if (n>buffered_.size()) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    size_=n;
                }
                auto result=app.feed(std::span{buffered_}.subspan(offset_,size_-offset_));
                if (!result) {
                    if (result.error()==ApplicationIoError::record_overflow) co_return std::unexpected(AsyncApplicationError::record_overflow);
                    app.cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                }
                offset_+=result->consumed;
                if (result->event) co_return AsyncReadResult{AsyncReadKind::event,std::move(result->event)};
                if (!result->consumed) co_return AsyncReadResult{AsyncReadKind::backpressure,{}};
            }
        }
    };
    // Single writer. The owner serializes all ApplicationIo calls on one executor and keeps
    // the socket and state alive until this coroutine completes, including after cancellation.
    // The copy protects a parked write from a concurrent receive failing or changing output.
    template<class Socket>
    auto flush_application(Socket& socket, ApplicationIo& app, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
        while (!app.pending_output().empty()) {
            if (expired(deadline)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            auto pending=app.pending_output(); crypto::Bytes owned(pending.begin(),pending.end());
            auto operation=socket.write_some(nex::capy::const_buffer(owned.data(),owned.size()));
            auto [error,n]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (nex::capy::is_timeout(error) || (!error && expired(deadline))) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            if (error || !n || n>owned.size()) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
            if (!app.written(n)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
        }
        co_return std::expected<void,AsyncApplicationError>{};
    }

    // Socket and this owner must remain alive until both pending operations complete.
    // All methods and completions run on the same executor. One reader and one writer
    // may overlap; a second operation in either direction is rejected. Deadlines use
    // steady_clock and apply to the complete operation; timeout cancels both directions.
    // An unread suffix larger than 4096 bytes makes the owner inactive.
    // send() automatically writes KeyUpdate before data when the local budget is exhausted.
    // The caller keeps the input span alive until send() completes.
    template<class Socket>
    class ApplicationConnection {
        Socket& socket_;
        ApplicationIo app_;
        ApplicationInput input_;
#ifdef NEXUS_ENABLE_KTLS
        std::optional<KtlsSession> ktls_;
#endif
        bool reading_=false, writing_=false, stream_writing_=false, canceled_=false;
        nex::capy::async_event writer_changed_;
        struct WriterGuard { ApplicationConnection& owner; ~WriterGuard() { owner.writing_=false; owner.writer_changed_.set(); } };
    public:
        ApplicationConnection(Socket& socket, ApplicationRecords&& records, crypto::Bytes&& unread)
            : socket_(socket), app_(std::move(records)), input_(std::move(unread)), canceled_(!input_.valid()) {
            if (canceled_) app_.cancel();
        }
        ApplicationConnection(ApplicationConnection const&)=delete;
        auto operator=(ApplicationConnection const&) -> ApplicationConnection& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool { return !reading_ && !writing_ && !stream_writing_; }
        [[nodiscard]] auto active() const noexcept -> bool { return !canceled_; }
        [[nodiscard]] auto pending_output() const noexcept -> bool { return !app_.pending_output().empty(); }
        [[nodiscard]] auto buffered_input() const noexcept -> bool {return !input_.unread().empty();}
        [[nodiscard]] auto ktls_active() const noexcept -> bool {
#ifdef NEXUS_ENABLE_KTLS
            return ktls_.has_value() && ktls_->tx_active() && ktls_->rx_active();
#else
            return false;
#endif
        }
#ifdef NEXUS_ENABLE_KTLS
        // Zero-residual barrier: only offloads to Linux kTLS when both directions are idle,
        // no plaintext/ciphertext remains buffered in userspace, and the underlying socket has a raw fd.
        [[nodiscard]] auto try_enable_ktls(ApplicationRole role = ApplicationRole::client,
            KtlsOps ops = default_ktls_ops()) noexcept -> KtlsStatus {
            if constexpr (!requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                (void)role; (void)ops;
                return KtlsStatus::unavailable;
            } else {
                if (ktls_ || reading_ || writing_ || stream_writing_ || canceled_ ||
                    pending_output() || buffered_input() || !input_.valid())
                    return KtlsStatus::invalid_state;
                int fd = static_cast<int>(socket_.native_handle());
                if (fd < 0) return KtlsStatus::invalid_state;
                KtlsSession candidate(role, ops);
                auto status = candidate.offload(fd, app_, true, true);
                if (status == KtlsStatus::ok) {
                    ktls_.emplace(std::move(candidate));
                } else if (status == KtlsStatus::fatal_error) {
                    cancel();
                }
                return status;
            }
        }
#endif
        // Returns transport bytes beyond the last TLS record; the writer may
        // continue using TLS independently. The reader must not be in flight.
        [[nodiscard]] auto detach_input() -> std::expected<crypto::Bytes,AsyncApplicationError> {
            if (reading_ || canceled_ || !input_.valid()) return std::unexpected(AsyncApplicationError::state);
            auto suffix=input_.unread(); crypto::Bytes bytes(suffix.begin(),suffix.end());
            if (!app_.detach_input()) return std::unexpected(AsyncApplicationError::state);
            input_.detach(); return bytes;
        }
        // Call only while owning the sole writer. Raw writes may begin after
        // this succeeds; the TLS reader may continue on the same executor.
        [[nodiscard]] auto detach_output() noexcept -> bool {
            return !canceled_ && !writing_ && !stream_writing_ && app_.detach_output();
        }
        // With all operations drained, release owned TLS state without changing
        // the caller-owned socket. The connection cannot be used afterward.
        auto discard() noexcept -> void { canceled_=true; app_.cancel(); }
        auto cancel() noexcept -> void { if (!canceled_) { canceled_=true; app_.cancel(); socket_.cancel(); writer_changed_.set(); } }
        auto read(ApplicationDeadline deadline = {},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) -> nex::capy::task<std::expected<AsyncReadResult,AsyncApplicationError>> {
            if (reading_ || canceled_ || !input_.valid()) co_return std::unexpected(AsyncApplicationError::state);
            reading_=true;
            try {
                auto result=co_await input_.read(socket_,app_,deadline,policy);
                if (!result && result.error()==AsyncApplicationError::record_overflow) {
                    while (writing_ && !canceled_) {
                        writer_changed_.clear();
                        if (!writing_ || canceled_) break;
                        auto operation=writer_changed_.wait();
                        auto [error]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                        if (error || expired(deadline)) { reading_=false; cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                    }
                    if (!canceled_ && !app_.overflow_alert_written() && !app_.output_detached()) {
                        writing_=true;WriterGuard guard{*this};
                        (void)co_await flush_application(socket_,app_,deadline);
                    }
                    reading_=false;cancel();co_return std::unexpected(AsyncApplicationError::protocol);
                }
                reading_=false;
                if ((!result && !(policy==ReadTimeoutPolicy::preserve_connection && result.error()==AsyncApplicationError::timeout)) || (result && result->event && result->event->kind==ApplicationEventKind::fatal_alert)) { canceled_=true; socket_.cancel(); writer_changed_.set(); }
                co_return result;
            } catch (...) { reading_=false; cancel(); throw; }
        }
        auto flush(ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_ || app_.output_detached()) co_return std::unexpected(AsyncApplicationError::state);
            writing_=true;WriterGuard guard{*this};
            try {
                auto result=co_await flush_application(socket_,app_,deadline);
                if (!result) { canceled_=true; socket_.cancel(); }
                if (result && app_.overflow()) co_return std::unexpected(AsyncApplicationError::protocol);
                co_return result;
            } catch (...) { writing_=false; cancel(); throw; }
        }
    private:
        auto send_record(std::span<std::uint8_t const> data, ApplicationDeadline deadline, bool stream) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || (stream_writing_ && !stream) || canceled_ || app_.output_detached()) co_return std::unexpected(AsyncApplicationError::state);
#ifdef NEXUS_ENABLE_KTLS
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                if (ktls_) {
                    writing_ = true; WriterGuard guard{*this};
                    int fd = static_cast<int>(socket_.native_handle());
                    while (!data.empty()) {
                        if (expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                        int err = 0;
                        auto sent = ktls_->send_application(fd, data, &err);
                        if (sent > 0) {
                            data = data.subspan(static_cast<std::size_t>(sent));
                            continue;
                        }
                        if (sent == 0 || (sent < 0 && (err == EAGAIN || err == EWOULDBLOCK || err == EINTR))) {
                            auto op = socket_.wait(nex::corosio::wait_type::write);
                            auto [we] = deadline ? co_await nex::corosio::timeout(std::move(op), *deadline) : co_await std::move(op);
                            if (nex::capy::is_timeout(we) || expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                            if (we || canceled_) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                            continue;
                        }
                        cancel();
                        co_return std::unexpected(AsyncApplicationError::transport);
                    }
                    co_return std::expected<void,AsyncApplicationError>{};
                }
            }
#endif
            try {
            auto result=app_.send(data);
            if (!result && result.error()!=ApplicationIoError::key_update_required) {
                if (result.error()==ApplicationIoError::record_error) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                co_return std::unexpected(AsyncApplicationError::state);
            }
            writing_=true;WriterGuard guard{*this};
            if (!result) {
                auto update=app_.request_key_update(false);
                if (!update) {
                    if (update.error()==ApplicationIoError::record_error) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                    co_return std::unexpected(AsyncApplicationError::key_update_required);
                }
                auto updated=co_await flush_application(socket_,app_,deadline);
                if (!updated) { canceled_=true; socket_.cancel(); co_return std::unexpected(updated.error()); }
                // A peer update received while the write was in flight can queue a response.
                while (!app_.pending_output().empty()) {
                    auto response=co_await flush_application(socket_,app_,deadline);
                    if (!response) { canceled_=true; socket_.cancel(); co_return std::unexpected(response.error()); }
                }
                if (canceled_ || !app_.send(data)) { co_return std::unexpected(AsyncApplicationError::state); }
            }
            auto written=co_await flush_application(socket_,app_,deadline);
            if (!written) { canceled_=true; socket_.cancel(); }
            if (written && app_.overflow()) co_return std::unexpected(AsyncApplicationError::protocol);
            co_return written;
            } catch (...) { writing_=false; cancel(); throw; }
        }
    public:
        auto send(std::span<std::uint8_t const> data, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            co_return co_await send_record(data,deadline,false);
        }
        // Sends an entire byte span in bounded records. On failure a prefix may have reached
        // the peer; the caller must not retry it blindly. Input remains valid until completion.
        auto send_all(std::span<std::uint8_t const> data, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_ || app_.output_detached()) co_return std::unexpected(AsyncApplicationError::state);
            if (expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
#ifdef NEXUS_ENABLE_KTLS
            if (ktls_) {
                stream_writing_ = true;
                auto res = co_await send_record(data, deadline, true);
                stream_writing_ = false;
                co_return res;
            }
#endif
            auto limit=app_.max_write_size();
            if (!limit) co_return std::unexpected(AsyncApplicationError::state);
            stream_writing_=true;
            try {
            while (!data.empty()) {
                auto count=std::min(limit,data.size());
                auto result=co_await send_record(data.first(count),deadline,true);
                if (!result) { stream_writing_=false; co_return std::unexpected(result.error()); }
                data=data.subspan(count);
            }
            stream_writing_=false;
            co_return std::expected<void,AsyncApplicationError>{};
            } catch (...) { stream_writing_=false; cancel(); throw; }
        }
        auto key_update(bool request, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
#ifdef NEXUS_ENABLE_KTLS
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                if (ktls_) {
                    writing_ = true; WriterGuard guard{*this};
                    auto status = ktls_->rekey_tx(static_cast<int>(socket_.native_handle()), request);
                    if (status != KtlsStatus::ok) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                    co_return std::expected<void,AsyncApplicationError>{};
                }
            }
#endif
            try { if (!app_.request_key_update(request)) co_return std::unexpected(AsyncApplicationError::state);
                co_return co_await flush(deadline); }
            catch (...) { cancel(); throw; }
        }
        auto close_notify(ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
#ifdef NEXUS_ENABLE_KTLS
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                if (ktls_) {
                    writing_ = true; WriterGuard guard{*this};
                    auto status = ktls_->send_close_notify(static_cast<int>(socket_.native_handle()));
                    if (status != KtlsStatus::ok) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    co_return std::expected<void,AsyncApplicationError>{};
                }
            }
#endif
            try { if (!app_.close_notify()) co_return std::unexpected(AsyncApplicationError::state);
                co_return co_await flush(deadline); }
            catch (...) { cancel(); throw; }
        }
#ifdef NEXUS_ENABLE_KTLS
        // Direct kernel-decrypted read into caller buffer when kTLS RX is active.
        auto read_ktls(std::span<std::uint8_t> output, ApplicationDeadline deadline = {},
            ReadTimeoutPolicy policy = ReadTimeoutPolicy::cancel_connection)
            -> nex::capy::task<std::expected<std::size_t, AsyncApplicationError>> {
            if constexpr (!requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                (void)output; (void)deadline; (void)policy;
                co_return std::unexpected(AsyncApplicationError::state);
            } else {
                if (reading_ || canceled_ || !ktls_) co_return std::unexpected(AsyncApplicationError::state);
                reading_ = true;
                struct ReadGuard { bool& r; ~ReadGuard() { r = false; } } rg{reading_};
                int fd = static_cast<int>(socket_.native_handle());
                for (;;) {
                    if (expired(deadline)) {
                        if (policy == ReadTimeoutPolicy::cancel_connection) cancel();
                        co_return std::unexpected(AsyncApplicationError::timeout);
                    }
                    auto res = ktls_->recv_record(fd, output);
                    switch (res.kind) {
                    case KtlsRecvKind::data:
                        co_return res.bytes;
                    case KtlsRecvKind::eof:
                    case KtlsRecvKind::close_notify:
                        co_return std::size_t{0};
                    case KtlsRecvKind::ticket_discarded:
                    case KtlsRecvKind::key_update:
                        continue;
                    case KtlsRecvKind::key_update_requested:
                        if (ktls_->rekey_tx(fd, false) != KtlsStatus::ok) {
                            cancel();
                            co_return std::unexpected(AsyncApplicationError::protocol);
                        }
                        continue;
                    case KtlsRecvKind::would_block: {
                        auto op = socket_.wait(nex::corosio::wait_type::read);
                        auto [re] = deadline ? co_await nex::corosio::timeout(std::move(op), *deadline) : co_await std::move(op);
                        if (nex::capy::is_timeout(re) || expired(deadline)) {
                            if (policy == ReadTimeoutPolicy::cancel_connection) cancel();
                            co_return std::unexpected(AsyncApplicationError::timeout);
                        }
                        if (re || canceled_) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                        continue;
                    }
                    default:
                        cancel();
                        co_return std::unexpected(AsyncApplicationError::protocol);
                    }
                }
            }
        }
#endif
    };

    enum class AsyncStreamReadKind { data, event, backpressure, eof };
    struct AsyncStreamReadResult { AsyncStreamReadKind kind; std::size_t size=0; std::optional<ApplicationEvent> event; };
    struct DetachedStreamInput { crypto::Bytes plaintext; crypto::Bytes transport; };
    // Byte-oriented adapter for the single reader of an ApplicationConnection. Control events
    // remain visible to the caller, which must flush requested KeyUpdate responses. Neither
    // this adapter nor its connection may be destroyed before an outstanding read completes.
    template<class Socket>
    class ApplicationStreamReader {
        ApplicationConnection<Socket>& connection_;
        crypto::Bytes buffered_;
        std::size_t offset_=0;
        bool reading_=false, closed_=false, detached_=false;
    public:
        explicit ApplicationStreamReader(ApplicationConnection<Socket>& connection) : connection_(connection) {}
        ApplicationStreamReader(ApplicationStreamReader const&)=delete;
        auto operator=(ApplicationStreamReader const&) -> ApplicationStreamReader& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool { return !reading_ && !closed_ && !detached_ && connection_.active(); }
        [[nodiscard]] auto pending_plaintext() const noexcept -> bool {return offset_<buffered_.size();}
        // Startup adapters can return bytes that precede this reader's
        // retained same-record suffix. Reuse its one owned plaintext buffer.
        // Failure/exception preserves both the suffix and the caller's bytes.
        [[nodiscard]] auto prepend_owned(crypto::Bytes&& prefix) -> bool {
            if (!idle() || offset_>buffered_.size()) return false;
            auto remaining=buffered_.size()-offset_;
            if (prefix.size()>16384 || remaining>16384-prefix.size()) return false;
            if (prefix.empty()) return true;
            if (!remaining) buffered_=std::move(prefix);
            else {
                crypto::Bytes combined;
                combined.reserve(prefix.size()+remaining);
                combined.insert(combined.end(),prefix.begin(),prefix.end());
                combined.insert(combined.end(),buffered_.begin()+static_cast<std::ptrdiff_t>(offset_),buffered_.end());
                buffered_=std::move(combined); crypto::Bytes{}.swap(prefix);
            }
            offset_=0; return true;
        }
        // Deliver plaintext first, then the transport suffix, then read the raw
        // socket. This operation is irreversible and requires the sole reader.
        [[nodiscard]] auto detach_input() -> std::expected<DetachedStreamInput,AsyncApplicationError> {
            if (reading_ || closed_ || !connection_.active()) return std::unexpected(AsyncApplicationError::state);
            crypto::Bytes plaintext(buffered_.begin()+static_cast<std::ptrdiff_t>(offset_),buffered_.end());
            auto transport=connection_.detach_input();
            if (!transport) return std::unexpected(transport.error());
            crypto::Bytes{}.swap(buffered_); offset_=0; detached_=true;
            return DetachedStreamInput{std::move(plaintext),std::move(*transport)};
        }
        // The output span must remain alive until completion. An empty span is rejected.
        auto read_some(std::span<std::uint8_t> output, ApplicationDeadline deadline = {},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) -> nex::capy::task<std::expected<AsyncStreamReadResult,AsyncApplicationError>> {
            if (reading_ || detached_ || output.empty() || !connection_.active()) co_return std::unexpected(AsyncApplicationError::state);
            if (expired(deadline)) { if(policy==ReadTimeoutPolicy::cancel_connection)connection_.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            reading_=true;
            try {
            while (true) {
                if (offset_<buffered_.size()) {
                    auto count=std::min(output.size(),buffered_.size()-offset_);
                    std::copy_n(buffered_.begin()+static_cast<std::ptrdiff_t>(offset_),count,output.begin());
                    offset_+=count;
                    if (offset_==buffered_.size()) { crypto::Bytes{}.swap(buffered_); offset_=0; }
                    reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::data,count,{}};
                }
                if (closed_) { reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof,0,{}}; }
#ifdef NEXUS_ENABLE_KTLS
                if (connection_.ktls_active()) {
                    auto k = co_await connection_.read_ktls(output, deadline, policy);
                    reading_ = false;
                    if (!k) co_return std::unexpected(k.error());
                    if (*k == 0) { closed_ = true; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof, 0, {}}; }
                    co_return AsyncStreamReadResult{AsyncStreamReadKind::data, *k, {}};
                }
#endif
                auto result=co_await connection_.read(deadline,policy);
                if (!result) { reading_=false; co_return std::unexpected(result.error()); }
                if (result->kind==AsyncReadKind::backpressure) { reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::backpressure,0,{}}; }
                if (result->kind==AsyncReadKind::eof) { closed_=true; reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof,0,{}}; }
                auto event=std::move(*result->event);
                if (event.kind==ApplicationEventKind::data) { buffered_=std::move(event.data); continue; }
                if (event.kind==ApplicationEventKind::close_notify) closed_=true;
                reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::event,0,std::move(event)};
            }
            } catch (...) { reading_=false; connection_.cancel(); throw; }
        }
    };
}
