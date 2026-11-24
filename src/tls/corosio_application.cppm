module;
#include <cerrno>
#include <boost/corosio/wait_type.hpp>
export module tls.corosio_application;
import std;
import tls.application_io;
export import tls.corosio_application_io;
import tls.ktls;
import capy;
import corosio;
export namespace tls::detail {
    // One executor; one reader and one writer may overlap. Deadlines use steady_clock and cancel
    // both directions on timeout. Unread suffix > 4096B invalidates the owner. send() emits
    // KeyUpdate automatically when budget is exhausted; callers keep input spans alive until done.
    template<class Socket>
    class ApplicationConnection {
        Socket& socket_;
        ApplicationIo app_;
        ApplicationInput input_;
        crypto::Bytes write_scratch_;
        TlsPooledBuffer<66560> write_buf_;
#ifdef NEXUS_ENABLE_KTLS
        std::optional<KtlsSession> ktls_;
        bool ktls_rekey_pending_ = false, ktls_rekey_writing_ = false;
#endif
        bool reading_=false, writing_=false, stream_writing_=false, canceled_=false;
        capy::async_event writer_changed_;
        struct LockGuard { bool& f; capy::async_event& ev; ~LockGuard() { f = false; ev.set(); } };
        struct FlagGuard { bool& f; ~FlagGuard() { f = false; } };
    public:
        ApplicationConnection(Socket& socket, ApplicationRecords&& records, crypto::Bytes&& unread)
            : socket_(socket), app_(std::move(records)), input_(std::move(unread)), canceled_(!input_.valid()) {
            if (canceled_) app_.cancel();
        }
        ApplicationConnection(ApplicationConnection const&)=delete;
        auto operator=(ApplicationConnection const&) -> ApplicationConnection& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool {
#ifdef NEXUS_ENABLE_KTLS
            if (ktls_rekey_writing_) return false;
#endif
            return !reading_ && !writing_ && !stream_writing_;
        }
        [[nodiscard]] auto active() const noexcept -> bool { return !canceled_; }
        [[nodiscard]] auto pending_output() const noexcept -> bool { return app_.output_busy(); }
        [[nodiscard]] auto buffered_input() const noexcept -> bool {return !input_.unread().empty();}
        [[nodiscard]] auto ktls_active() const noexcept -> bool {
#ifdef NEXUS_ENABLE_KTLS
            return ktls_.has_value() && ktls_->tx_active() && ktls_->rx_active();
#else
            return false;
#endif
        }
#ifdef NEXUS_ENABLE_KTLS
        // Zero-residual barrier: offload to Linux kTLS only when idle with no buffered userspace data.
        [[nodiscard]] auto try_enable_ktls(ApplicationRole role = ApplicationRole::client,
            KtlsOps ops = default_ktls_ops()) noexcept -> KtlsStatus {
            if constexpr (!requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                (void)role; (void)ops; return KtlsStatus::unavailable;
            } else {
                if (ktls_ || reading_ || writing_ || stream_writing_ || canceled_ || pending_output() || buffered_input() || !input_.valid())
                    return KtlsStatus::invalid_state;
                int fd = static_cast<int>(socket_.native_handle());
                if (fd < 0) return KtlsStatus::invalid_state;
                KtlsSession candidate(role, ops);
                auto status = candidate.offload(fd, app_, true, true);
                if (status == KtlsStatus::ok) ktls_.emplace(std::move(candidate));
                else if (status == KtlsStatus::fatal_error) cancel();
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
        auto discard() noexcept -> void { canceled_=true; app_.cancel(); crypto::Bytes{}.swap(write_scratch_); write_buf_.reset(); }
        auto cancel() noexcept -> void { if (!canceled_) { canceled_=true; app_.cancel(); socket_.cancel(); writer_changed_.set(); } }
        auto read(ApplicationDeadline deadline = {},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) -> capy::task<std::expected<AsyncReadResult,AsyncApplicationError>> {
            if (reading_ || canceled_ || !input_.valid()) co_return std::unexpected(AsyncApplicationError::state);
            reading_=true;
            try {
                auto result=co_await input_.read(socket_,app_,deadline,policy);
                if (!result && result.error()==AsyncApplicationError::record_overflow) {
                    co_await handle_record_overflow(deadline);
                    reading_=false; cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                }
                reading_=false;
                if ((!result && !(policy==ReadTimeoutPolicy::preserve_connection && result.error()==AsyncApplicationError::timeout)) || (result && result->event && result->event->kind==ApplicationEventKind::fatal_alert)) { canceled_=true; socket_.cancel(); writer_changed_.set(); }
                co_return result;
            } catch (...) { reading_=false; cancel(); throw; }
        }
        auto read_into(std::span<std::uint8_t> output, ApplicationDeadline deadline = {}, ReadTimeoutPolicy policy = ReadTimeoutPolicy::cancel_connection)
            -> capy::task<std::expected<AsyncReadIntoResult, AsyncApplicationError>> {
            if (reading_ || canceled_ || !input_.valid()) co_return std::unexpected(AsyncApplicationError::state);
            reading_ = true;
            try {
                auto result = co_await input_.read_into(socket_, app_, output, deadline, policy);
                if (!result && result.error() == AsyncApplicationError::record_overflow) {
                    co_await handle_record_overflow(deadline);
                    reading_ = false; cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                }
                reading_ = false;
                auto fatal = [](std::optional<ApplicationEvent> const& ev) { return ev && ev->kind == ApplicationEventKind::fatal_alert; };
                if ((!result && !(policy == ReadTimeoutPolicy::preserve_connection && result.error() == AsyncApplicationError::timeout)) ||
                    (result && (fatal(result->event) || fatal(result->deferred_event)))) { canceled_ = true; socket_.cancel(); writer_changed_.set(); }
                co_return result;
            } catch (...) { reading_ = false; cancel(); throw; }
        }
        auto flush(ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_ || app_.output_detached()) co_return std::unexpected(AsyncApplicationError::state);
            writing_=true;LockGuard guard{writing_,writer_changed_};
            try {
                auto result=co_await flush_application(socket_,app_,write_scratch_,deadline);
                if (!result) { canceled_=true; socket_.cancel(); }
                if (result && app_.overflow()) co_return std::unexpected(AsyncApplicationError::protocol);
                co_return result;
            } catch (...) { writing_=false; cancel(); throw; }
        }
    private:
        auto handle_record_overflow(ApplicationDeadline deadline) -> capy::task<void> {
            while (writing_ && !canceled_) {
                writer_changed_.clear();
                if (!writing_ || canceled_) break;
                auto operation = writer_changed_.wait();
                auto [error] = deadline ? co_await corosio::timeout(std::move(operation), *deadline) : co_await std::move(operation);
                if (error || expired(deadline)) co_return;
            }
            if (!canceled_ && !app_.overflow_alert_written() && !app_.output_detached()) {
                writing_ = true; LockGuard guard{writing_, writer_changed_};
                (void)co_await flush_application(socket_, app_, write_scratch_, deadline);
            }
        }
        auto flush_pending_locked(ApplicationDeadline deadline) -> capy::task<std::expected<void, AsyncApplicationError>> {
            while (!app_.pending_output().empty()) {
                auto flushed = co_await flush_application(socket_, app_, write_scratch_, deadline);
                if (!flushed) { canceled_ = true; socket_.cancel(); writer_changed_.set(); co_return std::unexpected(flushed.error()); }
            }
            co_return std::expected<void, AsyncApplicationError>{};
        }
#ifdef NEXUS_ENABLE_KTLS
        auto ktls_wait_writable(ApplicationDeadline deadline) -> capy::task<std::expected<void, AsyncApplicationError>> {
            auto op = socket_.wait(corosio::wait_type::write);
            auto [we] = deadline ? co_await corosio::timeout(std::move(op), *deadline) : co_await std::move(op);
            if (capy::is_timeout(we) || expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            if (we || canceled_) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
            co_return std::expected<void, AsyncApplicationError>{};
        }
        auto ktls_wait_rekey(ApplicationDeadline deadline) -> capy::task<std::expected<void, AsyncApplicationError>> {
            while (ktls_rekey_writing_ && !canceled_) {
                writer_changed_.clear();
                if (!ktls_rekey_writing_ || canceled_) break;
                auto op = writer_changed_.wait();
                auto [we] = deadline ? co_await corosio::timeout(std::move(op), *deadline) : co_await std::move(op);
                if (capy::is_timeout(we) || expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                if (we || canceled_) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
            }
            if (canceled_) co_return std::unexpected(AsyncApplicationError::transport);
            co_return std::expected<void, AsyncApplicationError>{};
        }
        auto ktls_run_tx_control(auto&& fn, ApplicationDeadline deadline, AsyncApplicationError fail_err)
            -> capy::task<std::expected<void, AsyncApplicationError>> {
            for (;;) {
                if (expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                auto status = fn();
                if (status == KtlsStatus::ok) co_return std::expected<void, AsyncApplicationError>{};
                if (status == KtlsStatus::would_block) {
                    if (auto w = co_await ktls_wait_writable(deadline); !w) co_return std::unexpected(w.error());
                    continue;
                }
                cancel(); co_return std::unexpected(fail_err);
            }
        }
#endif
        auto send_record(std::span<std::uint8_t const> data, ApplicationDeadline deadline, bool stream) -> capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || (stream_writing_ && !stream) || canceled_) co_return std::unexpected(AsyncApplicationError::state);
#ifdef NEXUS_ENABLE_KTLS
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                if (ktls_) {
                    writing_ = true; LockGuard guard{writing_, writer_changed_};
                    if (auto w = co_await ktls_wait_rekey(deadline); !w) co_return std::unexpected(w.error());
                    int fd = static_cast<int>(socket_.native_handle());
                    while (!data.empty()) {
                        if (expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                        if ((ktls_rekey_pending_ || ktls_->tx_rekey_required()) && !ktls_->tx_closed()) {
                            if (auto rk = co_await ktls_run_tx_control([&]{ return ktls_->rekey_tx(fd, false); }, deadline, AsyncApplicationError::protocol); !rk) co_return std::unexpected(rk.error());
                            if (std::exchange(ktls_rekey_pending_, false)) writer_changed_.set();
                        }
                        int err = 0;
                        auto sent = ktls_->send_application(fd, data, &err);
                        if (sent > 0) { data = data.subspan(static_cast<std::size_t>(sent)); continue; }
                        if (sent == 0 || (sent < 0 && (err == EAGAIN || err == EWOULDBLOCK || err == EINTR))) {
                            if (auto w = co_await ktls_wait_writable(deadline); !w) co_return std::unexpected(w.error());
                            continue;
                        }
                        cancel(); co_return std::unexpected(AsyncApplicationError::transport);
                    }
                    co_return std::expected<void,AsyncApplicationError>{};
                }
            }
#endif
            if (app_.output_detached()) co_return std::unexpected(AsyncApplicationError::state);
            try {
            auto result=app_.send(data);
            if (!result && result.error()!=ApplicationIoError::key_update_required) {
                if (result.error()==ApplicationIoError::record_error) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                co_return std::unexpected(AsyncApplicationError::state);
            }
            writing_=true;LockGuard guard{writing_,writer_changed_};
            if (!result) {
                auto update=app_.request_key_update(false);
                if (!update) {
                    if (update.error()==ApplicationIoError::record_error) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                    co_return std::unexpected(AsyncApplicationError::key_update_required);
                }
                auto updated=co_await flush_application(socket_,app_,write_scratch_,deadline);
                if (!updated) { canceled_=true; socket_.cancel(); co_return std::unexpected(updated.error()); }
                while (!app_.pending_output().empty()) {
                    auto response=co_await flush_application(socket_,app_,write_scratch_,deadline);
                    if (!response) { canceled_=true; socket_.cancel(); co_return std::unexpected(response.error()); }
                }
                if (canceled_ || !app_.send(data)) { co_return std::unexpected(AsyncApplicationError::state); }
            }
            auto written=co_await flush_application(socket_,app_,write_scratch_,deadline);
            if (!written) { canceled_=true; socket_.cancel(); }
            if (written && app_.overflow()) co_return std::unexpected(AsyncApplicationError::protocol);
            co_return written;
            } catch (...) { writing_=false; cancel(); throw; }
        }
    public:
        auto send(std::span<std::uint8_t const> data, ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
            co_return co_await send_record(data,deadline,false);
        }
        auto send_all(std::span<std::uint8_t const> data, ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
            if (expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
#ifdef NEXUS_ENABLE_KTLS
            if (ktls_) { stream_writing_ = true; FlagGuard sg{stream_writing_}; co_return co_await send_record(data, deadline, true); }
#endif
            if (app_.output_detached() || !app_.max_write_size()) co_return std::unexpected(AsyncApplicationError::state);
            stream_writing_=true;
            try {
            while (!data.empty()) {
                if (expired(deadline)) { cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::timeout); }
                if (writing_ || canceled_ || app_.output_detached()) { stream_writing_=false; co_return std::unexpected(AsyncApplicationError::state); }
                if (!write_buf_.acquire()) { cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::transport); }
                auto sealed=app_.seal_batch_into(data,std::span<std::uint8_t>(write_buf_.get(),TlsPooledBuffer<66560>::size));
                if (!sealed) {
                    if (sealed.error()==ApplicationIoError::key_update_required) {
                        writing_=true; LockGuard guard{writing_,writer_changed_};
                        auto update=app_.request_key_update(false);
                        if (!update) {
                            if (update.error()==ApplicationIoError::record_error) { cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::protocol); }
                            stream_writing_=false; co_return std::unexpected(AsyncApplicationError::key_update_required);
                        }
                        auto flushed=co_await flush_pending_locked(deadline);
                        if (!flushed) { stream_writing_=false; co_return std::unexpected(flushed.error()); }
                        continue;
                    }
                    if (sealed.error()==ApplicationIoError::record_error) cancel();
                    stream_writing_=false;
                    co_return std::unexpected(sealed.error()==ApplicationIoError::record_error ? AsyncApplicationError::protocol : AsyncApplicationError::state);
                }
                writing_=true; LockGuard guard{writing_,writer_changed_};
                auto const* wire_ptr=write_buf_.get();
                auto const wire_len=sealed->wire_size;
                std::size_t off=0;
                if (!deadline && try_send_nonblock(socket_,wire_ptr,wire_len,off)==NonblockWriteStatus::error) {
                    write_buf_.reset(); cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::transport);
                }
                while (off<wire_len) {
                    auto op=socket_.write_some(capy::const_buffer(wire_ptr+off,wire_len-off));
                    auto [error,n]=deadline ? co_await corosio::timeout(std::move(op),*deadline) : co_await std::move(op);
                    if (capy::is_timeout(error) || (!error && expired(deadline))) { write_buf_.reset(); cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::timeout); }
                    if (error || !n || n>wire_len-off) { write_buf_.reset(); cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::transport); }
                    off+=n;
                }
                if (!app_.finish_external_output()) { cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::state); }
                auto flushed=co_await flush_pending_locked(deadline);
                if (!flushed) { stream_writing_=false; co_return std::unexpected(flushed.error()); }
                if (app_.overflow()) { cancel(); stream_writing_=false; co_return std::unexpected(AsyncApplicationError::protocol); }
                data=data.subspan(sealed->consumed);
            }
            stream_writing_=false;
            co_return std::expected<void,AsyncApplicationError>{};
            } catch (...) { crypto::Bytes{}.swap(write_scratch_); write_buf_.reset(); stream_writing_=false; writing_=false; cancel(); throw; }
        }
        auto key_update(bool request, ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
#ifdef NEXUS_ENABLE_KTLS
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                if (ktls_) {
                    writing_ = true; LockGuard guard{writing_, writer_changed_};
                    if (auto w = co_await ktls_wait_rekey(deadline); !w) co_return std::unexpected(w.error());
                    int fd = static_cast<int>(socket_.native_handle());
                    auto res = co_await ktls_run_tx_control([&]{ return ktls_->rekey_tx(fd, request); }, deadline, AsyncApplicationError::protocol);
                    if (res) ktls_rekey_pending_ = false;
                    co_return res;
                }
            }
#endif
            try { if (!app_.request_key_update(request)) co_return std::unexpected(AsyncApplicationError::state);
                co_return co_await flush(deadline); }
            catch (...) { cancel(); throw; }
        }
        auto close_notify(ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
#ifdef NEXUS_ENABLE_KTLS
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                if (ktls_) {
                    writing_ = true; LockGuard guard{writing_, writer_changed_};
                    if (auto w = co_await ktls_wait_rekey(deadline); !w) co_return std::unexpected(w.error());
                    int fd = static_cast<int>(socket_.native_handle());
                    co_return co_await ktls_run_tx_control([&]{ return ktls_->send_close_notify(fd); }, deadline, AsyncApplicationError::transport);
                }
            }
#endif
            try { if (!app_.close_notify()) co_return std::unexpected(AsyncApplicationError::state);
                co_return co_await flush(deadline); }
            catch (...) { cancel(); throw; }
        }
#ifdef NEXUS_ENABLE_KTLS
        auto read_ktls(std::span<std::uint8_t> output, ApplicationDeadline deadline = {},
            ReadTimeoutPolicy policy = ReadTimeoutPolicy::cancel_connection)
            -> capy::task<std::expected<std::size_t, AsyncApplicationError>> {
            if constexpr (!requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                (void)output; (void)deadline; (void)policy; co_return std::unexpected(AsyncApplicationError::state);
            } else {
                if (reading_ || canceled_ || !ktls_) co_return std::unexpected(AsyncApplicationError::state);
                reading_ = true; FlagGuard rg{reading_};
                int fd = static_cast<int>(socket_.native_handle());
                for (;;) {
                    if (expired(deadline)) { if (policy == ReadTimeoutPolicy::cancel_connection) cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                    auto res = ktls_->recv_record(fd, output);
                    switch (res.kind) {
                    case KtlsRecvKind::data: co_return res.bytes;
                    case KtlsRecvKind::close_notify: co_return std::size_t{0};
                    case KtlsRecvKind::ticket_discarded:
                    case KtlsRecvKind::key_update: continue;
                    case KtlsRecvKind::key_update_requested: {
                        if (ktls_->tx_closed()) continue;
                        ktls_rekey_pending_ = true;
                        while (writing_ && ktls_rekey_pending_ && !canceled_) {
                            writer_changed_.clear();
                            if (!writing_ || !ktls_rekey_pending_ || canceled_) break;
                            auto wop = writer_changed_.wait();
                            auto [we] = deadline ? co_await corosio::timeout(std::move(wop), *deadline) : co_await std::move(wop);
                            if (capy::is_timeout(we) || expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                            if (we || canceled_) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                        }
                        if (canceled_) co_return std::unexpected(AsyncApplicationError::transport);
                        if (ktls_rekey_pending_ && !ktls_->tx_closed()) {
                            ktls_rekey_writing_ = true; LockGuard kg{ktls_rekey_writing_, writer_changed_};
                            if (auto rk = co_await ktls_run_tx_control([&]{ return ktls_->rekey_tx(fd, false); }, deadline, AsyncApplicationError::protocol); !rk) co_return std::unexpected(rk.error());
                        }
                        ktls_rekey_pending_ = false;
                        continue;
                    }
                    case KtlsRecvKind::would_block: {
                        auto op = socket_.wait(corosio::wait_type::read);
                        auto [re] = deadline ? co_await corosio::timeout(std::move(op), *deadline) : co_await std::move(op);
                        if (capy::is_timeout(re) || expired(deadline)) { if (policy == ReadTimeoutPolicy::cancel_connection) cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                        if (re || canceled_) { cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                        continue;
                    }
                    default: cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                    }
                }
            }
        }
#endif
    };

    enum class AsyncStreamReadKind { data, event, backpressure, eof };
    struct AsyncStreamReadResult { AsyncStreamReadKind kind; std::size_t size=0; std::optional<ApplicationEvent> event; };
    struct DetachedStreamInput { crypto::Bytes plaintext; crypto::Bytes transport; };
    // Byte-oriented adapter for the single reader of an ApplicationConnection.
    template<class Socket>
    class ApplicationStreamReader {
        ApplicationConnection<Socket>& connection_;
        crypto::Bytes buffered_;
        std::optional<ApplicationEvent> deferred_event_;
        std::size_t offset_=0;
        bool reading_=false, closed_=false, detached_=false;
    public:
        explicit ApplicationStreamReader(ApplicationConnection<Socket>& connection) : connection_(connection) {}
        ApplicationStreamReader(ApplicationStreamReader const&)=delete;
        auto operator=(ApplicationStreamReader const&) -> ApplicationStreamReader& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool { return !reading_ && !closed_ && !detached_ && !deferred_event_ && connection_.active(); }
        [[nodiscard]] auto pending_plaintext() const noexcept -> bool {return offset_<buffered_.size();}
        // Prepend startup bytes preceding retained same-record suffix (preserving both on failure).
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
        // Irreversibly detach plaintext and transport suffix for raw socket reads (sole reader).
        [[nodiscard]] auto detach_input() -> std::expected<DetachedStreamInput,AsyncApplicationError> {
            if (reading_ || closed_ || deferred_event_ || !connection_.active()) return std::unexpected(AsyncApplicationError::state);
            crypto::Bytes plaintext(buffered_.begin()+static_cast<std::ptrdiff_t>(offset_),buffered_.end());
            auto transport=connection_.detach_input();
            if (!transport) return std::unexpected(transport.error());
            crypto::Bytes{}.swap(buffered_); offset_=0; detached_=true;
            return DetachedStreamInput{std::move(plaintext),std::move(*transport)};
        }
        auto read_some(std::span<std::uint8_t> output, ApplicationDeadline deadline = {},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) -> capy::task<std::expected<AsyncStreamReadResult,AsyncApplicationError>> {
            if (reading_ || detached_ || output.empty()) co_return std::unexpected(AsyncApplicationError::state);
            if (!connection_.active()) {
                if (deferred_event_ && deferred_event_->kind==ApplicationEventKind::fatal_alert && offset_==buffered_.size()) {
                    auto event=std::move(*deferred_event_); deferred_event_.reset();
                    co_return AsyncStreamReadResult{AsyncStreamReadKind::event,0,std::move(event)};
                }
                co_return std::unexpected(AsyncApplicationError::state);
            }
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
                if (deferred_event_) {
                    auto event=std::move(*deferred_event_); deferred_event_.reset();
                    if (event.kind==ApplicationEventKind::data) { buffered_=std::move(event.data); offset_=0; continue; }
                    if (event.kind==ApplicationEventKind::close_notify) closed_=true;
                    reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::event,0,std::move(event)};
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
                if (output.size()>=ApplicationInput::kMinDirectReadBuffer) {
                    auto res=co_await connection_.read_into(output,deadline,policy);
                    if (!res) { reading_=false; co_return std::unexpected(res.error()); }
                    if (res->kind==AsyncReadKind::backpressure) { reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::backpressure,0,{}}; }
                    if (res->kind==AsyncReadKind::eof) { closed_=true; reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof,0,{}}; }
                    if (res->data_size>0) { deferred_event_=std::move(res->deferred_event); reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::data,res->data_size,{}}; }
                    if (!res->event) continue;
                    auto event=std::move(*res->event);
                    if (event.kind==ApplicationEventKind::data) { buffered_=std::move(event.data); offset_=0; continue; }
                    if (event.kind==ApplicationEventKind::close_notify) closed_=true;
                    reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::event,0,std::move(event)};
                }
                auto result=co_await connection_.read(deadline,policy);
                if (!result) { reading_=false; co_return std::unexpected(result.error()); }
                if (result->kind==AsyncReadKind::backpressure) { reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::backpressure,0,{}}; }
                if (result->kind==AsyncReadKind::eof) { closed_=true; reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof,0,{}}; }
                auto event=std::move(*result->event);
                if (event.kind==ApplicationEventKind::data) {
                    if (!event.data.empty() && event.data.size()<=output.size()) {
                        auto count=event.data.size(); std::copy_n(event.data.begin(),count,output.begin());
                        crypto::Bytes{}.swap(event.data); reading_=false;
                        co_return AsyncStreamReadResult{AsyncStreamReadKind::data,count,{}};
                    }
                    buffered_=std::move(event.data); continue;
                }
                if (event.kind==ApplicationEventKind::close_notify) closed_=true;
                reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::event,0,std::move(event)};
            }
            } catch (...) { reading_=false; connection_.cancel(); throw; }
        }
    };
}
