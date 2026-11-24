module;
#include <cstring>
#if !defined(_WIN32)
#include <cerrno>
#include <sys/socket.h>
#endif
export module tls.corosio_application_io;
import std;
export import tls.application_io;
import capy;
import corosio;

export namespace tls::detail {
    enum class AsyncApplicationError { transport, state, truncated, protocol, timeout, key_update_required, record_overflow };
    using ApplicationDeadline = std::optional<std::chrono::steady_clock::time_point>;
    inline auto expired(ApplicationDeadline deadline) noexcept -> bool { return deadline && std::chrono::steady_clock::now() >= *deadline; }
    enum class ReadTimeoutPolicy { cancel_connection, preserve_connection };
    enum class AsyncReadKind { event, backpressure, eof };
    struct AsyncReadResult { AsyncReadKind kind; std::optional<ApplicationEvent> event; };
    struct AsyncReadIntoResult {
        AsyncReadKind kind;
        std::size_t data_size = 0;
        std::optional<ApplicationEvent> event;
        std::optional<ApplicationEvent> deferred_event;
    };

    template<std::size_t Size, std::size_t MaxCached = 32>
    class TlsPooledBuffer {
        struct Pool {
            std::vector<std::unique_ptr<std::uint8_t[]>> free;
            Pool() { free.reserve(MaxCached); }
        };
        static auto local_pool() noexcept -> Pool& {
            thread_local Pool pool;
            return pool;
        }
        std::unique_ptr<std::uint8_t[]> ptr_;
    public:
        static constexpr std::size_t size = Size;
        TlsPooledBuffer() noexcept = default;
        ~TlsPooledBuffer() { reset(); }
        TlsPooledBuffer(TlsPooledBuffer const&) = delete;
        auto operator=(TlsPooledBuffer const&) -> TlsPooledBuffer& = delete;
        TlsPooledBuffer(TlsPooledBuffer&& o) noexcept : ptr_(std::move(o.ptr_)) {}
        auto operator=(TlsPooledBuffer&& o) noexcept -> TlsPooledBuffer& {
            if (this != &o) { reset(); ptr_ = std::move(o.ptr_); }
            return *this;
        }
        auto acquire() noexcept -> bool {
            if (ptr_) return true;
            auto& free = local_pool().free;
            if (!free.empty()) {
                ptr_ = std::move(free.back());
                free.pop_back();
                return true;
            }
            ptr_.reset(new (std::nothrow) std::uint8_t[Size]);
            return ptr_ != nullptr;
        }
        auto reset() noexcept -> void {
            if (!ptr_) return;
            auto& free = local_pool().free;
            if (free.size() < MaxCached) {
                try { free.push_back(std::move(ptr_)); return; } catch (...) {}
            }
            ptr_.reset();
        }
        [[nodiscard]] auto get() const noexcept -> std::uint8_t* { return ptr_.get(); }
        [[nodiscard]] explicit operator bool() const noexcept { return ptr_ != nullptr; }
    };

    enum class NonblockWriteStatus { done, would_block, error };
    template<class Socket>
    auto try_send_nonblock(Socket& socket, std::uint8_t const* data, std::size_t len, std::size_t& off) noexcept -> NonblockWriteStatus {
#if !defined(_WIN32)
        if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
            int const fd = static_cast<int>(socket.native_handle());
            if (fd < 0) return NonblockWriteStatus::would_block;
#ifdef MSG_NOSIGNAL
            constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
            constexpr int kSendFlags = MSG_DONTWAIT;
#endif
            while (off < len) {
                ssize_t const w = ::send(fd, data + off, len - off, kSendFlags);
                if (w > 0) { off += static_cast<std::size_t>(w); continue; }
                if (w < 0 && errno == EINTR) continue;
                if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return NonblockWriteStatus::would_block;
                return NonblockWriteStatus::error;
            }
            return NonblockWriteStatus::done;
        }
#endif
        (void)socket; (void)data; (void)len; (void)off;
        return NonblockWriteStatus::would_block;
    }

    // One reader owns the buffered transport suffix, including any bytes read during handshake.
    class ApplicationInput {
        static constexpr std::size_t kMaxUnreadSuffix = 4096;
        static constexpr std::size_t kReadBufferSize = 65536;
        std::array<std::uint8_t,kMaxUnreadSuffix> buffered_;
        TlsPooledBuffer<kReadBufferSize> large_buf_;
        std::size_t offset_=0, size_=0, total_read_=0;
        bool valid_=true, large_failed_=false;
        [[nodiscard]] auto active_data() const noexcept -> std::uint8_t const* {
            return large_buf_ ? large_buf_.get() : buffered_.data();
        }
        [[nodiscard]] auto active_data() noexcept -> std::uint8_t* {
            return large_buf_ ? large_buf_.get() : buffered_.data();
        }
        [[nodiscard]] auto active_capacity() const noexcept -> std::size_t {
            return large_buf_ ? kReadBufferSize : buffered_.size();
        }
        auto ensure_large_buffer() noexcept -> void {
            if (!large_buf_ && !large_failed_ && total_read_ >= 16384) {
                if (!large_buf_.acquire()) { large_failed_ = true; return; }
                auto const rem = size_ - offset_;
                if (rem > 0) std::memmove(large_buf_.get(), buffered_.data() + offset_, rem);
                offset_ = 0;
                size_ = rem;
            }
        }
        auto compact_tail() noexcept -> void {
            auto const rem = size_ - offset_;
            if (offset_ > 0) {
                if (rem > 0) std::memmove(active_data(), active_data() + offset_, rem);
                offset_ = 0;
                size_ = rem;
            }
        }
        static auto can_complete_in_buffer(std::span<std::uint8_t const> avail, bool tls12, std::size_t cap) noexcept -> bool {
            if (avail.size() < 5) return true;
            auto const type = avail[0];
            auto const len = (std::size_t{avail[3]} << 8) | avail[4];
            if (avail[1] != 3 || avail[2] != 3 ||
                (tls12 ? (type < 21 || type > 23 || len < 16 || len > 16408u) : (type != 23 || len < 17 || len > 16640u)))
                return false;
            return 5 + len <= cap;
        }
    public:
        static constexpr std::size_t kMinDirectReadBuffer = 16624;
        // Handshake drivers read at most one 4096-byte transport block. Reject a
        // larger externally supplied suffix and do not retain its allocation.
        explicit ApplicationInput(crypto::Bytes&& unread) : valid_(unread.size()<=kMaxUnreadSuffix) {
            if (valid_) { size_=unread.size(); std::copy(unread.begin(),unread.end(),buffered_.begin()); }
            crypto::Bytes{}.swap(unread);
        }
        [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }
        [[nodiscard]] auto unread() const noexcept -> std::span<std::uint8_t const> { return std::span(active_data()+offset_,size_-offset_); }
        auto detach() noexcept -> void { valid_=false; offset_=size_=0; large_buf_.reset(); }
        ApplicationInput(ApplicationInput const&)=delete;
        auto operator=(ApplicationInput const&) -> ApplicationInput& = delete;
        // A backpressure result means the single writer must flush pending output first.
        template<class Socket>
        auto read(Socket& socket, ApplicationIo& app, ApplicationDeadline deadline = {},ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) -> capy::task<std::expected<AsyncReadResult,AsyncApplicationError>> {
            if (!valid_) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
            while (true) {
                if (expired(deadline)) { if(policy==ReadTimeoutPolicy::cancel_connection)app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                if (app.input_blocked()) co_return AsyncReadResult{AsyncReadKind::backpressure,{}};
                if (offset_==size_) {
                    offset_=size_=0;
                    ensure_large_buffer();
                    auto* buf=active_data();
                    auto const cap=active_capacity();
                    auto operation=socket.read_some(capy::mutable_buffer(buf,cap));
                    auto [error,n]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                    if (n>cap) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    if (capy::is_timeout(error) || (!error && expired(deadline))) {
                        if(policy==ReadTimeoutPolicy::cancel_connection)app.cancel();
                        else if(!error)size_=n; // A completed read at the deadline remains owned here.
                        co_return std::unexpected(AsyncApplicationError::timeout);
                    }
                    if (capy::is_eof(error) || (!error && !n)) {
                        if (!app.finish_input()) co_return std::unexpected(AsyncApplicationError::truncated);
                        co_return AsyncReadResult{AsyncReadKind::eof,{}};
                    }
                    if (error) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    size_=n;
                    total_read_+=n;
                }
                auto result=app.feed(std::span{active_data(),size_}.subspan(offset_,size_-offset_));
                if (!result) {
                    if (result.error()==ApplicationIoError::record_overflow) co_return std::unexpected(AsyncApplicationError::record_overflow);
                    app.cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                }
                offset_+=result->consumed;
                if (result->event) co_return AsyncReadResult{AsyncReadKind::event,std::move(result->event)};
                if (!result->consumed) co_return AsyncReadResult{AsyncReadKind::backpressure,{}};
            }
        }
        template<class Socket>
        auto read_into(Socket& socket, ApplicationIo& app, std::span<std::uint8_t> output,
            ApplicationDeadline deadline = {}, ReadTimeoutPolicy policy = ReadTimeoutPolicy::cancel_connection)
            -> capy::task<std::expected<AsyncReadIntoResult, AsyncApplicationError>> {
            if (!valid_) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
            while (true) {
                if (expired(deadline)) { if(policy==ReadTimeoutPolicy::cancel_connection)app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                if (app.input_blocked()) co_return AsyncReadIntoResult{AsyncReadKind::backpressure, 0, {}, {}};
                auto avail = std::span<std::uint8_t const>{active_data() + offset_, size_ - offset_};
                bool need_read = avail.empty();
                if (!need_read && app.input_pending_bytes() == 0 && !app.has_complete_buffered_record(avail)) {
                    ensure_large_buffer();
                    avail = std::span<std::uint8_t const>{active_data() + offset_, size_ - offset_};
                    if (can_complete_in_buffer(avail, app.records_tls12(), active_capacity())) {
                        compact_tail();
                        need_read = size_ < active_capacity();
                    }
                }
                if (need_read) {
                    if (offset_ == size_) { offset_ = size_ = 0; ensure_large_buffer(); }
                    auto* buf = active_data();
                    auto const cap = active_capacity();
                    auto const free_cap = cap - size_;
#if !defined(_WIN32)
                    if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                        if (!deadline) {
                            int const fd = static_cast<int>(socket.native_handle());
                            if (fd >= 0) {
                                ssize_t r = -1;
                                do { r = ::recv(fd, buf + size_, free_cap, MSG_DONTWAIT); } while (r < 0 && errno == EINTR);
                                if (r > 0) {
                                    size_ += static_cast<std::size_t>(r);
                                    total_read_ += static_cast<std::size_t>(r);
                                    continue;
                                }
                                if (r == 0) {
                                    if (size_ > offset_ || !app.finish_input()) {
                                        app.cancel();
                                        co_return std::unexpected(AsyncApplicationError::truncated);
                                    }
                                    co_return AsyncReadIntoResult{AsyncReadKind::eof, 0, {}, {}};
                                }
                                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                                    app.cancel();
                                    co_return std::unexpected(AsyncApplicationError::transport);
                                }
                            }
                        }
                    }
#endif
                    auto operation = socket.read_some(capy::mutable_buffer(buf + size_, free_cap));
                    auto [error, n] = deadline ? co_await corosio::timeout(std::move(operation), *deadline) : co_await std::move(operation);
                    if (n > free_cap) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    if (capy::is_timeout(error) || (!error && expired(deadline))) {
                        if (policy == ReadTimeoutPolicy::cancel_connection) app.cancel();
                        else if (!error) size_ += n;
                        co_return std::unexpected(AsyncApplicationError::timeout);
                    }
                    if (capy::is_eof(error) || (!error && !n)) {
                        if (size_ > offset_ || !app.finish_input()) {
                            app.cancel();
                            co_return std::unexpected(AsyncApplicationError::truncated);
                        }
                        co_return AsyncReadIntoResult{AsyncReadKind::eof, 0, {}, {}};
                    }
                    if (error) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    size_ += n;
                    total_read_ += n;
                    continue;
                }
                auto first = app.feed_into(avail, output);
                if (!first) {
                    if (first.error() == ApplicationIoError::record_overflow) co_return std::unexpected(AsyncApplicationError::record_overflow);
                    app.cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                }
                offset_ += first->consumed;
                if (first->event) co_return AsyncReadIntoResult{AsyncReadKind::event, 0, std::move(first->event), {}};
                if (first->data_size > 0) {
                    std::size_t total = first->data_size;
                    std::optional<ApplicationEvent> deferred;
                    while (offset_ < size_ && output.size() - total >= kMinDirectReadBuffer && !app.input_blocked()) {
                        auto rem = std::span<std::uint8_t const>{active_data() + offset_, size_ - offset_};
                        if (!app.has_complete_buffered_record(rem)) break;
                        auto next = app.feed_into(rem, output.subspan(total));
                        if (!next) {
                            if (next.error() == ApplicationIoError::record_overflow) co_return std::unexpected(AsyncApplicationError::record_overflow);
                            app.cancel(); co_return std::unexpected(AsyncApplicationError::protocol);
                        }
                        if (!next->consumed) break;
                        offset_ += next->consumed;
                        if (next->event) { deferred = std::move(*next->event); break; }
                        total += next->data_size;
                    }
                    co_return AsyncReadIntoResult{AsyncReadKind::event, total, {}, std::move(deferred)};
                }
                if (!first->consumed) co_return AsyncReadIntoResult{AsyncReadKind::backpressure, 0, {}, {}};
            }
        }
    };

    // Single writer. The owner serializes all ApplicationIo calls on one executor and keeps
    // the socket and state alive until this coroutine completes, including after cancellation.
    // The copy protects a parked write from a concurrent receive failing or changing output.
    template<class Socket>
    auto flush_application(Socket& socket, ApplicationIo& app, crypto::Bytes& scratch, ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
        while (!app.pending_output().empty()) {
            if (expired(deadline)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            auto pending=app.pending_output();
            scratch.assign(pending.begin(),pending.end());
            std::size_t off=0;
            while (off<scratch.size()) {
                auto operation=socket.write_some(capy::const_buffer(scratch.data()+off,scratch.size()-off));
                auto [error,n]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                if (capy::is_timeout(error) || (!error && expired(deadline))) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                if (error || !n || n>scratch.size()-off) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                if (!app.written(n)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
                off+=n;
            }
        }
        co_return std::expected<void,AsyncApplicationError>{};
    }

    template<class Socket>
    auto flush_application(Socket& socket, ApplicationIo& app, ApplicationDeadline deadline = {}) -> capy::task<std::expected<void,AsyncApplicationError>> {
        crypto::Bytes scratch;
        co_return co_await flush_application(socket,app,scratch,deadline);
    }
}
