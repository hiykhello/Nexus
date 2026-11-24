module;
#if !defined(_WIN32)
#include <cerrno>
#include <sys/socket.h>
#endif
export module net.stream_relay;
import std;
import capy;
import corosio;

export namespace net::stream_relay {
    template<std::size_t Size, std::size_t MaxCached>
    class PooledRelayBuffer {
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
        PooledRelayBuffer() noexcept = default;
        ~PooledRelayBuffer() { reset(); }
        PooledRelayBuffer(PooledRelayBuffer const&) = delete;
        auto operator=(PooledRelayBuffer const&) -> PooledRelayBuffer& = delete;
        PooledRelayBuffer(PooledRelayBuffer&& o) noexcept : ptr_(std::move(o.ptr_)) {}
        auto operator=(PooledRelayBuffer&& o) noexcept -> PooledRelayBuffer& {
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

    struct Delivery {
        void* owner=nullptr;
        void (*notify)(void*,bool,std::size_t) noexcept=nullptr;
        auto operator()(bool upstream,std::size_t size) const noexcept -> void {
            if (notify) notify(owner,upstream,size);
        }
    };

    enum class ReadState { data, eof, failure };

    template<class Adapter,class Result>
    auto read_state(Adapter& adapter,Result const& result,std::size_t size) -> ReadState {
        if constexpr (Adapter::socket_input) {
            auto const& [error,n]=result;
            if (adapter.eof(error,n)) return ReadState::eof;
            if (adapter.invalid_read(error,n,size)) return ReadState::failure;
            return ReadState::data;
        } else {
            if (adapter.invalid_read(result) || *result > size) return ReadState::failure;
            return *result ? ReadState::data : ReadState::eof;
        }
    }

    template<class Adapter,class Result>
    auto read_size(Result const& result) -> std::size_t {
        if constexpr (Adapter::socket_input) {
            auto const& [error,n]=result;
            (void)error; return n;
        } else return *result;
    }

    // Adapters describe a single direction. Socket operations expose partial
    // writes; framed streams expose complete writes. The owner drains the task.
    template<template<class> class Coroutine=capy::task,class Adapter>
    auto transfer(Adapter adapter) -> Coroutine<bool> {
        if constexpr (requires { adapter.delegates(); adapter.delegate(); })
            if (adapter.delegates()) co_return co_await adapter.delegate();
        if (!adapter.start()) co_return false;
        PooledRelayBuffer<16640, 64> small_buf;
        PooledRelayBuffer<65536, 32> large_buf;
        if (!small_buf.acquire()) { adapter.read_failed(); co_return false; }
        std::size_t total_bytes=0;
        bool large_failed=false;
        bool try_nonblock_read=false;
        for (;;) {
            if (!large_buf && !large_failed && total_bytes>=65536) {
                if (large_buf.acquire()) small_buf.reset();
                else large_failed=true;
            }
            auto buf=large_buf ? std::span<std::uint8_t>(large_buf.get(),65536) : std::span<std::uint8_t>(small_buf.get(),16640);
            std::size_t got=0;
            bool need_async_read=true;
#if !defined(_WIN32)
            if constexpr (Adapter::socket_input) {
                if (try_nonblock_read) {
                    if (adapter.invalid_read(std::error_code{}, std::size_t{1}, std::size_t{1})) {
                        adapter.read_failed(); co_return false;
                    }
                    int fd=-1;
                    if constexpr (requires { { adapter.input_fd() } -> std::convertible_to<int>; })
                        fd=static_cast<int>(adapter.input_fd());
                    if (fd>=0) {
                        ssize_t r=-1;
                        do { r=::recv(fd,buf.data(),buf.size(),MSG_DONTWAIT); } while (r<0 && errno==EINTR);
                        if (r>0) {
                            got=static_cast<std::size_t>(r);
                            if (adapter.invalid_read(std::error_code{}, got, buf.size())) {
                                adapter.read_failed(); co_return false;
                            }
                            need_async_read=false;
                        } else if (r==0) {
                            if constexpr (Adapter::locked_output) {
                                auto [lock_error,guard]=co_await adapter.lock();
                                if (lock_error || adapter.canceled()) co_return false;
                                auto closed_ok=co_await adapter.close_locked();
                                if (!closed_ok) { adapter.cancel(); co_return false; }
                                co_return true;
                            } else if constexpr (requires { adapter.close_now(); }) co_return adapter.close_now();
                            else co_return co_await adapter.close_output();
                        } else if (errno!=EAGAIN && errno!=EWOULDBLOCK) {
                            adapter.read_failed(); co_return false;
                        }
                    }
                }
            }
#endif
            if (need_async_read) {
                auto result=co_await adapter.read(buf);
                switch (read_state(adapter,result,buf.size())) {
                case ReadState::failure:
                    adapter.read_failed(); co_return false;
                case ReadState::eof:
                    if constexpr (Adapter::locked_output) {
                        auto [lock_error,guard]=co_await adapter.lock();
                        if (lock_error || adapter.canceled()) co_return false;
                        auto closed=co_await adapter.close_locked();
                        if (!closed) { adapter.cancel(); co_return false; }
                        co_return true;
                    } else if constexpr (requires { adapter.close_now(); }) co_return adapter.close_now();
                    else co_return co_await adapter.close_output();
                case ReadState::data:
                    break;
                }
                got=read_size<Adapter>(result);
                if constexpr (Adapter::socket_input) try_nonblock_read=true;
            }
            adapter.after_read();
            total_bytes+=got;
            if constexpr (requires {adapter.meters_output(); adapter.reserve_output(std::size_t{});}) {
                if (adapter.meters_output()) {
                    auto pending=buf.first(got);
                    while (!pending.empty()) {
                        auto credit=co_await adapter.reserve_output(pending.size());
                        if (!credit) co_return false;
                        auto output=pending.first(credit->size());
                        std::size_t written=output.size();
                        credit->submit();
                        if constexpr (Adapter::socket_output) {
                            auto [error,n]=co_await adapter.write(output);
                            written=n<=output.size() ? n : 0;
                            credit->complete(written);
                            if (written) adapter.delivered(written);
                            if (adapter.invalid_write(error,n,output.size())) {
                                adapter.write_failed(); co_return false;
                            }
                            adapter.after_write();
                        } else {
                            if (!co_await adapter.write(output)) co_return false;
                            credit->complete(written);
                            adapter.delivered(written);
                        }
                        pending=pending.subspan(written);
                    }
                    continue;
                }
            }
            if constexpr (Adapter::socket_output) {
                auto pending=buf.first(got);
#if !defined(_WIN32)
                {
                    if (adapter.invalid_write(std::error_code{}, std::size_t{1}, std::size_t{1})) {
                        adapter.write_failed(); co_return false;
                    }
                    int fd=-1;
                    if constexpr (requires { { adapter.output_fd() } -> std::convertible_to<int>; })
                        fd=static_cast<int>(adapter.output_fd());
                    if (fd>=0) {
#ifdef MSG_NOSIGNAL
                        constexpr int kSendFlags=MSG_DONTWAIT|MSG_NOSIGNAL;
#else
                        constexpr int kSendFlags=MSG_DONTWAIT;
#endif
                        while (!pending.empty()) {
                            ssize_t const w=::send(fd,pending.data(),pending.size(),kSendFlags);
                            if (w>0) {
                                auto const n=static_cast<std::size_t>(w);
                                if constexpr (requires { adapter.delivered(n); }) adapter.delivered(n);
                                if (adapter.invalid_write(std::error_code{}, n, pending.size())) {
                                    adapter.write_failed(); co_return false;
                                }
                                adapter.after_write();
                                pending=pending.subspan(n);
                                continue;
                            }
                            if (w<0 && errno==EINTR) continue;
                            if (w<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
                            adapter.write_failed(); co_return false;
                        }
                    }
                }
#endif
                while (!pending.empty()) {
                    auto [error,n]=co_await adapter.write(pending);
                    if constexpr (requires { adapter.delivered(n); })
                        if (n && n<=pending.size()) adapter.delivered(n);
                    if (adapter.invalid_write(error,n,pending.size())) { adapter.write_failed(); co_return false; }
                    adapter.after_write(); pending=pending.subspan(n);
                }
            } else if constexpr (Adapter::locked_output) {
                auto [lock_error,guard]=co_await adapter.lock();
                if (lock_error || adapter.canceled()) co_return false;
                auto pending=buf.first(got);
                auto sent=co_await adapter.send_locked(pending);
                if (!sent) { adapter.cancel(); co_return false; }
                if constexpr (requires { adapter.delivered(pending.size()); }) adapter.delivered(pending.size());
            } else {
                auto pending=buf.first(got);
                if (!co_await adapter.write(pending)) co_return false;
                if constexpr (requires { adapter.delivered(pending.size()); }) adapter.delivered(pending.size());
            }
        }
    }

    // Existing outbound adapters map their socket-to-stream direction here.
    template<class Adapter>
    struct UploadAdapter {
        Adapter adapter;
        static constexpr bool socket_input=true, socket_output=false, locked_output=Adapter::locked_upload;
        auto delegates() const requires requires(Adapter const& a) { a.delegates(); } { return adapter.delegates(); }
        auto delegate() const requires requires(Adapter const& a) { a.delegate(); } { return adapter.delegate(); }
        auto start() { return adapter.start_upload(); }
        auto input_fd() noexcept -> int {
            if constexpr (requires { { adapter.local().native_handle() } -> std::convertible_to<int>; })
                return static_cast<int>(adapter.local().native_handle());
            else return -1;
        }
        auto read(std::span<std::uint8_t> bytes) { return adapter.local().read_some(capy::mutable_buffer(bytes.data(),bytes.size())); }
        template<class Error> auto eof(Error const& error,std::size_t n) { return adapter.upload_eof(error,n); }
        template<class Error> auto invalid_read(Error const& error,std::size_t n,std::size_t size) { return adapter.invalid_upload(error,n,size); }
        auto read_failed() { adapter.cancel(); }
        auto after_read() { adapter.after_local_read(); }
        auto close_now() requires requires(Adapter& a) { a.close_now(); } { return adapter.close_now(); }
        auto close_output() { return adapter.close_upload(); }
        auto write(std::span<std::uint8_t const> bytes) { return adapter.send_upload(bytes); }
        auto lock() { return adapter.lock(); }
        auto canceled() { return adapter.canceled(); }
        auto close_locked() { return adapter.close_locked(); }
        auto send_locked(std::span<std::uint8_t const> bytes) { return adapter.send_locked(bytes); }
        auto delivered(std::size_t size) requires requires(Adapter& a) { a.delivery(true,size); } {
            adapter.delivery(true,size);
        }
        auto cancel() { adapter.cancel(); }
    };

    // Stream-to-socket direction retains the stream's own error handling.
    template<class Adapter>
    struct DownloadAdapter {
        Adapter adapter;
        static constexpr bool socket_input=false, socket_output=true, locked_output=false;
        auto start() { return adapter.start_download(); }
        auto read(std::span<std::uint8_t> bytes) { return adapter.receive(bytes); }
        template<class Result> auto invalid_read(Result const& result) { return !result; }
        auto read_failed() {}
        auto after_read() {}
        auto close_now() { return adapter.shutdown_local(); }
        auto output_fd() noexcept -> int {
            if constexpr (requires { { adapter.local().native_handle() } -> std::convertible_to<int>; })
                return static_cast<int>(adapter.local().native_handle());
            else return -1;
        }
        auto write(std::span<std::uint8_t const> bytes) { return adapter.local().write_some(capy::const_buffer(bytes.data(),bytes.size())); }
        template<class Error> auto invalid_write(Error const& error,std::size_t n,std::size_t size) { return adapter.invalid_download(error,n,size); }
        auto write_failed() { adapter.cancel(); }
        auto after_write() { adapter.after_local_write(); }
        auto delivered(std::size_t size) requires requires(Adapter& a) { a.delivery(false,size); } {
            adapter.delivery(false,size);
        }
    };

    template<template<class> class Coroutine=capy::task,class Adapter>
    auto upload(Adapter adapter) -> Coroutine<bool> { return transfer<Coroutine>(UploadAdapter<Adapter>{std::move(adapter)}); }
    template<class Adapter>
    auto download(Adapter adapter) -> capy::task<bool> { return transfer(DownloadAdapter<Adapter>{std::move(adapter)}); }
}

export namespace net {
    // A plain stream already owns authentication/framing. Reuse the shared
    // directional loops for protocols that expose read/send/close_output.
    template<class Local,class Stream,class Touch>
    struct ByteRelayAdapter {
        Local& socket;
        Stream& stream;
        Touch touch;
        bool cancel_local=true;
        stream_relay::Delivery delivery;
        static constexpr bool locked_upload=false;
        auto local() const -> Local& { return socket; }
        auto start_upload() const -> bool { return true; }
        auto start_download() const -> bool { return true; }
        template<class Error> auto upload_eof(Error const& error,std::size_t) const -> bool { return capy::is_eof(error); }
        template<class Error> auto invalid_upload(Error const& error,std::size_t n,std::size_t size) const -> bool { return error || !n || n>size; }
        template<class Error> auto invalid_download(Error const& error,std::size_t n,std::size_t size) const -> bool { return error || !n || n>size; }
        auto after_local_read() const -> void { touch(); }
        auto after_local_write() const -> void { touch(); }
        auto cancel() const noexcept -> void { stream.cancel(); if (cancel_local) socket.cancel(); }
        auto close_upload() const { return stream.close_output(); }
        auto send_upload(std::span<std::uint8_t const> bytes) const { return stream.send(bytes); }
        auto receive(std::span<std::uint8_t> bytes) const { return stream.read(bytes); }
        auto shutdown_local() const -> bool { (void)socket.shutdown(corosio::shutdown_send); return true; }
    };

    // Adapts a framed byte stream to the partial-I/O interface used by TLS
    // and protocol handshakes. send() must consume the entire borrowed span on
    // success; read() returns 0 only for clean EOF. The owner drains pending
    // operations before destroying either object. No adapter coroutine is made.
    template<class Transport>
    class ByteStreamAdapter {
        Transport& transport_;
        template<class Operation,bool Write>
        class ResultAdapter {
            std::optional<Operation> operation_;
            std::size_t limit_;
            std::stop_token const* stop_=nullptr;
            auto failure() const -> std::error_code {
                return std::make_error_code(stop_ && stop_->stop_requested() ?
                    std::errc::operation_canceled : std::errc::io_error);
            }
        public:
            ResultAdapter(std::optional<Operation>&& operation,std::size_t limit)
                : operation_(std::move(operation)),limit_(limit) {}
            auto await_ready() const noexcept -> bool { return !operation_ || operation_->await_ready(); }
            template<class Context>
            auto await_suspend(std::coroutine_handle<> continuation,Context const* context) {
                stop_=&context->stop_token;
                return operation_->await_suspend(continuation,context);
            }
            [[nodiscard]] auto await_resume() -> capy::results<std::size_t> {
                if (!operation_) return {std::error_code{},0};
                if constexpr (Write) {
                    if (!operation_->await_resume()) return {failure(),0};
                    return {std::error_code{},limit_};
                } else {
                    auto result=operation_->await_resume();
                    if (!result) return {failure(),0};
                    if (*result>limit_) return {std::make_error_code(std::errc::protocol_error),0};
                    return {std::error_code{},*result};
                }
            }
        };
    public:
        explicit ByteStreamAdapter(Transport& transport) noexcept : transport_(transport) {}
        ByteStreamAdapter(ByteStreamAdapter const&)=delete;
        auto operator=(ByteStreamAdapter const&) -> ByteStreamAdapter& = delete;
        auto read_some(capy::mutable_buffer buffer) {
            using Operation=decltype(transport_.read(std::span<std::uint8_t>{}));
            std::optional<Operation> operation;
            if (buffer.size()) operation.emplace(transport_.read({static_cast<std::uint8_t*>(buffer.data()),buffer.size()}));
            return ResultAdapter<Operation,false>(std::move(operation),buffer.size());
        }
        auto write_some(capy::const_buffer buffer) {
            using Operation=decltype(transport_.send(std::span<std::uint8_t const>{}));
            std::optional<Operation> operation;
            if (buffer.size()) operation.emplace(transport_.send({static_cast<std::uint8_t const*>(buffer.data()),buffer.size()}));
            return ResultAdapter<Operation,true>(std::move(operation),buffer.size());
        }
        auto close_output() { return transport_.close_output(); }
        // Expose the asynchronous half-close as a cancellable results operation
        // so a caller can apply the same absolute deadline as its writes.
        auto close_output_some() {
            using Operation=decltype(transport_.close_output());
            std::optional<Operation> operation;
            operation.emplace(transport_.close_output());
            return ResultAdapter<Operation,true>(std::move(operation),0);
        }
        auto cancel() noexcept -> void { transport_.cancel(); }
    };
}
