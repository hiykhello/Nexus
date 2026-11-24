module;
#if !defined(_WIN32)
#include <cerrno>
#include <sys/socket.h>
#endif
export module shadowsocks.corosio_client;
import std;
import crypto;
import shadowsocks.chunk;
import shadowsocks.key;
import shadowsocks.request;
import shadowsocks.response;
import shadowsocks.frame;
import platform.wall_clock;
import capy;
import corosio;
export namespace shadowsocks::detail {
    enum class StartError { invalid_input, random, timeout, transport, partial_write };
    struct StartedRequest { std::vector<std::uint8_t> salt; ChunkCipher cipher; };
    // One executor owns the socket. Input spans and the socket must live until completion.
    // Failure after submission cancels the socket; retain it until cancellation drains.
    template<class Socket>
    auto start_request(Socket& socket, std::span<std::uint8_t const> psk,
                       std::span<std::uint8_t const> address, std::chrono::steady_clock::time_point deadline,
                       std::span<std::array<std::uint8_t,32> const> identity_keys={},CipherMethod method=CipherMethod::aes)
        -> capy::task<std::expected<StartedRequest,StartError>> {
        if (psk.size()!=16 && psk.size()!=32) co_return std::unexpected(StartError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(StartError::timeout);
        std::array<std::uint8_t, 32 + 2 + 900> rng;
        if (!crypto::random_bytes(std::span(rng).first(psk.size() + 2 + 900)))
            co_return std::unexpected(StartError::random);
        auto const salt_span = std::span<std::uint8_t const>(rng.data(), psk.size());
        auto const length = 1 + (((static_cast<std::size_t>(rng[psk.size()]) << 8) | rng[psk.size() + 1]) % 900);
        auto const padding = std::span<std::uint8_t const>(rng.data() + psk.size() + 2, length);
        auto wall=platform::calibrated_wall_seconds();
        if (wall<0) co_return std::unexpected(StartError::invalid_input);
        auto request=encode_request(psk,salt_span,static_cast<std::uint64_t>(wall),address,padding,{},identity_keys,method);
        if (!request) co_return std::unexpected(StartError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(StartError::timeout);
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        auto operation=socket.write_some(capy::const_buffer(request->wire.data(),request->wire.size()));
        auto [error,n]=co_await corosio::timeout(std::move(operation),deadline);
        if (capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline)) {
            co_return std::unexpected(StartError::timeout);
        }
        if (error) co_return std::unexpected(StartError::transport);
        if (n!=request->wire.size()) co_return std::unexpected(StartError::partial_write);
        guard.done=true;
        co_return StartedRequest{std::vector<std::uint8_t>(salt_span.begin(),salt_span.end()),std::move(request->cipher)};
    }
    enum class SendError { invalid_frame, timeout, transport };
    // Single writer; keep the socket, encoder and payload alive until completion.
    // Any error or exception closes the encoder and cancels the socket.
    template<class Socket>
    auto send_frame(Socket& socket, FrameEncoder& encoder, std::span<std::uint8_t const> payload,
                    std::chrono::steady_clock::time_point deadline) -> capy::task<std::expected<void,SendError>> {
        struct Guard {
            Socket& socket; FrameEncoder& encoder; bool done=false;
            ~Guard() { if (!done) { encoder.close(); socket.cancel(); } }
        } guard{socket,encoder};
        bool const bounded = deadline != std::chrono::steady_clock::time_point::max();
        if (bounded && std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(SendError::timeout);
        auto frame=encoder.encode_wire(payload);
        if (!frame) co_return std::unexpected(SendError::invalid_frame);
        std::size_t offset=0;
#if !defined(_WIN32)
        if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
            if (!bounded) {
                int const fd = static_cast<int>(socket.native_handle());
                if (fd >= 0) {
#ifdef MSG_NOSIGNAL
                    constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
                    constexpr int kSendFlags = MSG_DONTWAIT;
#endif
                    while (offset < frame->size()) {
                        ssize_t const w = ::send(fd, frame->data() + offset, frame->size() - offset, kSendFlags);
                        if (w > 0) { offset += static_cast<std::size_t>(w); continue; }
                        if (w < 0 && errno == EINTR) continue;
                        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                        co_return std::unexpected(SendError::transport);
                    }
                    if (offset == frame->size()) {
                        guard.done = true;
                        co_return std::expected<void,SendError>{};
                    }
                }
            }
        }
#endif
        while (offset<frame->size()) {
            if (bounded && std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(SendError::timeout);
            std::error_code error;
            std::size_t n=0;
            if (bounded) {
                auto operation=socket.write_some(capy::const_buffer(frame->data()+offset,frame->size()-offset));
                std::tie(error,n)=co_await corosio::timeout(std::move(operation),deadline);
                if (capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
                    co_return std::unexpected(SendError::timeout);
            } else {
                std::tie(error,n)=co_await socket.write_some(capy::const_buffer(frame->data()+offset,frame->size()-offset));
            }
            if (error || !n || n>frame->size()-offset) co_return std::unexpected(SendError::transport);
            offset+=n;
        }
        guard.done=true; co_return std::expected<void,SendError>{};
    }

    enum class ReceiveError { invalid_input, timeout, transport, truncated, invalid_header, authentication };
    struct StartedResponse { ChunkCipher cipher; std::vector<std::uint8_t> payload, unread; };
    // Exactly one initial read; later reads collect the first payload without consuming extra data.
    // One reader owns the socket and all inputs remain alive until completion.
    template<class Socket>
    auto receive_response(Socket& socket, std::span<std::uint8_t const> psk,
                          std::span<std::uint8_t const> request_salt, std::chrono::steady_clock::time_point deadline,
                          CipherMethod method=CipherMethod::aes)
        -> capy::task<std::expected<StartedResponse,ReceiveError>> {
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        if ((psk.size()!=16 && psk.size()!=32) || request_salt.size()!=psk.size())
            co_return std::unexpected(ReceiveError::invalid_input);
        bool const bounded = deadline != std::chrono::steady_clock::time_point::max();
        if (bounded && std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ReceiveError::timeout);
        std::array<std::uint8_t, 4096> initial_buf;
        std::error_code error;
        std::size_t n = 0;
        if (bounded) {
            auto operation=socket.read_some(capy::mutable_buffer(initial_buf.data(),initial_buf.size()));
            std::tie(error,n)=co_await corosio::timeout(std::move(operation),deadline);
            if (capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
                co_return std::unexpected(ReceiveError::timeout);
        } else {
            std::tie(error,n)=co_await socket.read_some(capy::mutable_buffer(initial_buf.data(),initial_buf.size()));
        }
        if (capy::is_eof(error) || (!error && !n)) co_return std::unexpected(ReceiveError::truncated);
        if (error || n>initial_buf.size()) co_return std::unexpected(ReceiveError::transport);
        auto wall=platform::calibrated_wall_seconds();
        if (wall<0) co_return std::unexpected(ReceiveError::invalid_input);
        auto prefix=decode_response_prefix(psk,request_salt,std::span<std::uint8_t const>(initial_buf.data(),n),static_cast<std::uint64_t>(wall),method);
        if (!prefix) co_return std::unexpected(prefix.error()==ResponseError::authentication ? ReceiveError::authentication : ReceiveError::invalid_header);
        auto const start=prefix->consumed;
        auto const end=start+prefix->payload_length+16;
        std::unique_ptr<std::uint8_t[]> overflow;
        std::uint8_t* storage = initial_buf.data();
        if (end > initial_buf.size()) {
            overflow = std::make_unique_for_overwrite<std::uint8_t[]>(end);
            std::memcpy(overflow.get(), initial_buf.data(), n);
            storage = overflow.get();
        }
        auto filled = n;
        while (filled < end) {
            if (bounded && std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ReceiveError::timeout);
            std::error_code read_error;
            std::size_t count = 0;
            if (bounded) {
                auto read=socket.read_some(capy::mutable_buffer(storage+filled,end-filled));
                std::tie(read_error,count)=co_await corosio::timeout(std::move(read),deadline);
                if (capy::is_timeout(read_error) || (!read_error && std::chrono::steady_clock::now()>=deadline))
                    co_return std::unexpected(ReceiveError::timeout);
            } else {
                std::tie(read_error,count)=co_await socket.read_some(capy::mutable_buffer(storage+filled,end-filled));
            }
            if (capy::is_eof(read_error) || (!read_error && !count)) co_return std::unexpected(ReceiveError::truncated);
            if (read_error || count>end-filled) co_return std::unexpected(ReceiveError::transport);
            filled+=count;
        }
        auto decoded=decode_response_payload(std::move(*prefix),std::span<std::uint8_t const>(storage+start,end-start));
        if (!decoded) co_return std::unexpected(decoded.error()==ResponseError::authentication ? ReceiveError::authentication : ReceiveError::invalid_header);
        std::vector<std::uint8_t> unread;
        if (filled > end) unread.assign(storage + end, storage + filled);
        guard.done=true; co_return StartedResponse{std::move(decoded->cipher),std::move(decoded->payload),std::move(unread)};
    }

    class PooledBuffer64K {
        static constexpr std::size_t kMaxCached = 32;
        struct Pool {
            std::vector<std::unique_ptr<std::uint8_t[]>> free;
            Pool() { free.reserve(kMaxCached); }
        };
        static auto local_pool() noexcept -> Pool& {
            thread_local Pool pool;
            return pool;
        }
        std::unique_ptr<std::uint8_t[]> ptr_;
    public:
        static constexpr std::size_t size = 65536;
        PooledBuffer64K() noexcept = default;
        ~PooledBuffer64K() { reset(); }
        PooledBuffer64K(PooledBuffer64K const&) = delete;
        auto operator=(PooledBuffer64K const&) -> PooledBuffer64K& = delete;
        PooledBuffer64K(PooledBuffer64K&& o) noexcept : ptr_(std::move(o.ptr_)) {}
        auto operator=(PooledBuffer64K&& o) noexcept -> PooledBuffer64K& {
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
            ptr_.reset(new (std::nothrow) std::uint8_t[size]);
            return ptr_ != nullptr;
        }
        auto reset() noexcept -> void {
            if (!ptr_) return;
            auto& free = local_pool().free;
            if (free.size() < kMaxCached) {
                try { free.push_back(std::move(ptr_)); return; } catch (...) {}
            }
            ptr_.reset();
        }
        [[nodiscard]] auto get() const noexcept -> std::uint8_t* { return ptr_.get(); }
        [[nodiscard]] explicit operator bool() const noexcept { return ptr_ != nullptr; }
    };

    enum class ReadError { state, timeout, transport, truncated, authentication };
    // Single reader on one executor. The socket and this object outlive any pending read.
    template<class Socket>
    class FrameReader {
        Socket& socket_;
        FrameDecoder decoder_;
        std::array<std::uint8_t, 4096> small_input_;
        PooledBuffer64K large_input_;
        std::vector<std::uint8_t> extra_input_;
        std::vector<std::uint8_t> output_;
        std::size_t input_offset_=0, input_len_=0, output_offset_=0, total_read_=0;
        std::optional<ReadError> pending_error_;
        bool reading_=false, active_=true, eof_=false, using_extra_=false;
        [[nodiscard]] auto input_data() noexcept -> std::uint8_t* {
            if (using_extra_) return extra_input_.data();
            return large_input_ ? large_input_.get() : small_input_.data();
        }
        [[nodiscard]] auto input_capacity() const noexcept -> std::size_t {
            if (using_extra_) return extra_input_.size();
            return large_input_ ? PooledBuffer64K::size : small_input_.size();
        }
    public:
        FrameReader(Socket& socket, StartedResponse response)
            : socket_(socket), decoder_(std::move(response.cipher)), output_(std::move(response.payload)) {
            auto const n = response.unread.size();
            if (n == 0) return;
            if (n <= small_input_.size()) {
                std::memcpy(small_input_.data(), response.unread.data(), n);
                input_len_ = n;
            } else if (n <= PooledBuffer64K::size && large_input_.acquire()) {
                std::memcpy(large_input_.get(), response.unread.data(), n);
                input_len_ = n;
            } else {
                extra_input_ = std::move(response.unread);
                input_len_ = extra_input_.size();
                using_extra_ = true;
            }
        }
        FrameReader(FrameReader const&)=delete;
        auto operator=(FrameReader const&) -> FrameReader& = delete;
        auto cancel() noexcept -> void { active_=false; socket_.cancel(); }
        // Returns zero only for clean EOF. Errors and exceptions cancel the socket.
        auto read(std::span<std::uint8_t> output, std::chrono::steady_clock::time_point deadline,bool preserve_timeout=false)
            -> capy::task<std::expected<std::size_t,ReadError>> {
            if (!active_ || reading_ || output.empty()) co_return std::unexpected(ReadError::state);
            reading_=true;
            struct Guard { FrameReader& self; bool done=false; ~Guard() { self.reading_=false; if (!done) self.cancel(); } } guard{*this};
            bool const bounded = deadline != std::chrono::steady_clock::time_point::max();
            for (;;) {
                if (!active_) co_return std::unexpected(ReadError::state);
                if (bounded && std::chrono::steady_clock::now()>=deadline) {guard.done=preserve_timeout;co_return std::unexpected(ReadError::timeout);}
                if (output_offset_<output_.size()) {
                    auto n=std::min(output.size(),output_.size()-output_offset_);
                    std::copy_n(output_.data()+output_offset_,n,output.data()); output_offset_+=n;
                    if (output_offset_==output_.size()) { output_.clear(); output_offset_=0; }
                    guard.done=true; co_return n;
                }
                if (pending_error_) {
                    auto const err = *pending_error_;
                    pending_error_.reset();
                    co_return std::unexpected(err);
                }
                if (eof_) { guard.done=true; co_return 0; }
                if (input_offset_<input_len_) {
                    auto const* in_ptr = input_data();
                    std::size_t written = 0;
                    while (input_offset_<input_len_ && written<output.size()) {
                        auto step=decoder_.feed_span(
                            std::span<std::uint8_t const>(in_ptr+input_offset_, input_len_-input_offset_),
                            output.subspan(written), output_);
                        if (!step) {
                            auto const err = step.error()==FrameError::authentication ? ReadError::authentication : ReadError::transport;
                            output_.clear(); output_offset_ = 0;
                            if (written > 0) { pending_error_ = err; guard.done = true; co_return written; }
                            co_return std::unexpected(err);
                        }
                        input_offset_+=step->consumed;
                        if (step->has_overflow) {
                            output_offset_=0;
                            if (written > 0) { guard.done=true; co_return written; }
                            break;
                        }
                        written += step->direct_written;
                        if (!step->has_frame) break;
                    }
                    if (written > 0) { guard.done=true; co_return written; }
                    if (output_offset_<output_.size()) continue;
                    if (input_offset_<input_len_) continue;
                }
                input_offset_=0; input_len_=0;
                if (using_extra_) { std::vector<std::uint8_t>{}.swap(extra_input_); using_extra_=false; }
                if (!large_input_ && total_read_ >= 4096) (void)large_input_.acquire();
                auto* buf = input_data();
                auto const cap = input_capacity();
#if !defined(_WIN32)
                if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
                    if (!bounded) {
                        int const fd = static_cast<int>(socket_.native_handle());
                        if (fd >= 0) {
                            ssize_t r = -1;
                            do { r = ::recv(fd, buf, cap, MSG_DONTWAIT); } while (r < 0 && errno == EINTR);
                            if (r > 0) {
                                input_len_ = static_cast<std::size_t>(r);
                                total_read_ += input_len_;
                                continue;
                            }
                            if (r == 0) {
                                if (!decoder_.finish()) co_return std::unexpected(ReadError::truncated);
                                eof_ = true; continue;
                            }
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                                co_return std::unexpected(ReadError::transport);
                        }
                    }
                }
#endif
                std::error_code error;
                std::size_t n=0;
                if (bounded) {
                    auto operation=socket_.read_some(capy::mutable_buffer(buf,cap));
                    std::tie(error,n)=co_await corosio::timeout(std::move(operation),deadline);
                    if(n>cap)co_return std::unexpected(ReadError::transport);
                    if (capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline)) {
                        if(preserve_timeout && !error && n) {input_len_=n;input_offset_=0;}
                        else {input_len_=0;input_offset_=0;}
                        guard.done=preserve_timeout;co_return std::unexpected(ReadError::timeout);
                    }
                } else {
                    std::tie(error,n)=co_await socket_.read_some(capy::mutable_buffer(buf,cap));
                }
                if (!active_) co_return std::unexpected(ReadError::state);
                if (capy::is_eof(error) || (!error && !n)) {
                    input_len_=0; input_offset_=0;
                    if (!decoder_.finish()) co_return std::unexpected(ReadError::truncated);
                    eof_=true; continue;
                }
                if (error || n>cap) co_return std::unexpected(ReadError::transport);
                input_len_=n; input_offset_=0; total_read_+=n;
            }
        }
    };

}
