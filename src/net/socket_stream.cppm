export module net.socket_stream;
import std;
import capy;
import corosio;

export namespace net {
    using StreamDeadline=std::optional<std::chrono::steady_clock::time_point>;
    namespace socket_stream_detail {
        inline auto expired(StreamDeadline deadline) noexcept -> bool { return deadline && std::chrono::steady_clock::now()>=*deadline; }
    }
    // Raw/layered socket bridge to the complete byte-stream contract. The
    // owner retains socket and buffers, allows one reader and one writer,
    // then cancels and drains all operations before destroying either.
    template<class Socket>
    class SocketByteStream {
        Socket& socket_;
    public:
        explicit SocketByteStream(Socket& socket) noexcept : socket_(socket) {}
        auto cancel() noexcept -> void { socket_.cancel(); }
        auto read(std::span<std::uint8_t> output,StreamDeadline deadline={})
            -> capy::task<std::expected<std::size_t,std::error_code>> {
            if (socket_stream_detail::expired(deadline)) { cancel(); co_return std::unexpected(std::make_error_code(std::errc::timed_out)); }
            if (output.empty()) co_return 0;
            auto operation=socket_.read_some(capy::mutable_buffer(output.data(),output.size()));
            auto [error,size]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (capy::is_timeout(error) || socket_stream_detail::expired(deadline)) {
                cancel(); co_return std::unexpected(std::make_error_code(std::errc::timed_out));
            }
            if (capy::is_eof(error)) co_return 0;
            if (error || size>output.size()) { cancel(); co_return std::unexpected(error ? error : std::make_error_code(std::errc::protocol_error)); }
            co_return size;
        }
        auto send(std::span<std::uint8_t const> input,StreamDeadline deadline={}) -> capy::task<bool> {
            if (socket_stream_detail::expired(deadline)) { cancel(); co_return false; }
            while (!input.empty()) {
                auto operation=socket_.write_some(capy::const_buffer(input.data(),input.size()));
                auto [error,size]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                if (error || !size || size>input.size() || socket_stream_detail::expired(deadline)) { cancel(); co_return false; }
                input=input.subspan(size);
            }
            co_return true;
        }
        auto close_output(StreamDeadline deadline={}) -> capy::task<bool> {
            if (socket_stream_detail::expired(deadline)) { cancel(); co_return false; }
            if constexpr (requires { socket_.close_output_some(); }) {
                auto operation=socket_.close_output_some();
                auto [error,size]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                (void)size;
                if (error || socket_stream_detail::expired(deadline)) { cancel(); co_return false; }
                co_return true;
            } else {
                auto error=socket_.shutdown(corosio::shutdown_send);
                if (error) { cancel(); co_return false; }
                co_return true;
            }
        }
    };
}
