export module net.tcp_fast_open_stream;
import std;
import net.socket_stream;
import platform.socket_options;
import capy;
import corosio;

export namespace net {
    // Single executor, one reader and one writer. Owner retains this object
    // and input buffers until cancellation and all operations have drained.
    class FastOpenStream {
        using Clock=std::chrono::steady_clock;
        enum class State {idle,connecting,ready,failed};
        corosio::tcp_socket socket_;
        std::vector<corosio::endpoint> endpoints_;
        platform::TcpSocketOptions options_;
        Clock::time_point connect_deadline_;
        capy::async_event connected_;
        State state_=State::idle;
        std::error_code error_;
        std::uint32_t interface_index_=0;
        bool reading_=false,writing_=false,output_closed_=false;
        auto fail(std::error_code error) noexcept -> void;
        auto connect(std::span<std::uint8_t const> first,StreamDeadline deadline)
            -> capy::task<std::expected<std::size_t,std::error_code>>;
    public:
        FastOpenStream(corosio::io_context& context,std::vector<corosio::endpoint> endpoints,
            Clock::time_point deadline,platform::TcpSocketOptions options={});
        FastOpenStream(FastOpenStream const&)=delete;
        auto operator=(FastOpenStream const&) -> FastOpenStream& = delete;
        [[nodiscard]] auto remote_endpoint() const noexcept -> corosio::endpoint { return state_==State::ready ? endpoints_.front() : corosio::endpoint{}; }
        [[nodiscard]] auto interface_index() const noexcept -> std::uint32_t { return interface_index_; }
        auto cancel() noexcept -> void;
        auto read(std::span<std::uint8_t> output,StreamDeadline deadline={})
            -> capy::task<std::expected<std::size_t,std::error_code>>;
        auto send(std::span<std::uint8_t const> input,StreamDeadline deadline={}) -> capy::task<bool>;
        auto close_output(StreamDeadline deadline={}) -> capy::task<bool>;
    };
}
