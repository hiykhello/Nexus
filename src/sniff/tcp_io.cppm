export module sniff.tcp_io;
import std;
import sniff.tcp;
import capy;
import corosio;

export namespace sniff {
    enum class TcpReadStop { classified,deadline,eof,canceled,io_error };
    struct TcpReadResult { TcpReadStop stop;TcpStep sniff;std::error_code error{}; };
    // The socket and sniffer outlive the task. The caller owns the only read
    // operation and has already fed any prefetched bytes, retaining any suffix
    // not accepted by feed(). Timeout cancels the
    // individual read, not the socket or its independent write direction.
    // All bytes returned by the socket are retained before reporting any
    // simultaneous error; the caller decides how to replay or abandon them.
    template<class Socket>
    auto read_tcp_sniff(Socket& socket,TcpSniffer& sniffer,std::chrono::steady_clock::time_point deadline)
        -> capy::task<TcpReadResult> {
        std::array<std::uint8_t,4096> input{};
        for (;;) {
            auto state=sniffer.limit();
            if(state.status!=TcpStatus::need_more)co_return {TcpReadStop::classified,state,{}};
            if(std::chrono::steady_clock::now()>=deadline)co_return {TcpReadStop::deadline,state,{}};
            auto amount=std::min(input.size(),sniffer.remaining());
            auto operation=socket.read_some(capy::mutable_buffer(input.data(),amount));
            auto [error,size]=co_await corosio::timeout(std::move(operation),deadline);
            if(size>amount)co_return {TcpReadStop::io_error,sniffer.current(),std::make_error_code(std::errc::protocol_error)};
            if(size) {
                auto accepted=sniffer.feed(std::span(input).first(size));
                if(accepted.consumed!=size)co_return {TcpReadStop::io_error,accepted,std::make_error_code(std::errc::protocol_error)};
            }
            state=sniffer.current();
            if(error) {
                if(capy::is_timeout(error))co_return {TcpReadStop::deadline,state,error};
                if(error==capy::cond::canceled)co_return {TcpReadStop::canceled,state,error};
                if(capy::is_eof(error))co_return {TcpReadStop::eof,sniffer.finish(),error};
                co_return {TcpReadStop::io_error,state,error};
            }
            if(!size)co_return {TcpReadStop::io_error,state,std::make_error_code(std::errc::io_error)};
        }
    }
}
