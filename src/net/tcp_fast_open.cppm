module;
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>

export module net.tcp_fast_open;
import std;
import net.tcp_connect;
import capy;
import corosio;

export namespace net {
    // The accepted byte count is meaningful even on error: once the kernel
    // accepts data, retrying it on another connection can duplicate it.
    struct FastOpenResult {std::error_code error;std::size_t accepted=0;bool unsupported=false,preparation_failed=false;};

    // Single candidate. The caller retains socket and payload until return,
    // closes the socket on error, and sends only the unaccepted suffix on
    // success. An empty first write performs an ordinary connection.
    [[nodiscard]] inline auto tcp_fast_open_first_write(corosio::tcp_socket& socket,
        corosio::endpoint endpoint,std::span<std::uint8_t const> payload,
        std::chrono::steady_clock::time_point deadline,platform::TcpSocketOptions const& options={})
        -> capy::task<FastOpenResult> {
        using Clock=std::chrono::steady_clock;
        auto stop=co_await capy::this_coro::stop_token;
        if(stop.stop_requested())co_return FastOpenResult{std::make_error_code(std::errc::operation_canceled)};
        if(Clock::now()>=deadline)co_return FastOpenResult{std::make_error_code(std::errc::timed_out)};
        if(socket.is_open())co_return FastOpenResult{std::make_error_code(std::errc::already_connected)};
        if(auto error=prepare_tcp_socket(socket,endpoint,options,deadline))co_return FastOpenResult{error,0,false,true};
        if(!socket.is_open())if(auto error=socket.open(endpoint.address().family()))co_return FastOpenResult{error,0,false,true};
        if(payload.empty()) {
            auto [error]=co_await corosio::timeout(socket.connect(endpoint),deadline);
            if(!error && Clock::now()>=deadline)error=std::make_error_code(std::errc::timed_out);
            co_return FastOpenResult{error};
        }
        sockaddr_storage address{};socklen_t length;
        if(endpoint.is_v4()) {
            auto* value=reinterpret_cast<sockaddr_in*>(&address);value->sin_family=AF_INET;value->sin_port=htons(endpoint.port());
            auto bytes=endpoint.address().to_v4().to_bytes();std::memcpy(&value->sin_addr,bytes.data(),bytes.size());length=sizeof(*value);
        } else {
            auto* value=reinterpret_cast<sockaddr_in6*>(&address);value->sin6_family=AF_INET6;value->sin6_port=htons(endpoint.port());
            auto ip=endpoint.address().to_v6();auto bytes=ip.to_bytes();std::memcpy(&value->sin6_addr,bytes.data(),bytes.size());
            value->sin6_scope_id=ip.scope_id();length=sizeof(*value);
        }
        if(stop.stop_requested())co_return FastOpenResult{std::make_error_code(std::errc::operation_canceled)};
        if(Clock::now()>=deadline)co_return FastOpenResult{std::make_error_code(std::errc::timed_out)};
#if defined(__linux__) && defined(MSG_FASTOPEN)
        auto count=::sendto(socket.native_handle(),payload.data(),payload.size(),MSG_FASTOPEN|MSG_DONTWAIT|MSG_NOSIGNAL,
                            reinterpret_cast<sockaddr const*>(&address),length);
        std::size_t accepted=0;
        if(count>=0)accepted=static_cast<std::size_t>(count);
        else if(errno!=EINPROGRESS) {
            auto error=errno;
            co_return FastOpenResult{{error,std::generic_category()},0,error==EPIPE || error==EOPNOTSUPP};
        }
        auto [wait_error]=co_await corosio::timeout(socket.wait(corosio::wait_type::write),deadline);
        if(wait_error)co_return FastOpenResult{wait_error,accepted};
        if(Clock::now()>=deadline)co_return FastOpenResult{std::make_error_code(std::errc::timed_out),accepted};
        int socket_error=0;socklen_t error_length=sizeof(socket_error);
        if(::getsockopt(socket.native_handle(),SOL_SOCKET,SO_ERROR,&socket_error,&error_length)<0)
            co_return FastOpenResult{{errno,std::generic_category()},accepted};
        if(error_length!=sizeof(socket_error))co_return FastOpenResult{std::make_error_code(std::errc::protocol_error),accepted};
        co_return FastOpenResult{{socket_error,std::generic_category()},accepted};
#else
        (void)address; (void)length;
        co_return FastOpenResult{std::make_error_code(std::errc::operation_not_supported),0,true};
#endif
    }

    struct FastOpenCandidatesResult {
        FastOpenResult result;
        corosio::endpoint endpoint;
        bool preparation_failed=false;
        std::uint32_t interface_index=0;
    };
    // Retry a new candidate only if the previous socket accepted no data.
    // Unsupported TFO may use ordinary connect on that same candidate; the
    // caller remains responsible for the complete first-write suffix.
    template<std::ranges::input_range Range,class Condition>
    [[nodiscard]] auto tcp_fast_open_candidates(corosio::tcp_socket& socket,Range endpoints,Condition condition,
        std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point deadline,
        platform::TcpSocketOptions const& options={}) -> capy::task<FastOpenCandidatesResult> {
        std::error_code last;
        for(auto&& item:endpoints) {
            corosio::endpoint endpoint=item;
            if(!condition(std::as_const(last),std::as_const(endpoint)))continue;
            if(std::chrono::steady_clock::now()>=deadline)
                co_return FastOpenCandidatesResult{{std::make_error_code(std::errc::timed_out)}, {}};
            auto interfaces=detail::tcp_interfaces(options,endpoint.is_v6());
            if (interfaces.indices.empty()) {
                last=std::make_error_code(std::errc::network_unreachable);
                continue;
            }
            for (std::size_t index=0;index<interfaces.indices.size();++index) {
                if(socket.is_open())socket.close();
                auto stop=detail::tcp_attempt_deadline(deadline,interfaces,index);
                platform::TcpSocketOptions selected;
                auto const& settings=detail::tcp_interface_options(options,interfaces.indices[index],selected);
                auto result=co_await tcp_fast_open_first_write(socket,endpoint,payload,stop,settings);
                if(result.unsupported) {
                    socket.close();
                    result=co_await tcp_fast_open_first_write(socket,endpoint,{},stop,settings);
                }
                if(!result.error)co_return FastOpenCandidatesResult{result,endpoint,false,settings.binding.interface_index};
                socket.close();
                if (result.preparation_failed && options.binding.network &&
                    platform::network::retry_interface_error(result.error)) {
                    last=result.error;
                    continue;
                }
                if(result.preparation_failed || result.accepted || result.error==capy::cond::canceled ||
                    ((capy::is_timeout(result.error) || result.error==std::errc::timed_out) && stop==deadline))
                    co_return FastOpenCandidatesResult{result,endpoint,result.preparation_failed};
                last=result.error;
            }
        }
        if(!last)last=std::make_error_code(std::errc::no_such_device_or_address);
        co_return FastOpenCandidatesResult{{last},{}};
    }
}
