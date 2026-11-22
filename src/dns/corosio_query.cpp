module dns.corosio_query;
import std;
import net.tcp_connect;
import net.udp_connect;
import dns.input_budget;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns::detail {
    auto prepare_dns_udp(dns_io::udp_socket& socket,dns_io::endpoint const& endpoint,
        platform::SocketBinding const& binding) -> std::error_code {
        return net::prepare_udp_socket(socket,endpoint,&binding);
    }

    auto prepare_dns_tcp(dns_io::tcp_socket& socket,dns_io::endpoint const& endpoint,
        platform::SocketBinding const& binding) -> std::error_code {
        return net::prepare_tcp_socket(socket,endpoint,platform::TcpSocketOptions{.binding=binding});
    }

    auto make_bound_query(platform::SocketBinding binding,bool tcp_only) -> ProtectedQuery {
        return [binding=std::move(binding),tcp_only](dns_io::io_context& context,dns_io::endpoint endpoint,
            QueryMessage const& query,std::uint16_t id,std::chrono::steady_clock::time_point deadline,
            InputBudget& budget,std::stop_token stop) -> dns_capy::task<std::expected<Response,UdpError>> {
            FallbackQuery operation(context,tcp_only,&budget,nullptr,&binding);
            std::stop_callback cancellation(stop,[&]() noexcept {operation.cancel();});
            co_return co_await operation.query_borrowed(endpoint,query,deadline,id);
        };
    }
}
