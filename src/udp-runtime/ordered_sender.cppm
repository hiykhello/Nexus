export module ss_udp.ordered_sender;
import std;
import rules;
import relay;
import ss_udp.listener;

export namespace relay::udp_runtime {
    auto make_ordered_udp_sender(Server&,std::shared_ptr<rules::RouteProgram const>,std::size_t,bool,std::chrono::milliseconds)
        -> shadowsocks::detail::UdpOrderedRouting;
}
