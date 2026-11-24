export module net.ordered_datagram;
import std;
export import functional;
import net.datagram_frame;
import net.udp_socket;
import sniff.udp_quic;
import capy;

export namespace net::stream_datagrams {
    struct OrderedSelection {
        std::size_t outbound;
        std::vector<UdpEndpoint> candidates;
        std::optional<std::size_t> rule{};
        std::optional<std::vector<std::uint8_t>> dns_reply;
    };
    using OrderedSniffer=functional::move_only_function<capy::task<sniff::QuicProbeResult>(
        std::chrono::steady_clock::time_point) const>;
    using OrderedRouter=functional::move_only_function<capy::task<std::optional<OrderedSelection>>(
        ProxyAddress const&,std::span<std::uint8_t const>,std::chrono::steady_clock::time_point received,
        std::chrono::steady_clock::time_point& deadline,OrderedSniffer const&) const>;
}
