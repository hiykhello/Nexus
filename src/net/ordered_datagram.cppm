export module net.ordered_datagram;
import std;
export import nexus.compat;
import net.datagram_frame;
import net.udp_socket;
import sniff.udp_quic;
import nexus.thirdparty.capy;

export namespace net::stream_datagrams {
    struct OrderedSelection {
        std::size_t outbound;
        std::vector<UdpEndpoint> candidates;
        std::optional<std::size_t> rule{};
        std::optional<std::vector<std::uint8_t>> dns_reply;
    };
    using OrderedSniffer=nexus::move_only_function<nex::capy::task<sniff::QuicProbeResult>(
        std::chrono::steady_clock::time_point) const>;
    using OrderedRouter=nexus::move_only_function<nex::capy::task<std::optional<OrderedSelection>>(
        ProxyAddress const&,std::span<std::uint8_t const>,std::chrono::steady_clock::time_point received,
        std::chrono::steady_clock::time_point& deadline,OrderedSniffer const&) const>;
}
