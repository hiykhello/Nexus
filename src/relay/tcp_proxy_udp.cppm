// SOCKS5 UDP relay helper shared by TCP proxy outbound tunnels.
module relay:tcp_proxy_udp;
import std;
import capy;
import corosio;
import net.datagram_frame;
import net.udp_connect;
import platform.socket_options;
import socks5;
import :types;

namespace relay::tcp_proxy_detail {
    class SocksUdpRelay {
        corosio::udp_socket socket_;
        corosio::endpoint relay_;
        std::vector<std::uint8_t> response_;
        std::size_t sent_ = 0;
        bool stopped_ = false;

    public:
        explicit SocksUdpRelay(corosio::io_context& context) : socket_(context) {}

        auto start(socks5::UdpPeer const& address, corosio::endpoint control,
            platform::SocketBinding const& binding, Clock::time_point deadline) -> bool {
            if (address.address_type == 4)
                relay_ = {corosio::ipv6_address(address.address), address.port};
            else {
                corosio::ipv4_address::bytes_type bytes{};
                std::copy_n(address.address.begin(), bytes.size(), bytes.begin());
                relay_ = {corosio::ipv4_address(bytes), address.port};
            }
            if (relay_.address().is_unspecified()) relay_ = {control.address(), relay_.port()};
            if (!valid_destination(relay_) || relay_.is_v6() != control.is_v6()) return false;
            return !net::prepare_udp_socket(socket_, relay_, &binding, deadline);
        }

        auto stop() noexcept -> void {
            stopped_ = true;
            socket_.close();
        }

        template<class Transport>
        auto monitor(std::shared_ptr<Transport> transport) -> capy::task<> {
            std::array<std::uint8_t, 1> unexpected;
            (void)co_await transport->stream->read(unexpected);
            stop();
        }

        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            auto packet = net::parse_datagram({}, {}, bytes);
            if (stopped_ || packet.status != net::DatagramStatus::accepted || packet.consumed != bytes.size())
                co_return false;
            auto const& target = packet.destination;
            socks5::UdpDatagram datagram;
            datagram.address_type = target.family == net::ProxyAddressFamily::ipv4 ? 1 :
                target.family == net::ProxyAddressFamily::ipv6 ? 4 : 3;
            datagram.address = target.bytes;
            datagram.address_length = target.length;
            datagram.port = target.port;
            datagram.data = packet.payload;
            auto wire = socks5::encode_udp_datagram(datagram);
            if (!wire || wire->size() > 65507) co_return false;
            auto [error, size] = co_await socket_.send_to(capy::const_buffer(wire->data(), wire->size()), relay_);
            co_return !error && size == wire->size() && !stopped_;
        }

        auto read(std::span<std::uint8_t> output) -> capy::task<std::expected<std::size_t, std::string>> {
            if (output.empty()) co_return std::size_t{};
            std::array<std::uint8_t, 65536> wire;
            while (!stopped_ && sent_ == response_.size()) {
                corosio::endpoint source;
                auto [error, count] = co_await socket_.recv_from(capy::mutable_buffer(wire.data(), wire.size()), source);
                if (error || stopped_) co_return std::unexpected("SOCKS5 UDP relay closed");
                if (source != relay_) continue;
                auto packet = socks5::parse_udp_datagram(std::span(wire).first(count));
                if (!packet || !packet->port) continue;
                net::ProxyAddress address;
                address.family = packet->address_type == 1 ? net::ProxyAddressFamily::ipv4 :
                    packet->address_type == 4 ? net::ProxyAddressFamily::ipv6 : net::ProxyAddressFamily::domain;
                address.bytes = packet->address;
                address.length = packet->address_length;
                address.port = packet->port;
                auto frame = net::encode_datagram({}, address, packet->data);
                if (!frame) continue;
                response_ = std::move(*frame);
                sent_ = 0;
            }
            if (stopped_) co_return std::unexpected("SOCKS5 UDP relay closed");
            auto count = std::min(output.size(), response_.size() - sent_);
            std::copy_n(response_.begin() + sent_, count, output.begin());
            sent_ += count;
            co_return count;
        }
    };
}
