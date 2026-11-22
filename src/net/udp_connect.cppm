export module net.udp_connect;
import std;
import platform.socket_options;
import nexus.thirdparty.corosio;

export namespace net {
    // One native socket per peer address family. A failed preparation leaves
    // the socket closed so another peer can be tried on the same owner.
    [[nodiscard]] auto prepare_udp_socket(nex::corosio::udp_socket& socket,
        nex::corosio::endpoint const& peer,platform::SocketBinding const* binding=nullptr,
        platform::SocketDeadline deadline=platform::SocketDeadline::max()) -> std::error_code {
        if (binding && !binding->valid()) return std::make_error_code(std::errc::invalid_argument);
        if (binding && !binding->network_namespace.empty()) {
            auto fd=platform::open_physical_socket(peer.is_v6(),true,false,binding->network_namespace);
            if (!fd) return fd.error();
            if (auto error=socket.assign(*fd)) { platform::close_unadopted_socket(*fd); return error; }
        } else if (auto error=socket.open(peer.address().family())) return error;
        auto port=binding ? binding->udp_bind_port.value_or(0) : std::uint16_t{};
        nex::corosio::endpoint local;
        if (peer.is_v6()) local={nex::corosio::ipv6_address(binding ?
            binding->inet6_bind_address.value_or(std::array<std::uint8_t,16>{}) : std::array<std::uint8_t,16>{}),port};
        else local={nex::corosio::ipv4_address(binding ?
            binding->inet4_bind_address.value_or(std::array<std::uint8_t,4>{}) : std::array<std::uint8_t,4>{}),port};
        auto error=binding ? platform::apply_socket_binding(socket.native_handle(),*binding,true,deadline) : std::error_code{};
        if (!error && std::chrono::steady_clock::now()>=deadline) error=std::make_error_code(std::errc::timed_out);
        if (!error) error=socket.bind(local);
        if (error) socket.close();
        return error;
    }
}
