module net.udp_dial;
import std;
import platform.socket_options;

namespace net {
    auto UdpDialSockets::split() const noexcept -> bool { return binding_ && binding_->separate_families(); }
    auto UdpDialSockets::prepare(std::size_t index,std::uint8_t family,platform::SocketBinding const* binding,
        platform::SocketDeadline deadline) -> std::expected<void,std::error_code> {
        auto& socket=sockets_[index];
        auto separate=split();
        // A wildcard bind must only reserve this family's port when another
        // socket in the same association will bind that port for the other family.
        auto ipv6_only=separate && family==6;
        auto result=binding ? socket.open(ipv6_only,binding->network_namespace) : socket.open(ipv6_only);
        if (result && binding) {
            if (auto error=platform::apply_socket_binding(socket.native_handle(),*binding,true,deadline)) result=std::unexpected(error);
            if (result && family==4 && binding->inet4_bind_address) {
                UdpEndpoint local{.family=4,.port=binding->udp_bind_port.value_or(0)};
                std::ranges::copy(*binding->inet4_bind_address,local.address.begin()); result=socket.bind(local);
            } else if (result && family==6 && binding->inet6_bind_address)
                result=socket.bind(UdpEndpoint{6,*binding->inet6_bind_address,binding->udp_bind_port.value_or(0)});
            else if (result && binding->udp_bind_port)
                result=socket.bind(UdpEndpoint{.family=separate ? family : std::uint8_t{6},.port=*binding->udp_bind_port});
        }
        if (!result) socket.discard();
        return result;
    }
    auto UdpDialSockets::send_first(std::size_t index,UdpEndpoint target,std::span<std::uint8_t const> bytes,
        platform::SocketDeadline deadline) -> std::expected<void,std::error_code> {
        if (binding_ && !binding_->valid()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto& socket=sockets_[index];
        auto send_ready=[&] {
            if (deadline!=platform::SocketDeadline::max() && std::chrono::steady_clock::now()>=deadline)
                return std::expected<void,std::error_code>(std::unexpected(std::make_error_code(std::errc::timed_out)));
            return socket.send(target,bytes);
        };
        if (binding_ && binding_->network) {
            auto interfaces=(*binding_->network)(target.family==6);
            auto selected=*binding_;
            selected.network.reset();
            auto error=std::make_error_code(std::errc::network_unreachable);
            for (auto candidate:interfaces.indices) {
                selected.interface_index=candidate;
                auto ready=prepare(index,target.family,&selected,deadline);
                auto sent=ready ? send_ready() : ready;
                if (sent) return sent;
                socket.discard();
                error=sent.error();
                if (!platform::network::retry_interface_error(error)) break;
            }
            return std::unexpected(error);
        }
        auto ready=prepare(index,target.family,binding_,deadline);
        if (!ready) {
            if (ready.error()!=std::errc::timed_out) { failure_=ready.error(); close(); }
            return ready;
        }
        return send_ready();
    }
    auto UdpDialSockets::send(UdpEndpoint target,std::span<std::uint8_t const> bytes,
        platform::SocketDeadline deadline) -> std::expected<void,std::error_code> {
        if (failure_) return std::unexpected(failure_);
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if ((target.family!=4 && target.family!=6) || !target.port ||
            (target.family==4 && std::ranges::any_of(std::span(target.address).subspan(4),[](auto byte) { return byte!=0; })))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (deadline!=platform::SocketDeadline::max() && std::chrono::steady_clock::now()>=deadline)
            return std::unexpected(std::make_error_code(std::errc::timed_out));
        auto index=split() && target.family==6 ? std::size_t{1} : 0;
        if (sockets_[index].native_handle()<0) return send_first(index,target,bytes,deadline);
        return sockets_[index].send(target,bytes);
    }
    auto UdpDialSockets::peek(std::span<std::uint8_t> bytes) -> std::expected<std::optional<UdpPacket>,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if (peeked_>=0) return sockets_[static_cast<std::size_t>(peeked_)].peek(bytes);
        auto count=split() ? std::size_t{2} : 1;
        for (std::size_t i=0;i<count;++i) {
            auto index=(next_+i)%count;
            auto packet=sockets_[index].peek(bytes);
            if (!packet) return std::unexpected(packet.error());
            if (*packet) { peeked_=static_cast<std::int8_t>(index); return packet; }
        }
        return std::optional<UdpPacket>{};
    }
    auto UdpDialSockets::consume() -> std::expected<std::optional<std::size_t>,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if (peeked_<0) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto index=static_cast<std::size_t>(peeked_);
        auto consumed=sockets_[index].consume();
        if (consumed) { peeked_=-1; next_=static_cast<std::uint8_t>(split() ? 1-index : 0); }
        return consumed;
    }
    auto UdpDialSockets::receive(std::span<std::uint8_t> bytes) -> std::expected<std::optional<UdpPacket>,std::error_code> {
        if (closed_) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if (peeked_>=0) {
            auto index=static_cast<std::size_t>(peeked_);
            auto packet=sockets_[index].receive(bytes);
            if (packet && *packet) { peeked_=-1; next_=static_cast<std::uint8_t>(split() ? 1-index : 0); }
            return packet;
        }
        auto count=split() ? std::size_t{2} : 1;
        for (std::size_t i=0;i<count;++i) {
            auto index=(next_+i)%count;
            auto packet=sockets_[index].receive(bytes);
            if (!packet) return std::unexpected(packet.error());
            if (*packet) { next_=static_cast<std::uint8_t>(split() ? 1-index : 0); return packet; }
        }
        return std::optional<UdpPacket>{};
    }
    auto UdpDialSockets::close() noexcept -> void {
        for (auto& socket:sockets_) socket.close();
        peeked_=-1; closed_=true;
    }
}
