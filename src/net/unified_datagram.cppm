module;
#include <proxy/proxy_macros.h>

export module net.unified_datagram;
import std;
import proxy.v4;
import net.datagram_frame;
import net.packet_stream_socket;
import net.udp_connect;
import platform.socket_options;
import capy;
import corosio;

export namespace net {
    PRO_DEF_MEM_DISPATCH(PacketLowerSend, send);
    PRO_DEF_MEM_DISPATCH(PacketLowerRead, read);
    PRO_DEF_MEM_DISPATCH(PacketLowerCancel, cancel);

    struct PacketLowerFacade : pro::facade_builder
        ::add_convention<PacketLowerSend, capy::task<bool>(std::span<std::uint8_t const>)>
        ::add_convention<PacketLowerRead, capy::task<std::expected<std::size_t, std::string>>(std::span<std::uint8_t>)>
        ::add_convention<PacketLowerCancel, void() noexcept>
        ::build {};

    struct ErasedPacketLower {
        pro::proxy_view<PacketLowerFacade> view;

        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            return view->send(bytes);
        }
        auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
            return view->read(bytes);
        }
        auto cancel() noexcept -> void {
            if (view) view->cancel();
        }
    };

    // Unified datagram socket supporting physical UDP sockets and packet-tunnel detours.
    // The 16 KiB PacketStreamSocket input buffer stays unallocated unless attach_detour is called.
    class UnifiedDatagramSocket {
        corosio::io_context& context_;
        corosio::udp_socket udp_;
        ErasedPacketLower erased_{};
        std::optional<PacketStreamSocket<ErasedPacketLower>> layered_;

    public:
        explicit UnifiedDatagramSocket(corosio::io_context& ctx) : context_(ctx), udp_(ctx) {}
        UnifiedDatagramSocket(UnifiedDatagramSocket const&) = delete;
        auto operator=(UnifiedDatagramSocket const&) -> UnifiedDatagramSocket& = delete;
        UnifiedDatagramSocket(UnifiedDatagramSocket&&) = delete;
        auto operator=(UnifiedDatagramSocket&&) -> UnifiedDatagramSocket& = delete;

        [[nodiscard]] auto is_layered() const noexcept -> bool { return layered_.has_value(); }

        auto prepare_physical(corosio::endpoint peer, platform::SocketBinding const* binding,
                              platform::SocketDeadline deadline) -> std::error_code {
            return net::prepare_udp_socket(udp_, peer, binding, deadline);
        }

        template<class Lower>
        auto attach_detour(Lower& lower, PacketTransport transport, corosio::endpoint peer) -> bool {
            erased_.view = pro::make_proxy_view<PacketLowerFacade>(lower);
            layered_.emplace(context_);
            if (!layered_->attach(erased_, transport, peer)) {
                layered_.reset();
                erased_.view = {};
                return false;
            }
            return true;
        }

        auto prepare_detour(std::chrono::steady_clock::time_point deadline) -> capy::task<bool> {
            if (!layered_) co_return false;
            co_return co_await layered_->prepare(deadline);
        }

        [[nodiscard]] auto local_endpoint() const -> corosio::endpoint {
            return layered_ ? layered_->local_endpoint() : udp_.local_endpoint();
        }

        auto close() noexcept -> void {
            if (layered_) layered_->close();
            udp_.close();
        }

        auto recv_from(capy::mutable_buffer buf, corosio::endpoint& from) -> capy::task<capy::results<std::size_t>> {
            if (layered_) co_return co_await layered_->recv_from(buf, from);
            co_return co_await udp_.recv_from(buf, from);
        }

        auto send_to(capy::const_buffer buf, corosio::endpoint to) -> capy::task<capy::results<std::size_t>> {
            if (layered_) co_return co_await layered_->send_to(buf, to);
            co_return co_await udp_.send_to(buf, to);
        }
    };
}
