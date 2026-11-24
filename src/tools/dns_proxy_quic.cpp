module cli.dns_proxy_quic;
import std;
import proxy.v4;
import dns.corosio_query;
import dns.quic_query;
import net.packet_stream_socket;
import relay;
import relay.session_quota;

namespace cli {
    namespace {
        using dns::QuicDnsDatagram;
        namespace capy=dns::detail::dns_capy;
        namespace io=dns::detail::dns_io;

        class ProxyDatagram {
            using Clock=std::chrono::steady_clock;
            relay::Session session_;
            std::unique_ptr<relay::PacketTunnel> tunnel_;
            net::PacketStreamSocket<relay::PacketTunnel> socket_;
            struct CloseOnStop {
                ProxyDatagram& owner;
                auto operator()() const noexcept -> void { owner.close(); }
            };
            std::stop_callback<CloseOnStop> stop_;

        public:
            ProxyDatagram(io::io_context& context,relay::Server& server,
                relay::SessionQuota::Lease lease,std::size_t outbound,std::shared_ptr<dns::detail::TransportSnapshot const> snapshot)
                :session_(context),socket_(context),stop_(session_.stop.get_token(),CloseOnStop{*this}) {
                server.attach_session(session_,std::move(lease));
                session_.dns_transport_override=std::move(snapshot);
                // The DNS connection owns its idle timer.
                session_.relaying=true;
                tunnel_=server.open_packet_tunnel(session_,outbound);
            }
            auto prepare(io::endpoint peer,Clock::time_point deadline) -> capy::task<bool> {
                if (!tunnel_ || session_.closed) co_return false;
                auto connect_by=tunnel_->connection_deadline(deadline);
                if (co_await tunnel_->connect_until(net::packet_peer_address(peer),connect_by)!=relay::PacketConnectResult::connected)
                    co_return false;
                if (session_.closed || !socket_.attach(*tunnel_,tunnel_->transport(),peer)) co_return false;
                co_return co_await socket_.prepare(connect_by);
            }
            auto local_endpoint() const noexcept -> io::endpoint {return socket_.local_endpoint();}
            auto close() noexcept -> void {
                socket_.close();
                if (tunnel_) tunnel_->cancel();
            }
            auto send_to(capy::const_buffer buffer,io::endpoint peer) -> capy::task<capy::results<std::size_t>> {
                session_.touched=Clock::now();
                return socket_.send_to(buffer,peer);
            }
            auto recv_from(capy::mutable_buffer buffer,io::endpoint& source) -> capy::task<capy::results<std::size_t>> {
                return socket_.recv_from(buffer,source);
            }
        };
    }
    auto make_proxy_quic_datagram(std::size_t outbound,dns::detail::TransportSnapshotRef snapshot) -> dns::QuicDnsDatagramFactory {
        return [outbound,snapshot=std::move(snapshot)](io::io_context& context) -> QuicDnsDatagram {
            auto transport=snapshot ? snapshot->lock() : nullptr;
            if (snapshot && !transport) return {};
            auto* server=relay::Server::from_context(context);
            if (!server) return {};
            auto lease=server->acquire_session();
            if (!lease) return {};
            return pro::make_proxy<dns::QuicDnsDatagramFacade,ProxyDatagram>(context,*server,std::move(*lease),outbound,std::move(transport));
        };
    }

    auto prepare_proxy_quic(std::string_view server_name,std::string_view ca_file,std::size_t outbound,bool early_data,dns::detail::TransportSnapshotRef snapshot)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        return dns::make_quic_query(server_name,ca_file,{},std::chrono::seconds(5),early_data,make_proxy_quic_datagram(outbound,std::move(snapshot)));
    }
}
