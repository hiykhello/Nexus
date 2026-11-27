module relay;
import std;

namespace relay {
    auto Server::add_hysteria2(std::string_view host,std::uint16_t port,std::string_view password_file,std::string_view server_name,
        std::string_view ca_file,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,
        TcpSocketOptions options,std::uint32_t handshake_ms,std::uint32_t idle_ms,std::size_t native_bytes,bool udp,
        std::optional<std::string_view> salamander_file,std::optional<std::size_t> max_udp_payload_size,bool disable_path_mtu_discovery,std::uint64_t send_bps,std::uint64_t receive_bps,bool disable_compensation,TlsFingerprint fingerprint,bool lazy_tcp_response,QuicEchOptions const& ech,quic::ReceiveWindows windows,std::span<std::array<std::uint8_t,32> const> pins,
        std::span<config::PortRange const> port_ranges,std::uint32_t hop_interval_ms,std::uint32_t hop_interval_max_ms) -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_HY2_CLIENT
        if (outbounds.size()>=max_tunnel_outbounds) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_hysteria2_factory(host,port,password_file,server_name,ca_file,exchange,bootstrap,timeout_ms,options,handshake_ms,idle_ms,native_bytes,udp,salamander_file,max_udp_payload_size,disable_path_mtu_discovery,send_bps,receive_bps,disable_compensation,fingerprint,lazy_tcp_response,ech,dns_routing.has_value(),windows,pins,port_ranges,hop_interval_ms,hop_interval_max_ms);
        if (!factory) return std::unexpected(factory.error());
        auto index=outbounds.size()+2;outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host;(void)port;(void)password_file;(void)server_name;(void)ca_file;(void)exchange;(void)bootstrap;(void)timeout_ms;
        (void)options;(void)handshake_ms;(void)idle_ms;(void)native_bytes;(void)udp;(void)salamander_file;(void)max_udp_payload_size;(void)disable_path_mtu_discovery;(void)send_bps;(void)receive_bps;(void)disable_compensation;(void)fingerprint;(void)lazy_tcp_response;(void)ech;(void)windows;(void)pins;(void)port_ranges;(void)hop_interval_ms;(void)hop_interval_max_ms;
        return std::unexpected("Hysteria2 outbound is not available in this build");
#endif
    }
}
