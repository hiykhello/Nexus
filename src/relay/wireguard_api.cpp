module relay;
import std;
import proxy.v4;

namespace relay {
    auto Server::add_wireguard(std::string_view host,std::uint16_t port,std::string_view private_key_file,
        std::string_view peer_public_key_file,std::optional<std::string_view> preshared_key_file,
        bool has_v4,std::array<std::uint8_t,4> local_v4,bool has_v6,std::array<std::uint8_t,16> local_v6,
        bool warp,std::array<std::uint8_t,3> reserved,std::uint16_t mtu,std::uint16_t keepalive_s,
        std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,TcpSocketOptions options) -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_WIREGUARD
        if (outbounds.size()>=256) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_wireguard_factory(host,port,private_key_file,peer_public_key_file,preshared_key_file,
            has_v4,local_v4,has_v6,local_v6,warp,reserved,mtu,keepalive_s,bootstrap,timeout_ms,options);
        if (!factory) return std::unexpected(factory.error());
        auto index=outbounds.size()+2; outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)private_key_file; (void)peer_public_key_file; (void)preshared_key_file;
        (void)has_v4; (void)local_v4; (void)has_v6; (void)local_v6; (void)warp; (void)reserved;
        (void)mtu; (void)keepalive_s; (void)bootstrap; (void)timeout_ms; (void)options;
        return std::unexpected("WireGuard outbound is not available in this build");
#endif
    }
}
