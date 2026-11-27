module relay;
import std;
import proxy.v4;

namespace relay {
    auto Server::add_shadowtls(std::string_view host,std::uint16_t port,std::string_view password_file,
        std::string_view server_name,std::string_view ca_file,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,
        std::uint32_t timeout_ms,TcpSocketOptions options,TlsFingerprint fingerprint,bool strict_tls13,std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_SHADOWTLS
        if (outbounds.size()>=max_tunnel_outbounds) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_shadowtls_factory(host,port,password_file,server_name,ca_file,exchange,bootstrap,timeout_ms,options,fingerprint,strict_tls13,pins);
        if (!factory) return std::unexpected(factory.error());
        auto index=outbounds.size()+2; outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)password_file; (void)server_name; (void)ca_file; (void)exchange; (void)bootstrap;
        (void)timeout_ms; (void)options; (void)fingerprint; (void)strict_tls13; (void)pins;
        return std::unexpected("ShadowTLS outbound is not available in this build");
#endif
    }

    auto Server::prepare_shadowtls_inbound(std::string_view handshake_host,std::uint16_t handshake_port,
        std::string_view target_host,std::uint16_t target_port,std::span<std::string const> password_files,
        std::span<std::string const> names,bool strict_tls13,std::span<std::pair<std::string,config::FallbackTarget> const> handshake_for_server_name,std::string_view wildcard_sni) -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("stop the server before changing authentication");
#ifdef NEXUS_ENABLE_SHADOWTLS
        auto prepared=make_shadowtls_inbound_factory(handshake_host,handshake_port,target_host,target_port,password_files,names,strict_tls13,handshake_for_server_name,wildcard_sni);
        if (!prepared) return std::unexpected(prepared.error());
        shadowtls_inbound=std::move(*prepared);
        return {};
#else
        (void)handshake_host; (void)handshake_port; (void)target_host; (void)target_port;
        (void)password_files; (void)names; (void)strict_tls13; (void)handshake_for_server_name; (void)wildcard_sni;
        return std::unexpected("ShadowTLS inbound is not available in this build");
#endif
    }
}
