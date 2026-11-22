module proxy;
import std;
import proxy.v4;

namespace proxy {
    auto Server::add_masque(std::string_view host,std::uint16_t port,std::string_view authority,std::string_view bearer_file,
        std::string_view server_name,std::string_view ca_file,TlsKeyExchange exchange,TlsFingerprint fingerprint,
        std::uint32_t handshake_ms,std::uint32_t idle_ms,std::size_t native_bytes,std::optional<std::size_t> bootstrap,
        std::uint32_t timeout_ms,TcpSocketOptions options,MasqueIpOptions ip,QuicEchOptions const& ech,std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_MASQUE_OUTBOUND
        if (outbounds.size()>=16) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_masque_factory(host,port,authority,bearer_file,server_name,ca_file,exchange,fingerprint,handshake_ms,idle_ms,native_bytes,bootstrap,timeout_ms,options,std::move(ip),ech,dns_routing.has_value(),pins);
        if (!factory) return std::unexpected(factory.error());
        auto index=outbounds.size()+2; outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)authority; (void)bearer_file; (void)server_name; (void)ca_file;
        (void)exchange; (void)fingerprint; (void)handshake_ms; (void)idle_ms; (void)native_bytes;
        (void)bootstrap; (void)timeout_ms; (void)options; (void)ip; (void)ech; (void)pins;
        return std::unexpected("MASQUE outbound is not available in this build");
#endif
    }
}
