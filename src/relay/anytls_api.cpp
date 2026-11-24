module relay;
import std;

namespace relay {
    auto Server::add_anytls(std::string_view host,std::uint16_t port,std::string_view password_file,
        std::string_view server_name,std::string_view ca_file,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,
        std::uint32_t timeout_ms,TcpSocketOptions options,AnyTlsOptions pool,bool fast_open,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,std::span<std::array<std::uint8_t,32> const> pins,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc) -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_ANYTLS
        if (outbounds.size()>=256) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_anytls_factory(host,port,password_file,server_name,ca_file,exchange,bootstrap,timeout_ms,options,pool,fast_open,fingerprint,record_size_limit,pins,std::move(transport),std::move(grpc));
        if (!factory) return std::unexpected(factory.error());
        auto index=outbounds.size()+2; outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)password_file; (void)server_name; (void)ca_file; (void)exchange; (void)bootstrap; (void)timeout_ms; (void)options; (void)pool; (void)fast_open; (void)fingerprint; (void)record_size_limit; (void)pins; (void)transport; (void)grpc;
        return std::unexpected("AnyTLS outbound is not available in this build");
#endif
    }
    auto Server::prepare_anytls_inbound(std::string_view certificate,std::string_view key,std::span<std::string const> passwords,
        std::span<std::string const> names,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc) -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("stop the server before changing authentication");
#ifdef NEXUS_ENABLE_ANYTLS
        auto prepared=make_anytls_inbound_factory(certificate,key,passwords,names,std::move(transport),std::move(grpc));
        if (!prepared) return std::unexpected(prepared.error());
        anytls_inbound=std::move(*prepared); return {};
#else
        (void)certificate; (void)key; (void)passwords; (void)names; (void)transport; (void)grpc;
        return std::unexpected("AnyTLS inbound is not available in this build");
#endif
    }
}
