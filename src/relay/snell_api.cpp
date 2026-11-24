module relay;
import std;
namespace relay {
#ifndef NEXUS_ENABLE_SNELL
    auto create_snell_replay_registry() -> std::shared_ptr<SnellReplayRegistry> {return {};}
#endif
    auto Server::add_snell(std::string_view host,std::uint16_t port,std::string_view psk,std::optional<std::string_view> user,
        std::optional<std::size_t> bootstrap,std::uint32_t timeout,TcpSocketOptions options,bool fast_open,bool http_obfs,std::string_view obfs_host,std::string_view obfs_uri,bool reuse)->std::expected<std::size_t,std::string> {
        if(running||(listener && listener->is_open())||!sessions.empty()||!workers.empty())return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_SNELL
        if(outbounds.size()>=256)return std::unexpected("too many tunnel outbounds");
        if(bootstrap&&(!dns_routing||*bootstrap>=dns_routing->resolver_count()))return std::unexpected("invalid bootstrap resolver");
        auto factory=make_snell_factory(host,port,psk,user,bootstrap,timeout,options,fast_open,http_obfs,obfs_host,obfs_uri,reuse);if(!factory)return std::unexpected(factory.error());
        auto index=outbounds.size()+2;outbounds.push_back(std::move(*factory));
        if(bootstrap&&(!max_bootstrap_index||*bootstrap>*max_bootstrap_index))max_bootstrap_index=bootstrap;return index;
#else
        (void)host;(void)port;(void)psk;(void)user;(void)bootstrap;(void)timeout;(void)options;(void)fast_open;(void)http_obfs;(void)obfs_host;(void)obfs_uri;(void)reuse;
        return std::unexpected("Snell outbound is not available in this build");
#endif
    }

    auto Server::prepare_snell_inbound(std::string_view psk,std::optional<std::string_view> user,std::uint32_t window,std::shared_ptr<SnellReplayRegistry> registry,bool http_obfs)->std::expected<void,std::string> {
        if(running||(listener && listener->is_open())||!sessions.empty()||!workers.empty())return std::unexpected("stop the server before changing authentication");
#ifdef NEXUS_ENABLE_SNELL
        if(snell_inbound)return std::unexpected("Snell inbound is already configured");
        auto prepared=make_snell_inbound_factory(psk,user,window,std::move(registry),http_obfs);if(!prepared)return std::unexpected(prepared.error());
        snell_inbound=std::move(*prepared);return {};
#else
        (void)psk;(void)user;(void)window;(void)registry;(void)http_obfs;return std::unexpected("Snell inbound is not available in this build");
#endif
    }

}
