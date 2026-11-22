module cli.endpoint;
import std;
import endpoint.config;
import endpoint.credentials;
import endpoint.bootstrap;
import endpoint.owner;
import endpoint.process_signals;
import platform.netlink_abi;
import packet.tun_default_policy;
import wireguard.port_types;
import wireguard;
import endpoint.host_dns_types;
import endpoint.resolved_dns;
import rulefile;
import cli.tailscale_endpoint;

namespace cli::endpoint {
    namespace endpoint_detail=::endpoint::process;
    auto run(int argc,char**argv) -> int {
        auto usage=[] { std::cout << "usage: nexus endpoint check --config <file.kdl> [--resolve]\n       nexus endpoint run --config <file.kdl>\n"; };
        if (argc==2 && std::string_view(argv[1])=="--help") { usage(); return 0; }
        if (argc<2) { usage(); return 2; }
        auto command=std::string_view(argv[1]); bool check=command=="check";
        if (!check && command!="run") { usage(); return 2; }
        std::string_view path; bool resolve=false;
        for (int i=2;i<argc;++i) {
            auto option=std::string_view(argv[i]);
            if (option=="--config" && path.empty() && i+1<argc) path=argv[++i];
            else if (option=="--resolve" && check && !resolve) resolve=true;
            else { usage(); return 2; }
        }
        if (path.empty()) { usage(); return 2; }
        try {
            using Clock=std::chrono::steady_clock;
            auto begin=Clock::now();
            endpoint_detail::Signals signals;
            if (!signals.install()) { std::cerr << "endpoint: cannot install stop handlers\n"; return 1; }
            auto input=rulefile::read_regular_file(path);
            if (!input) { std::cerr << "endpoint configuration: " << input.error() << '\n'; return 1; }
            auto tailscale=tailscale_endpoint::parse(*input);
            if (!tailscale) { std::cerr << "endpoint configuration: " << tailscale.error() << '\n'; return 1; }
            if (*tailscale) return tailscale_endpoint::run(**tailscale,check,resolve);
            auto document=::endpoint::parse_kdl(*input);
            if (!document) { std::cerr << "endpoint configuration: " << document.error() << '\n'; return 1; }
            auto const& config=document->wireguard;
#ifndef NEXUS_ENDPOINT_HOST_DNS
            if(config.host_dns.enabled()){std::cerr << "endpoint: resolved host-dns backend is not enabled in this build\n";return 1;}
#endif
            auto deadline=begin+std::chrono::milliseconds(config.startup_timeout_ms);
            endpoint_detail::StopRequested cancel;
            auto material=::endpoint::prepare_credentials(config,deadline,cancel);
            if (!material) {
                if (signals.requested()) return signals.requested()==platform::netlink_abi::SIGHUP ? 1 : 0;
                std::cerr << "endpoint: " << material.error() << '\n'; return 1;
            }
            if (!check || resolve) {
                auto bootstrapped=::endpoint::bootstrap(config,*material,deadline,signals);
                if (!bootstrapped) {
                    if (signals.requested()) return signals.requested()==platform::netlink_abi::SIGHUP ? 1 : 0;
                    std::cerr << "endpoint: " << bootstrapped.error() << '\n'; return 1;
                }
            }
            if (check) {
                auto hostnames=std::ranges::count_if(config.peers,[](auto const& peer) { return peer.server && !peer.server->numeric; });
                std::cout << "endpoint configuration valid (" << (resolve ? "local bootstrap checked" : "offline") << ")";
                if (!resolve && hostnames) std::cout << "; " << hostnames << " hostname endpoint(s) require local bootstrap";
                std::cout << '\n'; return 0;
            }
            auto drive=[&]<class Policy,class WireProfile=wireguard::PortStandardWire,class DnsPolicy=::endpoint::NoHostDns>(WireProfile profile={}) -> int {
            ::endpoint::Owner<endpoint_detail::NetlinkHooks,wireguard::PortNoHooks,Policy,WireProfile,DnsPolicy> owner(config,*material,std::move(profile));
            // Startup never passes its original deadline. Rollback has one
            // explicit two-second grace; active stop receives a fresh budget.
            auto started=owner.start(*material,deadline,deadline+std::chrono::seconds(2));
            if (!started) {
                auto report=owner.stop(Clock::now()+std::chrono::seconds(2));
                if (!signals.requested()) std::cerr << "endpoint: " << started.error() << '\n';
                if (report.total || !owner.drained()) std::cerr << "endpoint cleanup could not be fully verified\n";
                return signals.requested() && signals.requested()!=platform::netlink_abi::SIGHUP && !report.total && owner.drained() ? 0 : 1;
            }
            auto local=owner.local_endpoint();
            if (!local) { (void)owner.stop(Clock::now()+std::chrono::seconds(2)); std::cerr << "endpoint: cannot inspect ready UDP port\n"; return 1; }
            std::cout << "WireGuard endpoint \"" << config.name << "\" ready: device=" << config.device << " port=" << local->port << '\n'; std::cout.flush();
            auto active=owner.run(cancel);
            auto report=owner.stop(Clock::now()+std::chrono::seconds(2));
            if (!active) std::cerr << "endpoint: " << active.error() << '\n';
            if (signals.requested()==platform::netlink_abi::SIGHUP) std::cerr << "endpoint: SIGHUP reload is unsupported; endpoint stopped\n";
            if (report.total || !owner.drained()) std::cerr << "endpoint cleanup could not be fully verified\n";
            if (!active || report.total || !owner.drained() || signals.requested()==platform::netlink_abi::SIGHUP) return 1;
            std::cout << "WireGuard endpoint \"" << config.name << "\" stopped\n"; return 0;
            };
#ifdef NEXUS_ENDPOINT_HOST_DNS
            if(config.host_dns.enabled()) {
                using Dns=::endpoint::ResolvedHostDns<endpoint_detail::NetlinkHooks>;
                if(config.provider_profile==wireguard::Provider::warp) {
                    auto profile=wireguard::ReservedProfile::create(config.provider_profile,config.reserved);
                    if(!profile){std::cerr << "endpoint: invalid provider profile\n";return 1;}
                    if(config.default_route)return drive.template operator()<packet::TunDefaultPolicy<endpoint_detail::NetlinkHooks>,wireguard::ReservedProfile,Dns>(*profile);
                    return drive.template operator()<::endpoint::SplitRoutePolicy,wireguard::ReservedProfile,Dns>(*profile);
                }
                if(config.default_route)return drive.template operator()<packet::TunDefaultPolicy<endpoint_detail::NetlinkHooks>,wireguard::PortStandardWire,Dns>();
                return drive.template operator()<::endpoint::SplitRoutePolicy,wireguard::PortStandardWire,Dns>();
            }
#endif
            if(config.provider_profile==wireguard::Provider::warp) {
                auto profile=wireguard::ReservedProfile::create(config.provider_profile,config.reserved);
                if(!profile){std::cerr << "endpoint: invalid provider profile\n";return 1;}
                if(config.default_route)return drive.template operator()<packet::TunDefaultPolicy<endpoint_detail::NetlinkHooks>>(*profile);
                return drive.template operator()<::endpoint::SplitRoutePolicy>(*profile);
            }
            if(config.default_route)return drive.template operator()<packet::TunDefaultPolicy<endpoint_detail::NetlinkHooks>>();
            return drive.template operator()<::endpoint::SplitRoutePolicy>();
        } catch (std::bad_alloc const&) { std::cerr << "endpoint: out of memory\n"; return 1; }
        catch (std::exception const&) { std::cerr << "endpoint: initialization failed\n"; return 1; }
    }
}
