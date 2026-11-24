import std;
import platform.netlink_abi;
import platform.netlink_socket;
import platform.netlink_codec;
import platform.resolved_bus;
import packet.tun_linux;
import packet.tun_network;
import endpoint.host_dns_types;
import endpoint.resolved_dns;
import test.lease_support;
namespace e=endpoint;
namespace p = ::packet;
namespace r = ::platform::resolved;
namespace t=test::lease;
struct Hooks: ::platform::netlink::NoHooks {
    static inline bool cancel=false;
    static auto cancelled() noexcept -> bool {return cancel;}
};
auto main(int argc,char**argv)->int {
    try {
        t::isolation(argc,argv);std::string_view mode=argc>3 ? argv[3] : "normal";
        auto device=p::LinuxTun::create("nx-hostdns");t::require(device.has_value());
        auto settings=t::options();if(mode=="uncovered")settings.route_count=0;
        auto lease=p::TunNetworkLease<Hooks>::create(*device,settings);t::require(lease.has_value());t::require(lease->start(t::deadline()).has_value());
        e::HostDnsOptions options;options.backend=e::HostDnsBackend::resolved;options.server_count=2;options.servers[0].address={10,42,0,2};options.servers[1].ipv6=true;options.servers[1].address[0]=0xfd;options.servers[1].address[1]=0x42;options.servers[1].address[15]=2;
        e::ResolvedHostDns<Hooks> dns;
        std::println("{{\"ifindex\":{},\"sealed_tun\":true}}",lease->status().ifindex);std::fflush(nullptr);
        std::string line;t::require(bool(std::getline(std::cin,line)) && line=="start");
        if(mode=="startup-cancel")Hooks::cancel=true;
        auto deadline=mode=="startup-timeout" ? r::Clock::now() : t::deadline();auto result=dns.start(*lease,options,false,deadline,t::deadline());
        if(mode.starts_with("conflict") || mode=="uncovered" || mode=="startup-cancel" || mode=="startup-timeout") {
            auto expected=(mode.starts_with("conflict") || mode=="uncovered") ? r::Error::conflict : mode=="startup-cancel" ? r::Error::canceled : r::Error::timeout;
            if(result || result.error().code!=expected){std::println("unexpected rejected startup {}",result ? -1 : int(result.error().code));return 2;}
            auto cleanup=dns.cleanup();t::require(cleanup.restored && !cleanup.uncertain && dns.drained());
            std::println("{{\"rejected\":true,\"no_mutation\":true}}");std::fflush(nullptr);
        } else {
            if(!result){std::println("hostDNS start failure {} {} submitted {}",int(result.error().code),result.error().system.value(),result.error().submitted);return 3;}
            std::println("{{\"ready\":true}}");std::fflush(nullptr);
            t::require(bool(std::getline(std::cin,line)) && line=="check");
            if(mode=="cancel-stop")Hooks::cancel=true;
            if(mode!="cancel-stop") {
                std::this_thread::sleep_for(std::chrono::milliseconds(270));auto checked=dns.poll(r::Clock::now(),t::deadline());
                if(mode=="normal")t::require(checked.has_value());
                else t::require(!checked && (checked.error().code==r::Error::ownership || checked.error().code==r::Error::conflict));
            }
            auto cleanup=dns.stop(t::deadline());
            if(mode=="normal" || mode=="cancel-stop")t::require(cleanup.restored && !cleanup.preserved && !cleanup.uncertain && dns.drained());
            else if(mode=="restart")t::require(cleanup.uncertain && cleanup.descriptors_closed && !dns.drained());
            else t::require(cleanup.preserved && !cleanup.uncertain && cleanup.descriptors_closed);
            std::println("{{\"restored\":{},\"preserved\":{},\"uncertain\":{},\"descriptors_closed\":true}}",cleanup.restored,cleanup.preserved,cleanup.uncertain);std::fflush(nullptr);
        }
        t::require(bool(std::getline(std::cin,line)) && line=="finish");
        Hooks::cancel=true;
        auto canceled_proof=lease->verified_device(t::deadline());
        t::require(!canceled_proof && canceled_proof.error().netlink && canceled_proof.error().netlink->code==::platform::netlink::Error::canceled);
        Hooks::cancel=false;
        if(mode!="uncovered") {
            e::ResolvedHostDns<Hooks> recovered;
            auto restarted=recovered.start(*lease,options,false,t::deadline(),t::deadline());
            if(!restarted){std::println("fresh same-lease recovery failed {} {}",int(restarted.error().code),restarted.error().system.value());return 4;}
            auto report=recovered.stop(t::deadline());t::require(report.restored && !report.preserved && !report.uncertain && recovered.drained());
        }
        auto cleaned=lease->stop(t::deadline());t::require(!cleaned.total && lease->drained());
        std::println("actual sealed TUN hostDNS lifecycle {} passed; policy={} options={} originalLease={}",mode,sizeof(dns),sizeof(options),sizeof(*lease));
    }catch(int value){return value;}
}
