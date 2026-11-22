import std;
import platform.sd_bus_abi;
import platform.netlink_abi;
import platform.netlink_socket;
import platform.resolved_bus;
import packet.tun_linux;
import packet.tun_network;
import endpoint.host_dns_types;
import endpoint.resolved_dns;
import nexus.test.lease_support;
extern "C" void nexus_native_audit_arm(unsigned long long,int);
extern "C" void nexus_native_audit_disarm();
extern "C" unsigned long long nexus_native_audit_value(int);
namespace e=endpoint;
namespace p = ::packet;
namespace r = ::platform::resolved;
namespace a = ::platform::sd_bus_abi;
namespace t=nexus::test::lease;
auto main(int argc,char**argv)->int {
    try {
        t::isolation(argc,argv);if(argc!=6)return 1;std::string_view mode=argv[3];unsigned long long point=0;
        auto last=argv[4]+std::char_traits<char>::length(argv[4]);auto value=std::from_chars(argv[4],last,point);if(value.ec!=std::errc{} || value.ptr!=last)return 1;
        bool persistent=std::string_view(argv[5])=="persistent";
        // Calibrate that the interposer sees an allocation performed inside
        // the actual shared libsystemd implementation, not only executable PLT.
        nexus_native_audit_arm(1,0);a::sd_bus* check=nullptr;auto created=a::sd_bus_new(&check);if(check)a::sd_bus_unref(check);auto calibration=nexus_native_audit_value(4);nexus_native_audit_disarm();
        t::require(created<0 && calibration && !check && nexus_native_audit_value(9));
        auto device=p::LinuxTun::create("nx-dnsalloc");t::require(device.has_value());auto lease=p::TunNetworkLease<>::create(*device,t::options());t::require(lease.has_value());t::require(lease->start(t::deadline()).has_value());
        e::HostDnsOptions options;options.backend=e::HostDnsBackend::resolved;options.server_count=2;options.servers[0].address={10,42,0,2};options.servers[1].ipv6=true;options.servers[1].address[0]=0xfd;options.servers[1].address[1]=0x42;options.servers[1].address[15]=2;
        bool started=false;int code=-1;e::HostDnsCleanup cleanup;bool startup=mode=="start";
        if(startup)nexus_native_audit_arm(point,persistent);
        {
            e::ResolvedHostDns<> dns;
            auto result=dns.start(*lease,options,false,t::deadline(),t::deadline());started=result.has_value();if(!result)code=int(result.error().code);
            if(!startup)nexus_native_audit_arm(point,persistent);
            cleanup=dns.stop(t::deadline());
        }
        nexus_native_audit_disarm();
        auto calls=nexus_native_audit_value(0),live=nexus_native_audit_value(1),bytes=nexus_native_audit_value(2),peak=nexus_native_audit_value(3),fired=nexus_native_audit_value(4),overflow=nexus_native_audit_value(5);
        std::println("{{\"mode\":\"{}\",\"point\":{},\"persistent\":{},\"started\":{},\"error\":{},\"calls\":{},\"live\":{},\"bytes\":{},\"peak\":{},\"fired\":{},\"overflow\":{},\"restored\":{},\"preserved\":{},\"uncertain\":{},\"closed\":{}}}",mode,point,persistent,started,code,calls,live,bytes,peak,fired,overflow,cleanup.restored,cleanup.preserved,cleanup.uncertain,cleanup.descriptors_closed);std::fflush(nullptr);
        std::println("native-import-kinds malloc={} calloc={} realloc={} reallocarray={} strdup={} strndup={}",nexus_native_audit_value(6),nexus_native_audit_value(7),nexus_native_audit_value(8),nexus_native_audit_value(11),nexus_native_audit_value(12),nexus_native_audit_value(13));std::fflush(nullptr);
        t::require(!live && !bytes && !overflow && cleanup.descriptors_closed);
        std::string line;t::require(bool(std::getline(std::cin,line)) && line=="recover");
        e::ResolvedHostDns<> fresh;auto recovered=fresh.start(*lease,options,false,t::deadline(),t::deadline());if(!recovered){std::println("recovery failed {} {}",int(recovered.error().code),recovered.error().system.value());return 3;}
        auto restored=fresh.stop(t::deadline());t::require(restored.restored && !restored.preserved && !restored.uncertain && fresh.drained());
        auto end=lease->stop(t::deadline());t::require(!end.total&&lease->drained());std::println("native shared-library allocation failure/recovery and exact owner cleanup passed");
    }catch(int code){return code;}
}
