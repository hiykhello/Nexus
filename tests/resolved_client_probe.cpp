import std;
import platform.resolved_bus;
import platform.resolved_types;
import platform.resolved_client;
namespace r = ::platform::resolved;
auto main(int argc,char**argv)->int {
    if(argc!=2)return 1;int index=0;auto end=argv[1]+std::char_traits<char>::length(argv[1]);auto parsed=std::from_chars(argv[1],end,index);if(parsed.ec!=std::errc{} || parsed.ptr!=end || index<=0)return 1;
    r::Client<> client;auto deadline=r::Clock::now()+std::chrono::seconds(3);
    auto opened=client.open(index,deadline);if(!opened){std::println("open {} {}",int(opened.error().code),opened.error().system.value());return 2;}
    auto baseline=client.snapshot(deadline);if(!baseline){std::println("snapshot {} {}",int(baseline.error().code),baseline.error().system.value());return 3;}
    if(baseline->server_count || baseline->domain_count)return 4;
    auto competing=client.competing_domains(deadline);if(!competing || *competing)return 5;
    r::Snapshot desired;desired.server_count=2;desired.servers[0].family=4;desired.servers[0].address={10,42,0,2};desired.servers[1].family=6;desired.servers[1].address[0]=0xfd;desired.servers[1].address[1]=0x42;desired.servers[1].address[15]=2;
    auto set=client.set_servers(desired,deadline);if(!set){std::println("setDNS {} {}",int(set.error().code),set.error().system.value());return 6;}
    auto read=client.snapshot(deadline);if(!read || *read!=desired){std::println("DNS readback mismatch/error {} {}",read ? int(read->server_count) : -1,read ? int(read->domain_count) : int(read.error().code));return 7;}
    desired.domain_count=1;desired.domains[0].name[0]='.';desired.domains[0].route_only=true;
    set=client.set_domains(desired,deadline);if(!set)return 8;read=client.snapshot(deadline);if(!read || *read!=desired)return 9;
    std::println("{{\"servers\":2,\"root_domain\":true,\"readback\":true}}");std::fflush(nullptr);
    std::string line;if(!std::getline(std::cin,line) || line!="cleanup")return 10;
    deadline=r::Clock::now()+std::chrono::seconds(2);
    if(!client.set_domains<false>(*baseline,deadline) || !client.set_servers<false>(*baseline,deadline))return 11;
    read=client.snapshot<false>(deadline);if(!read || *read!=*baseline)return 12;
    client.close();if(client.native_handle()!=-1)return 13;
    std::println("real per-link DNSEx/root-domain set/readback/selective restore passed without changing DefaultRoute or resetting unrelated resolver settings; Snapshot={} Client={}",sizeof(r::Snapshot),sizeof(r::Client<>));
}
