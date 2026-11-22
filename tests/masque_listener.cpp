import std;
import masque.listener;
import masque.config;
import masque.bearer;
import crypto;
import dns.local_config;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
namespace m=masque;
namespace io=nex::corosio;
namespace capy=nex::capy;
namespace support=nexus::test::quic_tls;
using namespace std::chrono_literals;
auto main(int argc,char** argv) -> int {
    if(argc!=7)return 1;
    bool uring=std::string_view(argv[1])=="uring",ipv6=std::string_view(argv[2])=="6";
    auto cert=support::read(argv[3]),key=support::read(argv[4]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    std::string_view secret="approved";auto bearer=m::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(secret.data()),secret.size()});if(!bearer)return 3;
    m::DestinationRule rule;rule.network.family=ipv6 ? 6 : 4;if(ipv6)rule.network.address[15]=1;else{rule.network.address[0]=127;rule.network.address[3]=1;}
    rule.prefix=ipv6 ? 128 : 32;rule.first_port=1;rule.last_port=65535;
    m::HostConfig config("localhost",std::move(*bearer),{rule});
    dns::LocalSnapshotSource snapshots(argv[5],argv[6],50ms);
    auto context=io::make_io_context(uring);
    m::Listener<> listener(context,config,*credential,snapshots);
    auto local=ipv6 ? io::endpoint(io::ipv6_address::loopback(),0) : io::endpoint(io::ipv4_address::loopback(),0);
    auto bound=listener.prepare(local);if(!bound)return 4;listener.start();
    std::cout<<"READY "<<bound->port()<<std::endl;
    context.run_for(10s);listener.stop();context.restart();context.run_for(3s);
    std::println("listener drained={} clean={} failed={} sessions={}",listener.drained(),listener.clean(),listener.failed(),listener.sessions());
    return listener.drained() && listener.clean() && !listener.failed() ? 0 : 5;
}
