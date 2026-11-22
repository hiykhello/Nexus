import std;
import masque.listener;
import masque.config;
import masque.bearer;
import crypto;
import dns.local_config;
import tls.server_credential;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
namespace m=masque;
namespace io=nex::corosio;
namespace support=nexus::test::quic_tls;
using namespace std::chrono_literals;
unsigned selected=99;
extern "C" void nexus_test_masque_listener_start(unsigned stage) {if(stage==selected)throw std::bad_alloc();}
auto main(int argc,char** argv) -> int {
    if(argc!=6)return 1;bool uring=std::string_view(argv[1])=="uring";
    auto cert=support::read(argv[2]),key=support::read(argv[3]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    dns::LocalSnapshotSource snapshots(argv[4],argv[5],50ms);
    for(unsigned stage=0;stage<2;++stage) {
        auto context=io::make_io_context(uring);std::string_view secret="approved";
        auto bearer=m::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(secret.data()),secret.size()});if(!bearer)return 3;
        m::DestinationRule rule;rule.network.family=4;rule.network.address[0]=127;rule.prefix=8;rule.first_port=1;rule.last_port=65535;
        m::HostConfig config("localhost",std::move(*bearer),{rule});m::Listener<> listener(context,config,*credential,snapshots);
        auto local=io::endpoint(io::ipv4_address::loopback(),0);if(!listener.prepare(local))return 4;
        selected=stage;bool threw=false;try{listener.start();}catch(std::bad_alloc const&){threw=true;}
        selected=99;context.run_for(1s);
        if(!threw || !listener.drained() || !listener.clean() || listener.sessions())return 5+stage;
    }
    std::println("listener both startup submission failures drained");
}
