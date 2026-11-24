import std;
import crypto;
import hysteria2.stream_state;
import hysteria2.wire;
import net.datagram_driver;
import quic.tls_client;
import tls.server_credential;
import capy;
import corosio;
import test.quic_tls_link;
import test.hysteria2_application_link;
import test.hy2_retry_port_link;
import test.hy2_native_memory;
import test.hy2_retry_resource_link;
namespace io = ::corosio;namespace support=test::quic_tls;namespace mem=test::hy2_native_memory;
using test::hy2_retry_resource::phase;
auto main(int argc,char** argv) -> int {
    if(argc!=3 && argc!=4)return 1;if(argc==4 && std::string_view(argv[3])!="0" && std::string_view(argv[3])!="1")return 1;auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    for(bool uring:{false,true})for(auto kind:{mem::Kind::transport,mem::Kind::http3}){
        if(argc==4 && uring!=(std::string_view(argv[3])=="1"))continue;
        unsigned failures=0;
        for(std::size_t point=1;point<=300;++point){
            io::io_context context=io::make_io_context(uring);mem::fault.arm(kind,point);
            if(!phase(context,*credential,cert))return 3;auto denied=mem::fault.denied;auto calls=mem::fault.calls;
            mem::fault.arm(kind,0);if(!phase(context,*credential,cert))return 4;
            if(!denied){std::println("Hy2 native shared port budget cold backend={} kind={} failed_points={} first_success={} native_calls={} same_context_new_owner_recovery=true native_h3_key_budgets0=true",uring,static_cast<int>(kind),failures,point,calls);break;}
            ++failures;if(point==300)return 5;
        }
    }
}
