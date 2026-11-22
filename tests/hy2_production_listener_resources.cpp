import std;
import crypto;
import hysteria2.auth;
import hysteria2.credential;
import hysteria2.listener;
import hysteria2.stream_state;
import hysteria2.tcp_channel;
import hysteria2.wire;
import net.datagram_driver;
import quic.cid_registry;
import quic.tls_client;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.hysteria2_application_link;
import nexus.test.hy2_production_resource_link;
namespace io=nex::corosio;namespace h=hysteria2;namespace support=nexus::test::quic_tls;
using nexus::test::hy2_production_resource::Heap;using nexus::test::hy2_production_resource::phase;
auto main(int argc,char** argv)->int{
    if(argc!=3 && argc!=4)return 1;if(argc==4 && std::string_view(argv[3])!="0" && std::string_view(argv[3])!="1")return 1;auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);auto password=h::Password::create(support::bytes("test-password"));if(!credential || !password)return 2;
    for(bool backend:{false,true}){
        if(argc==4 && backend!=(std::string_view(argv[3])=="1"))continue;
        io::io_context context=io::make_io_context(backend);std::size_t failures=0;
        for(std::size_t point=1;point<=400;++point){
            Heap::arm(point);if(!phase(context,*credential,cert,*password))return 3;auto denied=Heap::denied;auto calls=Heap::calls;
            Heap::arm(0);if(!phase(context,*credential,cert,*password))return 4;
            if(!denied){std::println("production Hy2 native allocator backend={} failed_points={} first_success={} calls={} same_context_recovery=true blocks0=true",backend,failures,point,calls);break;}
            ++failures;if(point==400)return 5;
        }
    }
}
