import std;
import tls.fingerprint;
import tls.profiles;
import tls.server_handshake_io;
namespace t=tls; namespace c = ::crypto;
auto read(char const* path) -> c::Bytes {std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),{}};}
int main(int argc,char** argv) {
    if(argc!=4)return 1;
    auto cert=read(argv[1]),key=read(argv[2]);auto credential=t::ServerCredential::create(cert,key);c::cleanse(key);if(!credential)return 2;
    std::array<std::string_view,1> alpn{"h3"};auto profile=t::ClientProfile::load("server.example",argv[3],29,false,alpn);if(!profile)return 3;
    auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();unsigned passed=0;
    for(auto group:{23,24,25}) for(auto cipher:{0x1301u,0x1302u,0x1303u}) for(bool retry:{false,true}) for(bool grease:{false,true}) {
        t::FingerprintConfig config;config.profile=grease ? t::Fingerprint::tls13_randomized : t::Fingerprint::native;
        config.group_count=1;config.group_order[0]=group;config.key_share_count=retry ? 0 : 1;config.key_share_groups[0]=group;
        config.cipher_count=1;config.cipher_order[0]=cipher;config.pad_to=1600;
        auto client=profile->handshake(0,1000,now,config);auto copy=credential->clone();if(!client||!copy)return 4;
        auto server=t::ServerHandshakeIo::create(std::move(*copy),0,1000,"h3");if(!server)return 5;
        auto transfer=[](auto& from,auto& to) {
            auto pending=from.pending_output();if(pending.empty())return true;
            auto data=pending.first(std::min<std::size_t>(13,pending.size()));auto received=to.feed(data,1);
            if(!received) {std::println("receive error {}",static_cast<int>(received.error()));return false;}
            return received->consumed&&from.written(received->consumed,1).has_value();
        };
        for(unsigned round=0;round<10000&&(!client->complete()||!server->complete());++round) {
            if(!server->pending_output().empty()) {if(!transfer(*server,*client))return 6;}
            else if(!client->pending_output().empty()) {if(!transfer(*client,*server))return 7;}
            else return 8;
        }
        if(!client->complete()||!server->complete())return 9;
        auto ca=client->take_application_records();auto sa=server->take_application_records();if(!ca||!sa)return 10;
        std::array<std::uint8_t,5> data{0,1,255,127,0};auto encrypted=ca->seal(data);if(!encrypted)return 11;
        auto opened=sa->open_event(*encrypted);if(!opened||opened->kind!=t::ApplicationEventKind::data||!std::ranges::equal(opened->data,data))return 12;
        ++passed;
    }
    std::println("{} authenticated NIST ECDH TCP flights with3ciphers/direct+HRR/native+randomized passed",passed);
}
