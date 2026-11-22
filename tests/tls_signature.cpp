import std;
import tls.server_credential;
import tls.certificate_verify;
import tls.signature;
import tls.fingerprint;
import tls.profiles;
import tls.server_handshake_io;

namespace t=tls;
namespace c = ::crypto;
auto read(char const* path) -> c::Bytes {std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),{}};}
int main(int argc,char** argv) {
    if(argc!=6)return 1;
    auto cert=read(argv[1]),key=read(argv[2]);
    auto scheme=static_cast<std::uint16_t>(std::stoul(argv[3],nullptr,0));
    auto credential=t::ServerCredential::create(cert,key);c::cleanse(key);
    if(!credential || !std::ranges::contains(credential->signature_schemes(),scheme))return 2;
    for(auto hash:{c::Hash::sha256,c::Hash::sha384}) {
        c::Bytes transcript(hash==c::Hash::sha256 ? 32 : 48,0x42);
        auto signature=credential->sign(scheme,hash,transcript);if(!signature)return 3;
        std::array<std::uint16_t,1> offered{scheme};
        if(!t::verify_server_certificate_signature(cert,hash,transcript,offered,*signature))return 4;
        if(t::verify_server_certificate_signature(cert,hash,transcript,{},*signature).error()!=t::CertificateVerifyError::unoffered_scheme)return 5;
        auto altered=*signature;altered.back()^=1;
        if(t::verify_server_certificate_signature(cert,hash,transcript,offered,altered).error()!=t::CertificateVerifyError::invalid_signature)return 6;
        // Same key type but a different hash/curve identifier is never accepted.
        auto wrong=scheme==0x0804 ? 0x0805 : scheme==0x0403 ? 0x0503 : scheme==0x0503 ? 0x0603 : 0x0403;
        altered=*signature;altered[4]=wrong>>8;altered[5]=wrong;
        std::array<std::uint16_t,1> wrong_offered{static_cast<std::uint16_t>(wrong)};
        if(t::verify_server_certificate_signature(cert,hash,transcript,wrong_offered,altered))return 7;
        if(hash==c::Hash::sha256) {
            std::ofstream out(argv[4],std::ios::binary);out.write(reinterpret_cast<char const*>(signature->data()+8),signature->size()-8);if(!out)return 8;
        }
    }
    for(auto unsupported:{0x0401u,0x0501u,0x0601u,0x0201u,0x0808u,0x0809u}) {
        if(t::signature_parameters(unsupported)||credential->sign(unsupported,c::Hash::sha256,c::Bytes(32)))return 9;
    }
    t::FingerprintConfig policy;policy.signature_count=1;policy.signature_order[0]=scheme;
    auto shaped=t::make_fingerprint_hello("localhost",{},policy);if(!shaped)return 10;
    if(shaped->hello.extension(13)->data!=c::Bytes{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)})return 11;
    policy.signature_count=2;policy.signature_order[1]=scheme;
    if(t::make_fingerprint_hello("localhost",{},policy))return 12;
    std::array<std::string_view,1> alpn{"h3"};
    auto profile=t::ClientProfile::load("server.example",argv[5],29,false,alpn);if(!profile)return 13;
    auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    unsigned handshakes=0;
    for(auto cipher:{0x1301u,0x1302u,0x1303u}) for(bool retry:{false,true}) {
        t::FingerprintConfig config;config.profile=t::Fingerprint::tls13_randomized;
        config.shares=retry ? t::FingerprintShares::retry : t::FingerprintShares::dual;
        config.cipher_count=1;config.cipher_order[0]=cipher;
        config.signature_count=1;config.signature_order[0]=scheme;config.pad_to=1600;
        auto client=profile->handshake(0,1000,now,config);auto copy=credential->clone();if(!client||!copy)return 14;
        auto server=t::ServerHandshakeIo::create(std::move(*copy),0,1000,"h3");if(!server)return 15;
        auto transfer=[](auto& from,auto& to) {
            auto pending=from.pending_output();if(pending.empty())return true;
            auto data=pending.first(std::min<std::size_t>(13,pending.size()));
            auto received=to.feed(data,1);
            return received&&received->consumed&&from.written(received->consumed,1).has_value();
        };
        for(unsigned round=0;round<10000&&(!client->complete()||!server->complete());++round) {
            if(!server->pending_output().empty()) {if(!transfer(*server,*client))return 16;}
            else if(!client->pending_output().empty()) {if(!transfer(*client,*server))return 17;}
            else return 18;
        }
        if(!client->complete()||!server->complete())return 19;
        auto client_app=client->take_application_records();auto server_app=server->take_application_records();if(!client_app||!server_app)return 20;
        std::array<std::uint8_t,5> data{0,1,255,127,0};auto encrypted=client_app->seal(data);if(!encrypted)return 21;
        auto opened=server_app->open_event(*encrypted);if(!opened||opened->kind!=t::ApplicationEventKind::data||!std::ranges::equal(opened->data,data))return 22;
        ++handshakes;
    }
    if(handshakes!=6)return 23;
    std::println("TLS signature {:04x} sign/verify SHA256/SHA384 transcript, exact curve/offer, tamper and forbidden legacy schemes passed; credential={}",scheme,sizeof(t::ServerCredential));
}
