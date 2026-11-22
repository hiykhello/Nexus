import std;
import tls.client_handshake_io;
import tls.hello;
import vless.client_profile;
import config;
import httpupgrade;

int main(int argc,char** argv) {
    namespace t=tls;
    if(argc==4 && std::string_view(argv[1])=="--vless-host") {
        config::VlessOutbound config{"127.0.0.1",443,argv[2],"::1",argv[3]};
        config.transport.emplace();
        auto profile=vless::detail::ClientProfile::load(config);
        if(!profile || !profile->transport || profile->transport->host()!="[::1]")return 22;
        config.transport->host="example.test";
        profile=vless::detail::ClientProfile::load(config);
        if(!profile || !profile->transport || profile->transport->host()!="example.test")return 23;
        return 0;
    }
    if(argc!=1)return 21;
    for(auto name:{"127.0.0.1","2001:db8::1","server.example"}) {
        vless::detail::ClientProfile profile{"localhost",443,{},name,{{1}},config::TlsKeyExchange::x25519,{}};
        auto io=profile.handshake(0,1000,0);if(!io)return 6;
        auto record=io->pending_output();if(record.size()<9)return 7;
        auto parsed=t::ClientHello::parse(record.subspan(9));if(!parsed)return 8;
        bool sni=std::ranges::any_of(parsed->extensions,[](auto const& extension){return extension.type==0;});
        if(sni!=(std::string_view(name)=="server.example"))return 9;
        if(!sni){profile.reality.emplace();if(profile.handshake(0,1000,0))return 10;}
    }
    return 0;
}
