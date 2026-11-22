import std;
import tls.profiles;
import tls.fingerprint;
import tls.client_handshake_io;
import tls.hello;
import platform.ip_address;

int main(int argc,char** argv) {
    namespace t=tls;
    if(argc==5) {
        auto profile=t::ClientProfile::load(argv[1],argv[2]);if(!profile)return 11;
        auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        t::FingerprintConfig shape;shape.profile=t::Fingerprint::tls13_grease;
        auto io=std::string_view(argv[3])=="fingerprint" ? profile->handshake(0,1000,now,shape) : profile->handshake(0,1000,now);
        if(!io)return 12;
        auto flush=[&] {
            while(!io->pending_output().empty()){
                auto bytes=io->pending_output();std::cout.write(reinterpret_cast<char const*>(bytes.data()),bytes.size());std::cout.flush();
                if(!std::cout || !io->written(bytes.size(),0))return false;
            }return true;
        };
        if(!flush())return 13;
        while(!io->complete()){
            std::vector<std::uint8_t> record(5);std::cin.read(reinterpret_cast<char*>(record.data()),5);if(!std::cin)return 14;
            auto size=(std::size_t(record[3])<<8)|record[4];if(size>16640)return 15;
            record.resize(5+size);std::cin.read(reinterpret_cast<char*>(record.data()+5),size);if(!std::cin)return 16;
            for(std::size_t offset=0;offset<record.size();) {
                auto result=io->feed(std::span(record).subspan(offset),0);
                if(!result)return std::string_view(argv[4])=="reject" && result.error()==t::ClientHandshakeIoError::authentication_failed ? 0 : 17;
                if(!result->consumed)return 18;offset+=result->consumed;if(!flush())return 19;
            }
        }
        return std::string_view(argv[4])=="accept" ? 0 : 20;
    }
    if(argc!=1)return 21;
    auto ip4=::platform::parse_ip_address("127.0.0.1");
    auto ip6=::platform::parse_ip_address("2001:db8::1");
    if(!ip4 || ip4->size!=4 || ip4->bytes[0]!=127 || ip4->bytes[3]!=1 || !ip6 || ip6->size!=16 ||
       ::platform::parse_ip_address("::1%lo") || ::platform::parse_ip_address(std::string_view("::1\0extra",9)))return 1;
    for(auto name:{"127.0.0.1","2001:db8::1","server.example"}) {
        t::ClientProfile profile{name,{{1}},29,false,{}};
        for(bool fingerprint:{false,true}) {
            t::FingerprintConfig shape;shape.profile=t::Fingerprint::tls13_grease;
            auto io=fingerprint ? profile.handshake(0,1000,0,shape) : profile.handshake(0,1000,0);
            if(!io)return 2;
            auto record=io->pending_output();if(record.size()<9 || record[0]!=22 || record[5]!=1)return 3;
            auto parsed=t::ClientHello::parse(record.subspan(9));if(!parsed)return 4;
            bool sni=std::ranges::any_of(parsed->extensions,[](auto const& extension){return extension.type==0;});
            if(sni!=(std::string_view(name)=="server.example"))return 5;
        }
    }
    for(auto name:{"127.0.0.1","2001:db8::1","server.example"}) {
        for(auto shape:{t::Fingerprint::native,t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized}) {
            t::ClientProfile base{name,{{1}},29,false,{}};
            auto profile=t::ShapedClientProfile::create(std::move(base),shape);if(!profile)return 32;
            auto io=profile->handshake(0,1000,0);if(!io)return 33;
            auto record=io->pending_output();if(record.size()<9)return 34;
            auto parsed=t::ClientHello::parse(record.subspan(9));if(!parsed)return 35;
            bool sni=std::ranges::any_of(parsed->extensions,[](auto const& extension){return extension.type==0;});
            if(sni!=(std::string_view(name)=="server.example"))return 36;
        }
    }
    // A server cannot use HRR to introduce the unconfigured hybrid group.
    for(auto shape:{t::Fingerprint::native,t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized}) {
        t::ClientProfile base{"server.example",{{1}},29,false,{}};
        auto profile=t::ShapedClientProfile::create(std::move(base),shape);if(!profile)return 37;
        auto io=profile->handshake(0,1000,0);if(!io)return 38;
        auto initial=io->pending_output();if(initial.size()<9)return 39;
        auto hello=t::ClientHello::parse(initial.subspan(9));if(!hello)return 40;
        t::ServerHello retry;retry.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        retry.session_id_echo=hello->session_id;retry.cipher_suite=0x1301;retry.extensions={{43,{3,4}},{51,{0x11,0xec}}};
        auto body=retry.encode();if(!body || body->size()>65531)return 41;
        auto n=body->size();std::vector<std::uint8_t> record{22,3,3,static_cast<std::uint8_t>((n+4)>>8),static_cast<std::uint8_t>(n+4),2,static_cast<std::uint8_t>(n>>16),static_cast<std::uint8_t>(n>>8),static_cast<std::uint8_t>(n)};
        record.insert(record.end(),body->begin(),body->end());
        if(!io->written(initial.size(),0))return 42;
        auto result=io->feed(record,0);
        if(result || result.error()!=t::ClientHandshakeIoError::protocol_error || !io->pending_output().empty())return 43;
    }
    // Public TCP policy retains the configured real key exchange and SNI.
    for(auto [group,hybrid_only]:{std::pair<std::uint16_t,bool>{29,false},{0x11ec,false},{0x11ec,true},{23,false}}) {
        for(auto shape:{t::Fingerprint::native,t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized}) {
            t::ClientProfile base{"server.example",{{1}},group,hybrid_only,{}};
            auto profile=t::ShapedClientProfile::create(std::move(base),shape);if(!profile)return 24;
            auto io=profile->handshake(0,1000,0);if(!io)return 25;
            auto record=io->pending_output();if(record.size()<9)return 26;
            auto hello=t::ClientHello::parse(record.subspan(9));if(!hello || !hello->extension(10) || !hello->extension(51))return 27;
            auto shares=t::KeyShare::parse_client(hello->extension(51)->data);if(!shares)return 28;
            auto count=0u;bool matched=false;std::vector<std::uint16_t> grease_shares;
            for(auto const& share:*shares) {
                if(t::is_grease(share.group)) {
                    if(share.key_exchange!=std::vector<std::uint8_t>{0})return 44;
                    grease_shares.push_back(share.group);
                } else {++count;matched|=share.group==group;}
            }
            if(count!=1 || !matched)return 29;
            auto const& groups=hello->extension(10)->data;
            std::vector<std::uint16_t> advertised,grease_groups;
            for(std::size_t i=2;i+1<groups.size();i+=2) {
                auto value=static_cast<std::uint16_t>((std::uint16_t(groups[i])<<8)|groups[i+1]);
                if(t::is_grease(value))grease_groups.push_back(value);else advertised.push_back(value);
            }
            std::vector<std::uint16_t> expected{group};
            if(group==0x11ec && !hybrid_only)expected.push_back(29);
            if(advertised!=expected || grease_groups!=grease_shares || grease_groups.size()!=(shape==t::Fingerprint::native ? 0u : 1u))return 30;
        }
    }
    { t::ClientProfile base{"server.example",{{1}},29,false,{}};
      if(t::ShapedClientProfile::create(std::move(base),static_cast<t::Fingerprint>(255)))return 31; }
    return 0;
}
