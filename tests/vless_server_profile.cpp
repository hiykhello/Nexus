import std;
import nexus.vless;
import nexus.tls.server_handshake_io;
import nexus.vless.server_profile;
namespace v=nexus::vless; namespace t=nexus::tls; namespace c=nexus::crypto;
auto read(char const* path) -> c::Bytes { std::ifstream f(path,std::ios::binary); return {std::istreambuf_iterator<char>(f),{}}; }
int main(int argc,char** argv) {
    if (argc==6) {
        std::array<std::string,1> paths{argv[4]};
        auto loaded=v::ServerProfile::load(argv[1],argv[2],paths);
        if (std::string_view(argv[5])=="reject") return loaded ? 20 : 0;
        if (!loaded || !loaded->tls_handshake(1,10) || !loaded->vless_handshake()) return 21;
        return 0;
    }
    if (argc!=4) return 1;
    auto cert=read(argv[1]),key=read(argv[2]),wrong=read(argv[3]);
    v::UserId user{}; user[0]=1; std::array<v::UserId,1> users{user};
    if (v::ServerProfile::create(cert,wrong,users) || v::ServerProfile::create(cert,key,{})) return 2;
    std::array<v::UserId,2> duplicates{user,user};
    if (v::ServerProfile::create(cert,key,duplicates)) return 3;
    auto profile=v::ServerProfile::create(cert,key,users); if (!profile) return 4;
    if (profile->tls_handshake(5,5)) return 5;
    auto first=profile->tls_handshake(1,10),second=profile->tls_handshake(2,11);
    auto a=profile->vless_handshake(), b=profile->vless_handshake();
    if (!first || !second || !a || !b) return 6;
    auto request=v::encode_tcp_request({user,v::AddressKind::ipv4,80,{127,0,0,1}});
    if (!request || a->feed(*request).status!=v::ServerStatus::dialing || b->status()!=v::ServerStatus::reading) return 7;
    if (!first->cancel() || second->complete() || !second->pending_output().empty()) return 8;
    profile=std::unexpected(std::string("released"));
    if (b->feed(*request).status!=v::ServerStatus::dialing || !second->tick(3)) return 9;
    std::cout << "VLESS server startup snapshot and independent handshakes passed\n";
}
