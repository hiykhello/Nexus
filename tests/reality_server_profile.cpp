import std;
import reality.server_profile;
import reality.auth;
import memory.budget;
namespace r=reality; namespace c = ::crypto;
int main(int argc,char** argv) {
    if (argc!=6) return 1;
    std::array names{std::string("localhost")}; std::array<std::array<std::uint8_t,8>,1> ids{{{1,2,3,4,5,6,7,8}}};
    auto load=[&](char const* secret,char const* key) { return r::ServerProfile::load(secret,argv[2],key,names,ids,60); };
    if (load(argv[4],argv[3]) || load(argv[1],argv[5])) return 2;
    if (r::ServerProfile::load(argv[1],argv[2],argv[3],{},ids,60) ||
        r::ServerProfile::load(argv[1],argv[2],argv[3],names,{},60)) return 3;
    auto generated=r::ServerProfile::load(argv[1],{},{},names,ids,60);
    if (!generated || r::ServerProfile::load(argv[1],argv[2],{},names,ids,60)) return 11;
    auto profile=load(argv[1],argv[3]); if (!profile) return 4;
    auto p=profile->policy(); if (p.server_names.size()!=1 || p.server_names[0]!="localhost" || p.short_ids[0]!=ids[0] || p.max_time_difference_seconds!=60) return 5;
    std::array<std::uint8_t,32> seed{}; seed[0]=3;
    auto peer=c::X25519Private::from_bytes(seed); auto pub=peer ? peer->public_key() : std::unexpected(c::Error::invalid_state);
    std::array<std::uint8_t,32> random{};
    auto auth=pub ? r::AuthKey::derive(profile->private_key(),*pub,random) : std::unexpected(r::AuthError::invalid_state);
    if (!auth || !generated->handshake(*auth,1,100)) return 6;
    auto small=std::make_shared<::memory::Budget>(1);
    if (profile->handshake(*auth,1,100,small) || small->reserved()!=0) return 7;
    auto budget=std::make_shared<::memory::Budget>(8*1024*1024);
    { auto handshake=profile->handshake(*auth,1,100,budget); if (!handshake || !budget->reserved()) return 8;
      if (!handshake->cancel() || budget->reserved()!=0) return 9; }
    if (budget->reserved()!=0 || profile->handshake(*auth,100,100,budget) || budget->reserved()!=0) return 10;
    std::println("Reality server profile credentials, policy and budget passed");
}
