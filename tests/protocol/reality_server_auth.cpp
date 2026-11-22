import std;
import reality.auth;
import reality.server_auth;
import tls.hello;
import tls.key_share;
namespace r=reality; namespace c = ::crypto; namespace t=tls;
auto wire(t::ClientHello const& hello) -> c::Bytes {
    auto body=hello.encode(); if (!body) return {};
    auto size=body->size(); c::Bytes result{1,static_cast<std::uint8_t>(size>>16),static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
    result.insert(result.end(),body->begin(),body->end()); return result;
}
int main() {
    std::array<std::uint8_t,32> client_seed{},server_seed{}; client_seed[0]=7; server_seed[0]=9;
    auto client=c::X25519Private::from_bytes(client_seed),server=c::X25519Private::from_bytes(server_seed);
    if (!client || !server) return 1;
    auto public_client=client->public_key(),public_server=server->public_key(); if (!public_client || !public_server) return 2;
    t::ClientHello hello; hello.session_id.resize(32); hello.cipher_suites={0x1301}; hello.compression_methods={0};
    for (std::size_t i=0;i<hello.random.size();++i) hello.random[i]=static_cast<std::uint8_t>(i);
    hello.extensions.push_back({0,{0,12,0,0,9,'l','o','c','a','l','h','o','s','t'}});
    hello.extensions.push_back({43,{2,3,4}});
    t::KeyShareEntry share{0x001d,c::Bytes(public_client->begin(),public_client->end())};
    auto encoded=t::KeyShare::encode_client(std::span{&share,1}); if (!encoded) return 3;
    hello.extensions.push_back({51,*encoded});
    r::Identity identity{{1,2,3},1000,{1,2,3,4,5,6,7,8}};
    auto sealed=r::seal_client_hello(wire(hello),*client,*public_server,identity); if (!sealed) return 4;
    std::array names{std::string("localhost")}; std::array<std::array<std::uint8_t,8>,1> ids{identity.short_id};
    r::ServerPolicy policy{names,ids,{{1,2,3}},{{1,2,3}},10};
    auto accept=[&](std::span<std::uint8_t const> bytes,std::uint64_t now) { return r::authenticate_server_hello(bytes,*server,policy,now); };
    auto accepted=accept(sealed->wire,1010); if (!accepted || accepted->identity.short_id!=identity.short_id || !c::constant_time_equal(accepted->key.view(),sealed->key.view())) return 5;
    if (accept(sealed->wire,1011) || accept(sealed->wire,989)) return 6;
    policy.max_time_difference_seconds=0; if (!accept(sealed->wire,std::numeric_limits<std::uint64_t>::max())) return 7;
    ids[0][0]^=1; if (accept(sealed->wire,1000)) return 8; ids[0][0]^=1;
    names[0]="other"; if (accept(sealed->wire,1000)) return 9; names[0]="localhost";
    policy.min_version=std::array<std::uint8_t,3>{1,2,4}; if (accept(sealed->wire,1000)) return 10; policy.min_version.reset();
    policy.max_version=std::array<std::uint8_t,3>{1,2,2}; if (accept(sealed->wire,1000)) return 11; policy.max_version.reset();
    auto damaged=sealed->wire; damaged[39]^=1; if (accept(damaged,1000)) return 12;
    damaged.resize(damaged.size()-1); if (accept(damaged,1000)) return 13;
    // Pinned server prefers a standalone X25519 share over the hybrid share.
    c::Bytes hybrid(1216,0); std::copy(public_client->begin(),public_client->end(),hybrid.end()-32);
    t::KeyShareEntry h{0x11ec,hybrid}; encoded=t::KeyShare::encode_client(std::span{&h,1}); if (!encoded) return 14;
    hello.extensions.back().data=*encoded; sealed=r::seal_client_hello(wire(hello),*client,*public_server,identity);
    if (!sealed || !accept(sealed->wire,1000)) return 15;
    std::println("Reality server ClientHello identity policy passed");
}
