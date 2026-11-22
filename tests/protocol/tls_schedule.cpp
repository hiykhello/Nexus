import std;
import tls.schedule;
namespace c = ::crypto;
namespace t=tls;
auto hex(std::string_view value) -> c::Bytes {
    auto nibble=[](char ch) { return ch<='9' ? ch-'0' : ch-'a'+10; };
    c::Bytes out; for (std::size_t i=0;i<value.size();i+=2) out.push_back(static_cast<std::uint8_t>((nibble(value[i])<<4)|nibble(value[i+1])));
    return out;
}
int main() {
    auto early=t::early_secret(c::Hash::sha256);
    if (!early || !std::ranges::equal(early->view(),hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"))) return 1;
    auto shared=hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    auto handshake=t::handshake_secret(c::Hash::sha256,early->view(),shared);
    if (!handshake || !std::ranges::equal(handshake->view(),hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"))) return 1;
    auto transcript=hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    auto client=t::derive_secret(c::Hash::sha256,handshake->view(),"c hs traffic",transcript);
    auto server=t::derive_secret(c::Hash::sha256,handshake->view(),"s hs traffic",transcript);
    if (!client || !server || !std::ranges::equal(client->view(),hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")) ||
        !std::ranges::equal(server->view(),hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"))) return 1;
    auto key=t::expand_label(c::Hash::sha256,server->view(),"key",{},16);
    auto iv=t::expand_label(c::Hash::sha256,server->view(),"iv",{},12);
    auto finished=t::expand_label(c::Hash::sha256,server->view(),"finished",{},32);
    if (!key || !iv || !finished || !std::ranges::equal(key->view(),hex("3fce516009c21727d0f2e4e86ee403bc")) ||
        !std::ranges::equal(iv->view(),hex("5d313eb2671276ee13000b30")) ||
        !std::ranges::equal(finished->view(),hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"))) return 1;
    auto verify=t::finished_verify_data(c::Hash::sha256,server->view(),c::Bytes(32));
    if (!verify || !std::ranges::equal(verify->view(),hex("5b9da977b291c010724658fb86bc8281788fbc589a9d04f85b9bfdc44d935c68"))) return 1;
    auto master=t::master_secret(c::Hash::sha256,handshake->view());
    if (!master || !std::ranges::equal(master->view(),hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"))) return 1;
    if (t::expand_label(c::Hash::sha256,server->view(),"",{},1).error()!=c::Error::invalid_length ||
        t::expand_label(c::Hash::sha256,server->view(),std::string(250,'x'),{},1).error()!=c::Error::invalid_length ||
        t::expand_label(c::Hash::sha256,server->view(),"x",c::Bytes(256),1).error()!=c::Error::invalid_length ||
        t::expand_label(c::Hash::sha256,server->view(),"x",{},65536).error()!=c::Error::invalid_length ||
        t::derive_secret(c::Hash::sha256,server->view(),"x",{}).error()!=c::Error::invalid_length ||
        t::handshake_secret(c::Hash::sha256,early->view(),{}).error()!=c::Error::invalid_length) return 1;
    auto sha384=t::early_secret(c::Hash::sha384); if (!sha384 || sha384->view().size()!=48) return 1;
    auto mac=c::hmac(c::Hash::sha256,c::Bytes(20,0x0b),c::Bytes{'H','i',' ','T','h','e','r','e'});
    if (!mac || *mac!=hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")) return 1;
    auto different=*mac; different[0]^=1;
    if (!c::constant_time_equal(*mac,*mac) || c::constant_time_equal(*mac,different) || c::constant_time_equal(*mac,{})) return 1;
    std::cout << "TLS 1.3 RFC 8448 key schedule and Finished derivation passed\n";
}
