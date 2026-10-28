import std;
import nexus.crypto.mlkem;
#include "support/mlkem768_nist_keygen.hpp"
namespace c=nexus::crypto;
auto hex(std::string_view s) -> std::vector<std::uint8_t> { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; std::vector<std::uint8_t> b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
int main() {
    auto seed=hex(mlkem_seed), expected=hex(mlkem_public); auto key=c::Mlkem768Private::from_seed(seed);
    if (!key) return 1; auto pub=key->public_key(); if (!pub || !std::ranges::equal(*pub,expected)) return 2;
    auto encapsulated=c::mlkem768_encapsulate(*pub); if (!encapsulated) return 3;
    auto secret=key->decapsulate(encapsulated->ciphertext); if (!secret || !std::ranges::equal(secret->view(),encapsulated->secret.view())) return 4;
    auto altered=encapsulated->ciphertext; altered[5]^=1;
    auto rejected=key->decapsulate(altered), repeated=key->decapsulate(altered);
    if (!rejected || !repeated || !std::ranges::equal(rejected->view(),repeated->view()) || std::ranges::equal(rejected->view(),secret->view())) return 5;
    if (key->decapsulate(std::span{altered}.first(1087)).error()!=c::MlkemError::invalid_ciphertext || c::mlkem768_encapsulate(std::span{*pub}.first(1183)).error()!=c::MlkemError::invalid_key || c::Mlkem768Private::from_seed(std::span{seed}.first(63)).error()!=c::MlkemError::invalid_key) return 6;
    auto invalid=*pub; invalid[0]=0xff; invalid[1]|=0x0f;
    if (c::mlkem768_encapsulate(invalid).error()!=c::MlkemError::invalid_key) return 7;
    auto moved=std::move(*key); if (key->public_key().error()!=c::MlkemError::invalid_state || !moved.public_key()) return 8;
    auto generated=c::Mlkem768Private::generate(); if (!generated) return 9; auto gp=generated->public_key(); if (!gp) return 10;
    auto fresh=c::mlkem768_encapsulate(*gp); if (!fresh) return 11; auto dec=generated->decapsulate(fresh->ciphertext);
    if (!dec || !std::ranges::equal(dec->view(),fresh->secret.view())) return 12;
    *generated=std::move(moved);
    if (moved.public_key().error()!=c::MlkemError::invalid_state || generated->public_key()!=pub) return 13;
    *generated=std::move(*generated);
    if (generated->public_key()!=pub) return 14;
    std::cout << "ML-KEM-768 NIST keygen, encapsulation and implicit rejection passed\n";
}
