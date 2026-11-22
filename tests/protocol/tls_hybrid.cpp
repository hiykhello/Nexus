import std;
import tls.hybrid;
import tls.key_share;
import tls.schedule;
#include "../support/mlkem768_nist_keygen.hpp"
namespace t=tls; namespace c = ::crypto;
auto hex(std::string_view s) -> c::Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; c::Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
int main() {
    auto seed=hex(mlkem_seed), public_bytes=hex(mlkem_public);
    auto xbytes=hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto sbytes=hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    auto kem=c::Mlkem768Private::from_seed(seed); auto x=c::X25519Private::from_bytes(xbytes); auto server_x=c::X25519Private::from_bytes(sbytes);
    if (!kem || !x || !server_x) return 1; auto client=t::HybridClient::from_keys(std::move(*kem),std::move(*x));
    auto offer=client.share(); if (!offer || !std::ranges::equal(std::span{*offer}.first(1184),public_bytes) ||
        !std::ranges::equal(std::span{*offer}.subspan(1184),hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))) return 2;
    auto reply=t::hybrid_server_accept(*offer,std::move(*server_x)); if (!reply) return 3;
    if (!std::ranges::equal(std::span{reply->share}.subspan(1088),hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))) return 4;
    auto reference=c::Mlkem768Private::from_seed(seed); if (!reference) return 5; auto pq=reference->decapsulate(std::span{reply->share}.first(1088));
    if (!pq || !std::ranges::equal(pq->view(),reply->secret.view().first(32)) ||
        !std::ranges::equal(reply->secret.view().subspan(32),hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))) return 6;
    auto result=client.finish(reply->share); if (!result || !std::ranges::equal(result->view(),reply->secret.view()) || client.finish(reply->share).error()!=t::HybridError::invalid_state || client.share().error()!=t::HybridError::invalid_state) return 7;
    auto early=t::early_secret(c::Hash::sha256); if (!early || !t::handshake_secret(c::Hash::sha256,early->view(),result->view())) return 8;
    t::KeyShareEntry entry{t::x25519_mlkem768_group,c::Bytes(offer->begin(),offer->end())}; auto encoded=t::KeyShare::encode_client(std::span{&entry,1});
    if (!encoded || t::KeyShare::parse_client(*encoded).value()[0]!=entry) return 9;
    auto bad=*offer; std::ranges::fill(std::span{bad}.subspan(1184),0); auto sx=c::X25519Private::from_bytes(sbytes);
    if (!sx || t::hybrid_server_accept(bad,std::move(*sx)).error()!=t::HybridError::invalid_public_key) return 10;
    auto badkem=*offer; badkem[0]=0xff; badkem[1]|=0x0f; auto sx2=c::X25519Private::from_bytes(sbytes);
    if (!sx2 || t::hybrid_server_accept(badkem,std::move(*sx2)).error()!=t::HybridError::invalid_public_key) return 11;
    auto another=t::HybridClient::generate(); if (!another || another->finish(std::span{reply->share}.first(1119)).error()!=t::HybridError::invalid_share || another->share().error()!=t::HybridError::invalid_state) return 12;
    auto third=t::HybridClient::generate(); if (!third) return 13;
    auto moved=std::move(*third); if (third->share().error()!=t::HybridError::invalid_state) return 14;
    auto moved_share=moved.share(); auto sx3=c::X25519Private::generate(); if (!moved_share || !sx3) return 15;
    auto third_reply=t::hybrid_server_accept(*moved_share,std::move(*sx3)); if (!third_reply) return 16;
    auto corrupted=third_reply->share; corrupted[0]^=1; auto corrupted_secret=moved.finish(corrupted);
    if (!corrupted_secret || std::ranges::equal(corrupted_secret->view(),third_reply->secret.view()) ||
        !std::ranges::equal(corrupted_secret->view().subspan(32),third_reply->secret.view().subspan(32))) return 17;
    std::cout << "TLS X25519MLKEM768 hybrid share and secret passed\n";
}
