import std;
import reality.auth;
namespace c = ::crypto;
namespace r=reality;
auto hex(std::string_view value) -> c::Bytes {
    auto nibble=[](char ch) { return ch<='9' ? ch-'0' : ch-'a'+10; };
    c::Bytes out; for (std::size_t i=0;i<value.size();i+=2) out.push_back(static_cast<std::uint8_t>((nibble(value[i])<<4)|nibble(value[i+1])));
    return out;
}
int main() {
    // Independently generated with Go's crypto/ecdh, crypto/hmac and crypto/cipher.
    auto client=c::X25519Private::from_bytes(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    auto server=c::X25519Private::from_bytes(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    auto client_public=hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    auto server_public=hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    auto hello=hex("010000750303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000000000000000000000000000000000000000000000000000000000213010100002a003300260024001d00208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    auto expected=hello; auto ciphertext=hex("0d1cc2d168daf221363144ba2eb8cd58bf2ce19827d7079351d629adb614d766");
    std::ranges::copy(ciphertext,expected.begin()+39);
    if (!client || !server) return 1;
    r::Identity id{{1,2,3},0x6553f100,{1,2,3,4,5,6,7,8}};
    auto sealed=r::seal_client_hello(hello,*client,server_public,id);
    if (!sealed || sealed->wire!=expected) return 2;
    auto opened=r::open_client_hello(expected,*server,client_public);
    if (!opened || opened->identity.version!=id.version || opened->identity.timestamp!=id.timestamp || opened->identity.short_id!=id.short_id) return 3;
    if (!c::constant_time_equal(opened->key.view(),sealed->key.view())) return 9;
    // Go's x509 package generated the leaf; its signature was replaced with
    // HMAC-SHA512(AuthKey, Ed25519 public key), as done by Reality.
    auto cert=hex("3081ee3081a1a003020102020101300506032b65703017311530130603550403130c746573742e696e76616c6964301e170d3730303130313030303030305a170d3730303130323030303030305a3017311530130603550403130c746573742e696e76616c6964302a300506032b6570032100ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca3123010300e0603551d0f0101ff040403020780300506032b6570034100269b816ba319c68819d9c3044869081b874ffd4c61ae1c51bd163f4757a0322171045415293836b4adcf7f7610d166d3fe5d8a00c9aa4704f0fd9a95f9e6dd25");
    if (!sealed->key.verify_certificate(cert) || !opened->key.verify_certificate(cert)) return 10;
    auto changed=cert; changed.back()^=1;
    if (sealed->key.verify_certificate(changed) || sealed->key.verify_certificate(c::Bytes{})) return 11;
    changed=cert; changed.push_back(0);
    if (sealed->key.verify_certificate(changed)) return 12;
    auto moved=std::move(opened->key);
    if (!opened->key.view().empty() || opened->key.verify_certificate(cert).error()!=r::AuthError::invalid_state || !moved.verify_certificate(cert)) return 13;
    auto random=std::span{hello}.subspan(6,32); auto other_random=c::Bytes(random.begin(),random.end()); other_random[0]^=1;
    auto other_key=r::AuthKey::derive(*client,server_public,other_random);
    if (!other_key || other_key->verify_certificate(cert)) return 14;
    for (auto offset : {std::size_t{6},std::size_t{39},std::size_t{70},expected.size()-1}) {
        auto damaged=expected; damaged[offset]^=1;
        auto result=r::open_client_hello(damaged,*server,client_public);
        if (result || result.error()!=r::AuthError::authentication_failed) return 4;
    }
    auto wrong=client_public; wrong[0]^=1;
    auto rejected=r::open_client_hello(expected,*server,wrong);
    if (rejected || rejected.error()!=r::AuthError::authentication_failed) return 5;
    for (auto offset : {std::size_t{0},std::size_t{3},std::size_t{4},std::size_t{38},std::size_t{72},std::size_t{82}}) {
        auto damaged=hello; damaged[offset]^=0xff;
        auto result=r::seal_client_hello(damaged,*client,server_public,id);
        if (result || result.error()!=r::AuthError::invalid_hello) return 6;
    }
    auto truncated=hello; truncated.resize(71); truncated[3]=67;
    auto bad=r::open_client_hello(truncated,*server,client_public);
    if (bad || bad.error()!=r::AuthError::invalid_hello) return 7;
    auto invalid=r::seal_client_hello(hello,*client,c::Bytes(32),id);
    if (invalid || invalid.error()!=r::AuthError::cryptographic_failure) return 8;
}
