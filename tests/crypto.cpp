import std;
import nexus.crypto;
namespace c=nexus::crypto;
auto hex(std::string_view value) -> c::Bytes {
    auto nibble=[](char ch) { return ch<='9' ? ch-'0' : ch-'a'+10; };
    c::Bytes out; for (std::size_t i=0;i<value.size();i+=2) out.push_back(static_cast<std::uint8_t>((nibble(value[i])<<4)|nibble(value[i+1])));
    return out;
}
int main() {
    c::Bytes abc{'a','b','c'};
    auto sha=c::digest(c::Hash::sha256,abc);
    auto sha384=c::digest(c::Hash::sha384,abc);
    if (!sha || *sha!=hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ||
        !sha384 || *sha384!=hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")) return 1;
    auto context=c::DigestContext::create(c::Hash::sha256);
    auto destination=c::DigestContext::create(c::Hash::sha384);
    if (!context || !destination || !context->update(abc)) return 1;
    auto moved_context=std::move(*context);
    if (context->snapshot().error()!=c::Error::invalid_state || moved_context.snapshot()!=sha) return 1;
    *destination=std::move(moved_context);
    if (moved_context.update(abc).error()!=c::Error::invalid_state || destination->snapshot()!=sha) return 1;
    *destination=std::move(*destination);
    if (destination->snapshot()!=sha) return 1;
    c::Bytes ikm(22,0x0b);
    auto salt=hex("000102030405060708090a0b0c"), info=hex("f0f1f2f3f4f5f6f7f8f9");
    auto prk=c::hkdf_extract(c::Hash::sha256,salt,ikm);
    if (!prk || *prk!=hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")) return 1;
    auto okm=c::hkdf_expand(c::Hash::sha256,*prk,info,42);
    if (!okm || *okm!=hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")) return 1;
    if (c::hkdf_expand(c::Hash::sha256,*prk,info,8161).error()!=c::Error::invalid_length ||
        c::hkdf_expand(c::Hash::sha256,{},info,1).error()!=c::Error::invalid_length ||
        !c::hkdf_expand(c::Hash::sha256,*prk,{},0)) return 1;
    c::Bytes key(16), nonce(12), plain(16);
    auto ciphertext=c::seal(c::Aead::aes_128_gcm,key,nonce,plain);
    if (!ciphertext || *ciphertext!=hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")) return 1;
    auto opened=c::open(c::Aead::aes_128_gcm,key,nonce,*ciphertext);
    if (!opened || *opened!=plain) return 1;
    (*ciphertext)[0]^=1;
    auto rejected=c::open(c::Aead::aes_128_gcm,key,nonce,*ciphertext);
    if (rejected || rejected.error()!=c::Error::authentication_failed) return 1;
    auto aes256=c::seal(c::Aead::aes_256_gcm,c::Bytes(32),nonce,plain);
    if (!aes256 || *aes256!=hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")) return 1;
    auto chacha_key=hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto chacha_nonce=hex("070000004041424344454647"), chacha_aad=hex("50515253c0c1c2c3c4c5c6c7");
    std::string_view text="Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    c::Bytes message(text.begin(),text.end());
    auto chacha=c::seal(c::Aead::chacha20_poly1305,chacha_key,chacha_nonce,message,chacha_aad);
    if (!chacha || *chacha!=hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")) return 1;
    auto xkey=hex("eb27969c7abf9aff79348e1e77f1fcba7508ceb29a7471961b017aef9ceaf1c2");
    auto xnonce=hex("990009311eab3459c1bee84b5b860bb5bdf93c7bec8767e2");
    auto xsealed=c::seal(c::Aead::xchacha20_poly1305,xkey,xnonce,hex("e7ec3d4b9f"));
    if (!xsealed || *xsealed!=hex("66bd48486107e31b4dd0f51f0819a0641c86380f32")) return 1;
    constexpr std::array algorithms{c::Aead::aes_128_gcm,c::Aead::aes_256_gcm,c::Aead::chacha20_poly1305,c::Aead::xchacha20_poly1305};
    for (auto alg : algorithms) {
        c::Bytes k(alg==c::Aead::aes_128_gcm ? 16 : 32,0x42);
        c::Bytes n(alg==c::Aead::xchacha20_poly1305 ? 24 : 12,0x37), aad{1,2,3};
        auto encrypted=c::seal(alg,k,n,abc,aad); if (!encrypted) return 1;
        auto decrypted=c::open(alg,k,n,*encrypted,aad); if (!decrypted || *decrypted!=abc) return 1;
        aad[0]^=1;
        auto invalid=c::open(alg,k,n,*encrypted,aad); if (invalid || invalid.error()!=c::Error::authentication_failed) return 1;
        auto empty=c::seal(alg,k,n,{}); if (!empty || !c::open(alg,k,n,*empty)) return 1;
        k.pop_back(); auto badkey=c::seal(alg,k,n,abc); if (badkey || badkey.error()!=c::Error::invalid_key) return 1;
        k.push_back(0); n.pop_back(); auto badnonce=c::seal(alg,k,n,abc);
        if (badnonce || badnonce.error()!=c::Error::invalid_nonce) return 1;
    }
    auto a=c::X25519Private::from_bytes(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    auto b=c::X25519Private::from_bytes(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    if (!a || !b) return 1;
    auto ap=a->public_key(), bp=b->public_key();
    if (!ap || !bp || !std::ranges::equal(*ap,hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")) ||
        !std::ranges::equal(*bp,hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))) return 1;
    auto shared_a=a->agree(*bp), shared_b=b->agree(*ap);
    if (!shared_a || !shared_b || !std::ranges::equal(shared_a->view(),shared_b->view()) ||
        !std::ranges::equal(shared_a->view(),hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))) return 1;
    c::Bytes low_order(32);
    auto invalid_peer=a->agree(low_order);
    if (invalid_peer || invalid_peer.error()!=c::Error::invalid_peer || a->agree({}).error()!=c::Error::invalid_peer ||
        c::X25519Private::from_bytes({}).error()!=c::Error::invalid_key) return 1;
    auto moved=std::move(*a);
    if (a->public_key().error()!=c::Error::invalid_key || !moved.public_key()) return 1;
    auto generated_a=c::X25519Private::generate(), generated_b=c::X25519Private::generate();
    if (!generated_a || !generated_b) return 1;
    auto public_a=generated_a->public_key(), public_b=generated_b->public_key();
    if (!public_a || !public_b) return 1;
    auto first=generated_a->agree(*public_b), second=generated_b->agree(*public_a);
    if (!first || !second || !std::ranges::equal(first->view(),second->view())) return 1;
    auto moved_secret=std::move(*shared_a);
    if (!std::ranges::all_of(shared_a->view(),[](auto value) { return value==0; }) ||
        !std::ranges::equal(moved_secret.view(),shared_b->view())) return 1;
    std::array<std::uint8_t,32> random{};
    if (!c::random_bytes(random) || !c::random_bytes({})) return 1;
    c::cleanse(*prk); if (std::ranges::any_of(*prk,[](auto byte) { return byte!=0; })) return 1;
    std::cout << "crypto SHA-2, HKDF, AEAD and X25519 vectors passed\n";
}
