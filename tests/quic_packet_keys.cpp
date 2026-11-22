import std;
import crypto;
import quic.packet_keys;
import quic.varint;

namespace q=quic;
namespace c = ::crypto;
// RFC 9001 Appendix A.2/A.3, https://www.rfc-editor.org/rfc/rfc9001#appendix-A
// Copyright (c) 2021 IETF Trust and the persons identified as document authors.
// Code components are provided under the Simplified BSD License (RFC 9001 section 4).
namespace vectors {
    inline constexpr std::string_view client_payload=
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113"
        "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1"
        "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806"
        "048000ffff";
    inline constexpr std::string_view client_packet=
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c"
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89"
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e"
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7"
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7"
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf"
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2"
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd"
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07"
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d"
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723"
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd"
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
    inline constexpr std::string_view server_payload=
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200"
        "130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
        "020304";
    inline constexpr std::string_view server_packet=
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3"
        "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee";
}

namespace {
    template<std::size_t N> auto hex(std::string_view input) -> std::array<std::uint8_t,N> {
        if (input.size()!=2*N) throw std::invalid_argument("hex length");
        auto digit=[](char x) -> unsigned { return x<='9' ? x-'0' : x-'a'+10; };
        std::array<std::uint8_t,N> result{};
        for (std::size_t i=0;i<N;++i) result[i]=static_cast<std::uint8_t>((digit(input[2*i])<<4)|digit(input[2*i+1]));
        return result;
    }
    template<std::size_t Size,std::size_t Header,std::size_t Payload,std::size_t Prefix>
    auto rfc_packet(q::PacketKeys& keys,std::array<std::uint8_t,Header> header,
        std::array<std::uint8_t,Payload> payload,std::uint64_t packet,std::size_t pn_size,
        std::array<std::uint8_t,Size> const& expected,std::array<std::uint8_t,Prefix> const& expected_mask) -> int {
        auto nonce=q::packet_nonce(keys.iv(),packet); if (!nonce) return 1;
        std::array<std::uint8_t,Size> encrypted{};
        std::ranges::copy(header,encrypted.begin());
        auto sealed=keys.seal_to(std::span(encrypted).subspan(Header),*nonce,payload,header);
        if (!sealed || *sealed!=Payload+16) return 2;
        std::array<std::uint8_t,16> sample{},mask{};
        std::copy_n(encrypted.begin()+Header-pn_size+4,16,sample.begin());
        if (!keys.mask_to(mask,sample) || !std::ranges::equal(std::span(mask).first(Prefix),expected_mask)) return 3;
        encrypted[0]^=mask[0]&15;
        for (std::size_t i=0;i<pn_size;++i) encrypted[Header-pn_size+i]^=mask[i+1];
        if (encrypted!=expected) return 4;
        std::array<std::uint8_t,Payload> opened{};
        auto result=keys.open_to(opened,*nonce,std::span(encrypted).subspan(Header),header);
        if (!result || *result!=Payload || opened!=payload) return 5;
        // Exact-start in-place encryption/decryption retains the same wire bytes.
        std::array<std::uint8_t,Payload+16> inplace{};
        std::ranges::copy(payload,inplace.begin());
        sealed=keys.seal_to(inplace,*nonce,std::span(inplace).first(Payload),header);
        if (!sealed || !std::ranges::equal(inplace,std::span(expected).subspan(Header))) return 6;
        result=keys.open_to(inplace,*nonce,inplace,header);
        if (!result || *result!=Payload || !std::ranges::equal(std::span(inplace).first(Payload),payload)) return 7;
        // Ciphertext, tag, authenticated header, and nonce are authenticated.
        for (auto offset:{std::size_t(0),Payload,Payload+15}) {
            auto bad=std::array<std::uint8_t,Payload+16>{};
            std::ranges::copy(std::span(encrypted).subspan(Header),bad.begin()); bad[offset]^=1;
            auto failed=keys.open_to(opened,*nonce,bad,header);
            if (failed || failed.error()!=c::Error::authentication_failed || std::ranges::any_of(opened,[](auto x) { return x; })) return 8;
        }
        header[0]^=1;
        auto failed=keys.open_to(opened,*nonce,std::span(encrypted).subspan(Header),header);
        if (failed || failed.error()!=c::Error::authentication_failed) return 9;
        header[0]^=1; (*nonce)[0]^=1;
        failed=keys.open_to(opened,*nonce,std::span(encrypted).subspan(Header),header);
        if (failed || failed.error()!=c::Error::authentication_failed) return 10;
        // Header masks also allow partial buffer overlap, independent of AES ABI.
        std::array<std::uint8_t,17> overlap{}; std::ranges::copy(sample,overlap.begin());
        if (!keys.mask_to(std::span(overlap).template subspan<1,16>(),std::span(overlap).template first<16>()) ||
            !std::ranges::equal(std::span(overlap).subspan(1),mask)) return 11;
        return 0;
    }
    auto rfc_vectors() -> int {
        q::InitialSecrets secrets;
        auto id=hex<8>("8394c8f03e515708");
        if (!secrets.client().empty() || !secrets.server().empty() || !secrets.reset(1,id)) return 1;
        if (!std::ranges::equal(secrets.client(),hex<32>("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")) ||
            !std::ranges::equal(secrets.server(),hex<32>("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")) || secrets.reset(1,id)) return 2;
        q::PacketKeys client,server;
        if (!client.reset(q::PacketSuite::aes128_gcm_sha256,secrets.client()) || !server.reset(q::PacketSuite::aes128_gcm_sha256,secrets.server())) return 3;
        if (!std::ranges::equal(client.iv(),hex<12>("fa044b2f42a3fd3b46fb255c")) || !std::ranges::equal(server.iv(),hex<12>("0ac1493ca1905853b0bba03e"))) return 4;
        std::array<std::uint8_t,1162> payload{};
        std::ranges::copy(hex<245>(vectors::client_payload),payload.begin());
        auto result=rfc_packet(client,hex<22>("c300000001088394c8f03e5157080000449e00000002"),payload,2,4,
            hex<1200>(vectors::client_packet),hex<5>("437b9aec36"));
        if (result) return 10+result;
        result=rfc_packet(server,hex<20>("c1000000010008f067a5502a4262b50040750001"),hex<99>(vectors::server_payload),1,2,
            hex<135>(vectors::server_packet),hex<5>("2ec0d8356a"));
        return result ? 30+result : 0;
    }
    auto validation_and_aes256() -> int {
        static_assert(!std::is_copy_constructible_v<q::PacketKeys> && !std::is_move_constructible_v<q::PacketKeys>);
        static_assert(!std::is_move_constructible_v<q::InitialSecrets>);
        q::InitialSecrets secrets;
        if (secrets.reset(2,hex<8>("8394c8f03e515708")) || secrets.reset(1,{}) || secrets.reset(1,std::array<std::uint8_t,21>{})) return 1;
        q::PacketKeys keys;
        std::array<std::uint8_t,48> secret{}; for (std::size_t i=0;i<secret.size();++i) secret[i]=static_cast<std::uint8_t>(i);
        std::array<std::uint8_t,16> mask{},sample{};
        if (keys.ready() || keys.mask_to(mask,sample) || keys.seal_to(mask,std::array<std::uint8_t,12>{},{})) return 2;
        if (keys.reset(static_cast<q::PacketSuite>(255),secret) || keys.reset(q::PacketSuite::aes256_gcm_sha384,std::span(secret).first(32)) || keys.ready()) return 3;
        if (!keys.reset(q::PacketSuite::aes256_gcm_sha384,secret) || !keys.ready()) return 4;
        // Independent Python HMAC/SHA384 HKDF and Go crypto/aes GCM+ECB oracle.
        if (!std::ranges::equal(keys.iv(),hex<12>("a8d8316bf5bb0bbfa74cbf17")) ||
            !keys.mask_to(mask,sample) || mask!=hex<16>("fb26a6decff80c4f87260eaa9b34a0b5")) return 5;
        auto nonce=q::packet_nonce(keys.iv(),1); if (!nonce || *nonce!=hex<12>("a8d8316bf5bb0bbfa74cbf16")) return 6;
        std::array<std::uint8_t,23> output{};
        auto sealed=keys.seal_to(output,*nonce,std::array<std::uint8_t,7>{0,1,2,3,4,5,6},std::array<std::uint8_t,2>{0x40,1});
        if (!sealed || *sealed!=23 || output!=hex<23>("3c43014f30927207ec5012f4fda37bcdc9e181b80bc17b")) return 7;
        auto zero=q::packet_nonce(keys.iv(),0),max=q::packet_nonce(keys.iv(),q::max_varint);
        if (!zero || !std::ranges::equal(*zero,keys.iv()) || !max || *max!=hex<12>("a8d8316bca44f44058b340e8") || q::packet_nonce(keys.iv(),q::max_varint+1)) return 8;
        if (keys.reset(q::PacketSuite::aes256_gcm_sha384,secret)) return 9;
        std::array<std::uint8_t,32> buffer{};
        if (keys.seal_to(std::span(buffer).first(15),*nonce,{}) || keys.open_to(buffer,*nonce,std::span(buffer).first(15)) ||
            keys.seal_to(buffer,std::span(*nonce).first(11),{})) return 10;
        if (!keys.seal_to(buffer,*nonce,{})) return 11;
        auto opened=keys.open_to({},*nonce,std::span(buffer).first(16)); if (!opened || *opened) return 12;
        auto untouched=buffer;
        if (keys.seal_to(std::span(buffer).subspan(1),*nonce,std::span(buffer).first(4)) || buffer!=untouched) return 13;
        keys.clear();
        if (keys.ready() || keys.mask_to(mask,sample) || !std::ranges::all_of(keys.iv(),[](auto x) { return x==0; }) ||
            !keys.reset(q::PacketSuite::aes256_gcm_sha384,secret)) return 14;
        return 0;
    }
}
auto main() -> int {
    if (auto result=rfc_vectors()) { std::println("QUIC RFC 9001 packet vector case {} failed",result); return result; }
    if (auto result=validation_and_aes256()) { std::println("QUIC packet validation/AES256 case {} failed",result); return 100+result; }
    std::println("QUIC RFC 9001 Initial secrets, full client/server packets, AES header protection, AEAD mutations, nonce bounds and independent AES256 vectors passed; sizeof packet keys={}",sizeof(q::PacketKeys));
}
