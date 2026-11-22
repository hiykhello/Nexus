import std;
import quic.packet_keys;
import quic.varint;
import sniff.quic;
import sniff.quic_datagrams;

// RFC 9001 Appendix A.2; IETF Trust Simplified BSD License.
namespace {
constexpr std::string_view sample_payload =
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113"
    "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1"
    "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806"
    "048000ffff";
// RFC 9369 Appendix A.2; IETF Trust Simplified BSD License.
constexpr std::string_view sample_v2 =
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485dd04de806071bf03dceebfa162e75d6c"
    "96058bdbfb127cdfcbf903388e99ad049f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d"
    "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a12834e3f249a78d395e0d18f4d766004"
    "f1a2674802a747eaa901c3f10cda5500cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68"
    "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff3312ae50b187c1433c0f028edcc4c2838b"
    "6a9bfc226ca4b4530e7a4ccee1bfa2a3d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd"
    "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520bcfb7966fc49b393f0061d974a2706df"
    "8c4a9449f11d7f3d2dcbb90c6b877045636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f"
    "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c1216ccce2d0193f958bb3850a833f7ae43"
    "2b65bc5a53975c155aa4bcb4f7b2c4e54df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4"
    "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b8017c25ca9052ca1079d8b78aebd4787"
    "6d330a30f6a8c6d61dd1ab5589329de714d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9"
    "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91abfe43960977c87471cf9ad4074d30e1"
    "0d6a7f03c63bd5d4317f68ff325ba3bd80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db"
    "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18d703dd84045a274ae8bfa73379661388"
    "d6991fe39b0d93debb41700b41f90a15c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc"
    "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61f6b5b984d4d3dfa033c1bb7e4f0037fe"
    "bf406d91c0dccf32acf423cfa1e7071010d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b"
    "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e06ebfde206bfb0fcbc0edc4ebec30966"
    "1bdd908d532eb0c6adc38b7ca7331dce8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1"
    "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1e86215c2d54e6670e07383a27bbffb5a"
    "ddf47d66aa85a0c6f9f32e59d85a44dd5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3"
    "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89d5974ee12e5cf7d5da4d6a31123041f3"
    "3e61407e76cffcdcfd7e19ba58cf4b536f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19"
    "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96ba18b2faa745b6fe189cf772a9f84cbfc";
constexpr std::string_view sample_packet =
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
auto hex(std::string_view value) -> std::vector<std::uint8_t> {
    auto digit=[](char c){return c<='9' ? c-'0' : c-'a'+10;};
    std::vector<std::uint8_t> result;result.reserve(value.size()/2);
    for(std::size_t i=0;i<value.size();i+=2)result.push_back(static_cast<std::uint8_t>((digit(value[i])<<4)|digit(value[i+1])));
    return result;
}
auto packet(std::uint8_t id,std::size_t offset,std::span<std::uint8_t const> data,
            std::string_view cid_hex="8394c8f03e515708") -> std::vector<std::uint8_t> {
    namespace q=quic;
    std::vector<std::uint8_t> plain; (void)q::append_varint(plain,6);(void)q::append_varint(plain,offset);
    (void)q::append_varint(plain,data.size());plain.insert(plain.end(),data.begin(),data.end());
    while(plain.size()<4)plain.push_back(0);
    auto cid=hex(cid_hex);q::InitialSecrets secrets;if(!secrets.reset(1,cid))throw std::runtime_error("secrets");
    q::PacketKeys keys;if(!keys.reset(q::PacketSuite::aes128_gcm_sha256,secrets.client()))throw std::runtime_error("keys");
    std::vector<std::uint8_t> header{0xc0,0,0,0,1,8};header.insert(header.end(),cid.begin(),cid.end());
    header.push_back(0);header.push_back(0);std::array<std::uint8_t,2> length{};
    if(!q::write_varint(length,1+plain.size()+16,2))throw std::runtime_error("length");
    header.insert(header.end(),length.begin(),length.end());
    auto pn=header.size();header.push_back(id);auto nonce=q::packet_nonce(keys.iv(),id);if(!nonce)throw std::runtime_error("nonce");
    std::vector<std::uint8_t> ciphertext(plain.size()+16);
    if(!keys.seal_to(ciphertext,*nonce,plain,header))throw std::runtime_error("seal");
    auto wire=header;wire.insert(wire.end(),ciphertext.begin(),ciphertext.end());std::array<std::uint8_t,16> mask{};
    if(!keys.mask_to(mask,std::span<std::uint8_t const,16>(wire.data()+pn+4,16)))throw std::runtime_error("mask");
    wire[0]^=mask[0]&15;wire[pn]^=mask[1];return wire;
}
}
auto main(int argc,char** argv) -> int {
    using namespace sniff;
    auto original=hex(sample_packet);QuicSniffer rfc;
    auto matched=rfc.feed(original);
    if(matched.status!=QuicSniffStatus::matched || matched.server_name!="example.com" || matched.ech_offered)return 1;
    QuicSniffer v2;auto v2_result=v2.feed(hex(sample_v2));
    if(v2_result.status!=QuicSniffStatus::matched || v2_result.server_name!="example.com")return 11;
    QuicSniffer rejected;auto tampered=original;tampered.back()^=1;
    if(rejected.feed(tampered).status!=QuicSniffStatus::authentication_failed)return 2;
    if(rejected.feed(original).status!=QuicSniffStatus::matched)return 3;
    auto payload=hex(sample_payload);auto hello=std::span(payload).subspan(4);
    auto first=packet(0,0,hello.first(100));auto second=packet(1,100,hello.subspan(100));
    auto emit=[](std::initializer_list<std::vector<std::uint8_t> const*> packets) -> int {
        for(auto const* value:packets) {
            std::array<char,2> size{static_cast<char>(value->size()>>8),static_cast<char>(value->size())};
            std::cout.write(size.data(),size.size());
            std::cout.write(reinterpret_cast<char const*>(value->data()),value->size());
        }
        return std::cout ? 0 : 26;
    };
    if(argc==2 && std::string_view(argv[1])=="--interleaved") {
        auto alternate=std::vector<std::uint8_t>(hello.begin(),hello.end());
        std::string_view old_name="example.com",new_name="example.net";
        auto found=std::ranges::search(alternate,old_name);
        if(found.empty())return 27;
        std::ranges::copy(new_name,found.begin());
        auto bfirst=packet(0,0,std::span(alternate).first(100),"8394c8f03e515709");
        auto bsecond=packet(1,100,std::span(alternate).subspan(100),"8394c8f03e515709");
        QuicSniffer a,b;
        if(a.feed(first).status!=QuicSniffStatus::need_more || a.feed(bfirst).status!=QuicSniffStatus::not_initial ||
           a.feed(bsecond).status!=QuicSniffStatus::not_initial || a.feed(second).server_name!="example.com")return 28;
        if(b.feed(bfirst).status!=QuicSniffStatus::need_more || b.feed(bsecond).server_name!="example.net")return 29;
        return emit({&first,&bfirst,&bsecond,&second});
    }
    if(argc==2 && std::string_view(argv[1])=="--conflicting-complete") {
        auto alternate=std::vector<std::uint8_t>(hello.begin(),hello.end());
        alternate[6]^=1; // ClientHello.random; valid alone, conflicting with the earlier CRYPTO range.
        auto full=packet(1,0,alternate);QuicSniffer standalone,conflicting;
        auto known=standalone.feed(full);
        if(known.status!=QuicSniffStatus::matched || known.server_name!="example.com")return 30;
        if(conflicting.feed(first).status!=QuicSniffStatus::need_more ||
           conflicting.feed(full).status!=QuicSniffStatus::malformed)return 31;
        return emit({&first,&full});
    }
    if(argc==2 && std::string_view(argv[1])=="--fragments") {
        for(auto const* value:{&first,&second}) {
            std::array<char,2> size{static_cast<char>(value->size()>>8),static_cast<char>(value->size())};
            std::cout.write(size.data(),size.size());
            std::cout.write(reinterpret_cast<char const*>(value->data()),value->size());
        }
        return std::cout ? 0 : 26;
    }
    auto combined=first;combined.insert(combined.end(),second.begin(),second.end());
    QuicSniffer coalesced;auto combined_result=coalesced.feed(combined);
    if(combined_result.status!=QuicSniffStatus::matched || combined_result.server_name!="example.com")return 13;
    auto prefixed=hex("d000000001088394c8f03e515708000100");
    prefixed.insert(prefixed.end(),combined.begin(),combined.end());QuicSniffer noninitial;
    if(noninitial.feed(prefixed).status!=QuicSniffStatus::matched)return 14;
    auto damaged=tampered;damaged.insert(damaged.end(),original.begin(),original.end());QuicSniffer invalid_first;
    if(invalid_first.feed(damaged).status!=QuicSniffStatus::matched)return 15;
    QuicSniffer mixed;
    if(mixed.feed(first).status!=QuicSniffStatus::need_more || mixed.feed(hex(sample_v2)).status!=QuicSniffStatus::not_initial ||
       mixed.feed(second).status!=QuicSniffStatus::matched)return 12;
    QuicSniffer fragmented;
    if(fragmented.feed(second).status!=QuicSniffStatus::need_more)return 4;
    auto result=fragmented.feed(first);
    if(result.status!=QuicSniffStatus::matched || result.server_name!="example.com")return 5;
    QuicSniffer conflict;if(conflict.feed(first).status!=QuicSniffStatus::need_more)return 6;
    auto bad=std::vector<std::uint8_t>(hello.begin()+50,hello.begin()+60);bad[0]^=1;
    if(conflict.feed(packet(1,50,bad)).status!=QuicSniffStatus::malformed)return 7;
    if(conflict.feed(packet(2,100,hello.subspan(100))).status!=QuicSniffStatus::malformed)return 8;
    auto complete=packet(0,0,hello);auto contradict=packet(1,50,bad);
    complete.insert(complete.end(),contradict.begin(),contradict.end());QuicSniffer ambiguous;
    if(ambiguous.feed(complete).status!=QuicSniffStatus::malformed)return 16;
    auto other=original;other[4]=2;QuicSniffer unknown;
    if(unknown.feed(other).status!=QuicSniffStatus::unsupported)return 9;
    auto ech=std::vector<std::uint8_t>(hello.begin(),hello.end());
    auto pos=std::size_t{4+2+32};pos+=1+ech[pos];
    auto ciphers=(std::size_t(ech[pos])<<8)|ech[pos+1];pos+=2+ciphers;pos+=1+ech[pos];
    auto extensions=(std::size_t(ech[pos])<<8)|ech[pos+1];extensions+=4;
    ech[pos]=static_cast<std::uint8_t>(extensions>>8);ech[pos+1]=static_cast<std::uint8_t>(extensions);
    auto body=ech.size();ech[1]=static_cast<std::uint8_t>(body>>16);ech[2]=static_cast<std::uint8_t>(body>>8);ech[3]=static_cast<std::uint8_t>(body);
    ech.insert(ech.end(),{0xfe,0x0d,0,0});QuicSniffer encrypted;
    auto flagged=encrypted.feed(packet(0,0,ech));
    if(flagged.status!=QuicSniffStatus::matched || !flagged.ech_offered || flagged.server_name!="example.com")return 10;
    if(argc==2 && std::string_view(argv[1])=="--protocol-vectors") {
        auto protected_name=packet(0,0,ech);
        return emit({&original,&protected_name,&tampered,&first,&second});
    }
    using Clock=std::chrono::steady_clock;auto now=Clock::now();
    QuicDatagramBuffer queued(2,first.size()+second.size(),now+std::chrono::seconds(1));
    if(queued.push(first,now).status!=QuicBufferStatus::waiting || queued.front())return 17;
    auto ready=queued.push(second,now);
    if(ready.status!=QuicBufferStatus::known || ready.domain!="example.com" || queued.count()!=2)return 18;
    if(!queued.front() || !std::ranges::equal(*queued.front(),first) || !queued.consume() ||
       !queued.front() || !std::ranges::equal(*queued.front(),second) || !queued.consume() || queued.front())return 19;
    QuicDatagramBuffer limited(1,first.size(),now+std::chrono::seconds(1));
    if(limited.push(first,now).status!=QuicBufferStatus::waiting || limited.push(second,now).status!=QuicBufferStatus::full || limited.count()!=1)return 20;
    if(limited.poll(now+std::chrono::seconds(1)).status!=QuicBufferStatus::expired || !limited.front() || !limited.consume())return 21;
    QuicDatagramBuffer fallback(1,first.size(),now+std::chrono::seconds(1));
    if(fallback.push(first,now).status!=QuicBufferStatus::waiting || fallback.push(second,now).status!=QuicBufferStatus::full ||
       fallback.finish_unknown().status!=QuicBufferStatus::unknown || !fallback.front() || !fallback.consume())return 25;
    QuicDatagramBuffer private_name(1,2048,now+std::chrono::seconds(1));
    if(private_name.push(packet(0,0,ech),now).status!=QuicBufferStatus::unknown)return 22;
    QuicDatagramBuffer canceled(1,2048,now+std::chrono::seconds(1));
    if(canceled.push(first,now).status!=QuicBufferStatus::waiting)return 23;
    canceled.close();if(canceled.count() || canceled.bytes() || canceled.front() || canceled.poll(now).status!=QuicBufferStatus::invalid_state)return 24;
    return 0;
}
