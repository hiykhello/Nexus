import std;
import tls.server_hello;
import tls.transcript;
import tls.schedule;
static bool deny_allocations=false;
static bool count_allocations=false;
static std::size_t allocation_count=0;
void* operator new(std::size_t size) {
    if (deny_allocations) throw std::bad_alloc{};
    if (count_allocations) ++allocation_count;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=tls; namespace c = ::crypto;
auto hex(std::string_view s) -> c::Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; c::Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
int main() {
    auto client_wire=hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto server_wire=hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    auto client=t::ClientHello::parse(std::span{client_wire}.subspan(4)); auto server=t::ServerHello::parse(std::span{server_wire}.subspan(4));
    if (!client || !server || server->is_retry()) return 1;
    auto encoded=server->encode(); if (!encoded || !std::ranges::equal(*encoded,std::span{server_wire}.subspan(4))) return 2;
    count_allocations=true; auto counted=server->encode(); count_allocations=false;
    if (!counted || *counted!=*encoded || allocation_count!=1) return 47;
    auto share=server->validate_x25519(*client); if (!share || share->key_exchange!=hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")) return 3;
    auto priv=c::X25519Private::from_bytes(hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"));
    if (!priv) return 4; auto shared=priv->agree(share->key_exchange); if (!shared || !std::ranges::equal(shared->view(),hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"))) return 5;
    auto early=t::early_secret(c::Hash::sha256); if (!early) return 6; auto hs=t::handshake_secret(c::Hash::sha256,early->view(),shared->view());
    if (!hs || !std::ranges::equal(hs->view(),hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"))) return 7;
    auto transcript=t::Transcript::create(c::Hash::sha256); if (!transcript || !transcript->append(client_wire) || !transcript->append(server_wire)) return 8;
    auto hash=transcript->snapshot(); if (!hash || *hash!=hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")) return 9;
    auto bad=*server; bad.session_id_echo={1}; if (bad.validate_x25519(*client).error()!=t::ServerHelloError::session_mismatch) return 10;
    bad=*server; bad.cipher_suite=0x1304; if (bad.validate_x25519(*client).error()!=t::ServerHelloError::cipher_mismatch) return 11;
    bad=*server; bad.compression_method=1; if (bad.validate_x25519(*client).error()!=t::ServerHelloError::invalid_compression) return 12;
    bad=*server; bad.extensions.push_back(bad.extensions[0]); if (bad.validate_x25519(*client).error()!=t::ServerHelloError::duplicate_extension || bad.encode().error()!=t::ServerHelloError::duplicate_extension) return 13;
    bad=*server; bad.extensions[0].data[1]=0x17; if (bad.validate_x25519(*client).error()!=t::ServerHelloError::group_mismatch) return 14;
    bad=*server; bad.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c}; if (bad.validate_x25519(*client).error()!=t::ServerHelloError::retry) return 15;
    for (std::size_t i=0;i<server_wire.size()-4;++i) if (t::ServerHello::parse(std::span{server_wire}.subspan(4,i))) return 16;
    auto client_bad=*client;
    for (auto& ext:client_bad.extensions) if (ext.type==10) ext.data={0,2,0,0x17};
    if (server->validate_x25519(client_bad).error()!=t::ServerHelloError::group_mismatch) return 17;
    bad=*server; bad.extensions[1].data={3,3}; if (bad.validate_x25519(*client).error()!=t::ServerHelloError::invalid_version) return 18;
    bad=*server; bad.extensions[0].data.resize(5); if (bad.validate_x25519(*client).error()!=t::ServerHelloError::group_mismatch) return 19;
    bad=*server; bad.extensions.push_back({16,{}}); if (bad.validate_x25519(*client).error()!=t::ServerHelloError::invalid_extension) return 20;
    auto zero=share->key_exchange; std::ranges::fill(zero,0); if (priv->agree(zero).error()!=c::Error::invalid_peer) return 21;
    auto first=*client; for (auto& e:first.extensions) if (e.type==51) e.data={0,0};
    auto retry=*server; retry.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    retry.extensions={{43,{3,4}},{51,{0,0x1d}},{44,{0,2,0xab,0xcd}}};
    auto second=*client; second.extensions.push_back({44,{0,2,0xab,0xcd}});
    if (!retry.validate_retry(first,second,*server)) return 22;
    auto padded=second; padded.extensions.insert(padded.extensions.begin(),{21,{0,0}});
    if (!retry.validate_retry(first,padded,*server)) return 41;
    auto reordered=second; std::swap(reordered.extensions[0],reordered.extensions[1]);
    if (retry.validate_retry(first,reordered,*server)) return 42;
    auto missing=second; missing.extensions.erase(missing.extensions.begin());
    if (retry.validate_retry(first,missing,*server)) return 43;
    auto duplicate_share=second;
    for (auto& e:duplicate_share.extensions) if (e.type==51) {
        auto entry=c::Bytes(e.data.begin()+2,e.data.end());
        e.data[1]=static_cast<std::uint8_t>(entry.size()*2);
        e.data.insert(e.data.end(),entry.begin(),entry.end());
    }
    if (retry.validate_retry(first,duplicate_share,*server).error()!=t::ServerHelloError::group_mismatch) return 45;
    auto multiple_shares=second;
    for (auto& e:multiple_shares.extensions) if (e.type==51) {
        e.data[1]=static_cast<std::uint8_t>(e.data[1]+5);
        e.data.insert(e.data.end(),{0,23,0,1,1});
    }
    if (retry.validate_retry(first,multiple_shares,*server).error()!=t::ServerHelloError::group_mismatch) return 46;
    auto wrong=second; wrong.random[0]^=1; if (retry.validate_retry(first,wrong,*server)) return 23;
    wrong=second; wrong.extensions.back().data.back()^=1; if (retry.validate_retry(first,wrong,*server)) return 24;
    if (retry.validate_retry(*client,second,*server)) return 25;
    auto bad_retry=retry; bad_retry.extensions[1].data={0,0x17}; if (bad_retry.validate_retry(first,second,*server)) return 26;
    bad_retry=retry; bad_retry.extensions.push_back({16,{}}); if (bad_retry.validate_retry(first,second,*server)) return 27;
    bad=*server; bad.cipher_suite=0x1302; if (retry.validate_retry(first,second,bad)) return 28;
    bad_retry=retry; bad_retry.extensions.erase(bad_retry.extensions.begin()+1);
    if (!bad_retry.validate_retry(*client,second,*server)) return 29;
    wrong=second; for (auto& e:wrong.extensions) if (e.type==51) e.data={0,0}; if (bad_retry.validate_retry(*client,wrong,*server)) return 30;
    auto requested=retry.validate_retry_request(first); if (!requested || !*requested || **requested!=0x001d) return 31;
    deny_allocations=true;
    auto request_without_allocation=retry.validate_retry_request(first);
    auto invalid_without_allocation=retry.validate_retry(first,reordered,*server);
    deny_allocations=false;
    if (!request_without_allocation || !*request_without_allocation || **request_without_allocation!=0x001d || invalid_without_allocation.error()!=t::ServerHelloError::invalid_extension) return 44;
    auto entries=t::KeyShare::parse_client(client->extension(51)->data); if (!entries || entries->size()!=1) return 32;
    auto generated=retry.retry_client_hello(first,(*entries)[0]); if (!generated || *generated!=second) return 33;
    if (retry.retry_client_hello(first,std::nullopt) || retry.retry_client_hello(*client,(*entries)[0])) return 34;
    auto invalid_entry=(*entries)[0]; invalid_entry.key_exchange.pop_back(); if (retry.retry_client_hello(first,invalid_entry)) return 35;
    auto cookie_only=bad_retry.validate_retry_request(*client); if (!cookie_only || cookie_only->has_value()) return 36;
    auto cookie_hello=bad_retry.retry_client_hello(*client,std::nullopt); if (!cookie_hello || *cookie_hello!=second || bad_retry.retry_client_hello(*client,(*entries)[0])) return 37;
    bad_retry=retry; bad_retry.extensions[2].data={0,0}; if (bad_retry.validate_retry_request(first)) return 38;
    bad_retry=retry; bad_retry.extensions.push_back({43,{3,4}}); if (bad_retry.validate_retry_request(first)) return 39;
    bad_retry=retry; bad_retry.extensions[1].data={0,0x17};
    auto nist_retry=bad_retry.validate_retry_request(first);if (!nist_retry || !*nist_retry || **nist_retry!=23) return 40;
    bad_retry.extensions[1].data={1,0};if (bad_retry.validate_retry_request(first).error()!=t::ServerHelloError::unsupported) return 50;
    auto large=*server; large.extensions={{43,{3,4}},{16,c::Bytes(65525,0)}};
    auto large_wire=large.encode(); if (!large_wire || !t::ServerHello::parse(*large_wire) || *t::ServerHello::parse(*large_wire)!=large) return 48;
    large.extensions.back().data.push_back(0);
    if (large.encode().error()!=t::ServerHelloError::invalid_length) return 49;
    std::cout << "TLS ServerHello RFC 8448 negotiation and key agreement passed\n";
}
