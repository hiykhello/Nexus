import std;
import nexus.tls.server_negotiation;
import nexus.tls.client_hello_stream;
static bool deny_allocations=false;
void* operator new(std::size_t size) {
    if (deny_allocations) throw std::bad_alloc{};
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=nexus::tls;
using Bytes=std::vector<std::uint8_t>;
constexpr std::array<std::uint16_t,2> credentials{0x0403,0x0804};
auto hello() -> t::ClientHello {
    t::ClientHello h; h.cipher_suites={0x1303,0x1301}; h.compression_methods={0};
    Bytes shares{0,36,0,29,0,32}; shares.insert(shares.end(),32,7);
    h.extensions={{43,{2,3,4}},{10,{0,4,0,29,0,23}},{13,{0,4,8,4,4,3}},{51,std::move(shares)}};
    return h;
}
int main(int argc,char** argv) {
    if (argc==2) {
        std::ifstream file(argv[1],std::ios::binary); if (!file) return 20;
        Bytes bytes{std::istreambuf_iterator<char>(file),{}}; auto stream=t::ClientHelloStream::create(); std::size_t pos=0;
        while (pos<bytes.size()) {
            auto part=stream->feed(std::span{bytes}.subspan(pos)); if (!part || part->consumed==0) return 21; pos+=part->consumed;
            if (part->hello) { auto result=t::negotiate_server(*part->hello,credentials);
                if (!result || (!result->x25519_share && !result->hybrid_share) || pos!=bytes.size()) return 22;
                std::cout << "OpenSSL TLS 1.3 offer selected\n"; return 0; }
        }
        return 23;
    }
    auto h=hello(); auto selected=t::negotiate_server(h,credentials);
    if (!selected || selected->cipher_suite!=0x1301 || selected->signature_scheme!=0x0403 || !selected->x25519_share || (*selected->x25519_share)[0]!=7) return 1;
    auto retry=h; retry.extensions[3].data={0,0}; auto r=t::negotiate_server(retry,credentials); if (!r || r->x25519_share) return 2;
    auto no_cipher=h; no_cipher.cipher_suites={0xc02f}; if (t::negotiate_server(no_cipher,credentials).error()!=t::ServerNegotiationError::no_cipher) return 3;
    auto no_group=h; no_group.extensions[1].data={0,2,0,23}; no_group.extensions[3].data={0,0}; if (t::negotiate_server(no_group,credentials).error()!=t::ServerNegotiationError::no_group) return 4;
    auto missing=h; missing.extensions.erase(missing.extensions.begin()+2); if (t::negotiate_server(missing,credentials).error()!=t::ServerNegotiationError::missing_extension) return 5;
    auto malformed=h; malformed.extensions[2].data={0,3,8,4,0}; if (t::negotiate_server(malformed,credentials).error()!=t::ServerNegotiationError::malformed_extension) return 6;
    auto wrong=h; wrong.extensions[3].data={0,5,0,23,0,1,1}; wrong.extensions[1].data={0,2,0,29}; if (t::negotiate_server(wrong,credentials).error()!=t::ServerNegotiationError::invalid_key_share) return 7;
    auto length=h; length.extensions[3].data={0,5,0,29,0,1,1}; if (t::negotiate_server(length,credentials).error()!=t::ServerNegotiationError::invalid_key_share) return 8;
    auto order=h; order.extensions[3].data={0,10,0,23,0,1,1,0,29,0,1,1}; if (t::negotiate_server(order,credentials).error()!=t::ServerNegotiationError::invalid_key_share) return 9;
    auto no_sig=h; no_sig.extensions[2].data={0,2,8,7}; if (t::negotiate_server(no_sig,credentials).error()!=t::ServerNegotiationError::no_signature) return 10;
    auto psk=h; psk.extensions.push_back({41,{}}); if (t::negotiate_server(psk,credentials).error()!=t::ServerNegotiationError::unsupported_psk) return 11;
    auto early=h; early.extensions.push_back({42,{}}); if (t::negotiate_server(early,credentials).error()!=t::ServerNegotiationError::unsupported_psk) return 12;
    auto invalid=h; invalid.compression_methods={0,1}; if (t::negotiate_server(invalid,credentials).error()!=t::ServerNegotiationError::invalid_hello) return 13;
    auto hybrid=h; hybrid.extensions[1].data={0,4,0x11,0xec,0,29};
    hybrid.extensions[3].data={0x04,0xc4,0x11,0xec,0x04,0xc0}; hybrid.extensions[3].data.insert(hybrid.extensions[3].data.end(),1216,7);
    auto pq=t::negotiate_server(hybrid,credentials); if (!pq || pq->group!=0x11ec || !pq->hybrid_share || pq->x25519_share) return 14;
    deny_allocations=true; auto no_alloc_hybrid=t::negotiate_server(hybrid,credentials); deny_allocations=false;
    if (!no_alloc_hybrid || !no_alloc_hybrid->hybrid_share) return 26;
    auto fallback=h; fallback.extensions[1].data=hybrid.extensions[1].data;
    auto fallback_selection=t::negotiate_server(fallback,credentials); if (!fallback_selection || fallback_selection->group!=29 || !fallback_selection->x25519_share) return 15;
    hybrid.extensions[3].data={0,0}; auto retry_pq=t::negotiate_server(hybrid,credentials);
    if (!retry_pq || retry_pq->group!=0x11ec || retry_pq->x25519_share || retry_pq->hybrid_share) return 16;
    hybrid.extensions[3].data={0,5,0x11,0xec,0,1,1};
    if (t::negotiate_server(hybrid,credentials).error()!=t::ServerNegotiationError::invalid_key_share) return 17;
    auto duplicate=h; auto& dup=duplicate.extensions[3].data;
    auto duplicate_entry=Bytes(dup.begin()+2,dup.end()); dup[1]=72; dup.insert(dup.end(),duplicate_entry.begin(),duplicate_entry.end());
    if (t::negotiate_server(duplicate,credentials).error()!=t::ServerNegotiationError::invalid_key_share) return 24;
    deny_allocations=true;
    auto no_alloc=t::negotiate_server(h,credentials);
    auto no_alloc_retry=t::negotiate_server(retry,credentials);
    auto no_alloc_invalid=t::negotiate_server(duplicate,credentials);
    deny_allocations=false;
    if (!no_alloc || !no_alloc->x25519_share || !no_alloc_retry || no_alloc_invalid.error()!=t::ServerNegotiationError::invalid_key_share) return 25;
    std::cout << "TLS server offer negotiation passed\n";
}
