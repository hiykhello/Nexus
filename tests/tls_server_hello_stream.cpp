import std;
import nexus.tls.server_hello_stream;
static thread_local int fail_after=-1;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=nexus::tls; using Bytes=std::vector<std::uint8_t>;
auto record(std::span<std::uint8_t const> p, std::uint8_t type=22) -> Bytes {
    Bytes b{type,3,3,static_cast<std::uint8_t>(p.size()>>8),static_cast<std::uint8_t>(p.size())}; b.insert(b.end(),p.begin(),p.end()); return b;
}
auto hello(bool retry) -> Bytes {
    t::ServerHello s; s.cipher_suite=0x1301;
    if (retry) s.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    auto body=*s.encode(); Bytes wire{2,0,static_cast<std::uint8_t>(body.size()>>8),static_cast<std::uint8_t>(body.size())}; wire.insert(wire.end(),body.begin(),body.end()); return wire;
}
int main() {
    auto packet=record(hello(false)); int failures=0;
    for (int index=0;index<40;++index) {
        auto candidate=t::ServerHelloStream::create(); if (!candidate) return 30;
        bool threw=false; fail_after=index;
        try { (void)candidate->feed(packet); } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) { ++failures; auto again=candidate->feed(packet); if (again || again.error()!=t::ServerHelloStreamError::invalid_state) return 31; }
    }
    if (failures<3) return 32;
    auto wire=hello(false), retry=hello(true); auto s=t::ServerHelloStream::create(); if (!s) return 1;
    auto ccs=record(Bytes{1},20); auto cc=s->feed(ccs); if (!cc || cc->message) return 2;
    for (std::size_t i=0;i<wire.size();++i) {
        auto r=record(std::span{wire}.subspan(i,1));
        for (std::size_t j=0;j<r.size();++j) { auto out=s->feed(std::span{r}.subspan(j,1)); if (!out || out->consumed!=1 || (out->message.has_value()!=(i+1==wire.size() && j+1==r.size()))) return 3; if (out->message && (*out->message!=wire || out->retry)) return 4; }
    }
    if (s->feed(ccs) || s->resume_retry()) return 5;
    auto h=t::ServerHelloStream::create(); auto hr=h->feed(record(retry)); if (!hr || !hr->retry || *hr->message!=retry || h->feed(ccs)) return 6;
    if (!h->resume_retry() || h->resume_retry()) return 7;
    auto final=h->feed(record(wire)); if (!final || final->retry || *final->message!=wire) return 8;
    auto twice=t::ServerHelloStream::create(); if (!twice->feed(record(retry)) || !twice->resume_retry() || twice->feed(record(retry)).error()!=t::ServerHelloStreamError::invalid_retry) return 9;
    auto mixed=t::ServerHelloStream::create(); Bytes both=wire; both.push_back(2); if (mixed->feed(record(both)).error()!=t::ServerHelloStreamError::invalid_message) return 10;
    auto fragment=t::ServerHelloStream::create(); if (!fragment->feed(record(std::span{wire}.first(2))) || fragment->feed(ccs).error()!=t::ServerHelloStreamError::invalid_record) return 11;
    auto truncated=t::ServerHelloStream::create(); if (!truncated->feed(std::span{ccs}.first(2)) || truncated->finish_input().error()!=t::ServerHelloStreamError::truncated || truncated->feed(ccs)) return 12;
    auto wrong=t::ServerHelloStream::create(); if (wrong->feed(record(Bytes{2},20)).error()!=t::ServerHelloStreamError::invalid_record) return 13;
    auto extra=t::ServerHelloStream::create(); auto r=record(wire); r.insert(r.end(),ccs.begin(),ccs.end()); auto out=extra->feed(r); if (!out || out->consumed!=r.size()-ccs.size() || !out->message) return 14;
    std::cout << "TLS plaintext ServerHello stream framing and retry passed\n";
}
