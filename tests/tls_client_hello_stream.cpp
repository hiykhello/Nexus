import std;
import nexus.tls.client_hello_stream;
static thread_local int fail_after=-1;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=nexus::tls;
using Bytes=std::vector<std::uint8_t>;
auto record(std::span<std::uint8_t const> p, std::uint8_t type=22, std::uint8_t version=3) -> Bytes {
    Bytes out{type,3,version,static_cast<std::uint8_t>(p.size()>>8),static_cast<std::uint8_t>(p.size())};
    out.insert(out.end(),p.begin(),p.end()); return out;
}
auto wire(t::ClientHello const& hello) -> Bytes {
    auto body=*hello.encode(); Bytes out{1,static_cast<std::uint8_t>(body.size()>>16),static_cast<std::uint8_t>(body.size()>>8),static_cast<std::uint8_t>(body.size())};
    out.insert(out.end(),body.begin(),body.end()); return out;
}
int main(int argc, char** argv) {
    if (argc==2) {
        std::ifstream file(argv[1],std::ios::binary);
        if (!file) return 20;
        Bytes input{std::istreambuf_iterator<char>(file),{}};
        auto stream=t::ClientHelloStream::create(); std::size_t offset=0;
        while (offset<input.size()) {
            auto result=stream->feed(std::span{input}.subspan(offset,1));
            if (!result || result->consumed!=1) return 21;
            ++offset;
            if (result->hello) {
                if (offset!=input.size() || !result->hello->extension(51) || !result->hello->extension(43)) return 22;
                std::cout << "independent TLS ClientHello accepted\n"; return 0;
            }
        }
        return 23;
    }
    t::ClientHello hello; hello.random.fill(0x42); hello.session_id={1,2,3}; hello.cipher_suites={0x1301};
    hello.compression_methods={0}; hello.extensions={{43,{2,3,4}}}; auto message=wire(hello);
    auto packet=record(message); int failures=0;
    for (int index=0;index<40;++index) {
        auto candidate=t::ClientHelloStream::create(); if (!candidate) return 30;
        bool threw=false; fail_after=index;
        try { (void)candidate->feed(packet); } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) { ++failures; auto retry=candidate->feed(packet); if (retry || retry.error()!=t::ClientHelloStreamError::invalid_state) return 31; }
    }
    if (failures<3) return 32;
    auto stream=t::ClientHelloStream::create(); if (!stream) return 1;
    for (std::size_t i=0;i<message.size();++i) {
        auto fragment=record(std::span{message}.subspan(i,1),22,i==0 ? 1 : 3);
        for (std::size_t j=0;j<fragment.size();++j) {
            auto out=stream->feed(std::span{fragment}.subspan(j,1));
            if (!out || out->consumed!=1 || out->hello.has_value()!=(i+1==message.size() && j+1==fragment.size())) return 2;
            if (out->hello && (*out->hello!=hello || out->message!=message)) return 3;
        }
    }
    if (stream->feed({}) || stream->finish_input()) return 4;
    auto tail=t::ClientHelloStream::create(); auto input=record(message); auto length=input.size(); input.insert(input.end(),{20,3,3,0,1,1});
    auto out=tail->feed(input); if (!out || out->consumed!=length || !out->hello || out->message!=message) return 5;
    auto mixed=t::ClientHelloStream::create(); auto extra=message; extra.push_back(1);
    if (mixed->feed(record(extra)).error()!=t::ClientHelloStreamError::invalid_message) return 6;
    auto wrong=t::ClientHelloStream::create(); auto bad=message; bad[0]=2;
    if (wrong->feed(record(bad)).error()!=t::ClientHelloStreamError::invalid_message || wrong->feed({})) return 7;
    auto bad_version=t::ClientHelloStream::create(); if (bad_version->feed(record(message,22,2)).error()!=t::ClientHelloStreamError::invalid_record) return 8;
    auto bad_type=t::ClientHelloStream::create(); if (bad_type->feed(record(Bytes{1},20)).error()!=t::ClientHelloStreamError::invalid_record) return 9;
    auto truncated=t::ClientHelloStream::create(); if (!truncated->feed(std::span{input}.first(3)) || truncated->finish_input().error()!=t::ClientHelloStreamError::truncated || truncated->feed(input)) return 10;
    auto limited=t::ClientHelloStream::create(16); if (!limited || limited->feed(record(message)).error()!=t::ClientHelloStreamError::invalid_message) return 11;
    if (t::ClientHelloStream::create(0) || t::ClientHelloStream::create(65536)) return 12;
    auto old=hello; old.extensions[0].data={2,3,3}; auto legacy=t::ClientHelloStream::create(); if (legacy->feed(record(wire(old))).error()!=t::ClientHelloStreamError::invalid_message) return 13;
    std::cout << "TLS initial ClientHello stream passed\n";
}
