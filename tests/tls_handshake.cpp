import std;
import tls.handshake;
static thread_local int fail_after=-1;
static void* watched_pending=nullptr;
static bool watch_pending=false, pending_released=false;
static bool trace_encode=false;
static std::size_t encode_allocations=0, encode_size=0;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) {
        if (watch_pending && size==8196) watched_pending=p;
        if (trace_encode) { ++encode_allocations; encode_size=size; }
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { if (p && p==watched_pending) { watched_pending=nullptr; pending_released=true; } std::free(p); }
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
namespace t=tls;
int main() {
    std::vector<std::uint8_t> hello{1,0,0,3,'a','b','c'}, cert{11,0,0,0}, done{20,0,0,1,7};
    auto decoder=t::HandshakeDecoder::create(16); if (!decoder) return 1;
    auto first=decoder->feed(std::span{hello}.first(1)); if (!first || !first->empty() || decoder->pending_bytes()!=1) return 2;
    auto second=decoder->feed(std::span{hello}.subspan(1,2)); if (!second || !second->empty() || decoder->pending_bytes()!=3) return 3;
    auto third=decoder->feed(std::span{hello}.subspan(3)); if (!third || third->size()!=1 || (*third)[0].type!=1 || (*third)[0].body!=std::vector<std::uint8_t>{'a','b','c'}) return 4;
    std::vector<std::uint8_t> combined=cert; combined.insert(combined.end(),done.begin(),done.end());
    auto batch=decoder->feed(combined); if (!batch || batch->size()!=2 || (*batch)[0].type!=11 || (*batch)[1].type!=20 || !(*batch)[0].body.empty() || (*batch)[1].body!=std::vector<std::uint8_t>{7}) return 5;
    auto limited=t::HandshakeDecoder::create(16);
    if (!limited || limited->feed(combined,1).error()!=t::HandshakeError::too_many_messages || !limited->failed() || limited->pending_bytes() || limited->feed({})) return 27;
    auto single=t::HandshakeDecoder::create(16);
    if (!single || !single->feed(std::span{hello}.first(3),1)) return 28;
    auto single_result=single->feed(std::span{hello}.subspan(3),1);
    if (!single_result || single_result->size()!=1 || !single->finish()) return 29;
    auto suffix=t::HandshakeDecoder::create(16); auto partial=hello; partial.push_back(20);
    if (!suffix || suffix->feed(partial,1).error()!=t::HandshakeError::too_many_messages) return 30;
    if (!decoder->finish() || decoder->failed()) return 6;
    auto encoded=t::HandshakeDecoder::encode(1,std::vector<std::uint8_t>{'x','y'}); if (!encoded || *encoded!=std::vector<std::uint8_t>({1,0,0,2,'x','y'})) return 7;
    auto empty=t::HandshakeDecoder::encode(8,std::span<std::uint8_t const>{}); if (!empty || *empty!=std::vector<std::uint8_t>({8,0,0,0})) return 8;
    std::vector<std::uint8_t> encode_body(65535,42);
    encode_allocations=encode_size=0; trace_encode=true;
    auto encoded_large=t::HandshakeDecoder::encode(1,encode_body,65535);
    trace_encode=false;
    if (!encoded_large || encode_allocations!=1 || encode_size!=encode_body.size()+4 ||
        encoded_large->size()!=encode_body.size()+4 || !std::ranges::equal(std::span{*encoded_large}.subspan(4),encode_body)) return 36;
    auto bad_type=t::HandshakeDecoder::create(8); if (!bad_type || bad_type->feed(std::vector<std::uint8_t>{0xfe,0,0,0}).error()!=t::HandshakeError::invalid_type || bad_type->feed(std::span<std::uint8_t const>{}).error()!=t::HandshakeError::invalid_state) return 9;
    auto too_long=t::HandshakeDecoder::create(2); if (!too_long || too_long->feed(std::vector<std::uint8_t>{1,0,0,3}).error()!=t::HandshakeError::message_too_large || too_long->finish().error()!=t::HandshakeError::invalid_state) return 10;
    auto truncated=t::HandshakeDecoder::create(8); if (!truncated || !truncated->feed(std::vector<std::uint8_t>{1,0,0,2,9}) || truncated->finish().error()!=t::HandshakeError::truncated || truncated->feed(std::span<std::uint8_t const>{}).error()!=t::HandshakeError::invalid_state) return 11;
    auto invalid_max=t::HandshakeDecoder::create(0); if (invalid_max || t::HandshakeDecoder::encode(1,std::vector<std::uint8_t>{},0).error()!=t::HandshakeError::input_too_large) return 12;
    std::vector<std::uint8_t> large(17,1); auto too_body=t::HandshakeDecoder::encode(1,large,16); if (too_body.error()!=t::HandshakeError::message_too_large) return 13;
    auto oversized=t::HandshakeDecoder::create(); std::vector<std::uint8_t> huge(16385);
    if (!oversized || oversized->feed(huge).error()!=t::HandshakeError::input_too_large || oversized->feed(std::span<std::uint8_t const>{}).error()!=t::HandshakeError::invalid_state) return 14;
    for (std::size_t split=0; split<=hello.size(); ++split) {
        auto d=t::HandshakeDecoder::create(16); if (!d) return 15;
        auto a=d->feed(std::span{hello}.first(split)); auto b=d->feed(std::span{hello}.subspan(split));
        if (!a || !b || a->size()+b->size()!=1 || !d->finish()) return 16;
    }
    // Moving after a complete header must transfer its expected body length,
    // and the source must never be usable with a moved-out buffer.
    for (std::size_t split=1;split<hello.size();++split) {
        auto source=t::HandshakeDecoder::create(16); if (!source || !source->feed(std::span{hello}.first(split))) return 20;
        auto target=std::move(*source);
        if (!source->failed() || source->feed({}).error()!=t::HandshakeError::invalid_state || source->finish().error()!=t::HandshakeError::invalid_state) return 21;
        auto result=target.feed(std::span{hello}.subspan(split));
        if (!result || result->size()!=1 || (*result)[0].body!=std::vector<std::uint8_t>{'a','b','c'} || !target.finish()) return 22;
    }
    auto source=t::HandshakeDecoder::create(16), target=t::HandshakeDecoder::create(16);
    if (!source || !target || !source->feed(std::span{hello}.first(5)) || !target->feed(std::span{done}.first(2))) return 23;
    *target=std::move(*source);
    if (!source->failed() || source->feed({}).error()!=t::HandshakeError::invalid_state) return 24;
    auto completed=target->feed(std::span{hello}.subspan(5));
    if (!completed || completed->size()!=1 || (*completed)[0].body!=std::vector<std::uint8_t>{'a','b','c'}) return 25;
    *target=std::move(*target); if (!target->finish()) return 26;
    std::vector<std::uint8_t> multiple{1,0,0,1,42,11,0,0x20,0}; multiple.resize(8201,7);
    int failures=0;
    for (int index=0;index<12;++index) {
        auto d=t::HandshakeDecoder::create(8192); if (!d) return 17;
        bool threw=false; fail_after=index;
        try { (void)d->feed(multiple); } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            if (!d->failed() || d->pending_bytes()!=0 || d->feed({}).error()!=t::HandshakeError::invalid_state ||
                d->finish().error()!=t::HandshakeError::invalid_state) return 18;
        }
    }
    if (failures<3) return 19;
    for (bool finish_input:{false,true}) {
        auto d=t::HandshakeDecoder::create(8192); if (!d) return 31;
        watch_pending=true; pending_released=false; watched_pending=nullptr;
        auto part=d->feed(std::array<std::uint8_t,5>{1,0,0x20,0,7});
        watch_pending=false;
        if (!part || !watched_pending || pending_released || d->pending_bytes()!=5) return 32;
        if (finish_input) {
            auto result=d->finish(); if (result || result.error()!=t::HandshakeError::truncated) return 33;
        } else {
            auto result=d->feed(std::array<std::uint8_t,1>{0},0);
            if (result || result.error()!=t::HandshakeError::too_many_messages) return 34;
        }
        if (!pending_released || watched_pending || !d->failed() || d->pending_bytes()) return 35;
    }
    std::cout << "TLS handshake framing boundaries passed\n";
}
