import std;
import nexus.tls.record;
static thread_local int allocation_countdown=-1;
void* operator new(std::size_t size) {
    if (allocation_countdown==0) { allocation_countdown=-1; throw std::bad_alloc{}; }
    if (allocation_countdown>0) --allocation_countdown;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace c=nexus::crypto; namespace t=nexus::tls;
auto hex(std::string_view s) -> c::Bytes {
    auto n=[](char ch) { return ch<='9' ? ch-'0' : ch-'a'+10; };
    c::Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b;
}
int main() {
    auto key=hex("920205a5b7bf2115e6fc5c2942834f54"), iv=hex("6d475f0993c8e564610db2b9");
    auto expected=hex("1703030017ab1df420e75c457a7cc5d2844f76d5aee4b4edbf049be0");
    auto make=[&](t::RecordDirection d) { return t::RecordLayer::create(d,c::Aead::aes_128_gcm,key,iv); };
    auto send=make(t::RecordDirection::send), recv=make(t::RecordDirection::receive);
    c::Bytes msg{'A','B','C','D','E','F'};
    if (!send || !recv || send->seal(t::ContentType::application_data,msg)!=expected) return 1;
    auto got=recv->open(expected); if (!got || got->content!=msg || got->type!=t::ContentType::application_data) return 2;
    auto next=send->seal(t::ContentType::handshake,msg,9); if (!next || *next==expected) return 3;
    got=recv->open(*next); if (!got || got->content!=msg || got->type!=t::ContentType::handshake) return 4;
    auto bad=send->seal(t::ContentType::alert,msg); if (!bad) return 5; bad->back()^=1;
    if (recv->open(*bad).error()!=t::RecordError::authentication_failed || recv->open(expected).error()!=t::RecordError::invalid_state) return 6;
    auto bounded=make(t::RecordDirection::send); c::Bytes max(16384,42), too_big(16385,42);
    if (!bounded || bounded->seal(t::ContentType::alert,too_big).error()!=t::RecordError::invalid_input ||
        bounded->seal(t::ContentType::alert,max,1).error()!=t::RecordError::invalid_input || !bounded->seal(t::ContentType::alert,max)) return 7;
    auto malformed=make(t::RecordDirection::receive); auto invalid=expected; invalid[1]=2;
    if (!malformed || malformed->open(invalid).error()!=t::RecordError::invalid_record || malformed->open(expected).error()!=t::RecordError::invalid_state) return 8;
    auto invalid_inner=make(t::RecordDirection::receive);
    c::Bytes inner{0,0,0}; std::array<std::uint8_t,5> header{23,3,3,0,19};
    auto encrypted=c::seal(c::Aead::aes_128_gcm,key,iv,inner,header);
    if (!invalid_inner || !encrypted) return 13;
    c::Bytes wire(header.begin(),header.end()); wire.insert(wire.end(),encrypted->begin(),encrypted->end());
    if (invalid_inner->open(wire).error()!=t::RecordError::invalid_record || invalid_inner->open(expected).error()!=t::RecordError::invalid_state) return 14;
    auto moved=std::move(*send); if (send->seal(t::ContentType::alert,msg).error()!=t::RecordError::invalid_state || !moved.seal(t::ContentType::alert,msg)) return 9;
    for (auto algorithm : {c::Aead::aes_256_gcm,c::Aead::chacha20_poly1305}) {
        c::Bytes k(32,7); auto w=t::RecordLayer::create(t::RecordDirection::send,algorithm,k,iv), r=t::RecordLayer::create(t::RecordDirection::receive,algorithm,k,iv);
        if (!w || !r) return 10; auto wire=w->seal(t::ContentType::application_data,{},100); if (!wire) return 11;
        auto plain=r->open(*wire); if (!plain || !plain->content.empty()) return 12;
    }
    auto limited=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key,iv,2);
    if (!limited || limited->send_remaining()!=2 || !limited->seal(t::ContentType::application_data,msg) || limited->send_remaining()!=1 ||
        !limited->seal(t::ContentType::alert,msg) || limited->send_remaining()!=0) return 15;
    auto exhausted=limited->seal(t::ContentType::application_data,msg);
    if (exhausted || exhausted.error()!=t::RecordError::key_usage_limit || t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key,iv,0) ||
        t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key,iv,(1u<<24)+1)) return 16;
    bool before_nonce=false, after_nonce=false;
    for (int index=0; index<16; ++index) {
        auto candidate=make(t::RecordDirection::send); if (!candidate) return 17;
        bool failed=false; allocation_countdown=index;
        try { (void)candidate->seal(t::ContentType::application_data,msg); }
        catch (std::bad_alloc const&) { failed=true; }
        allocation_countdown=-1;
        if (!failed) continue;
        if (candidate->usable(t::RecordDirection::send)) {
            before_nonce=true;
            if (candidate->seal(t::ContentType::application_data,msg)!=expected) return 18;
        } else {
            after_nonce=true;
            auto retry=candidate->seal(t::ContentType::application_data,msg);
            if (retry || retry.error()!=t::RecordError::invalid_state) return 19;
        }
    }
    if (!before_nonce || !after_nonce) return 20;
    std::cout << "TLS record RFC 8448 and boundaries passed\n";
}
