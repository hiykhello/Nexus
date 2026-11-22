import std;
import tls.client_handshake_io;
import reality.client;
static thread_local int fail_after=-1;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=tls; using Bytes=std::vector<std::uint8_t>; using View=std::span<std::uint8_t const>;
auto retry() -> Bytes {
    t::ServerHello h; h.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c}; h.cipher_suite=0x1301; h.extensions={{43,{3,4}},{51,{0,0x1d}}}; auto body=*h.encode(); auto n=body.size(); Bytes r{22,3,3,0,static_cast<std::uint8_t>(n+4),2,0,0,static_cast<std::uint8_t>(n)}; r.insert(r.end(),body.begin(),body.end()); return r;
}
int main() {
    std::array<std::uint16_t,2> groups{0x001d,t::x25519_mlkem768_group};
    std::array<std::string_view,2> protocols{"h2","http/1.1"};
    auto hello=t::make_client_hello("server.example",protocols,groups);
    if (!hello || !hello->validate_tls13() || !hello->extension(0) || !hello->extension(16) || !hello->extension(10)) return 90;
    auto encoded=hello->encode(); if (!encoded || t::ClientHello::parse(*encoded)!=*hello) return 91;
    auto sni=hello->extension(0)->data;
    if (sni!=Bytes({0,17,0,0,14,'s','e','r','v','e','r','.','e','x','a','m','p','l','e'})) return 92;
    std::array<std::uint16_t,2> duplicate{0x001d,0x001d}; std::array<std::uint16_t,1> unsupported{26};
    std::array<std::string_view,2> repeat{"h2","h2"}; std::array<std::string_view,1> empty{""};
    if (t::make_client_hello("127.0.0.1",protocols,groups) || t::make_client_hello("bad..name",protocols,groups) ||
        t::make_client_hello("-bad.example",protocols,groups) || t::make_client_hello("bad:name",protocols,groups) ||
        t::make_client_hello({},protocols,duplicate) || t::make_client_hello({},protocols,unsupported) ||
        t::make_client_hello({},repeat,groups) || t::make_client_hello({},empty,groups)) return 93;
    Bytes anchor{1}; std::array<std::span<std::uint8_t const>,1> config_anchors{anchor};
    Bytes bad_name{'a',0,'b'};
    if (t::ClientSessionHandshake::create(*hello,0,config_anchors,t::PeerNameKind::dns,bad_name,0)) return 95;
    auto no_sni=t::make_client_hello({},std::span<std::string_view const>{},groups);
    if (!no_sni || no_sni->extension(0) || no_sni->extension(16)) return 94;
    auto server=::crypto::X25519Private::generate(); if (!server) return 102;
    auto server_public=server->public_key(); if (!server_public) return 103;
    reality::Identity identity{{1,2,3},123456,{1,2,3,4,5,6,7,8}};
    auto real=reality::create_client_session(*hello,*server_public,identity);
    auto real2=reality::create_client_session(*hello,*server_public,identity);
    if (!real || !real2 || real->take_application_records() || real->negotiated()) return 104;
    auto wire=real->initial_record(); auto wire2=real2->initial_record();
    if (!wire || !wire2 || std::ranges::equal(View(*wire).subspan(11,32),View(*wire2).subspan(11,32))) return 105;
    auto parsed=t::ClientHello::parse(View(*wire).subspan(9)); if (!parsed) return 106;
    auto shares=t::KeyShare::parse_client(parsed->extension(51)->data); if (!shares || shares->size()!=1) return 107;
    auto opened=reality::open_client_hello(View(*wire).subspan(5),*server,(*shares)[0].key_exchange);
    if (!opened || opened->identity.timestamp!=identity.timestamp || opened->identity.short_id!=identity.short_id) return 108;
    auto io=t::ClientHandshakeIo::create(std::move(*real),1,20); if (!io || !io->written(io->pending_output().size(),1)) return 109;
    if (io->feed(retry(),2) || io->take_application_records() || io->complete()) return 110;
    auto unauthenticated=t::ClientHelloDriver::create(*hello,0x001d);
    if (!unauthenticated || t::ClientSessionHandshake::create_authenticated(std::move(*unauthenticated))) return 111;
    if (reality::create_client_session(*hello,Bytes(32),identity)) return 112;

    t::ClientHello h; h.cipher_suites={0x1301}; h.compression_methods={0}; h.extensions={{43,{2,3,4}},{10,{0,2,0,0x1d}},{51,{0,0}}};
    Bytes root{1}, name{'a'}; std::array<View,1> anchors{root};
    auto make=[&]() { return t::ClientSessionHandshake::create(h,0,anchors,t::PeerNameKind::dns,name,0); };
    auto retry_wire=retry(); int session_failures=0, io_failures=0; bool session_success=false, io_success=false;
    for (int index=0;index<128;++index) {
        auto candidate=make(); if (!candidate || !candidate->sent()) return 96;
        bool threw=false; fail_after=index;
        try { auto result=candidate->feed(retry_wire); if (result && result->outbound) session_success=true; }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++session_failures; auto again=candidate->feed(retry_wire);
            if (again || again.error()!=t::ClientSessionHandshakeError::invalid_state || candidate->sent() || candidate->take_application_records()) return 97;
        } else if (session_success) break;
    }
    for (int index=0;index<128;++index) {
        auto session=make(); if (!session) return 98;
        auto candidate=t::ClientHandshakeIo::create(std::move(*session),1,100); if (!candidate || !candidate->written(candidate->pending_output().size(),1)) return 99;
        bool threw=false; fail_after=index;
        try { auto result=candidate->feed(retry_wire,2); if (result && !candidate->pending_output().empty()) io_success=true; }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++io_failures; auto again=candidate->feed(retry_wire,2);
            if (again || again.error()!=t::ClientHandshakeIoError::invalid_state || !candidate->pending_output().empty() || candidate->tick(2) || candidate->take_application_records()) return 100;
        } else if (io_success) break;
    }
    if (session_failures<5 || io_failures<5 || !session_success || !io_success) return 101;
    auto s=make(); if (!s) return 1; auto d=t::ClientHandshakeIo::create(std::move(*s),10,100); if (!d || d->pending_output().empty()) return 2;
    auto first_size=d->pending_output().size(); auto r=retry(); if (d->feed(r,10)->consumed!=0 || d->written(first_size+1,10).error()!=t::ClientHandshakeIoError::invalid_argument) return 3;
    for (std::size_t i=0;i<first_size;++i) if (!d->written(1,10) || (d->pending_output().empty()!=(i+1==first_size))) return 4;
    for (auto byte:r) { auto result=d->feed(View(&byte,1),11); if (!result || result->consumed!=1) return 5; }
    if (d->pending_output().empty() || d->feed(r,11)->consumed!=0 || d->take_application_records()) return 6;
    auto n=d->pending_output().size(); if (!d->written(n-1,12) || d->pending_output().size()!=1 || !d->written(1,12)) return 7;
    if (d->tick(11).error()!=t::ClientHandshakeIoError::time_reversed || !d->tick(99) || d->tick(100).error()!=t::ClientHandshakeIoError::timeout || !d->pending_output().empty() || d->feed(r,100)) return 8;
    auto s2=make(); auto c=t::ClientHandshakeIo::create(std::move(*s2),1,2); if (!c || !c->cancel() || c->cancel() || c->tick(1) || !c->pending_output().empty()) return 9;
    auto s3=make(); auto e=t::ClientHandshakeIo::create(std::move(*s3),1,9); if (!e || e->finish_input(2).error()!=t::ClientHandshakeIoError::protocol_error || e->written(1,2)) return 10;
    auto s4=make(); if (t::ClientHandshakeIo::create(std::move(*s4),2,2)) return 11;
    auto s5=make(); auto old=t::ClientHandshakeIo::create(std::move(*s5),1,9); if (!old->written(1,1)) return 12;
    auto moved=std::move(*old); if (old->tick(1) || !old->pending_output().empty() || !moved.tick(1)) return 12;
    std::cout << "TLS handshake I/O partial writes, backpressure and deadline passed\n";
}
