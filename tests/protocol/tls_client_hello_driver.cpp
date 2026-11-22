import std;
import tls.client_hello_driver;
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
namespace t=tls; using Bytes=std::vector<std::uint8_t>;
auto retry(std::uint16_t group) -> Bytes {
    t::ServerHello h; h.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c}; h.cipher_suite=0x1301; h.extensions={{43,{3,4}},{51,{static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}}};
    auto body=*h.encode(); auto n=body.size(); Bytes record{22,3,3,static_cast<std::uint8_t>((n+4)>>8),static_cast<std::uint8_t>(n+4),2,0,static_cast<std::uint8_t>(n>>8),static_cast<std::uint8_t>(n)}; record.insert(record.end(),body.begin(),body.end()); return record;
}
int main() {
    t::ClientHello h; h.cipher_suites={0x1301}; h.compression_methods={0}; h.extensions={{43,{2,3,4}},{10,{0,4,0,0x1d,0x11,0xec}},{51,{0,0}}};
    auto retry_wire=retry(0x001d); int failures=0;
    for (int index=0;index<80;++index) {
        auto candidate=t::ClientHelloDriver::create(h,0); if (!candidate || !candidate->initial_sent()) return 20;
        bool threw=false; fail_after=index;
        try { (void)candidate->feed(retry_wire); } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures; auto again=candidate->feed(retry_wire);
            if (again || again.error()!=t::ClientHelloDriverError::invalid_state || candidate->retry_sent()) return 21;
        }
    }
    if (failures<5) return 22;
    auto d=t::ClientHelloDriver::create(h,0); if (!d || !d->initial_record() || d->feed({}) || d->retry_sent()) return 1;
    if (!d->initial_sent() || d->initial_record() || d->initial_sent()) return 2;
    auto r=retry(0x001d); auto event=d->feed(r); if (!event || !event->outbound || event->server_hello || event->consumed!=r.size() || d->feed({})) return 3;
    auto& wire=*event->outbound; auto parsed=t::ClientHello::parse(std::span{wire}.subspan(9)); if (!parsed) return 4;
    auto shares=t::KeyShare::parse_client(parsed->extension(51)->data); if (!shares || shares->size()!=1 || (*shares)[0].group!=0x001d || (*shares)[0].key_exchange.size()!=32) return 5;
    if (!d->retry_sent() || d->retry_sent()) return 6;
    if (d->feed(r) || d->feed({})) return 7;
    auto bad=t::ClientHelloDriver::create(h,0x001d); if (!bad || !bad->initial_sent()) return 8;
    if (bad->feed(r).error()!=t::ClientHelloDriverError::invalid_retry || bad->feed({})) return 9;
    if (t::ClientHelloDriver::create(h,0x0017)) return 10;
    auto missing=h; missing.extensions[1].data={0,1,0}; if (t::ClientHelloDriver::create(missing,0)) return 11;
    auto moved=std::move(*bad); if (bad->initial_record() || moved.initial_record()) return 12;
    // Strict hybrid ClientHello already has a hybrid share and does not offer X25519.
    auto strict=h; strict.extensions[1].data={0,2,0x11,0xec};
    auto downgrade=t::ClientHelloDriver::create(strict,0x11ec);
    if (!downgrade || !downgrade->initial_sent()) return 13;
    auto rejected=downgrade->feed(retry(0x001d));
    if (rejected || rejected.error()!=t::ClientHelloDriverError::invalid_retry || downgrade->feed({})) return 14;
    auto same_group=t::ClientHelloDriver::create(strict,0x11ec);
    if (!same_group || !same_group->initial_sent()) return 15;
    auto repeated=same_group->feed(retry(0x11ec));
    if (repeated || repeated.error()!=t::ClientHelloDriverError::invalid_retry || same_group->feed({})) return 16;
    auto server=::crypto::X25519Private::generate(); if (!server) return 23;
    auto public_key=server->public_key(); if (!public_key) return 24;
    auto reality_hello=h; reality_hello.session_id.resize(32); reality_hello.extensions.push_back({13,{0,2,8,7}});
    auto reality=t::ClientHelloDriver::create(reality_hello,0x001d); if (!reality) return 25;
    reality::Identity identity{{1,2,3},0x12345678,{1,2,3,4,5,6,7,8}};
    if (!reality::authenticate_client_hello(*reality,*public_key,identity) || reality::authenticate_client_hello(*reality,*public_key,identity) || reality->take_authenticated_handshake()) return 26;
    auto initial=reality->initial_record(); if (!initial) return 27;
    auto hello=t::ClientHello::parse(std::span{*initial}.subspan(9)); if (!hello) return 28;
    auto entries=t::KeyShare::parse_client(hello->extension(51)->data); if (!entries || entries->size()!=1) return 29;
    auto opened=reality::open_client_hello(std::span{*initial}.subspan(5),*server,(*entries)[0].key_exchange);
    if (!opened || opened->identity.timestamp!=identity.timestamp || opened->identity.short_id!=identity.short_id || opened->identity.version!=identity.version) return 30;
    auto moved_reality=std::move(*reality); if (!moved_reality.initial_sent()) return 31;
    auto retry_result=moved_reality.feed(r);
    if (retry_result || retry_result.error()!=t::ClientHelloDriverError::invalid_retry || moved_reality.take_authenticated_handshake()) return 32;
    auto no_session=t::ClientHelloDriver::create(h,0x001d);
    if (!no_session || reality::authenticate_client_hello(*no_session,*public_key,identity)) return 33;
    auto ready=t::ClientHelloDriver::create(reality_hello,0x001d);
    if (!ready || !reality::authenticate_client_hello(*ready,*public_key,identity)) return 34;
    auto client_record=ready->initial_record(); if (!client_record || !ready->initial_sent()) return 35;
    auto sent_hello=t::ClientHello::parse(std::span{*client_record}.subspan(9)); if (!sent_hello) return 36;
    auto tls_key=::crypto::X25519Private::generate(); if (!tls_key) return 37;
    auto tls_public=tls_key->public_key(); if (!tls_public) return 38;
    t::ServerHello server_hello; server_hello.random.fill(0x42); server_hello.session_id_echo=sent_hello->session_id;
    server_hello.cipher_suite=0x1301; Bytes share{0,0x1d,0,32}; share.insert(share.end(),tls_public->begin(),tls_public->end());
    server_hello.extensions={{43,{3,4}},{51,std::move(share)}};
    auto body=server_hello.encode(); if (!body) return 39; auto size=body->size();
    Bytes record{22,3,3,static_cast<std::uint8_t>((size+4)>>8),static_cast<std::uint8_t>(size+4),2,0,static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
    record.insert(record.end(),body->begin(),body->end());
    auto parsed_server=ready->feed(record); if (!parsed_server || !parsed_server->server_hello) return 40;
    auto reality_handshake=ready->take_authenticated_handshake();
    if (!reality_handshake || ready->take_authenticated_handshake() || reality_handshake->take_application_records()) return 41;
    // The first hybrid share authenticates Reality. HRR keeps the exact session
    // ID and uses a fresh TLS share without sealing the identity a second time.
    auto hybrid=t::ClientHelloDriver::create(reality_hello,0x11ec);
    if (!hybrid || !reality::authenticate_client_hello(*hybrid,*public_key,identity)) return 42;
    auto hybrid_record=hybrid->initial_record(); if (!hybrid_record || !hybrid->initial_sent()) return 43;
    auto first=t::ClientHello::parse(std::span{*hybrid_record}.subspan(9)); if (!first) return 44;
    auto hybrid_shares=t::KeyShare::parse_client(first->extension(51)->data);
    if (!hybrid_shares || hybrid_shares->size()!=1 || (*hybrid_shares)[0].key_exchange.size()!=1216) return 45;
    auto auth=reality::open_client_hello(std::span{*hybrid_record}.subspan(5),*server,std::span{(*hybrid_shares)[0].key_exchange}.last(32));
    if (!auth || auth->identity.short_id!=identity.short_id) return 46;
    auto retry_hello=t::ServerHello::parse(std::span{r}.subspan(9)); if (!retry_hello) return 47;
    retry_hello->session_id_echo=first->session_id;
    auto retry_body=retry_hello->encode(); if (!retry_body) return 48;
    auto retry_size=retry_body->size(); Bytes reality_retry{22,3,3,static_cast<std::uint8_t>((retry_size+4)>>8),static_cast<std::uint8_t>(retry_size+4),2,0,static_cast<std::uint8_t>(retry_size>>8),static_cast<std::uint8_t>(retry_size)};
    reality_retry.insert(reality_retry.end(),retry_body->begin(),retry_body->end());
    auto retried=hybrid->feed(reality_retry); if (!retried || !retried->outbound) return 49;
    auto second=t::ClientHello::parse(std::span{*retried->outbound}.subspan(9));
    if (!second || second->session_id!=first->session_id || !hybrid->retry_sent()) return 50;
    auto second_shares=t::KeyShare::parse_client(second->extension(51)->data);
    if (!second_shares || second_shares->size()!=1 || (*second_shares)[0].group!=0x001d) return 51;
    auto final_record=record; std::copy(first->session_id.begin(),first->session_id.end(),final_record.begin()+44);
    auto final=hybrid->feed(final_record); if (!final || !final->server_hello) return 52;
    auto retry_handshake=hybrid->take_authenticated_handshake();
    if (!retry_handshake || retry_handshake->take_application_records()) return 53;
    std::cout << "TLS client Hello driver retry and state checks passed\n";
}
