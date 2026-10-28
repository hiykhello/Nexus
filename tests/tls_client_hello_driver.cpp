import std;
import nexus.tls.client_hello_driver;
namespace t=nexus::tls; using Bytes=std::vector<std::uint8_t>;
auto retry(std::uint16_t group) -> Bytes {
    t::ServerHello h; h.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c}; h.cipher_suite=0x1301; h.extensions={{43,{3,4}},{51,{static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}}};
    auto body=*h.encode(); auto n=body.size(); Bytes record{22,3,3,static_cast<std::uint8_t>((n+4)>>8),static_cast<std::uint8_t>(n+4),2,0,static_cast<std::uint8_t>(n>>8),static_cast<std::uint8_t>(n)}; record.insert(record.end(),body.begin(),body.end()); return record;
}
int main() {
    t::ClientHello h; h.cipher_suites={0x1301}; h.compression_methods={0}; h.extensions={{43,{2,3,4}},{10,{0,4,0,0x1d,0x11,0xec}},{51,{0,0}}};
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
    std::cout << "TLS client Hello driver retry and state checks passed\n";
}
