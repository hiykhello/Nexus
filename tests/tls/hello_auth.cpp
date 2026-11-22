import std;
import tls.client_session_handshake;

static bool deny_allocations=false;
void* operator new(std::size_t size) {
    if (deny_allocations) throw std::bad_alloc{};
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }

namespace t=tls;
using Bytes=std::vector<std::uint8_t>;
using View=std::span<std::uint8_t const>;

auto hello() -> t::ClientHello {
    t::ClientHello h; h.random.fill(5); h.session_id.resize(32);
    h.cipher_suites={0x1301}; h.compression_methods={0};
    h.extensions={{43,{2,3,4}},{10,{0,2,0,0x1d}},{51,{0,0}},{13,{0,2,8,4}}};
    return h;
}

auto server_record(std::span<std::uint8_t const> session) -> Bytes {
    auto key=::crypto::X25519Private::generate();
    if (!key) return {};
    auto public_key=key->public_key(); if (!public_key) return {};
    t::ServerHello server; server.random.fill(0x42); server.session_id_echo.assign(session.begin(),session.end());
    server.cipher_suite=0x1301; Bytes share{0,0x1d,0,32}; share.insert(share.end(),public_key->begin(),public_key->end());
    server.extensions={{43,{3,4}},{51,std::move(share)}};
    auto body=server.encode(); if (!body) return {};
    auto n=body->size(); Bytes record{22,3,3,static_cast<std::uint8_t>((n+4)>>8),static_cast<std::uint8_t>(n+4),
        2,0,static_cast<std::uint8_t>(n>>8),static_cast<std::uint8_t>(n)};
    record.insert(record.end(),body->begin(),body->end()); return record;
}

int main() {
    auto driver=t::ClientHelloDriver::create(hello(),0x001d); if (!driver) return 1;
    auto before=driver->initial_record(); if (!before) return 2;
    unsigned calls=0;
    auto auth=[&](View wire,::crypto::X25519Private const& key)
        -> std::expected<t::ClientHelloAuthentication,t::ClientHelloDriverError> {
        ++calls;
        auto parsed=t::ClientHello::parse(wire.subspan(4)); if (!parsed) return std::unexpected(t::ClientHelloDriverError::invalid_hello);
        auto shares=t::KeyShare::parse_client(parsed->extension(51)->data); auto public_key=key.public_key();
        if (!shares || !public_key || shares->size()!=1 || !std::ranges::equal((*shares)[0].key_exchange,*public_key))
            return std::unexpected(t::ClientHelloDriverError::invalid_hello);
        t::ClientHelloAuthentication out; out.session_id.fill(0x71); out.session_id_size=32;
        out.verifier=[](std::span<View const>) { return false; }; return out;
    };
    if (!driver->authenticate_first(auth) || calls!=1 || driver->authenticate_first(auth) || calls!=1) return 3;
    auto after=driver->initial_record(); if (!after || after->size()!=before->size()) return 4;
    for (std::size_t i=0;i<after->size();++i) {
        if (i>=44 && i<76) { if ((*after)[i]!=0x71) return 5; }
        else if ((*after)[i]!=(*before)[i]) return 6;
    }
    if (!driver->initial_sent()) return 7;
    auto server=server_record(View(*after).subspan(44,32));
    auto step=driver->feed(server); if (!step || !step->server_hello) return 8;
    Bytes anchor{1},name{'x'}; std::array<View,1> anchors{anchor};
    if (driver->take_handshake(anchors,t::PeerNameKind::dns,name,0) || driver->take_authenticated_handshake()) return 9;

    auto usable=t::ClientHelloDriver::create(hello(),0x001d); if (!usable) return 10;
    auto no_allocation=[](View,::crypto::X25519Private const&)
        -> std::expected<t::ClientHelloAuthentication,t::ClientHelloDriverError> {
        t::ClientHelloAuthentication out; out.session_id.fill(1); out.session_id_size=32;
        out.verifier=[padding=std::array<std::uint8_t,40>{}](std::span<View const>) { return padding[0]!=0; }; return out;
    };
    deny_allocations=true;
    auto configured=usable->authenticate_first(no_allocation);
    deny_allocations=false;
    if (!configured) return 11;
    auto session=t::ClientSessionHandshake::create_authenticated(std::move(*usable));
    if (!session || !session->initial_record() || session->take_application_records()) return 12;

    auto failed=t::ClientHelloDriver::create(hello(),0x001d); if (!failed) return 13;
    auto invalid=[](View,::crypto::X25519Private const&)
        -> std::expected<t::ClientHelloAuthentication,t::ClientHelloDriverError> {
        t::ClientHelloAuthentication out; out.session_id_size=31;
        out.verifier=[](std::span<View const>) { return true; }; return out;
    };
    if (failed->authenticate_first(invalid) || failed->initial_record() ||
        t::ClientSessionHandshake::create_authenticated(std::move(*failed))) return 14;
    auto missing=t::ClientHelloDriver::create(hello(),0x001d); if (!missing) return 15;
    auto no_verifier=[](View,::crypto::X25519Private const&)
        -> std::expected<t::ClientHelloAuthentication,t::ClientHelloDriverError> {
        t::ClientHelloAuthentication out; out.session_id_size=32; return out;
    };
    if (missing->authenticate_first(no_verifier) || missing->initial_record()) return 16;
    auto throwing=t::ClientHelloDriver::create(hello(),0x001d); if (!throwing) return 17;
    try {
        (void)throwing->authenticate_first([](View,::crypto::X25519Private const&)
            -> std::expected<t::ClientHelloAuthentication,t::ClientHelloDriverError> { throw std::bad_alloc{}; });
        return 18;
    } catch (std::bad_alloc const&) {}
    if (throwing->initial_record() || throwing->initial_sent()) return 19;
    return 0;
}
