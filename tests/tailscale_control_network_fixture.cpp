import std;
import tailscale.control;
import net.socket_stream;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tailscale::control;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::tcp_socket>;
struct Fixture {
    io::io_context context;
    io::tcp_socket socket{context};
    bool done=false,passed=false;
    std::string_view stage="connect";
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
struct Cancel {Lower& stream;t::Records& records;~Cancel() {records.cancel();stream.cancel();}};
auto read_exact(Lower& lower,std::span<std::uint8_t> bytes,t::Clock::time_point deadline) -> capy::task<bool> {
    while (!bytes.empty()) {
        auto n=co_await lower.read(bytes,deadline);if (!n || !*n || *n>bytes.size()) co_return false;bytes=bytes.subspan(*n);
    }
    co_return true;
}
auto send_fragmented(Lower& lower,std::span<std::uint8_t const> bytes,t::Clock::time_point deadline) -> capy::task<bool> {
    auto first=std::min(std::size_t{19},bytes.size());
    while (first) {
        auto size=std::min(std::size_t{3},first);if (!co_await lower.send(bytes.first(size),deadline)) co_return false;
        bytes=bytes.subspan(size);first-=size;
    }
    co_return bytes.empty() || co_await lower.send(bytes,deadline);
}
struct Channel {
    Lower& lower;
    t::Records& records;
    t::RecordDecoder decoder;
    std::array<std::uint8_t,t::max_record_wire> input{};
    std::array<std::uint8_t,t::max_record_plaintext> plaintext{};
    std::size_t begin=0,end=0,plain_begin=0,plain_end=0;
    auto next(t::Clock::time_point deadline) -> capy::task<bool> {
        if (decoder.ready() && !decoder.consume()) co_return false;
        for (;;) {
            if (begin==end) {
                auto n=co_await lower.read(input,deadline);if (!n || !*n || *n>input.size()) co_return false;
                begin=0;end=*n;
            }
            auto n=decoder.feed(std::span(input).subspan(begin,end-begin));if (!n) co_return false;begin+=*n;
            if (decoder.ready()) {
                auto opened=records.open_to(plaintext,decoder.wire());if (!opened) co_return false;
                plain_begin=0;plain_end=*opened;co_return true;
            }
        }
    }
    auto read(std::span<std::uint8_t> bytes,t::Clock::time_point deadline) -> capy::task<bool> {
        while (!bytes.empty()) {
            if (plain_begin==plain_end) {if (!co_await next(deadline)) co_return false;if (plain_begin==plain_end) continue;}
            auto size=std::min(bytes.size(),plain_end-plain_begin);
            std::copy_n(plaintext.begin()+plain_begin,size,bytes.begin());plain_begin+=size;bytes=bytes.subspan(size);
        }
        co_return true;
    }
    auto write(std::span<std::uint8_t const> bytes,t::Clock::time_point deadline) -> capy::task<bool> {
        std::array<std::uint8_t,t::max_record_wire> wire{};
        do {
            auto size=std::min(bytes.size(),t::max_record_plaintext);
            auto sealed=records.seal_to(wire,bytes.first(size));if (!sealed) co_return false;
            struct Pending {t::Records& owner;bool sent=false;~Pending() {if (!sent) owner.fail_send();}} pending{records};
            if (!co_await lower.send(std::span(wire).first(*sealed),deadline) || !records.sent()) co_return false;
            pending.sent=true;bytes=bytes.subspan(size);
        } while (!bytes.empty());
        co_return true;
    }
};
template<class Key> auto fixed_key(unsigned seed) -> std::expected<Key,::crypto::Error> {
    t::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+seed);
    auto key=Key::from_bytes(bytes);::crypto::cleanse(bytes);return key;
}
template<t::Role Side>
auto handshake(Fixture& fixture,Lower& lower,t::Records& records,t::ControlPublic pin,t::MachinePublic machine,std::uint16_t version,
    t::Clock::time_point started,t::Clock::time_point deadline) -> capy::task<std::optional<t::KeyBytes>> {
    auto ephemeral=fixed_key<t::EphemeralPrivate>(Side==t::Role::client ? 141 : 211);if (!ephemeral) co_return std::nullopt;
    if constexpr (Side==t::Role::client) {
        fixture.stage="machine key";
        auto local=fixed_key<t::MachinePrivate>(3);if (!local || local->public_key()!=machine) co_return std::nullopt;
        t::ClientHandshake owner(*local,pin,version,started,deadline);
        fixture.stage="client initiation";
        auto first=owner.start(std::move(*ephemeral),t::Clock::now());if (!first) co_return std::nullopt;
        fixture.stage="client handshake write";if (!co_await send_fragmented(lower,*first,deadline)) co_return std::nullopt;
        std::array<std::uint8_t,t::response_size> response{};
        fixture.stage="server response read";if (!co_await read_exact(lower,response,deadline)) co_return std::nullopt;
        fixture.stage="server response authentication";
        if (!owner.finish(response,t::Clock::now()) || owner.control_peer()!=pin || owner.protocol_version()!=version) co_return std::nullopt;
        fixture.stage="client transport install";
        auto keys=owner.take_transport();if (!keys || !records.install(std::move(*keys))) co_return std::nullopt;
        co_return owner.handshake_hash();
    } else {
        fixture.stage="control key";
        auto local=fixed_key<t::ControlPrivate>(71);if (!local || local->public_key()!=pin) co_return std::nullopt;
        t::ServerHandshake owner(*local,started,deadline);std::array<std::uint8_t,t::initiation_size> initial{};
        fixture.stage="client initiation read";if (!co_await read_exact(lower,initial,deadline)) co_return std::nullopt;
        fixture.stage="client initiation authentication";
        auto response=owner.respond(initial,std::move(*ephemeral),t::Clock::now());
        if (!response || owner.machine_peer()!=machine || owner.protocol_version()!=version) co_return std::nullopt;
        fixture.stage="server handshake write";if (!co_await send_fragmented(lower,*response,deadline)) co_return std::nullopt;
        fixture.stage="server transport install";
        auto keys=owner.take_transport();if (!keys || !records.install(std::move(*keys))) co_return std::nullopt;
        co_return owner.handshake_hash();
    }
}
auto payload(std::size_t size,bool invert) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> bytes(size);for (std::size_t i=0;i<size;++i) bytes[i]=static_cast<std::uint8_t>(i*17+size)^(invert ? 0x5a : 0);return bytes;
}
auto direction(capy::task<bool> operation,Channel& channel) -> capy::task<capy::results<>> {
    if (co_await std::move(operation)) co_return capy::results<>{};
    channel.records.cancel();channel.lower.cancel();co_return capy::results<>{std::make_error_code(std::errc::io_error)};
}
auto application(Fixture& fixture,Channel& channel,t::KeyBytes hash,bool initiator,t::Clock::time_point deadline) -> capy::task<bool> {
    fixture.stage="handshake hash";t::KeyBytes peer_hash{};
    if (initiator) {
        if (!co_await channel.write({},deadline) || !co_await channel.write(hash,deadline) || !co_await channel.read(peer_hash,deadline) || peer_hash!=hash) co_return false;
    } else {
        if (!co_await channel.read(peer_hash,deadline) || peer_hash!=hash || !co_await channel.write({},deadline) || !co_await channel.write(hash,deadline)) co_return false;
    }
    fixture.stage="record payloads";
    for (std::size_t size:{1,17,4077,4078,16384,262144}) {
        auto original=payload(size,false),reply=payload(size,true);std::vector<std::uint8_t> actual(size);
        if (initiator) {
            if (!co_await channel.write(original,deadline) || !co_await channel.read(actual,deadline) || actual!=reply) co_return false;
        } else {
            if (!co_await channel.read(actual,deadline) || actual!=original || !co_await channel.write(reply,deadline)) co_return false;
        }
    }
    fixture.stage="simultaneous MiB";
    auto outgoing=payload(1024*1024,initiator),expected=payload(1024*1024,!initiator);std::vector<std::uint8_t> incoming(expected.size());
    auto [error,upload,download]=co_await capy::when_all(direction(channel.write(outgoing,deadline),channel),direction(channel.read(incoming,deadline),channel));
    (void)upload;(void)download;co_return !error && incoming==expected;
}
template<t::Role Side>
auto run(Fixture& fixture,std::uint16_t port,t::ControlPublic pin,t::MachinePublic machine,std::uint16_t version) -> capy::task<> {
    auto started=t::Clock::now(),deadline=started+10s;
    auto [error]=co_await io::timeout(fixture.socket.connect(io::endpoint(io::ipv4_address::loopback(),port)),deadline);if (error) co_return;
    Lower lower(fixture.socket);t::Records records;Cancel cancel{lower,records};fixture.stage="Noise handshake";
    auto binding=co_await handshake<Side>(fixture,lower,records,pin,machine,version,started,deadline);if (!binding) co_return;
    Channel channel{lower,records};fixture.passed=co_await application(fixture,channel,*binding,Side==t::Role::client,deadline);
}
auto root(Fixture& fixture,std::uint16_t port,t::ControlPublic pin,t::MachinePublic machine,std::uint16_t version,bool client) -> capy::task<> {
    try {
        if (client) co_await run<t::Role::client>(fixture,port,pin,machine,version);
        else co_await run<t::Role::server>(fixture,port,pin,machine,version);
    } catch (...) {fixture.passed=false;}
    fixture.socket.close();fixture.done=true;
}
auto decode(std::string_view text) -> std::optional<t::KeyBytes> {
    if (text.size()!=64) return std::nullopt;t::KeyBytes bytes{};
    auto digit=[](char c)->int {if (c>='0' && c<='9') return c-'0';if (c>='a' && c<='f') return c-'a'+10;return -1;};
    for (unsigned i=0;i<32;++i) {auto one=digit(text[i*2]),two=digit(text[i*2+1]);if (one<0 || two<0) return std::nullopt;bytes[i]=static_cast<std::uint8_t>(one*16+two);}return bytes;
}
auto number(std::string_view text,unsigned& value) -> bool {auto result=std::from_chars(text.data(),text.data()+text.size(),value);return result.ec==std::errc{} && result.ptr==text.data()+text.size();}
auto main(int argc,char** argv) -> int {
    if (argc!=7) return 64;unsigned port=0,backend=0,version=0;
    auto pin=decode(argv[2]),machine=decode(argv[3]);auto role=std::string_view(argv[5]);
    if (!number(argv[1],port) || !port || port>65535 || !number(argv[4],backend) || backend>1 || !number(argv[6],version) || version>65535 ||
        !pin || !machine || (role!="client" && role!="server")) return 64;
    if (backend && !io::has_uring) return 77;Fixture fixture(backend!=0);
    capy::run_async(fixture.context.get_executor())(root(fixture,static_cast<std::uint16_t>(port),*t::ControlPublic::from_bytes(*pin),
        *t::MachinePublic::from_bytes(*machine),static_cast<std::uint16_t>(version),role=="client"));
    fixture.context.run_for(12s);if (!fixture.done) {fixture.socket.close();fixture.context.restart();fixture.context.run_for(1s);}
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(65);
    if (!fixture.passed) {std::cerr<<"Control fixture failed at "<<fixture.stage<<'\n';return 1;}
    std::println("control-network-passed");
}
