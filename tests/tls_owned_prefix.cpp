import std;
import crypto;
import tls.client_flight;
import tls.application_io;
import tls.corosio_application;
import tls.byte_stream;
import capy;
import corosio;
namespace c = ::crypto;
namespace t=tls;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Bytes=c::Bytes;
thread_local bool reject_allocation=false;
auto operator new(std::size_t size) -> void* {
    if (reject_allocation) throw std::bad_alloc();
    auto* result=std::malloc(std::max<std::size_t>(size,1));
    if (!result) throw std::bad_alloc(); return result;
}
auto operator delete(void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { std::free(pointer); }
struct Socket {
    unsigned reads=0,writes=0;
    Bytes input; std::size_t offset=0;
    auto read_some(capy::mutable_buffer output) -> capy::task<capy::results<std::size_t>> {
        ++reads;
        if (offset==input.size()) co_return capy::results<std::size_t>{std::make_error_code(std::errc::io_error),0};
        auto size=std::min(output.size(),input.size()-offset);
        std::copy_n(input.data()+offset,size,static_cast<std::uint8_t*>(output.data())); offset+=size;
        co_return capy::results<std::size_t>{std::error_code{},size};
    }
    auto write_some(capy::const_buffer bytes) -> capy::task<capy::results<std::size_t>> {
        ++writes; co_return capy::results<std::size_t>{std::error_code{},bytes.size()};
    }
    auto cancel() noexcept -> void {}
};
auto secret(unsigned value) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(value))); }
auto layer(t::RecordDirection direction,unsigned value) -> t::RecordLayer {
    auto s=secret(value);
    auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16),iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort();
    auto result=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!result) std::abort(); return std::move(*result);
}
auto records(bool client) -> t::ApplicationRecords {
    auto send=client ? 1u : 2u,receive=client ? 2u : 1u;
    return {layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,receive),16385,16385,
        c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(receive),client ? t::ApplicationRole::client : t::ApplicationRole::server};
}
using Stream=t::detail::ByteStream<Socket>;
auto exercise(Stream& stream,Socket& socket,bool& passed) -> capy::task<> {
    auto deadline=std::chrono::steady_clock::now()+1s;
    Bytes initial(4096),prefix(257,0xee);
    auto first=co_await stream.read(initial,deadline);
    if (!first || *first!=initial.size()) co_return;
    Bytes oversized(16385,0xaa);
    if (stream.prepend_owned(std::move(oversized)) || oversized.size()!=16385) co_return;
    auto saved=prefix; bool threw=false;
    reject_allocation=true;
    try { (void)stream.prepend_owned(std::move(prefix)); } catch (std::bad_alloc const&) { threw=true; }
    reject_allocation=false;
    if (!threw || prefix!=saved) co_return;
    if (!stream.prepend_owned(std::move(prefix))) co_return;
    Bytes output(257+8192-4096);
    auto received=co_await stream.read(output,deadline);
    if (!received || *received!=output.size() || !std::ranges::equal(std::span(output).first(257),saved)) co_return;
    for (std::size_t i=257;i<output.size();++i) if (output[i]!=static_cast<std::uint8_t>(i-257+4096)) co_return;
    // With no retained suffix, owned prepend moves the existing vector.
    prefix=Bytes(32,0x39);
    reject_allocation=true;
    bool moved=stream.prepend_owned(std::move(prefix));
    reject_allocation=false;
    if (!moved || !prefix.empty()) co_return;
    std::array<std::uint8_t,32> moved_output{};
    if (!co_await stream.read(moved_output,deadline) || !std::ranges::all_of(moved_output,[](auto v) { return v==0x39; })) co_return;
    auto* reader=stream.release_reader();
    if (!reader || stream.release_reader()!=reader || stream.prepend_owned(Bytes{1}) || stream.prepend(std::array<std::uint8_t,1>{1})) co_return;
    if (co_await stream.read(moved_output,deadline)) co_return;
    auto tail=co_await reader->read_some(moved_output,deadline);
    if (!tail || tail->kind!=t::detail::AsyncStreamReadKind::data || tail->size!=3 || moved_output[0]!=7 || moved_output[1]!=8 || moved_output[2]!=9) co_return;
    if (!co_await stream.send(std::array<std::uint8_t,1>{5},deadline) || !co_await stream.close_output(deadline)) co_return;
    auto end=co_await reader->read_some(moved_output,deadline);
    passed=end && end->event && end->event->kind==t::ApplicationEventKind::close_notify && socket.reads==2 && socket.writes==2;
}
auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        auto context=io::make_io_context(uring);
        auto peer=records(false);
        Bytes plaintext(8192);
        for (std::size_t i=0;i<plaintext.size();++i) plaintext[i]=static_cast<std::uint8_t>(i);
        auto wire=peer.seal(plaintext),tail=peer.seal(Bytes{7,8,9}),end=peer.close_notify();
        if (!wire || !tail || !end) return 1;
        wire->insert(wire->end(),tail->begin(),tail->end()); wire->insert(wire->end(),end->begin(),end->end());
        // A real TLS handshake retains at most one 4096-byte transport block.
        // The 8KiB application record must arrive through bounded socket reads.
        Bytes unread(wire->begin(),wire->begin()+4096);
        Socket socket; socket.input.assign(wire->begin()+4096,wire->end());
        t::detail::ApplicationConnection<Socket> connection(socket,records(true),std::move(unread));
        Stream stream(connection); bool passed=false;
        capy::run_async(context.get_executor())(exercise(stream,socket,passed));
        context.run_for(2s);
        if (!context.stopped() || !passed || !connection.idle()) return 2;
    }
    std::println("TLS owned prefix/same-record suffix order, allocation rollback, zero-copy move and read-only ownership handoff passed");
}

