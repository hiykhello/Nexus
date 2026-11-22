#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <cerrno>
import std;
import vision;
import vision.corosio_writer;
import tls.application_io;
import tls.corosio_application;
import net.stream_relay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace v=vision; namespace t=tls; namespace c = ::crypto; namespace capy=nex::capy; namespace io=nex::corosio;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto value=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!value) std::abort(); return std::move(*value);
}
auto records() -> t::ApplicationRecords { return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),t::ApplicationRole::client}; }
using Writer=v::detail::Writer<io::local_stream_socket>;
auto execute(auto& writer,Bytes data,bool& success,t::detail::ApplicationDeadline deadline={}) -> capy::task<> {
    success=(co_await writer.write(data)) && writer.status()==v::SendStatus::direct && (co_await writer.write(Bytes{9,8,7})) && (co_await writer.close_output(deadline));
}
struct Stream {
    io::local_stream_socket& socket; int close_mode=0; unsigned closes=0,cancels=0;
    auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,int>> {
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
        if (capy::is_eof(error)) co_return 0;
        if (error) co_return std::unexpected(1);
        co_return n;
    }
    auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        while (!bytes.empty()) {
            auto [error,n]=co_await socket.write_some(capy::const_buffer(bytes.data(),bytes.size()));
            if (error || !n || n>bytes.size()) co_return false;
            bytes=bytes.subspan(n);
        }
        co_return true;
    }
    auto close_output() -> capy::task<bool> {
        ++closes;
        if (close_mode==2) {
            std::array<std::uint8_t,1> byte{};
            auto [error,n]=co_await socket.read_some(capy::mutable_buffer(byte.data(),byte.size()));
            (void)n; co_return !error;
        }
        co_return close_mode==0 && !socket.shutdown(io::shutdown_send);
    }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};
auto blocked_write(Writer& writer,bool& done,bool& success) -> capy::task<> {
    Bytes data(8192,42); success=co_await writer.write(data); done=true;
}
template<class Backend> auto cancel_test(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    std::array<char,4096> filler{};
    for (;;) {
        auto n=::send(a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n>0 || (n<0 && errno==EINTR)) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        return false;
    }
    t::detail::ApplicationConnection connection(a,records(),{}); v::TrafficFilter filter; v::UserId user{};
    Writer writer(a,connection,filter,user); bool done=false,success=false;
    capy::run_async(context.get_executor())(blocked_write(writer,done,success));
    context.restart(); (void)context.run_for(30ms);
    if (done || connection.idle()) { writer.cancel(); return false; }
    writer.cancel(); context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && !success && connection.idle() && !connection.active();
}
template<bool Adapted,class Backend> auto run(Backend backend,int close_mode=0) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    Stream stream{a,close_mode}; net::ByteStreamAdapter adapter(stream);
    auto& socket=[&]() -> auto& { if constexpr (Adapted) return adapter; else return a; }();
    t::detail::ApplicationConnection connection(socket,records(),{}); v::TrafficFilter filter;
    Bytes hello(85); hello[0]=0x16; hello[1]=hello[2]=3; hello[4]=80; hello[5]=2; hello[43]=32; hello[76]=0x13; hello[77]=1;
    std::array<std::uint8_t,6> extension{0,0x2b,0,2,3,4}; std::ranges::copy(extension,hello.begin()+79); filter.observe(hello);
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0}); v::detail::Writer writer(socket,connection,filter,user);
    Bytes data(8192,0x55); data[0]=0x17; data[1]=data[2]=3; data[3]=0x1f; data[4]=0xfb;
    bool success=false; auto begin=std::chrono::steady_clock::now();
    t::detail::ApplicationDeadline deadline=close_mode==2 ? t::detail::ApplicationDeadline{begin+50ms} : std::nullopt;
    capy::run_async(context.get_executor())(execute(writer,data,success,deadline)); context.restart(); (void)context.run_for(3s);
    if (close_mode) return context.stopped() && !success && connection.idle() && stream.closes==1 && stream.cancels>=1 &&
        (close_mode!=2 || std::chrono::steady_clock::now()-begin<1s);
    if (!context.stopped() || !success || !connection.idle() || (Adapted && stream.closes!=1)) { writer.cancel(); return false; }
    Bytes wire; std::array<std::uint8_t,4096> buffer{};
    for (;;) {
        auto n=::recv(b.native_handle(),buffer.data(),buffer.size(),0);
        if (n<0 && errno==EINTR) continue;
        if (n<0 || wire.size()+static_cast<std::size_t>(n)>20000) return false;
        if (!n) break;
        wire.insert(wire.end(),buffer.begin(),buffer.begin()+n);
    }
    if (wire.size()<8 || !std::ranges::equal(std::span(wire).last(3),std::array<std::uint8_t,3>{9,8,7})) return false;
    auto cipher=layer(t::RecordDirection::receive,1); auto plain=cipher.open(std::span(wire).first(wire.size()-3));
    if (!plain) return false;
    v::Receiver receiver(user); Bytes decoded(data.size()); auto step=receiver.feed(plain->content,decoded);
    return step.status==v::ReceiveStatus::direct && step.consumed==plain->content.size() && step.written==data.size() && decoded==data;
}
int main() {
    if (!run<false>(io::epoll) || !run<true>(io::epoll) || !run<true>(io::epoll,1) || !run<true>(io::epoll,2) || !cancel_test(io::epoll)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!run<false>(io::uring) || !run<true>(io::uring) || !run<true>(io::uring,1) || !run<true>(io::uring,2) || !cancel_test(io::uring)) return 2;
#endif
    std::cout << "Vision writer TLS-to-raw ordering and shutdown passed\n";
}
