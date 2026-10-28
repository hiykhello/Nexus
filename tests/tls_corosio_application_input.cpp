#include <boost/corosio/backend.hpp>
import std;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.tls.corosio_application;
namespace capy=nex::capy; namespace io=nex::corosio; namespace t=nexus::tls; namespace c=nexus::crypto; using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection dir,int n) -> t::RecordLayer { auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12); if (!key || !iv) std::abort(); auto l=t::RecordLayer::create(dir,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!l) std::abort(); return std::move(*l); }
auto app(int send,int recv) -> t::ApplicationIo { return t::ApplicationIo(t::ApplicationRecords(layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,recv),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),t::ApplicationRole::client)); }
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
 io::local_stream_socket a{context},b{context}; t::ApplicationIo receiver=app(1,2), sender=app(2,1); std::optional<t::detail::ApplicationInput> input; int result=0; bool done=false;
    ~Fixture() { a.close(); b.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(1); }
};
auto run(Fixture& f,bool truncated) -> capy::task<> {
    if (truncated) { auto r=co_await f.input->read(f.a,f.receiver); f.result=(!r && r.error()==t::detail::AsyncApplicationError::truncated) ? 1 : -1; f.done=true; co_return; }
    auto a=co_await f.input->read(f.a,f.receiver); if (!a || !a->event || a->event->data!=Bytes({1,2,3})) { f.result=-2; f.done=true; co_return; }
    auto b=co_await f.input->read(f.a,f.receiver); if (!b || !b->event || b->event->kind!=t::ApplicationEventKind::close_notify) { f.result=-3; f.done=true; co_return; }
    auto eof=co_await f.input->read(f.a,f.receiver); f.result=(eof && eof->kind==t::detail::AsyncReadKind::eof) ? 1 : -4; f.done=true;
}
auto backpressure(Fixture& f) -> capy::task<> {
    auto update=co_await f.input->read(f.a,f.receiver);
    if (!update || !update->event || update->event->kind!=t::ApplicationEventKind::key_update_requested) { f.result=-5; f.done=true; co_return; }
    auto blocked=co_await f.input->read(f.a,f.receiver);
    if (!blocked || blocked->kind!=t::detail::AsyncReadKind::backpressure) { f.result=-6; f.done=true; co_return; }
    auto n=f.receiver.pending_output().size(); if (!f.receiver.written(n) || f.receiver.pending_output().empty()) { f.result=-7; f.done=true; co_return; }
    auto data=co_await f.input->read(f.a,f.receiver);
    f.result=data && data->event && data->event->data==Bytes({1,2,3}) ? 1 : -8; f.done=true;
}
int main() {
    for (bool truncated:{false,true}) {
        Fixture f; if (io::connect_pair(f.a,f.b)) return 1; Bytes buffered;
        if (!truncated) { if (!f.sender.send(Bytes{1,2,3})) return 2; auto p=f.sender.pending_output(); buffered.insert(buffered.end(),p.begin(),p.end()); if (!f.sender.written(p.size()) || !f.sender.close_notify()) return 3; p=f.sender.pending_output(); buffered.insert(buffered.end(),p.begin(),p.end()); }
        f.input.emplace(std::move(buffered)); f.b.close(); capy::run_async(f.context.get_executor())(run(f,truncated)); (void)f.context.run_for(1s);
        if (!f.done || f.result!=1) { std::cerr << "input result " << f.result << '\n'; return 4; }
    }
    {
        Fixture f; if (io::connect_pair(f.a,f.b) || !f.receiver.send(Bytes{9}) || !f.sender.request_key_update(true)) return 5;
        auto pending=f.sender.pending_output(); Bytes buffered(pending.begin(),pending.end());
        if (!f.sender.written(pending.size()) || !f.sender.send(Bytes{1,2,3})) return 6;
        pending=f.sender.pending_output(); buffered.insert(buffered.end(),pending.begin(),pending.end());
        f.input.emplace(std::move(buffered)); capy::run_async(f.context.get_executor())(backpressure(f)); (void)f.context.run_for(1s);
        if (!f.done || f.result!=1) return 7;
    }
    std::cout << "Corosio TLS buffered input, close and truncated EOF passed\n";
}
