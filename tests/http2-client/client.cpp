import std;
import http2.client;
import http2.server;
import nexus.thirdparty.nghttp2;
namespace h=http2;
namespace c=nex::nghttp2;
struct Peer {
    std::vector<std::int32_t> opened,ended,closed;
    std::map<std::int32_t,std::vector<std::uint8_t>> request;
    std::unique_ptr<h::ServerSession> server;
    Peer() {
        h::ServerEvents events{this,
            [](void* p,std::int32_t id,std::span<h::Header const>,bool trailers,bool) noexcept { if (!trailers) static_cast<Peer*>(p)->opened.push_back(id); return true; },
            [](void* p,std::int32_t id,std::span<std::byte const> bytes) noexcept {
                auto& out=static_cast<Peer*>(p)->request[id]; for (auto byte:bytes) out.push_back(std::to_integer<std::uint8_t>(byte)); return h::DataDisposition::accepted;
            },
            [](void* p,std::int32_t id) noexcept { static_cast<Peer*>(p)->ended.push_back(id); return true; },
            [](void* p,std::int32_t id,std::uint32_t) noexcept { static_cast<Peer*>(p)->closed.push_back(id); }};
        auto result=h::ServerSession::create({8,100,8192,4*1024*1024,8*1024*1024},events);
        if (!result) std::abort(); server=std::move(*result);
    }
};
static auto fields(std::string_view path="/machine/register",std::string_view method="POST") -> std::array<h::FieldView,5> {
    return {{{":method",method},{":scheme","https"},{":authority","control.example"},{":path",path},{"content-type","application/json"}}};
}
static auto require(bool condition,unsigned line) -> void { if (!condition) { std::println("HTTP2 client failed at {}",line); std::exit(1); } }
template<class Client> auto pump(Client& client,Peer& peer) -> std::size_t {
    std::array<std::uint8_t,137> wire{}; std::size_t total=0;
    for (unsigned turn=0;turn<100000;++turn) {
        std::size_t moved=0;
        for (unsigned pass=0;pass<2;++pass) {
            auto size=pass ? peer.server->output({reinterpret_cast<std::byte*>(wire.data()),wire.size()}) : std::expected<std::size_t,h::ServerError>{0};
            std::size_t count=0;
            if (pass) { require(size.has_value(),__LINE__); count=*size; }
            else { auto result=client.output(wire); require(result.has_value(),__LINE__); count=*result; }
            if (!count) continue;
            moved+=count;
            for (std::size_t offset=0;offset<count;) {
                auto part=std::min(std::size_t{7},count-offset);
                std::size_t accepted=0;
                if (pass) { auto result=client.receive(std::span(wire).subspan(offset,part)); require(result.has_value(),__LINE__); accepted=*result; }
                else { auto result=peer.server->receive({reinterpret_cast<std::byte*>(wire.data()+offset),part}); require(result.has_value(),__LINE__); accepted=*result; }
                require(accepted && accepted<=part,__LINE__); offset+=accepted;
            }
        }
        total+=moved;
        if (!moved) return total;
    }
    require(false,__LINE__); return 0;
}
template<class Client> auto take(Client& client,h::StreamTicket ticket,std::uint8_t expected) -> std::size_t {
    auto bytes=client.peek(ticket); require(bytes.has_value(),__LINE__);
    require(std::ranges::all_of(*bytes,[expected](auto value) { return value==expected; }),__LINE__);
    auto size=bytes->size(); require(client.consume(ticket,size).has_value(),__LINE__); return size;
}
auto concurrent() -> void {
    h::ClientLimits limits; limits.stream_window=4096;
    auto made=h::Client<4>::create(limits); require(made.has_value(),__LINE__); auto& client=**made; Peer peer;
    std::array<std::uint8_t,3> json{'{','}','\n'};
    auto map=client.submit(fields("/machine/map"),{json,true});
    auto registration=client.submit(fields(),{json,true});
    auto update=client.submit(fields("/machine/update"),{{},false});
    require(map && registration && update && map->id==1 && registration->id==3 && update->id==5,__LINE__);
    pump(client,peer); require(peer.opened.size()==3,__LINE__);
    require(client.tx_consumed(*map)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    require(client.provide(*update,{json,true})==std::expected<bool,h::ClientFailure>{true},__LINE__);
    pump(client,peer); require(peer.request[5]==std::vector<std::uint8_t>(json.begin(),json.end()),__LINE__);
    std::vector<std::byte> body(180000,std::byte{73}); std::array<std::byte,5> short_body{};
    require(peer.server->respond_body(map->id,200,body).has_value(),__LINE__);
    require(peer.server->respond_body(registration->id,200,short_body).has_value(),__LINE__);
    require(peer.server->respond_empty(update->id,204).has_value(),__LINE__);
    pump(client,peer);
    auto response=client.response(*registration); require(response && response->status==200 && response->remote_end && response->closed,__LINE__);
    require(client.peek(*map) && client.peek(*map)->size()>0 && !client.response(*map)->remote_end,__LINE__);
    require(take(client,*registration,0)==5 && client.release(*registration)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    require(!client.response(*registration),__LINE__);
    auto renewed=client.submit(fields("/machine/register"),{json,true}); require(renewed && renewed->slot==registration->slot && renewed->generation>registration->generation,__LINE__);
    pump(client,peer); require(peer.server->respond_empty(renewed->id,200).has_value(),__LINE__); pump(client,peer);
    require(client.response(*renewed)->remote_end,__LINE__);
    std::size_t received=0;
    for (unsigned turn=0;turn<1000;++turn) {
        received+=take(client,*map,73); pump(client,peer);
        if (client.response(*map)->remote_end && client.peek(*map)->empty()) break;
    }
    require(received==body.size() && client.response(*map)->closed,__LINE__);
    require(client.release(*map)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    require(client.release(*update)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    require(client.release(*renewed)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    std::println("HTTP2 client simultaneous Map/register/update, independent manual credit and slot reuse passed");
}
auto cancel_and_credit() -> void {
    h::ClientLimits limits; limits.stream_window=4096;
    auto made=h::Client<2>::create(limits); require(made.has_value(),__LINE__); auto& client=**made; Peer peer;
    auto canceled=client.submit(fields(),{{},false}); require(canceled.has_value(),__LINE__);
    require(client.release(*canceled)==std::expected<bool,h::ClientFailure>{false},__LINE__);
    require(client.tx_consumed(*canceled)==std::expected<bool,h::ClientFailure>{true},__LINE__); // Empty body is already unborrowed.
    pump(client,peer); require(peer.opened.empty(),__LINE__);
    require(client.release(*canceled)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    auto map=client.submit(fields("/map")),other=client.submit(fields("/register")); require(map && other,__LINE__);
    pump(client,peer);
    std::vector<std::byte> body(200000,std::byte{7});
    auto submitted=peer.server->respond_body(map->id,200,body); if (!submitted) std::println("response error {}:{} id={} opened={} closed={}",int(submitted.error().kind),submitted.error().library_code,map->id,peer.opened,peer.closed); require(submitted.has_value(),__LINE__); pump(client,peer);
    require(!client.peek(*map)->empty(),__LINE__);
    require(client.reset(*map).has_value(),__LINE__); require(!*client.release(*map),__LINE__); pump(client,peer);
    require(client.response(*map)->failure && client.release(*map)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    require(peer.server->respond_body(other->id,200,body).has_value(),__LINE__); pump(client,peer);
    std::size_t total=0;
    for (unsigned turn=0;turn<1000;++turn) {
        total+=take(client,*other,7); pump(client,peer);
        if (client.response(*other)->remote_end && client.peek(*other)->empty()) break;
    }
    require(total==body.size() && client.response(*other)->closed,__LINE__);
    std::println("HTTP2 client pending-request cancellation and RST unread DATA credit preserve sibling progress");
}
auto shutdown() -> void {
    auto made=h::Client<2>::create(); require(made.has_value(),__LINE__); auto& client=**made; Peer peer;
    auto first=client.submit(fields()),second=client.submit(fields()); require(first && second,__LINE__);
    pump(client,peer); require(peer.server->start_shutdown().has_value(),__LINE__); pump(client,peer);
    require(client.goaway() && !client.submit(fields()),__LINE__);
    require(peer.server->finish_shutdown().has_value(),__LINE__); pump(client,peer);
    require(client.goaway()->last_id==second->id,__LINE__);
    require(peer.server->respond_empty(first->id,200).has_value() && peer.server->respond_empty(second->id,200).has_value(),__LINE__); pump(client,peer);
    if (!(client.response(*first)->closed && client.response(*second)->closed && client.goaway()->last_id==second->id)) std::println("shutdown first {} {} second {} {} last {} expected {}",client.response(*first)->status,client.response(*first)->closed,client.response(*second)->status,client.response(*second)->closed,client.goaway()->last_id,second->id); require(client.response(*first)->closed && client.response(*second)->closed && client.goaway()->last_id==second->id,__LINE__);
    std::println("HTTP2 client GOAWAY rejects new streams while accepted streams drain");
}
auto main() -> int { concurrent(); cancel_and_credit(); shutdown(); }
