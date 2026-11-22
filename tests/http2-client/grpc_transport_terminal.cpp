import std;
import grpc.headers;
import grpc.session;
namespace g=grpc;
struct Pair {
    std::unique_ptr<g::Session> client,server;
    bool valid=true;
    Pair(){
        auto profile=g::RequestProfile::create("nexus.Service","cover.example",false);
        if(!profile){valid=false;return;}
        auto c=g::Session::create(g::Role::client,*profile),s=g::Session::create(g::Role::server,*profile);
        if(!c||!s){valid=false;return;}client=std::move(*c);server=std::move(*s);
    }
    auto move(g::Session& from,g::Session& to) -> std::size_t {
        std::array<std::uint8_t,16384> bytes{};std::size_t total=0;
        for(unsigned count=0;count<10000;++count){
            auto size=from.output(bytes);if(!size){valid=false;return total;}if(!*size)return total;
            auto received=to.receive(std::span(bytes).first(*size));if(!received||*received!=*size){valid=false;return total;}total+=*size;
        }valid=false;return total;
    }
    auto pump() -> bool {
        for(unsigned count=0;count<10000&&valid;++count){auto c=move(*client,*server),s=move(*server,*client);if(!c&&!s)return valid;}
        return false;
    }
};
auto exercise(bool server,bool local_end,std::uint8_t code) -> bool {
    Pair pair;if(!pair.valid||!pair.pump())return false;
    auto& target=server?*pair.server:*pair.client;auto& peer=server?*pair.client:*pair.server;
    if(!peer.queue(std::array<std::uint8_t,3>{1,2,3})||!pair.pump())return false;
    if(local_end&&(!target.close_output()||!pair.pump()))return false;
    if(target.remote_ended()||target.transport_ended()||target.local_ended()!=local_end)return false;
    auto accepted=target.receive(std::array<std::uint8_t,13>{0,0,4,3,0,0,0,0,1,0,0,0,code});
    if(code){return !accepted&&accepted.error().error==g::Error::reset&&accepted.error().code==code&&!target.transport_ended();}
    if(!accepted||target.failure()||target.remote_ended()||target.transport_ended()!=(server&&local_end))return false;
    std::array<std::uint8_t,16> bytes{};auto data=target.pull(bytes);
    if(!data||data->size!=3||data->eof||!std::ranges::equal(std::span(bytes).first(3),std::array<std::uint8_t,3>{1,2,3}))return false;
    auto end=target.pull(bytes);
    return !end&&end.error().error==g::Error::reset&&end.error().code==0&&!target.remote_ended()&&!target.transport_ended();
}
auto main() -> int {
    for(bool server:{false,true})for(bool local_end:{false,true})for(std::uint8_t code:{0,8}){
        if(!exercise(server,local_end,code)){std::println("gRPC terminal role={} local_end={} code={} failed",server,local_end,code);return 1;}
    }
    Pair pair;if(!pair.valid||!pair.pump()||!pair.client->close_output()||!pair.server->close_output()||!pair.pump()||
        !pair.client->transport_ended()||!pair.server->transport_ended())return 2;
    std::println("gRPC transport terminal preserves NO_ERROR/CANCEL reader errors, retained bytes, role and genuine END boundaries: 9 cases passed");
}
