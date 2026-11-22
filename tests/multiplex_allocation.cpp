import std;
import grpc.multiplex;
import grpc.headers;
import grpc.session;
using namespace grpc;
extern "C" auto meter_begin(std::size_t,std::size_t)->void;
extern "C" auto meter_end()->std::size_t;
extern "C" auto meter_failed()->bool;
extern "C" auto meter_live()->std::size_t;
extern "C" auto meter_persistent(bool)->void;
using Peer=MultiplexSession<4>;
static auto require(bool value)->void{if(!value)throw std::runtime_error("assertion failed");}
template<class T>static auto take(std::expected<T,Failure> value)->T{require(bool(value));return std::move(*value);}
static auto pump(Peer& a,Peer& b)->bool{
    std::array<std::uint8_t,16384> buffer{};
    for(unsigned turn=0;turn<10000;++turn){bool progress=false;
        for(unsigned direction=0;direction<2;++direction){auto& from=direction?b:a;auto& to=direction?a:b;
            auto size=from.output(buffer);if(!size)return false;if(!*size)continue;progress=true;
            auto input=std::span(buffer).first(*size);auto received=to.receive(input);if(!received||*received!=input.size())return false;
        }
        if(!progress)return true;
    }
    return false;
}
static auto config()->Limits{Limits value;value.hunk_bytes=4096;value.message_bytes=4160;value.input_window=8192;return value;}
struct Pair{
    RequestProfile profile=*RequestProfile::create("test","localhost",false);
    std::unique_ptr<Peer> client=take(Peer::create(Role::client,profile,ResponsePolicy::standard,config()));
    std::unique_ptr<Peer> server=take(Peer::create(Role::server,profile,ResponsePolicy::standard,config()));
    RpcTicket healthy{},accepted{};
    Pair(){require(pump(*client,*server));healthy=take(client->open());require(pump(*client,*server));auto value=server->accept();require(value.has_value());accepted=*value;}
    auto recovery()->bool{
        std::array<std::uint8_t,3> payload{3,5,7};if(!client->queue(healthy,payload)||!pump(*client,*server))return false;
        std::array<std::uint8_t,3> output{};auto read=server->pull(accepted,output);return read&&read->size==3&&output==payload;
    }
};
static auto trial(std::string_view operation,std::size_t kind,std::size_t point,bool persistent)->int{
    std::size_t calls=0;bool fired=false,outcome=false,preserved=false;
    auto profile=*RequestProfile::create("test","localhost",false);
    meter_persistent(persistent);
    if(operation=="create"){
        meter_begin(kind,point);auto value=Peer::create(Role::client,profile,ResponsePolicy::standard,config());calls=meter_end();fired=meter_failed();outcome=bool(value);
        if(value)value->reset();
    }else{
        Pair pair;RpcTicket selected{};std::array<std::uint8_t,1024> data{};
        if(operation=="open"){
            meter_begin(kind,point);auto opened=pair.client->open();calls=meter_end();fired=meter_failed();outcome=bool(opened);
        }else if(operation=="queue"||operation=="pull"||operation=="trailers"||operation=="release"){
            selected=take(pair.client->open());require(pump(*pair.client,*pair.server));auto accepted=pair.server->accept();require(accepted.has_value());
            if(operation=="queue"){
                meter_begin(kind,point);auto queued=pair.client->queue(selected,data);calls=meter_end();fired=meter_failed();outcome=queued&&*queued;
            }else if(operation=="pull"){
                require(bool(pair.client->queue(selected,data)));require(pump(*pair.client,*pair.server));
                meter_begin(kind,point);auto read=pair.server->pull(*accepted,data);calls=meter_end();fired=meter_failed();outcome=read&&read->size==data.size();
            }else if(operation=="trailers"){
                require(bool(pair.server->queue(*accepted,data)));require(bool(pair.server->close_output(*accepted)));
                std::array<std::uint8_t,16384> output{};
                meter_begin(kind,point);auto size=pair.server->output(output);calls=meter_end();fired=meter_failed();outcome=size&&*size;
                if(size&&*size)(void)pair.client->receive(std::span(output).first(*size));
            }else{
                meter_begin(kind,point);auto released=pair.client->release(selected);calls=meter_end();fired=meter_failed();outcome=bool(released);
            }
        }else if(operation=="output"){
            selected=take(pair.client->open());std::array<std::uint8_t,16384> output{};
            meter_begin(kind,point);auto size=pair.client->output(output);calls=meter_end();fired=meter_failed();outcome=size&&*size;
            if(size&&*size)(void)pair.server->receive(std::span(output).first(*size));
        }else if(operation=="headers"){
            selected=take(pair.client->open());std::vector<std::uint8_t> wire;std::array<std::uint8_t,16384> buffer{};
            for(;;){auto size=take(pair.client->output(buffer));if(!size)break;wire.insert(wire.end(),buffer.begin(),buffer.begin()+size);}
            require(!wire.empty());
            meter_begin(kind,point);auto received=pair.server->receive(wire);calls=meter_end();fired=meter_failed();outcome=received&&pair.server->accept().has_value();
        }else throw std::runtime_error("unknown operation");
        if(!pair.client->failure()&&!pair.server->failure()){
            // Drain any stream-local reset before proving the original other
            // RPC still works. A fatal native failure is connection-scoped.
            require(pump(*pair.client,*pair.server));preserved=pair.recovery();require(preserved);
        }
    }
    auto live=meter_live();require(!live);require(point||outcome);
    Pair fresh;require(fresh.recovery());
    std::println("operation={} kind={} point={} persistent={} calls={} fired={} outcome={} other-rpc-preserved={} live={} fresh-recovery=true",operation,kind,point,persistent,calls,fired,outcome,preserved,live);
    return point&&!fired?77:0;
}
int main(int argc,char** argv){try{
    if(argc!=5)return 2;return trial(argv[1],std::stoul(argv[2]),std::stoul(argv[3]),std::string_view(argv[4])=="persistent");
}catch(std::exception const& error){std::println("exception {}",error.what());return 1;}}
