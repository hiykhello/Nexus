import std;
import grpc.multiplex;
import grpc.session;
import grpc.headers;

using namespace grpc;
static auto require(bool value,std::string_view label)->void {if(!value)throw std::runtime_error(std::string(label));}
template<class T>static auto take(std::expected<T,Failure> value,std::string_view label)->T {
    if(!value)throw std::runtime_error(std::string(label)+" error "+std::to_string(int(value.error().error))+" code "+std::to_string(value.error().code));
    return std::move(*value);
}
template<class A,class B>static auto move(A& a,B& b,std::size_t fragment)->bool {
    std::array<std::uint8_t,16384> output{};
    auto count=take(a.output(std::span(output).first(fragment)),"output");if(!count)return false;
    std::span<std::uint8_t const> pending=std::span(output).first(count);
    while(!pending.empty()){auto consumed=take(b.receive(pending),"receive");require(consumed&&consumed<=pending.size(),"receive progress");pending=pending.subspan(consumed);}
    a.written();
    return true;
}
template<class A,class B>static auto pump(A& a,B& b,std::size_t fragment)->void {
    for(unsigned i=0;i<1000000;++i){auto up=move(a,b,fragment);auto down=move(b,a,fragment);if(!up&&!down)return;}
    throw std::runtime_error("pump stuck");
}
static auto limits()->Limits {Limits value;value.hunk_bytes=4096;value.message_bytes=4160;value.input_window=8192;value.output_bytes=32768;return value;}
template<class P>static auto bytes(P& peer,RpcTicket ticket,std::span<std::uint8_t const> expected,bool allow_eof=false)->void {
    std::vector<std::uint8_t> received;std::array<std::uint8_t,711> buffer{};
    for(unsigned i=0;i<100;++i){auto pulled=take(peer.pull(ticket,buffer),"pull");if(pulled.size)received.insert(received.end(),buffer.begin(),buffer.begin()+pulled.size);else{require(!pulled.eof||allow_eof,"not early EOF");break;}}
    require(std::ranges::equal(received,expected),"payload equal");
}
static auto run(std::size_t fragment)->void {
    auto profile=take(RequestProfile::create("test","localhost",false).transform_error([](auto){return Failure{Error::headers};}),"profile");
    using Peer=MultiplexSession<4>;
    auto client=take(Peer::create(Role::client,profile,ResponsePolicy::standard,limits()),"client");
    auto server=take(Peer::create(Role::server,profile,ResponsePolicy::standard,limits()),"server");
    pump(*client,*server,fragment);
    std::array<RpcTicket,4> c{},s{};
    for(auto& ticket:c)ticket=take(client->open(),"open");
    require(!client->open(),"bounded capacity");pump(*client,*server,fragment);
    for(auto& ticket:s){auto accepted=server->accept();require(accepted.has_value(),"accept");ticket=*accepted;}
    require(!server->accept(),"accept exactly once");
    for(unsigned i=0;i<4;++i){require(c[i].id==s[i].id,"same native ID");require(client->ready(c[i]),"response headers");}
    std::array<std::vector<std::uint8_t>,4> payload;
    for(unsigned i=0;i<4;++i){payload[i].resize(2048+i*119);for(unsigned j=0;j<payload[i].size();++j)payload[i][j]=(i*51+j)%251;require(take(client->queue(c[i],payload[i]),"queue up"),"admitted up");}
    pump(*client,*server,fragment);
    // Withhold one stream's credit while all other streams make progress.
    for(unsigned i=1;i<4;++i)bytes(*server,s[i],payload[i]);
    require(server->uncredited_bytes(s[0])>payload[0].size(),"slow RPC retains exact credit");
    for(unsigned i=1;i<4;++i)require(take(server->queue(s[i],payload[i]),"queue down"),"admitted down");
    pump(*client,*server,fragment);
    for(unsigned i=1;i<4;++i)bytes(*client,c[i],payload[i]);
    // Cancel one RPC without terminating unrelated RPCs or their queued tail.
    require(bool(client->reset(c[1])),"scoped cancel");pump(*client,*server,fragment);
    require(client->rpc_failure(c[1]).has_value()&&server->rpc_failure(s[1]).has_value(),"cancel observed");
    require(!client->failure()&&!server->failure(),"connection healthy after reset");
    bytes(*server,s[0],payload[0]);require(take(server->queue(s[0],payload[0]),"slow response"),"slow admitted");
    pump(*client,*server,fragment);bytes(*client,c[0],payload[0]);
    for(unsigned i:{0u,2u,3u}){require(bool(client->close_output(c[i])),"client FIN");pump(*client,*server,fragment);std::array<std::uint8_t,1> b{};require(take(server->pull(s[i],b),"server EOF").eof,"server independent EOF");require(bool(server->close_output(s[i])),"server trailers");}
    pump(*client,*server,fragment);
    for(unsigned i:{0u,2u,3u}){std::array<std::uint8_t,1> b{};require(take(client->pull(c[i],b),"client EOF").eof,"client trailers EOF");}
    for(unsigned i=0;i<4;++i){require(take(client->release(c[i]),"client release"),"client released");require(take(server->release(s[i]),"server release"),"server released");}
    auto next=take(client->open(),"reopen");require(next.slot==c[0].slot&&next.generation>c[0].generation&&next.id>c[3].id,"slot generation and ID advance");
    require(!client->queue(c[0],payload[0]),"old ticket rejected");pump(*client,*server,fragment);
    auto accepted=server->accept();require(accepted.has_value(),"new accept after reuse");
    require(bool(server->shutdown()),"server GOAWAY");pump(*client,*server,fragment);
    auto denied=client->open();require(!denied&&denied.error().error==Error::goaway,"GOAWAY stops new calls");
    require(take(client->queue(next,payload[0]),"tail after GOAWAY"),"existing call retained");pump(*client,*server,fragment);bytes(*server,*accepted,payload[0]);
    require(!client->failure()&&!server->failure(),"healthy existing call after GOAWAY");
    require(bool(client->close_output(next)),"last client FIN");
    require(take(server->queue(*accepted,payload[0]),"unread last response"),"last response queued");
    require(bool(server->close_output(*accepted)),"last response trailers");pump(*client,*server,fragment);
    require(client->closed(next),"native closes before application consumes buffered body");
    bytes(*client,next,payload[0],true);std::array<std::uint8_t,1> last{};
    require(take(client->pull(next,last),"closed stream EOF").eof,"buffered tail followed by trailers");
    std::println("fragment {} passed client-size {} server-size {} library-peak {}/{}",fragment,sizeof(*client),sizeof(*server),client->library_peak(),server->library_peak());
}
static auto pressure(std::size_t fragment)->void {
    auto profile=*RequestProfile::create("test","localhost",false);
    auto client=take(MultiplexSession<4>::create(Role::client,profile,ResponsePolicy::standard,limits()),"pressure client");
    auto server=take(MultiplexSession<2>::create(Role::server,profile,ResponsePolicy::standard,limits()),"pressure server");
    pump(*client,*server,fragment);auto c0=take(client->open(),"pressure open0"),c1=take(client->open(),"pressure open1");
    auto extra=client->open();require(!extra&&extra.error().error==Error::limit,"peer concurrency honored before submit");
    pump(*client,*server,fragment);auto s0=*server->accept(),s1=*server->accept();
    std::vector<std::uint8_t> full(4096,65),small(37,7);
    require(take(client->queue(c0,full),"pressure queue1"),"pressure admitted1");pump(*client,*server,fragment);
    require(take(client->queue(c0,full),"pressure queue2"),"pressure admitted2");pump(*client,*server,fragment);
    require(server->uncredited_bytes(s0)==8192&&client->queued_bytes(c0)>0,"one stream is blocked at exact receive window");
    require(take(client->queue(c1,small),"free stream queue"),"free stream admitted");pump(*client,*server,fragment);bytes(*server,s1,small);
    bytes(*server,s0,full);pump(*client,*server,fragment);bytes(*server,s0,full);
    require(!client->queued_bytes(c0),"credit resumes blocked stream");
    // Inject a valid H2 DATA frame with an invalid compressed gRPC message.
    // It is a stream-local protocol error; another native RPC must survive.
    std::array<std::uint8_t,14> corrupt{0,0,5,0,0,0,0,0,0,1,0,0,0,0};
    auto id=std::uint32_t(c0.id);for(unsigned i=0;i<4;++i)corrupt[5+i]=std::uint8_t(id>>(24-i*8));
    require(take(server->receive(corrupt),"malformed RPC receive")==corrupt.size(),"H2 accepts data framing");
    std::array<std::uint8_t,32> buffer{};auto bad=server->pull(s0,buffer);require(!bad&&bad.error().error==Error::message,"RPC decoder rejects compressed message");
    pump(*client,*server,fragment);require(!client->failure()&&!server->failure(),"local protocol error preserves H2");
    require(client->rpc_failure(c0).has_value(),"peer sees local RST");
    require(take(client->queue(c1,small),"healthy stream after bad RPC"),"healthy admitted");pump(*client,*server,fragment);bytes(*server,s1,small);
    require(take(client->release(c0),"bad client release"),"bad client released");require(take(server->release(s0),"bad server release"),"bad server released");
    auto c2=take(client->open(),"after failure reuse");pump(*client,*server,fragment);auto s2=server->accept();require(s2.has_value(),"failed RPC slot reused");
    require(take(client->queue(c2,small),"reused stream payload"),"reused admitted");pump(*client,*server,fragment);bytes(*server,*s2,small);
    std::println("pressure fragment {} passed window8192 isolated reset and slot recovery",fragment);
}
static auto refused(std::size_t fragment)->void{
    auto profile=*RequestProfile::create("test","localhost",false),bad=*RequestProfile::create("other","localhost",false);
    auto client=take(MultiplexSession<4>::create(Role::client,profile,ResponsePolicy::standard,limits()),"reject client");
    auto server=take(MultiplexSession<2>::create(Role::server,profile,ResponsePolicy::standard,limits()),"reject server");
    pump(*client,*server,fragment);auto good=take(client->open(),"good call");pump(*client,*server,fragment);auto accepted=server->accept();require(accepted.has_value(),"good accepted");
    std::array<std::uint8_t,3> data{1,2,3};
    for(unsigned turn=0;turn<12;++turn){
        auto denied=take(client->open(bad),"bad profile submit");pump(*client,*server,fragment);
        require(client->rpc_failure(denied).has_value()&&client->closed(denied),"bad service refused on one stream");
        require(!server->accept(),"bad service never handed to application");require(take(client->release(denied),"refused release"),"refused client released");
        require(take(client->queue(good,data),"healthy alongside rejected call"),"healthy accepted");pump(*client,*server,fragment);bytes(*server,*accepted,data);
        require(!client->failure()&&!server->failure(),"bad service never poisons connection");
    }
    std::println("reject fragment {} passed 12 preaccept failures with automatic slot reclamation",fragment);
}
static auto goaway_unprocessed(std::size_t fragment)->void{
    auto profile=*RequestProfile::create("test","localhost",false);
    auto client=take(MultiplexSession<4>::create(Role::client,profile,ResponsePolicy::standard,limits()),"goaway client");
    auto server=take(MultiplexSession<4>::create(Role::server,profile,ResponsePolicy::standard,limits()),"goaway server");
    pump(*client,*server,fragment);auto ticket=take(client->open(),"not yet sent request");require(bool(server->shutdown()),"server rejects future work");
    while(move(*server,*client,fragment)){}
    pump(*client,*server,fragment);auto failure=client->rpc_failure(ticket);require(failure.has_value(),"unprocessed call fails");
    require(failure->error==Error::goaway,"unprocessed call retains GOAWAY error");require(!client->failure(),"NO_ERROR GOAWAY is not a connection error");
    require(!client->open(),"draining client cannot submit");require(take(client->release(ticket),"GOAWAY release"),"native provider retired before release");
    std::println("GOAWAY fragment {} passed unprocessed stream isolation",fragment);
}
static auto write_completion(std::size_t fragment)->void{
    auto profile=*RequestProfile::create("test","localhost",false);
    auto client=take(MultiplexSession<4>::create(Role::client,profile,ResponsePolicy::standard,limits()),"write client");
    auto server=take(MultiplexSession<4>::create(Role::server,profile,ResponsePolicy::standard,limits()),"write server");
    pump(*client,*server,fragment);auto a=take(client->open(),"write open0"),b=take(client->open(),"write open1");pump(*client,*server,fragment);
    require(server->accept().has_value()&&server->accept().has_value(),"write accept2");
    std::array<std::uint8_t,1024> payload{};require(take(client->queue(a,payload),"write queue0")&&take(client->queue(b,payload),"write queue1"),"write queue admitted");
    std::array<std::uint8_t,16384> output{};std::vector<std::uint8_t> wire;std::size_t total=0;std::optional<RpcTicket> current;
    for(unsigned turn=0;turn<10000;++turn){
        auto size=take(client->output(std::span(output).first(fragment)),"write output");require(size>0,"write progress");
        if(!current){bool x=!client->output_drained(a),y=!client->output_drained(b);require(x!=y,"exactly the emitted stream gets a pending write");current=x?a:b;}
        wire.insert(wire.end(),output.begin(),output.begin()+size);
        require(take(server->receive(std::span(output).first(size)),"write delivered")==size,"write peer consumed");
        require(!client->output_drained(*current),"copied bytes do not count as physical completion");
        if(wire.size()>=9)total=9+(std::size_t(wire[0])<<16)+(std::size_t(wire[1])<<8)+wire[2];
        client->written();
        if(total&&wire.size()==total){
            require(client->output_drained(*current),"last physical write releases this RPC");
            auto other=current->id==a.id?b:a;
            require(client->queued_bytes(other)>0&&client->write_pending(),"another RPC still has queued native output");
            std::println("write completion fragment {} passed independent RPC fence bytes={}",fragment,total);return;
        }
        require(!client->output_drained(*current),"partial native-frame writes retain the fence");
    }
    throw std::runtime_error("write fence did not complete");
}
int main(){try{for(auto n:{1u,7u,4096u,16384u}){run(n);pressure(n);refused(n);goaway_unprocessed(n);write_completion(n);}return 0;}catch(std::exception const& error){std::println("{}",error.what());return 1;}}
