import std;
import http2.client;
import nexus.thirdparty.nghttp2;
namespace h=http2;
namespace c=nex::nghttp2;
using Client=h::Client<4>;
extern "C" auto client_native(Client*) -> c::nghttp2_session*;
extern "C" auto client_connection_credit(Client*) -> std::size_t;
extern "C" auto client_stream_credit(Client*) -> std::size_t;
extern "C" auto client_seed_generation(Client*,std::size_t,std::uint32_t) -> void;
extern "C" auto client_seed_next_id(Client*,std::int32_t) -> int;
static auto require(bool yes,unsigned line) -> void {if(!yes){std::println("H2 boundary failed line {}",line);std::exit(1);}}
static auto nv(h::FieldView field) noexcept -> c::nghttp2_nv {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.name.data())),reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.value.data())),field.name.size(),field.value.size(),0};
}
static auto fields(std::string_view path="/register",std::string_view method="POST") -> std::array<h::FieldView,4> {
    return {{{":method",method},{":scheme","https"},{":authority","control.example"},{":path",path}}};
}
struct Peer {
    struct Body {std::span<std::uint8_t const> bytes;std::size_t offset=0;bool end=true;};
    c::nghttp2_session* session=nullptr;
    std::map<std::int32_t,Body> bodies;
    std::map<std::int32_t,std::vector<std::uint8_t>> request;
    std::vector<std::int32_t> opened,closed;
    std::vector<std::pair<std::int32_t,std::uint32_t>> resets;
    bool push_disabled=false;
    explicit Peer(std::uint32_t request_window=65535) {
        c::nghttp2_session_callbacks* cb=nullptr;require(!c::nghttp2_session_callbacks_new(&cb),__LINE__);
        c::nghttp2_session_callbacks_set_on_frame_recv_callback(cb,[](auto*,c::nghttp2_frame const* frame,void* p) noexcept {
            auto& self=*static_cast<Peer*>(p);
            if(frame->hd.type==c::NGHTTP2_HEADERS)self.opened.push_back(frame->hd.stream_id);
            if(frame->hd.type==3)self.resets.emplace_back(frame->hd.stream_id,frame->rst_stream.error_code);
            return 0;
        });
        c::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb,[](auto*,std::uint8_t,std::int32_t id,std::uint8_t const* bytes,std::size_t n,void* p) noexcept {
            auto& out=static_cast<Peer*>(p)->request[id];out.insert(out.end(),bytes,bytes+n);return 0;
        });
        c::nghttp2_session_callbacks_set_on_stream_close_callback(cb,[](auto*,std::int32_t id,std::uint32_t,void* p) noexcept {static_cast<Peer*>(p)->closed.push_back(id);return 0;});
        c::nghttp2_option* option=nullptr;require(!c::nghttp2_option_new(&option),__LINE__);c::nghttp2_option_set_no_auto_window_update(option,1);
        require(!c::nghttp2_session_server_new2(&session,cb,this,option),__LINE__);c::nghttp2_option_del(option);c::nghttp2_session_callbacks_del(cb);
        std::array<c::nghttp2_settings_entry,2> settings{{{c::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,4},{c::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,request_window}}};
        require(!c::nghttp2_submit_settings(session,0,settings.data(),settings.size()),__LINE__);
    }
    ~Peer(){c::nghttp2_session_del(session);}
    static auto provide(c::nghttp2_session*,std::int32_t,std::uint8_t* out,std::size_t n,std::uint32_t* flags,c::nghttp2_data_source* source,void*) noexcept -> c::nghttp2_ssize {
        auto& body=*static_cast<Body*>(source->ptr);auto count=std::min(n,body.bytes.size()-body.offset);
        if(count){std::memcpy(out,body.bytes.data()+body.offset,count);body.offset+=count;}
        if(body.offset==body.bytes.size()){if(body.end)*flags|=c::NGHTTP2_DATA_FLAG_EOF;else if(!count)return c::NGHTTP2_ERR_DEFERRED;}return static_cast<c::nghttp2_ssize>(count);
    }
    auto headers(std::int32_t id,std::span<h::FieldView const> fields,bool end=false) -> void {
        std::vector<c::nghttp2_nv> values;for(auto field:fields)values.push_back(nv(field));
        require(c::nghttp2_submit_headers(session,end?c::NGHTTP2_FLAG_END_STREAM:0,id,nullptr,values.data(),values.size(),nullptr)>=0,__LINE__);
    }
    auto respond(std::int32_t id,std::span<h::FieldView const> fields,std::span<std::uint8_t const> bytes={},bool end=true) -> void {
        std::vector<c::nghttp2_nv> values;for(auto field:fields)values.push_back(nv(field));
        auto& body=bodies[id];body={bytes,0,end};c::nghttp2_data_provider2 source{};source.source.ptr=&body;source.read_callback=provide;
        require(!c::nghttp2_submit_response2(session,id,values.data(),values.size(),bytes.empty()&&end?nullptr:&source),__LINE__);
    }
    auto ok(std::int32_t id) -> void {std::array<h::FieldView,1> status{{{":status","200"}}};respond(id,status);}
    auto goaway(std::int32_t last,std::uint32_t code=0) -> void {require(!c::nghttp2_submit_goaway(session,0,last,code,nullptr,0),__LINE__);}
    auto output() -> std::vector<std::uint8_t> {
        std::uint8_t const* p=nullptr;auto n=c::nghttp2_session_mem_send2(session,&p);require(n>=0,__LINE__);return {p,p+n};
    }
    auto receive(std::span<std::uint8_t const> bytes) -> void {require(c::nghttp2_session_mem_recv2(session,bytes.data(),bytes.size())==static_cast<c::nghttp2_ssize>(bytes.size()),__LINE__);}
};
static auto down(Client& client,Peer& peer) -> std::size_t {
    std::size_t total=0;
    for(unsigned n=0;n<10000;++n){auto bytes=peer.output();if(bytes.empty())return total;total+=bytes.size();
        for(std::size_t at=0;at<bytes.size();){auto count=std::min(std::size_t{7},bytes.size()-at);auto result=client.receive(std::span(bytes).subspan(at,count));require(result&&*result==count,__LINE__);at+=count;}}
    std::abort();
}
static auto up(Client& client,Peer& peer) -> std::size_t {
    std::size_t total=0;std::array<std::uint8_t,137> bytes{};
    for(unsigned n=0;n<10000;++n){auto out=client.output(bytes);require(out.has_value(),__LINE__);if(!*out)return total;total+=*out;peer.receive(std::span(bytes).first(*out));}std::abort();
}
static auto pump(Client& client,Peer& peer) -> void {for(unsigned n=0;n<10000;++n){auto a=up(client,peer),b=down(client,peer);if(!a&&!b)return;}std::abort();}
static auto make(h::ClientLimits limits={}) -> std::unique_ptr<Client> {auto result=Client::create(limits);require(result.has_value(),__LINE__);return std::move(*result);}
static auto request_validation() -> void {
    auto client=make();Peer peer;pump(*client,peer);
    std::array<h::FieldView,5> invalid{{{":method","POST"},{":scheme","https"},{":authority","x"},{":path","/"},{"connection","close"}}};
    for(auto name:{"connection","proxy-connection","upgrade","keep-alive","transfer-encoding","TE","te"}){invalid.back()={name,"close"};require(!client->submit(invalid),__LINE__);}
    invalid.back()={":path","/duplicate"};require(!client->submit(invalid),__LINE__);
    invalid.back()={"bad","\r\n"};require(!client->submit(invalid),__LINE__);
    invalid.back()={"content-length","4"};std::array<std::uint8_t,3> body{};require(!client->submit(invalid,{body,true}),__LINE__);
    auto ticket=client->submit(invalid,{body,false});require(ticket.has_value(),__LINE__);pump(*client,peer);
    require(client->tx_consumed(*ticket)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    require(!client->provide(*ticket,{body,true}),__LINE__);std::array<std::uint8_t,1> last{99};require(client->provide(*ticket,{last,true})==std::expected<bool,h::ClientFailure>{true},__LINE__);
    pump(*client,peer);peer.ok(ticket->id);pump(*client,peer);require(peer.request[ticket->id].size()==4&&client->response(*ticket)->closed,__LINE__);
    std::println("H2 request pseudo/header framing and deferred content-length accounting passed");
}
static auto goaway_borrow() -> void {
    auto client=make();Peer peer(1024);pump(*client,peer);
    std::vector<std::uint8_t> auth(200000,42),other(200000,43);
    auto first=client->submit(fields(),{auth,true}),second=client->submit(fields(),{other,true});require(first&&second,__LINE__);pump(*client,peer);
    require(!*client->tx_consumed(*first)&&!*client->tx_consumed(*second),__LINE__);
    auto delivered=peer.request[second->id].size();require(delivered==1024,__LINE__);
    peer.goaway(first->id);down(*client,peer);
    auto response=client->response(*second);require(response&&response->failure&&response->failure->error==h::ClientError::unprocessed,__LINE__);
    require(*client->tx_consumed(*second)&&response->body_released,__LINE__);other.assign(other.size(),0);
    require(client->release(*second)==std::expected<bool,h::ClientFailure>{true},__LINE__);
    pump(*client,peer);require(peer.request[second->id].size()==delivered&&!client->submit(fields()),__LINE__);
    require(client->reset(*first).has_value(),__LINE__);pump(*client,peer);require(*client->tx_consumed(*first),__LINE__);
    std::println("H2 GOAWAY last_id marks only unprocessed stream, ends provider borrow, and never replays POST");
}
static auto exact_credit() -> void {
    h::ClientLimits limits;limits.stream_window=4096;auto client=make(limits);Peer peer;pump(*client,peer);
    auto ticket=client->submit(fields());require(ticket.has_value(),__LINE__);pump(*client,peer);
    std::vector<std::uint8_t> body(20000,91);std::array<h::FieldView,1> status{{{":status","200"}}};peer.respond(ticket->id,status,body);pump(*client,peer);
    auto available=client->peek(*ticket);require(available&&available->size()==4096,__LINE__);
    auto base=client_connection_credit(client.get()),stream_base=client_stream_credit(client.get());
    require(client->consume(*ticket,101).has_value(),__LINE__);require(client_connection_credit(client.get())==base+101&&client_stream_credit(client.get())==stream_base+101,__LINE__);
    require(client->reset(*ticket).has_value(),__LINE__);pump(*client,peer);
    require(client_connection_credit(client.get())==base+4096&&client_stream_credit(client.get())==stream_base+101,__LINE__);
    require(client->release(*ticket)==std::expected<bool,h::ClientFailure>{true},__LINE__);require(client_connection_credit(client.get())==base+4096,__LINE__);
    auto next=client->submit(fields());require(next.has_value(),__LINE__);pump(*client,peer);peer.ok(next->id);pump(*client,peer);require(client->response(*next)->closed,__LINE__);
    std::println("H2 RST discards exactly uncredited connection DATA and never credits dead stream twice");
}
static auto response_semantics() -> void {
    for(unsigned mode=0;mode<8;++mode){
        auto client=make();Peer peer;pump(*client,peer);auto ticket=client->submit(fields("/",mode==1?"HEAD":"GET"));require(ticket.has_value(),__LINE__);pump(*client,peer);
        std::array<h::FieldView,2> headers{{{":status","200"},{"content-length","3"}}};std::array<std::uint8_t,3> body{1,2,3};
        if(mode==0){std::array<h::FieldView,1> hint{{{":status","103"}}};peer.headers(ticket->id,hint);peer.respond(ticket->id,headers,body,false);down(*client,peer);
            auto view=client->response(*ticket);require(view&&view->status==200&&!view->remote_end&&view->headers.size()==2,__LINE__);std::array<h::FieldView,1> trailer{{{"tail","done"}}};peer.headers(ticket->id,trailer,true);}
        if(mode==1)peer.respond(ticket->id,headers);
        if(mode==2){headers[0].value="204";peer.respond(ticket->id,std::span(headers).first(1));}
        if(mode==3){headers[0].value="304";peer.respond(ticket->id,headers);}
        if(mode==4){headers[0].value="204";peer.respond(ticket->id,headers);}
        if(mode==5){headers[1].value="4";peer.respond(ticket->id,headers,body);}
        if(mode==6){headers[1].value="2";peer.respond(ticket->id,headers,body);}
        if(mode==7){headers[1]={":status","201"};peer.respond(ticket->id,headers);}
        pump(*client,peer);auto response=client->response(*ticket);require(response.has_value(),__LINE__);
        if(mode<4){require(!response->failure&&response->remote_end&&response->closed,__LINE__);if(!mode)require(response->trailers.size()==1&&response->trailers[0].value=="done",__LINE__);}
        else {require(response->failure.has_value(),__LINE__);require(!client->failure(),__LINE__);}
    }
    std::println("H2 informational/final/trailer, HEAD/204/304 and malformed length/status stream errors passed");
}
static auto id_boundaries() -> void {
    auto client=make();Peer peer;pump(*client,peer);
    client_seed_generation(client.get(),0,std::numeric_limits<std::uint32_t>::max()-1);
    auto ticket=client->submit(fields());require(ticket&&ticket->slot==0&&ticket->generation==std::numeric_limits<std::uint32_t>::max(),__LINE__);pump(*client,peer);peer.ok(ticket->id);pump(*client,peer);require(*client->release(*ticket),__LINE__);
    auto next=client->submit(fields());require(next&&next->slot==1&&!client->response(*ticket),__LINE__);pump(*client,peer);peer.ok(next->id);pump(*client,peer);require(*client->release(*next),__LINE__);
    require(!client_seed_next_id(client.get(),std::numeric_limits<std::int32_t>::max()),__LINE__);
    auto last=client->submit(fields());require(last&&last->id==std::numeric_limits<std::int32_t>::max()&&!client->submit(fields()),__LINE__);pump(*client,peer);peer.ok(last->id);pump(*client,peer);require(client->response(*last)->closed,__LINE__);
    std::println("H2 stream IDs and per-slot generations reach final value once and never wrap");
}
static auto push_boundaries() -> void {
    auto client=make();Peer peer;
    std::vector<std::uint8_t> borrowed(200000,17);
    auto ticket=client->submit(fields(),{borrowed,true});require(ticket.has_value(),__LINE__);
    std::vector<std::uint8_t> initial;std::array<std::uint8_t,137> buffer{};
    for(;;){auto n=client->output(buffer);require(n.has_value(),__LINE__);if(!*n)break;initial.insert(initial.end(),buffer.begin(),buffer.begin()+*n);}
    require(initial.size()>24,__LINE__);
    bool changed=false;
    // The hostile peer ignores our disabled-push request. Keep native client
    // state unchanged; only the independent server's view is rewritten.
    for(std::size_t at=24;at+9<=initial.size();){auto n=(std::size_t(initial[at])<<16)|(std::size_t(initial[at+1])<<8)|initial[at+2];require(at+9+n<=initial.size(),__LINE__);
        if(initial[at+3]==c::NGHTTP2_SETTINGS)for(std::size_t p=at+9;p+6<=at+9+n;p+=6)if(initial[p]==0&&initial[p+1]==c::NGHTTP2_SETTINGS_ENABLE_PUSH){require(initial[p+5]==0,__LINE__);initial[p+5]=1;changed=true;}
        at+=9+n;
    }
    require(changed,__LINE__);peer.receive(initial);
    auto settings=peer.output(),ack=peer.output();require(settings.size()>=9&&ack.size()==9&&ack[3]==c::NGHTTP2_SETTINGS&&(ack[4]&c::NGHTTP2_FLAG_ACK),__LINE__);
    require(client->receive(settings).has_value(),__LINE__);
    auto request=fields("/push","GET");std::array<c::nghttp2_nv,4> promised{};std::ranges::transform(request,promised.begin(),nv);
    auto first=c::nghttp2_submit_push_promise(peer.session,0,ticket->id,promised.data(),promised.size(),nullptr);require(first==2,__LINE__);
    down(*client,peer);up(*client,peer);
    // Pinned nghttp2 cancels a push while ENABLE_PUSH=0 is pending before it
    // invokes application begin_headers; after ACK it becomes connection error.
    require(std::ranges::find(peer.resets,std::pair<std::int32_t,std::uint32_t>{first,c::NGHTTP2_CANCEL})!=peer.resets.end(),__LINE__);
    require(!client->failure()&&client->receive(ack).has_value(),__LINE__);
    auto second=c::nghttp2_submit_push_promise(peer.session,0,ticket->id,promised.data(),promised.size(),nullptr);require(second==4,__LINE__);down(*client,peer);
    std::vector<std::uint8_t> control;std::array<std::uint8_t,1> byte{};bool partial=false;
    for(;;){auto n=client->output(byte);require(n.has_value(),__LINE__);if(!*n)break;control.push_back(byte[0]);if(client->write_pending()&&!client->failure())partial=true;}
    require(partial&&client->failure()&&client->failure()->error==h::ClientError::http2&&client->failure()->code==c::NGHTTP2_PROTOCOL_ERROR,__LINE__);
    require(control.size()>=17&&control[3]==c::NGHTTP2_GOAWAY&&control[16]==c::NGHTTP2_PROTOCOL_ERROR,__LINE__);
    require(!client->submit(fields())&&!*client->tx_consumed(*ticket)&&client_native(client.get()),__LINE__);peer.receive(control);
    client->cancel();require(!client_native(client.get())&&*client->tx_consumed(*ticket)&&*client->release(*ticket),__LINE__);
    std::println("H2 rejects pre-ACK push per stream; post-ACK push drains complete error GOAWAY in one-byte output before surfacing connection failure");
}
static auto data_frame(std::int32_t id,std::span<std::uint8_t const> body,std::uint8_t flags=0) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> wire(9+body.size());auto n=body.size();wire[0]=static_cast<std::uint8_t>(n>>16);wire[1]=static_cast<std::uint8_t>(n>>8);wire[2]=static_cast<std::uint8_t>(n);wire[3]=c::NGHTTP2_DATA;wire[4]=flags;
    for(unsigned i=0;i<4;++i)wire[5+i]=static_cast<std::uint8_t>(std::uint32_t(id)>>(24-i*8));std::copy(body.begin(),body.end(),wire.begin()+9);return wire;
}
static auto stream_updates(Client& client,std::int32_t id) -> std::uint32_t {
    std::array<std::uint8_t,137> chunk{};std::vector<std::uint8_t> wire;
    for(;;){auto n=client.output(chunk);require(n.has_value(),__LINE__);if(!*n)break;wire.insert(wire.end(),chunk.begin(),chunk.begin()+*n);}
    std::uint32_t total=0;
    for(std::size_t at=0;at+9<=wire.size();){auto n=(std::size_t(wire[at])<<16)|(std::size_t(wire[at+1])<<8)|wire[at+2];require(at+9+n<=wire.size(),__LINE__);
        std::uint32_t stream=0;for(unsigned i=0;i<4;++i)stream=(stream<<8)|wire[at+5+i];
        if(wire[at+3]==c::NGHTTP2_WINDOW_UPDATE&&stream==std::uint32_t(id)){require(n==4,__LINE__);std::uint32_t increment=0;for(unsigned i=0;i<4;++i)increment=(increment<<8)|wire[at+9+i];total+=increment;}
        at+=9+n;
    }return total;
}
static auto settings_and_padding() -> void {
    {
        h::ClientLimits limits;limits.stream_window=4096;auto client=make(limits);Peer peer;auto ticket=client->submit(fields());require(ticket.has_value(),__LINE__);up(*client,peer);
        std::array<h::FieldView,1> status{{{":status","200"}}};peer.respond(ticket->id,status,{},false);
        std::vector<std::uint8_t> ack;
        for(;;){auto frame=peer.output();if(frame.empty())break;
            if(frame[3]==c::NGHTTP2_SETTINGS&&(frame[4]&c::NGHTTP2_FLAG_ACK))ack=frame;
            else require(client->receive(frame).has_value(),__LINE__);
        }
        require(!ack.empty()&&c::nghttp2_session_get_stream_local_window_size(client_native(client.get()),ticket->id)==65535,__LINE__);
        std::vector<std::uint8_t> data(5000,27);auto frame=data_frame(ticket->id,data);require(client->receive(frame).has_value(),__LINE__);
        require(c::nghttp2_session_get_stream_local_window_size(client_native(client.get()),ticket->id)==60535&&client->peek(*ticket)->size()==5000,__LINE__);
        require(client->receive(ack).has_value()&&c::nghttp2_session_get_stream_local_window_size(client_native(client.get()),ticket->id)==0,__LINE__);
        require(client->consume(*ticket,5000).has_value()&&stream_updates(*client,ticket->id)==5000,__LINE__);
        require(c::nghttp2_session_get_stream_local_window_size(client_native(client.get()),ticket->id)==4096&&!client->failure(),__LINE__);
    }
    {
        h::ClientLimits limits;limits.stream_window=4096;auto client=make(limits);Peer peer;pump(*client,peer);auto ticket=client->submit(fields());require(ticket.has_value(),__LINE__);pump(*client,peer);
        std::array<h::FieldView,1> status{{{":status","200"}}};peer.respond(ticket->id,status,{},false);down(*client,peer);
        std::array<std::uint8_t,1024> payload{};payload[0]=16;std::fill(payload.begin()+1,payload.end()-16,37);
        auto frame=data_frame(ticket->id,payload,8);auto conn=client_connection_credit(client.get()),stream=client_stream_credit(client.get());
        for(unsigned n=0;n<4;++n)require(client->receive(frame).has_value(),__LINE__);
        require(client->peek(*ticket)->size()==4028&&c::nghttp2_session_get_stream_local_window_size(client_native(client.get()),ticket->id)==0,__LINE__);
        require(client->consume(*ticket,4028).has_value()&&stream_updates(*client,ticket->id)==4096,__LINE__);
        require(client_connection_credit(client.get())==conn+4028&&client_stream_credit(client.get())==stream+4028&&c::nghttp2_session_get_stream_local_window_size(client_native(client.get()),ticket->id)==4096,__LINE__);
    }
    std::println("H2 pre-ACK default window, one exact SETTINGS adjustment and 68 automatic padding bytes plus 4028 application bytes restore exactly 4096 stream credit");
}
auto main() -> int {request_validation();goaway_borrow();exact_credit();response_semantics();id_boundaries();push_boundaries();settings_and_padding();}
