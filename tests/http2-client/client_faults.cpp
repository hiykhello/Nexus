import std;
import http2.client;
import memory.budget;
import nexus.thirdparty.nghttp2;
namespace h=http2;
namespace m=::memory;
namespace c=nex::nghttp2;
using Client=h::Client<4>;
extern "C" auto meter_begin(std::size_t,std::size_t) -> void;
extern "C" auto meter_end() -> std::size_t;
extern "C" auto meter_failed() -> bool;
extern "C" auto meter_live() -> std::size_t;
static auto require(bool yes,unsigned line) -> void {if(!yes){std::println("H2 fault failed line {}",line);std::exit(1);}}
static auto fields() -> std::array<h::FieldView,4> {return {{{":method","POST"},{":scheme","https"},{":authority","control.example"},{":path","/register"}}};}
static auto nv(h::FieldView field) -> c::nghttp2_nv {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.name.data())),reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.value.data())),field.name.size(),field.value.size(),0};
}
struct Peer {
    c::nghttp2_session* session=nullptr;
    Peer(){c::nghttp2_session_callbacks* callbacks=nullptr;require(!c::nghttp2_session_callbacks_new(&callbacks),__LINE__);
        c::nghttp2_option* option=nullptr;require(!c::nghttp2_option_new(&option),__LINE__);c::nghttp2_option_set_no_auto_window_update(option,1);
        require(!c::nghttp2_session_server_new2(&session,callbacks,this,option),__LINE__);c::nghttp2_option_del(option);c::nghttp2_session_callbacks_del(callbacks);
        c::nghttp2_settings_entry setting{c::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,4};require(!c::nghttp2_submit_settings(session,0,&setting,1),__LINE__);}
    ~Peer(){c::nghttp2_session_del(session);}
    auto receive(std::span<std::uint8_t const> bytes) -> void {require(c::nghttp2_session_mem_recv2(session,bytes.data(),bytes.size())==static_cast<c::nghttp2_ssize>(bytes.size()),__LINE__);}
    auto output() -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> result;
        for(unsigned n=0;n<10000;++n){std::uint8_t const* p=nullptr;auto size=c::nghttp2_session_mem_send2(session,&p);require(size>=0,__LINE__);if(!size)return result;result.insert(result.end(),p,p+size);}std::abort();
    }
    auto respond(std::int32_t id,std::span<h::FieldView const> fields) -> void {
        std::vector<c::nghttp2_nv> headers;for(auto value:fields)headers.push_back(nv(value));
        require(!c::nghttp2_submit_response2(session,id,headers.data(),headers.size(),nullptr),__LINE__);
    }
};
static auto move(Client& client,Peer& peer) -> std::size_t {
    std::array<std::uint8_t,137> bytes{};std::size_t total=0;
    for(unsigned n=0;n<10000;++n){auto size=client.output(bytes);require(size.has_value(),__LINE__);if(!*size)return total;peer.receive(std::span(bytes).first(*size));total+=*size;}std::abort();
}
static auto pump(Client& client,Peer& peer) -> void {
    for(unsigned n=0;n<10000;++n){auto sent=move(client,peer);auto received=peer.output();if(!received.empty()){auto result=client.receive(received);require(result&&*result==received.size(),__LINE__);}if(!sent&&received.empty())return;}std::abort();
}
static auto make(h::ClientLimits limits,std::shared_ptr<m::Budget> budget={}) -> std::unique_ptr<Client> {
    auto made=Client::create(limits,std::move(budget));require(made.has_value(),__LINE__);return std::move(*made);
}
static auto create_one(std::size_t kind,std::size_t failure) -> std::size_t {
    h::ClientLimits limits;limits.shared_bytes=1024*1024;
    auto budget=std::make_shared<m::Budget>(limits.shared_bytes);auto transport=m::Budget::reserve(budget,8192);require(transport.has_value(),__LINE__);
    meter_begin(kind,failure);auto made=Client::create(limits,budget);auto count=meter_end();
    if(failure)require(meter_failed(),__LINE__);
    if(made)made->reset();
    require(!meter_live()&&budget->used()==8192,__LINE__);
    auto recovered=make(limits,budget);recovered.reset();require(budget->used()==8192,__LINE__);
    return count;
}
static auto default_create(std::size_t failure) -> std::size_t {
    meter_begin(1,failure);auto made=Client::create();auto count=meter_end();if(failure)require(meter_failed()&&!made,__LINE__);
    if(made)made->reset();require(!meter_live(),__LINE__);auto recovered=Client::create();require(recovered.has_value(),__LINE__);return count;
}
static auto submit_one(std::size_t kind,std::size_t failure) -> std::size_t {
    h::ClientLimits limits;limits.shared_bytes=1024*1024;auto budget=std::make_shared<m::Budget>(limits.shared_bytes);
    auto transport=m::Budget::reserve(budget,8192);require(transport.has_value(),__LINE__);
    auto client=make(limits,budget);Peer peer;pump(*client,peer);std::array<std::uint8_t,200000> body{},wire{};
    meter_begin(kind,failure);auto ticket=client->submit(fields(),{body,true});
    if(ticket)for(unsigned n=0;n<10000;++n){auto out=client->output(std::span(wire).first(137));if(!out||!*out)break;}
    auto count=meter_end();if(failure)require(meter_failed(),__LINE__);
    require(budget->used()<=budget->limit(),__LINE__);client.reset();require(!meter_live()&&budget->used()==8192,__LINE__);
    return count;
}
static auto headers_one(std::size_t kind,std::size_t failure) -> std::size_t {
    h::ClientLimits limits;limits.shared_bytes=1024*1024;auto budget=std::make_shared<m::Budget>(limits.shared_bytes);
    auto transport=m::Budget::reserve(budget,8192);require(transport.has_value(),__LINE__);
    auto client=make(limits,budget);Peer peer;pump(*client,peer);std::array<std::uint8_t,200000> borrowed{};
    auto ticket=client->submit(fields(),{borrowed,true});require(ticket.has_value(),__LINE__);pump(*client,peer);require(!*client->tx_consumed(*ticket),__LINE__);
    std::array<std::string,10> names,values;std::array<h::FieldView,11> headers{};headers[0]={":status","200"};
    for(unsigned n=0;n<10;++n){names[n]="x-independent-header-"+std::to_string(n);values[n]=std::string(300,char('a'+n));headers[n+1]={names[n],values[n]};}
    peer.respond(ticket->id,headers);auto wire=peer.output();require(!wire.empty(),__LINE__);
    meter_begin(kind,failure);bool accepted=true;
    for(std::size_t at=0;at<wire.size();){auto n=std::min(std::size_t{7},wire.size()-at);auto result=client->receive(std::span(wire).subspan(at,n));if(!result){accepted=false;break;}require(*result==n,__LINE__);at+=n;}
    auto count=meter_end();if(failure)require(meter_failed(),__LINE__);require(budget->used()<=budget->limit(),__LINE__);
    if(kind==2&&failure&&client->failure())require(!client->library_used()&&*client->tx_consumed(*ticket),__LINE__);
    if(kind==1&&failure){require(accepted&&!client->failure(),__LINE__);pump(*client,peer);auto response=client->response(*ticket);require(response&&response->failure&&response->closed,__LINE__);
        require(*client->release(*ticket),__LINE__);auto next=client->submit(fields());require(next.has_value(),__LINE__);pump(*client,peer);
        peer.respond(next->id,std::span(headers).first(1));pump(*client,peer);require(!client->response(*next)->failure&&client->response(*next)->closed,__LINE__);}
    client.reset();require(!meter_live()&&budget->used()==8192,__LINE__);return count;
}
static auto caps_and_reservations() -> void {
    h::ClientLimits limits;limits.shared_bytes=1024*1024;auto budget=std::make_shared<m::Budget>(limits.shared_bytes);
    auto transport=m::Budget::reserve(budget,12345);require(transport.has_value(),__LINE__);
    auto client=make(limits,budget);require(!Client::create(limits,budget),__LINE__);Peer peer;pump(*client,peer);
    std::array<std::uint8_t,200000> body{},wire{};auto ticket=client->submit(fields(),{body,true});require(ticket.has_value(),__LINE__);
    auto admitted=budget->used(),available=budget->limit()-admitted;
    for(unsigned n=0;n<10000;++n){auto result=client->output(std::span(wire).first(137));require(result.has_value(),__LINE__);if(!*result)break;}
    require(!*client->tx_consumed(*ticket)&&budget->used()>=admitted&&!m::Budget::reserve(budget,available+1),__LINE__);
    require(client->release(*ticket)==std::expected<bool,h::ClientFailure>{false},__LINE__);require(!*client->tx_consumed(*ticket),__LINE__);
    for(unsigned n=0;n<10000;++n){auto result=client->output(std::span(wire).first(137));require(result.has_value(),__LINE__);if(!*result)break;}
    require(*client->tx_consumed(*ticket)&&*client->release(*ticket),__LINE__);client.reset();require(budget->used()==12345,__LINE__);
    limits.header_bytes=512;client=make(limits,budget);Peer limited;pump(*client,limited);
    auto a=client->submit(fields()),b=client->submit(fields());require(a&&b,__LINE__);pump(*client,limited);
    std::string large(500,'x');std::array<h::FieldView,2> headers{{{":status","200"},{"large",large}}};limited.respond(a->id,headers);limited.respond(b->id,std::span(headers).first(1));pump(*client,limited);
    require(client->response(*a)->failure&&client->response(*a)->closed&&!client->failure()&&!client->response(*b)->failure&&client->response(*b)->closed,__LINE__);
    client.reset();require(budget->used()==12345,__LINE__);
    std::println("H2 full original caller-body reservation survives partial provider reads; shared attachment and oversized-header stream isolation passed");
}
auto main() -> int {
    auto defaults=default_create(0);for(std::size_t failure=1;failure<=defaults;++failure)default_create(failure);
    std::println("H2 default-budget creation all {} C++ allocation failures passed without retained allocations",defaults);
    for(std::size_t kind:{1,2})for(unsigned scenario=0;scenario<3;++scenario){
        auto run=scenario==0?create_one:scenario==1?submit_one:headers_one;auto count=run(kind,0);require(count>0,__LINE__);
        for(std::size_t failure=1;failure<=count;++failure)run(kind,failure);
        std::println("H2 allocation failures: kind={} scenario={} all {} points passed with zero retained allocations/budget baseline",kind,scenario,count);
    }
    caps_and_reservations();
}
