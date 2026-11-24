import std;
import http2.client_channel;
import nghttp2;
import capy;
import corosio;
namespace h=http2;
namespace c = ::nghttp2;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
using Deadline=std::optional<Clock::time_point>;
struct State {
    std::string_view mode;
    capy::async_event gate;
    std::stop_source stop;
    h::StreamTicket first{},second{};
    std::array<std::uint8_t,200000> body{};
    std::size_t reading=0,writing=0,max_read=0,max_write=0,late_reads=0,tail=0;
    bool active=false,active_ready=false,fired=false,abandoned=false,done=false,success=false,caught=false,valid=true;
    bool canceled=false,last_started=false,last_done=false,last_ok=false,poisoned=false,eof=false,throw_read=false,throw_write=false;
    bool close_started=false,close_done=false,closed=false,grace_read=false;
};
struct Flight {
    std::size_t& value;
    Flight(std::size_t& counter,std::size_t& maximum):value(counter){++value;maximum=std::max(maximum,value);}
    ~Flight(){--value;}
};
struct Lower {
    State& state;
    c::nghttp2_session* peer=nullptr;
    std::vector<std::uint8_t> input;
    std::vector<std::int32_t> opened;
    std::size_t offset=0,responded=0;
    explicit Lower(State& value):state(value){
        c::nghttp2_session_callbacks* callbacks=nullptr;if(c::nghttp2_session_callbacks_new(&callbacks))std::abort();
        c::nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,[](auto*,c::nghttp2_frame const* frame,void* self) noexcept {
            if(frame->hd.type==c::NGHTTP2_HEADERS)static_cast<Lower*>(self)->opened.push_back(frame->hd.stream_id);return 0;
        });
        c::nghttp2_option* option=nullptr;if(c::nghttp2_option_new(&option))std::abort();c::nghttp2_option_set_no_auto_window_update(option,1);
        if(c::nghttp2_session_server_new2(&peer,callbacks,this,option))std::abort();c::nghttp2_option_del(option);c::nghttp2_session_callbacks_del(callbacks);
        std::array<c::nghttp2_settings_entry,2> settings{{{c::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,4},{c::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,1024}}};
        if(c::nghttp2_submit_settings(peer,0,settings.data(),settings.size()))std::abort();
    }
    ~Lower(){c::nghttp2_session_del(peer);}
    auto cancel() noexcept -> void{state.canceled=true;state.gate.set();}
    auto collect() -> void {
        for(;;){std::uint8_t const* p=nullptr;auto n=c::nghttp2_session_mem_send2(peer,&p);if(n<0)throw std::runtime_error("peer output");if(!n)return;input.insert(input.end(),p,p+n);}
    }
    auto respond() -> void {
        while(responded<opened.size()){
            auto id=opened[responded++];auto name=std::string_view(":status"),status=state.active&&id==state.first.id?std::string_view("200"):std::string_view("204");
            c::nghttp2_nv header{reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),reinterpret_cast<std::uint8_t*>(const_cast<char*>(status.data())),name.size(),status.size(),0};
            auto rc=state.active&&id==state.first.id?c::nghttp2_submit_headers(peer,0,id,nullptr,&header,1,nullptr):c::nghttp2_submit_response2(peer,id,&header,1,nullptr);
            if(rc<0)throw std::runtime_error("peer response");
        }
    }
    auto send(std::span<std::uint8_t const> bytes,Deadline deadline) -> capy::task<bool> {
        Flight flight(state.writing,state.max_write);if(state.canceled)co_return false;if(state.throw_write)throw std::bad_alloc();
        auto accepted=c::nghttp2_session_mem_recv2(peer,bytes.data(),bytes.size());if(accepted!=static_cast<c::nghttp2_ssize>(bytes.size()))co_return false;
        respond();collect();state.gate.set();
        if(bytes.size()>=9&&bytes[3]==c::NGHTTP2_GOAWAY){
            state.last_started=true;state.gate.set();auto [error]=co_await io::delay(state.mode=="last-deadline"?90ms:40ms);
            if(state.mode=="last-throw")throw std::bad_alloc();
            state.last_done=true;state.last_ok=!error&&!state.canceled&&!state.poisoned&&state.mode!="last-fail"&&(!deadline||Clock::now()<*deadline);
            co_return state.last_ok;
        }
        co_return true;
    }
    auto close_output(Deadline deadline) -> capy::task<bool> {
        Flight flight(state.writing,state.max_write);state.close_started=true;state.gate.set();
        if(state.mode.starts_with("close-")){
            auto [error]=co_await io::delay(state.mode=="close-deadline"?90ms:40ms);
            if(state.mode=="close-throw")throw std::bad_alloc();
            state.close_done=true;
            if(error||state.canceled||state.mode=="close-fail"||(deadline&&Clock::now()>=*deadline))co_return false;
        }else state.close_done=true;
        state.closed=true;state.gate.set();co_return true;
    }
    auto read(std::span<std::uint8_t> bytes,Deadline deadline) -> capy::task<std::expected<std::size_t,std::error_code>> {
        Flight flight(state.reading,state.max_read);
        for(;;){
            if(state.canceled)co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            if(state.throw_read)throw std::bad_alloc();
            if(state.closed){
                state.grace_read=true;state.gate.set();
                if(state.mode=="eof-throw")throw std::bad_alloc();
                if(state.mode=="eof-error"||state.mode=="eof-canceled")co_return std::unexpected(std::make_error_code(state.mode=="eof-error"?std::errc::connection_reset:std::errc::operation_canceled));
                if(state.mode=="eof-tail"||state.mode=="eof-overflow"){
                    auto remaining=(state.mode=="eof-tail"?65536u:65537u)-state.tail;
                    if(remaining){auto count=std::min<std::size_t>(bytes.size(),remaining);std::fill_n(bytes.begin(),count,0x5a);state.tail+=count;co_return count;}
                }
                if(!state.mode.starts_with("eof-")||state.mode=="eof-tail"||state.mode=="eof-overflow")co_return 0;
            }
            if(offset<input.size()){auto count=std::min(bytes.size(),input.size()-offset);std::copy_n(input.begin()+offset,count,bytes.begin());offset+=count;co_return count;}
            if(state.eof)co_return 0;
            if(state.last_started&&(state.mode=="late-read"||state.mode=="late-poison")){++state.late_reads;state.poisoned=state.mode=="late-poison";co_return std::unexpected(std::make_error_code(std::errc::connection_reset));}
            state.gate.clear();auto operation=state.gate.wait();auto [error]=deadline?co_await io::timeout(std::move(operation),*deadline):co_await std::move(operation);
            if(error)co_return std::unexpected(error);
        }
    }
};
using Channel=h::ClientChannel<Lower,4>;
auto fields() -> std::array<h::FieldView,4>{return {{{":method","POST"},{":scheme","https"},{":authority","control.example"},{":path","/map"}}};}
auto application(State& state,Channel& channel) -> capy::task<capy::results<>> {
    auto first=channel.submit(fields(),{state.active?std::span<std::uint8_t const>(state.body):std::span<std::uint8_t const>{},true});
    auto second=channel.submit(fields());if(!first||!second)co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    state.first=*first;state.second=*second;
    for(;;){
        if(channel.failure())co_return capy::results<>{};
        auto a=channel.response(*first),b=channel.response(*second);if(!a||!b)co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        if(state.active){
            if(b->closed&&a->status==200&&!*channel.tx_consumed(*first)){state.active_ready=true;state.gate.set();}
        }else if(a->closed&&b->closed){
            if(!*channel.release(*first)||!*channel.release(*second)||!channel.shutdown())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            co_return capy::results<>{};
        }
        if(!co_await channel.wait_change())co_return capy::results<>{};
    }
}
auto monitor(io::io_context& context,State& state,Channel& channel) -> capy::task<capy::results<>> {
    for(;;){
        bool ready=state.active?state.active_ready:state.mode.starts_with("close-")?state.close_started:state.mode.starts_with("eof-")?state.grace_read:state.last_started;
        if(ready)break;
        if(state.canceled)co_return capy::results<>{};state.gate.clear();auto [error]=co_await state.gate.wait();if(error)co_return capy::results<>{};
    }
    state.fired=true;
    if(state.mode.ends_with("abandon")){state.abandoned=true;context.stop();}
    else if(state.mode.ends_with("cancel"))channel.cancel();
    else if(state.mode.ends_with("stop"))state.stop.request_stop();
    else if(state.mode=="active-eof")state.eof=true;
    else if(state.mode=="active-read-throw")state.throw_read=true;
    else if(state.mode=="active-write-throw"){state.throw_write=true;if(!channel.reset(state.first))co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
    state.gate.set();co_return capy::results<>{};
}
auto root(io::io_context& context,State& state,Channel& channel) -> capy::task<> {
    try {
        auto [error,run,app,control]=co_await capy::when_all(channel.run(),application(state,channel),monitor(context,state,channel));(void)run;(void)app;(void)control;
        state.success=!error&&channel.finished()&&!channel.failure();
    }catch(std::bad_alloc const&){state.caught=true;channel.cancel();}catch(...){state.valid=false;channel.cancel();}
    state.done=true;
}
auto exercise(bool uring,std::string_view mode) -> bool {
    State state{mode};state.active=mode.starts_with("active-");
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    Lower lower(state);auto made=h::Client<4>::create();if(!made)return false;
    auto deadline=Clock::now()+(mode.ends_with("deadline")?70ms:1500ms);
    Channel channel(lower,std::move(*made),deadline);
    capy::run_async(context->get_executor(),state.stop.get_token(),[] {},[&](std::exception_ptr){state.valid=false;})(root(*context,state,channel));
    context->run_for(2s);if(!state.done&&!state.abandoned){channel.cancel();context->restart();context->run_for(200ms);}auto stopped=context->stopped();context.reset();
    auto failure=channel.failure();bool success=state.valid&&stopped&&state.fired&&channel.drained()&&!state.reading&&!state.writing&&state.max_read==1&&state.max_write==1;
    if(mode=="normal"||mode=="late-read"||mode=="eof-tail")success=success&&state.done&&state.success&&state.last_started&&state.last_done&&state.last_ok&&state.close_started&&state.close_done&&state.closed&&state.grace_read&&(!state.late_reads||mode=="late-read")&&(mode!="eof-tail"||state.tail==65536);
    else if(mode.ends_with("abandon"))success=success&&state.abandoned&&!state.done&&!state.success&&state.canceled&&!channel.finished()&&(!state.active||*channel.tx_consumed(state.first));
    else if(mode.ends_with("throw"))success=success&&state.done&&state.caught&&!state.success&&failure&&state.canceled&&(!state.active||*channel.tx_consumed(state.first));
    else {
        auto expected=mode.ends_with("deadline")?h::ClientError::timeout:mode=="active-eof"?h::ClientError::truncated:
            mode.ends_with("cancel")||(mode.ends_with("stop")&&mode!="close-stop")||mode=="eof-canceled"?h::ClientError::canceled:mode=="eof-overflow"?h::ClientError::http2:h::ClientError::transport;
        bool expected_failure=failure&&(failure->error==expected||(mode=="close-stop"&&state.stop.stop_requested()&&failure->error==h::ClientError::canceled));
        success=success&&state.done&&!state.success&&expected_failure&&state.canceled&&!channel.finished()&&(!state.active||*channel.tx_consumed(state.first));
    }
    if(!success)std::cerr<<"H2 lifecycle mode="<<mode<<" backend="<<uring<<" done="<<state.done<<" ok="<<state.success<<" caught="<<state.caught<<" fired="<<state.fired<<" late="<<state.late_reads<<" last="<<state.last_started<<":"<<state.last_done<<":"<<state.last_ok<<" failure="<<(failure?int(failure->error):-1)<<" live="<<state.reading<<":"<<state.writing<<" max="<<state.max_read<<":"<<state.max_write<<" close="<<state.close_started<<":"<<state.close_done<<":"<<state.closed<<" grace_read="<<state.grace_read<<" tail="<<state.tail<<'\n';
    return success;
}
auto main() -> int {
    for(bool uring:{false,true}){
        if(uring&&!io::has_uring)continue;
        for(auto mode:{"normal","late-read","late-poison","last-fail","last-throw","last-cancel","last-deadline","last-abandon",
            "active-cancel","active-stop","active-deadline","active-eof","active-read-throw","active-write-throw","active-abandon",
            "close-fail","close-throw","close-cancel","close-stop","close-deadline","close-abandon",
            "eof-error","eof-canceled","eof-throw","eof-cancel","eof-stop","eof-deadline","eof-abandon","eof-tail","eof-overflow"}){
            if(!exercise(uring,mode))return 1;std::println("H2 shared Driver lifecycle {} backend={} passed",mode,uring);
        }
    }
}
