import std;
import quic.http3;
import quic.http3_headers;
import nexus.thirdparty.nghttp3;
import hysteria2.auth;
import http.header;

namespace n=nex::nghttp3;
namespace q=quic;
namespace h=hysteria2;
using View=std::span<std::uint8_t const>;
namespace references {
    bool measure=false;
    std::size_t acquired=0,released=0,expected_acquired=0,expected_released=0;
    struct Scope { bool previous=std::exchange(measure,true); ~Scope() { measure=previous; } };
}
extern "C" auto __real_nghttp3_rcbuf_incref(n::nghttp3_rcbuf*) -> void __attribute__((weak));
extern "C" auto __real_nghttp3_rcbuf_decref(n::nghttp3_rcbuf*) -> void __attribute__((weak));
extern "C" auto __wrap_nghttp3_rcbuf_incref(n::nghttp3_rcbuf* buffer) -> void {
    if (references::measure) ++references::acquired;
    __real_nghttp3_rcbuf_incref(buffer);
}
extern "C" auto __wrap_nghttp3_rcbuf_decref(n::nghttp3_rcbuf* buffer) -> void {
    if (references::measure) ++references::released;
    __real_nghttp3_rcbuf_decref(buffer);
}
namespace allocation {
    std::size_t live=0,calls=0; bool enabled=false,denied=false; std::ptrdiff_t allowance=-1;
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) { ++calls; if (!allowance) { denied=true; throw std::bad_alloc(); } if (allowance>0) --allowance; }
        size=std::max<std::size_t>(size,1); auto* out=std::aligned_alloc(alignment,(size+alignment-1)/alignment*alignment);
        if (!out) throw std::bad_alloc();
        ++live; return out;
    }
    auto release(void* pointer) noexcept -> void { if (pointer) { --live; std::free(pointer); } }
}
auto operator new(std::size_t size) -> void* { return allocation::allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocation::allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocation::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocation::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* p) noexcept -> void { allocation::release(p); }
auto operator delete[](void* p) noexcept -> void { allocation::release(p); }
auto operator delete(void* p,std::size_t) noexcept -> void { allocation::release(p); }
auto operator delete[](void* p,std::size_t) noexcept -> void { allocation::release(p); }
auto operator delete(void* p,std::align_val_t) noexcept -> void { allocation::release(p); }
auto operator delete[](void* p,std::align_val_t) noexcept -> void { allocation::release(p); }
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void { allocation::release(p); }
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void { allocation::release(p); }
namespace {
    bool watch_reads=false;
    std::size_t native_peak=0;
    struct Memory {
        struct alignas(std::max_align_t) Header { std::size_t size; };
        std::size_t live=0,peak=0,calls=0,denied=0,limit=2*1024*1024;
        std::ptrdiff_t allowance=-1;
        static auto allocate(std::size_t size,void* owner) noexcept -> void* {
            auto& self=*static_cast<Memory*>(owner);
            if (!self.allowance) { ++self.denied; return nullptr; }
            if (self.allowance>0) --self.allowance;
            if (self.live>self.limit-sizeof(Header) || size>self.limit-self.live-sizeof(Header)) return nullptr;
            auto* out=static_cast<Header*>(std::malloc(size+sizeof(Header))); if (!out) return nullptr;
            out->size=size+sizeof(Header); self.live+=out->size; self.peak=std::max(self.peak,self.live); native_peak=std::max(native_peak,self.peak); ++self.calls; return out+1;
        }
        static auto release(void* pointer,void* owner) noexcept -> void {
            if (pointer) { auto& self=*static_cast<Memory*>(owner); auto* out=static_cast<Header*>(pointer)-1; self.live-=out->size; std::free(out); }
        }
        static auto zero(std::size_t count,std::size_t size,void* owner) noexcept -> void* {
            if (size && count>std::numeric_limits<std::size_t>::max()/size) return nullptr;
            auto bytes=count*size; auto* out=allocate(bytes,owner); if (out) std::memset(out,0,bytes); return out;
        }
        static auto resize(void* pointer,std::size_t size,void* owner) noexcept -> void* {
            if (!pointer) return allocate(size,owner);
            if (!size) { release(pointer,owner); return nullptr; }
            auto* out=allocate(size,owner); if (!out) return nullptr;
            auto old=(static_cast<Header*>(pointer)-1)->size-sizeof(Header); std::memcpy(out,pointer,std::min(old,size)); release(pointer,owner); return out;
        }
        auto callbacks() noexcept -> n::nghttp3_mem { return {this,allocate,release,zero,resize}; }
    };
    auto fields(std::span<http::HeaderField const> source) -> std::vector<n::nghttp3_nv> {
        std::vector<n::nghttp3_nv> out; out.reserve(source.size());
        for (auto const& field:source) out.push_back({reinterpret_cast<std::uint8_t const*>(field.name.data()),reinterpret_cast<std::uint8_t const*>(field.value.data()),field.name.size(),field.value.size(),static_cast<std::uint8_t>(field.name=="hysteria-auth" ? n::nv_flag_never_index : n::nv_flag_none)});
        return out;
    }
    struct Slot {
        std::int64_t stream=-1;
        q::Http3Headers<> headers;
        std::array<std::uint8_t,12000> body{};
        std::size_t body_size=0,acked=0;
        bool ended=false,fin=false,body_sent=false;
    };
    auto clear(Slot& slot) noexcept -> void {
        references::expected_released+=slot.headers.size()*2; references::Scope measure;
        slot.headers.clear();
    }
    struct Hooks {
        bool server=false,authenticated=false,retain=false,drained=true,reenter_close=false;
        unsigned settings_count=0,closed=0,header_calls=0,reentries=0,action=0,closing_calls=0;
        std::uint64_t input=0,credit=0,data_credit=0,deferred=0,time=0;
        std::array<Slot,8> slots;
        q::Http3<Hooks>* owner=nullptr;
        auto closing(auto& self,int) noexcept -> bool { ++closing_calls; if (reenter_close) self.stop(); return drained; }
        auto slot(std::int64_t id) -> Slot& {
            auto found=std::ranges::find(slots,id,&Slot::stream);
            if (found!=slots.end()) return *found;
            found=std::ranges::find(slots,std::int64_t{-1},&Slot::stream);
            if (found==slots.end()) throw std::runtime_error("bounded H3 slots");
            found->stream=id; return *found;
        }
        auto connection_closed(auto& self,int) noexcept -> void {
            if (self.native()) std::terminate();
            ++closed;
            if (!retain) for (auto& slot:slots) clear(slot);
        }
        auto begin_headers(auto&,std::int64_t id,bool,void*) -> int { clear(slot(id)); return 0; }
        auto header(auto& self,std::int64_t id,std::int32_t,n::nghttp3_rcbuf* name,n::nghttp3_rcbuf* value,std::uint8_t,bool,void*) -> int {
            ++header_calls;
            std::expected<void,q::Http3HeaderError> appended;
            { references::Scope measure; appended=slot(id).headers.append(name,value); }
            if (!appended) return n::err_callback_failure;
            references::expected_acquired+=2;
            if (action==1) throw std::bad_alloc();
            if (action==2) throw std::runtime_error("header policy exception");
            if (action==3) self.stop();
            if (action==4) {
                auto nested=self.read(id,{},false,time+1); if (nested) throw std::runtime_error("reentrant H3 read accepted"); ++reentries;
            }
            return 0;
        }
        auto read_data(auto&,std::int64_t id,std::span<n::nghttp3_vec> output,std::uint32_t& flags,void*) -> n::nghttp3_ssize {
            auto& state=slot(id);
            if (action==6) throw std::bad_alloc();
            if (action==7) throw std::runtime_error("body source exception");
            if (action==8) return n::err_wouldblock;
            if (output.empty() || state.body_sent) return n::err_callback_failure;
            state.body_sent=true; output[0]={state.body.data(),state.body.size()}; flags=n::data_flag_eof; return 1;
        }
        auto end_headers(auto& self,std::int64_t id,bool,bool,void*) -> int {
            auto& state=slot(id); state.ended=true;
            if (server) {
                auto parsed=h::parse_client_auth(state.headers.fields());
                if (parsed) {
                    if (parsed->credential!="test-password") return n::err_callback_failure;
                    auto response=h::ServerAuthHeaders::create({true,true,0}); if (!response) return n::err_callback_failure;
                    auto encoded=fields(response->fields()); auto error=self.response(id,encoded); if (!error) authenticated=true; return error;
                }
                std::array<http::HeaderField,3> response{{{":status","200"},{"content-length","12000"},{"server","nexus-native-h3"}}};
                auto encoded=fields(response);
                for (std::size_t i=0;i<state.body.size();++i) state.body[i]=static_cast<std::uint8_t>(i*73);
                return self.response(id,encoded,true);
            }
            if (id==0) {
                auto parsed=h::parse_server_auth(state.headers.fields()); if (!parsed || !parsed->udp) return n::err_callback_failure; authenticated=true;
            }
            return 0;
        }
        auto data(auto&,std::int64_t id,View bytes,void*) -> int {
            auto& state=slot(id); if (bytes.size()>state.body.size()-state.body_size) return n::err_callback_failure;
            std::ranges::copy(bytes,state.body.begin()+state.body_size); state.body_size+=bytes.size(); data_credit+=bytes.size(); return 0;
        }
        auto deferred_consume(auto&,std::int64_t,std::size_t count,void*) -> int { credit+=count; deferred+=count; return 0; }
        auto data_acked(auto&,std::int64_t id,std::uint64_t count,void*) -> int { slot(id).acked+=count; return 0; }
        auto end_stream(auto&,std::int64_t id,void*) -> int { slot(id).fin=true; return 0; }
        auto stream_closed(auto&,std::uint32_t,std::int64_t id,std::uint64_t,std::uint64_t,void*) -> int { clear(slot(id)); return 0; }
        auto stop_sending(auto&,std::int64_t,std::uint64_t,void*) -> int { return 0; }
        auto reset_stream(auto&,std::int64_t,std::uint64_t,void*) -> int { return 0; }
        auto shutdown(auto&,std::int64_t) -> int { return 0; }
        auto settings(auto&,n::nghttp3_settings const&) -> int { ++settings_count; return 0; }
    };
    struct Frame { std::int64_t stream; std::vector<std::uint8_t> bytes; bool fin; };
    struct Pair {
        Memory client_memory,server_memory;
        Hooks client_hooks,server_hooks;
        q::Http3<Hooks> client{client_hooks},server{server_hooks};
        Pair() { server_hooks.server=true; client_hooks.owner=&client; server_hooks.owner=&server; }
        auto initialize() -> int {
            n::nghttp3_settings settings{}; n::nghttp3_settings_default_versioned(n::settings_version,&settings);
            settings.max_field_section_size=1048576; settings.qpack_max_dtable_capacity=settings.qpack_encoder_max_dtable_capacity=4096; settings.qpack_blocked_streams=2;
            auto error=client.start(false,settings,client_memory.callbacks()); if (!error) error=server.start(true,settings,server_memory.callbacks());
            if (!error) { n::nghttp3_conn_set_max_client_streams_bidi(server.native(),16); n::nghttp3_conn_set_max_concurrent_streams(server.native(),8); }
            if (!error) error=client.bind(2,6,10);
            if (!error) error=server.bind(3,7,11);
            return error;
        }
        auto stop() -> bool { client.stop(); server.stop(); client.stop(); server.stop(); return !client_memory.live && !server_memory.live && client_hooks.closed<=1 && server_hooks.closed<=1; }
    };
    auto capture(q::Http3<Hooks>& sender,std::size_t partial=std::numeric_limits<std::size_t>::max()) -> std::expected<std::vector<Frame>,int> {
        std::vector<Frame> frames;
        for (unsigned attempts=0;attempts<10000;++attempts) {
            std::array<n::nghttp3_vec,16> output{}; auto written=sender.write(output); if (!written) return std::unexpected(written.error());
            if (written->stream==-1) return frames;
            Frame frame{written->stream,{},written->fin}; auto remaining=partial;
            for (std::size_t i=0;i<written->vectors && remaining;++i) { auto n=std::min(remaining,output[i].len); frame.bytes.insert(frame.bytes.end(),output[i].base,output[i].base+n); remaining-=n; }
            auto total=std::accumulate(output.begin(),output.begin()+written->vectors,std::size_t{0},[](auto sum,auto vector) { return sum+vector.len; });
            frame.fin&=frame.bytes.size()==total;
            auto error=sender.accepted(frame.stream,frame.bytes.size()); if (error) return std::unexpected(error); frames.push_back(std::move(frame));
        }
        return std::unexpected(n::err_callback_failure);
    }
    auto deliver(q::Http3<Hooks>& sender,q::Http3<Hooks>& receiver,Hooks& hooks,Frame const& frame,std::size_t chunk) -> int {
        auto receive=[&](View bytes,bool fin) -> int {
            hooks.input+=bytes.size(); allocation::enabled=watch_reads;
            auto consumed=receiver.read(frame.stream,bytes,fin,++hooks.time); allocation::enabled=false;
            if (!consumed) return consumed.error();
            hooks.credit+=*consumed; return 0;
        };
        if (frame.bytes.empty()) { auto error=receive({},frame.fin); if (error) return error; }
        for (std::size_t offset=0;offset<frame.bytes.size();) {
            auto count=std::min(chunk,frame.bytes.size()-offset); auto error=receive(std::span(frame.bytes).subspan(offset,count),frame.fin && offset+count==frame.bytes.size()); if (error) return error; offset+=count;
        }
        return sender.acknowledged(frame.stream,frame.bytes.size());
    }
    auto pump(Pair& pair,std::size_t chunk=7,std::size_t partial=13) -> int {
        for (unsigned attempt=0;attempt<64;++attempt) {
            auto first=capture(pair.client,partial); if (!first) return first.error();
            for (auto const& frame:*first) if (auto error=deliver(pair.client,pair.server,pair.server_hooks,frame,chunk)) return error;
            auto second=capture(pair.server,partial); if (!second) return second.error();
            for (auto const& frame:*second) if (auto error=deliver(pair.server,pair.client,pair.client_hooks,frame,chunk)) return error;
            if (first->empty() && second->empty()) return 0;
        }
        return n::err_callback_failure;
    }
    auto auth(Pair& pair) -> int {
        auto headers=h::ClientAuthHeaders::create("test-password",125000,"padding"); if (!headers) return n::err_callback_failure;
        auto encoded=fields(headers->fields()); return pair.client.request(0,encoded);
    }
    auto get(Pair& pair,std::int64_t stream,std::string_view agent) -> int {
        std::array<http::HeaderField,5> request{{{":method","GET"},{":scheme","https"},{":authority","cover.example"},{":path","/"},{"user-agent",agent}}};
        auto encoded=fields(request); return pair.client.request(stream,encoded);
    }
    auto ordinary(std::size_t chunk) -> int {
        auto before=allocation::live;
        {
            Pair pair; if (auto error=pair.initialize()) return error;
            if (auto error=pump(pair,chunk)) return error;
            if (pair.client_hooks.settings_count!=1 || pair.server_hooks.settings_count!=1) return 1;
            if (pair.server.read(2,{},false,0) || !pair.server.active()) return 9;
            if (auto error=auth(pair)) return error;
            if (auto error=pump(pair,chunk)) return error;
            if (!pair.client_hooks.authenticated || !pair.server_hooks.authenticated || !pair.client_hooks.slot(0).fin || !pair.server_hooks.slot(0).fin) return 2;
            if (auto error=get(pair,4,"first-new-dynamic-agent")) return error;
            pair.client.block(4);
            auto blocked=capture(pair.client); if (!blocked) return blocked.error();
            if (std::ranges::any_of(*blocked,[](auto const& frame) { return frame.stream==4; })) return 3;
            for (auto const& frame:*blocked) if (auto error=deliver(pair.client,pair.server,pair.server_hooks,frame,chunk)) return error;
            if (auto error=pair.client.unblock(4)) return error;
            if (auto error=pump(pair,chunk,5)) return error;
            auto& received=pair.client_hooks.slot(4);
            if (!received.fin || received.body_size!=12000 || pair.server_hooks.slot(4).acked!=12000) return 4;
            for (std::size_t i=0;i<received.body_size;++i) if (received.body[i]!=static_cast<std::uint8_t>(i*73)) return 5;
            if (pair.client_hooks.input!=pair.client_hooks.credit+pair.client_hooks.data_credit || pair.server_hooks.input!=pair.server_hooks.credit+pair.server_hooks.data_credit) return 6;
            if (auto error=pair.client.close_stream(0,4,n::h3_no_error,n::h3_no_error)) return error;
            if (auto error=pair.server.close_stream(0,4,n::h3_no_error,n::h3_no_error)) return error;
            if (!pair.stop()) return 7;
        }
        return allocation::live==before ? 0 : 8;
    }
    auto qpack_cancel() -> int {
        Pair pair; if (auto error=pair.initialize()) return error;
        if (auto error=pump(pair)) return error;
        if (auto error=get(pair,0,"new-blocked-agent-not-in-table")) return error;
        auto frames=capture(pair.client); if (!frames) return frames.error(); bool encoder=false;
        for (auto const& frame:*frames) {
            if (frame.stream==6) encoder=true;
            else if (auto error=deliver(pair.client,pair.server,pair.server_hooks,frame,1)) return error;
        }
        if (!encoder || pair.server_hooks.slot(0).ended) return 1;
        if (auto error=pair.server.shutdown_read(0)) return error;
        if (!pair.stop()) return 2;
        return 0;
    }
    auto retention() -> int {
        Pair pair; if (auto error=pair.initialize()) return error;
        if (auto error=pump(pair)) return error;
        if (auto error=auth(pair)) return error;
        if (auto error=pump(pair)) return error;
        pair.server_hooks.retain=true; pair.server.stop();
        auto headers=pair.server_hooks.slot(0).headers.fields(); auto parsed=h::parse_client_auth(headers);
        if (!parsed || parsed->credential!="test-password" || !pair.server_memory.live) return 1;
        for (auto& slot:pair.server_hooks.slots) { clear(slot); clear(slot); }
        if (!pair.stop()) return 2;
        return 0;
    }
    auto transport_drain() -> int {
        Pair pair; if (auto error=pair.initialize()) return error;
        if (auto error=pump(pair)) return error;
        if (auto error=auth(pair)) return error;
        if (auto error=pump(pair)) return error;
        pair.server_hooks.drained=false; pair.server.stop();
        auto parsed=h::parse_client_auth(pair.server_hooks.slot(0).headers.fields());
        if (!pair.server.native() || pair.server.active() || pair.server_hooks.closed || !pair.server_memory.live || !parsed || parsed->credential!="test-password") return 1;
        pair.server_hooks.drained=true;
        if (!pair.stop() || pair.server_hooks.closed!=1) return 2;
        {
            Pair pair; if (auto error=pair.initialize()) return error;
            pair.server_hooks.reenter_close=true; pair.server.stop();
            if (pair.server_hooks.closing_calls!=1 || pair.server_hooks.closed!=1 || !pair.stop()) return 3;
        }
        return 0;
    }
    auto callback_actions() -> int {
        for (unsigned action=1;action<=4;++action) {
            Pair pair; if (auto error=pair.initialize()) return error;
            if (auto error=pump(pair)) return error;
            pair.server_hooks.action=action;
            if (auto error=auth(pair)) return error;
            auto error=pump(pair); allocation::enabled=false;
            if (action==4) { if (error || !pair.server_hooks.reentries || !pair.server.active()) return 1; }
            else if (error!=(action==1 ? n::err_nomem : n::err_callback_failure)) return 2;
            if (action==3 && (pair.server.native() || pair.server_hooks.closed!=1 || pair.server_hooks.header_calls!=1)) return 3;
            if (!pair.stop()) return 4;
        }
        for (unsigned action:{6u,7u}) {
            Pair pair; if (auto error=pair.initialize()) return error;
            if (auto error=pump(pair)) return error;
            pair.server_hooks.action=action;
            if (auto error=get(pair,4,"body-reader-exception")) return error;
            auto error=pump(pair);
            if (error!=(action==6 ? n::err_nomem : n::err_callback_failure) || !pair.stop()) return 5;
        }
        return 0;
    }
    auto body_resume() -> int {
        Pair pair; if (auto error=pair.initialize()) return error;
        if (auto error=pump(pair)) return error;
        pair.server_hooks.action=8;
        if (auto error=get(pair,4,"delayed-body-source")) return error;
        if (auto error=pump(pair)) return error;
        if (pair.client_hooks.slot(4).fin || pair.client_hooks.slot(4).body_size || !pair.server.active()) return 1;
        pair.server_hooks.action=0; if (auto error=pair.server.resume(4)) return error;
        if (auto error=pump(pair)) return error;
        if (!pair.client_hooks.slot(4).fin || pair.client_hooks.slot(4).body_size!=12000 || !pair.stop()) return 2;
        return 0;
    }
    auto blocked_faults() -> int {
        unsigned failures=0; bool success=false;
        for (std::ptrdiff_t allowance=0;allowance<1000;++allowance) {
            Pair pair; if (auto error=pair.initialize()) return error;
            if (auto error=pump(pair)) return error;
            if (auto error=auth(pair)) return error;
            if (auto error=pump(pair)) return error;
            if (auto error=get(pair,4,"blocked-reader-allocation-sweep")) return error;
            auto frames=capture(pair.client); if (!frames) return frames.error();
            pair.server_memory.allowance=allowance; int error=0; bool encoder=false;
            for (auto const& frame:*frames) {
                if (frame.stream==6) { encoder=true; continue; }
                error=deliver(pair.client,pair.server,pair.server_hooks,frame,1); if (error) break;
            }
            if (!error && (!encoder || pair.server_hooks.slot(4).ended)) return 1;
            for (auto const& frame:*frames) if (!error && frame.stream==6) error=deliver(pair.client,pair.server,pair.server_hooks,frame,1);
            if (pair.server_memory.denied) { if (error!=n::err_nomem) return 2; ++failures; }
            else { if (error || !pair.server_hooks.slot(4).ended || !pair.server_hooks.deferred) return 3; success=true; }
            if (!pair.stop()) return 4;
            if (success) break;
        }
        if (!success || !failures) return 5;
        std::println("HTTP3 blocked QPACK allocation failures={} with deferred credit and complete cancellation release",failures); return 0;
    }
    auto owner_cost() -> int {
        auto before=allocation::live; allocation::calls=0; allocation::allowance=0; allocation::enabled=true;
        {
            Pair pair; auto error=pair.initialize(); auto clean=pair.stop();
            if (error || !clean) { allocation::enabled=false; return 1; }
        }
        allocation::enabled=false;
        return allocation::live==before && !allocation::calls ? 0 : 2;
    }
    auto limits() -> int {
        for (unsigned count:{64u,65u}) {
            Pair pair; if (auto error=pair.initialize()) return error;
            if (auto error=pump(pair)) return error;
            std::vector<http::HeaderField> request{{":method","GET"},{":scheme","https"},{":authority","cover.example"},{":path","/"}};
            while (request.size()<count) request.push_back({"x-limit","a"});
            auto encoded=fields(request); if (auto error=pair.client.request(4,encoded)) return error;
            auto error=pump(pair);
            if (count==64 ? error!=0 || pair.server_hooks.slot(4).headers.size()!=64 : error!=n::err_callback_failure) return 1;
            if (!pair.stop()) return 2;
        }
        for (unsigned extra:{0u,1u}) {
            Pair pair; if (auto error=pair.initialize()) return error;
            if (auto error=pump(pair)) return error;
            std::array<http::HeaderField,5> request{{{":method","GET"},{":scheme","https"},{":authority","cover.example"},{":path","/"},{"user-agent",""}}};
            std::size_t base=0; for (auto const& field:request) base+=field.name.size()+field.value.size();
            std::string value(16384-base+extra,'a'); request.back().value=value;
            auto encoded=fields(request); if (auto error=pair.client.request(4,encoded)) return error;
            auto error=pump(pair);
            if (!extra ? error!=0 || pair.server_hooks.slot(4).headers.bytes()!=16384 : error!=n::err_callback_failure) return 3;
            if (!pair.stop()) return 4;
        }
        q::Http3Headers<> empty;
        if (empty.append(nullptr,nullptr).error()!=q::Http3HeaderError::invalid_reference || empty.size() || empty.bytes()) return 5;
        return 0;
    }
    auto cpp_faults() -> int {
        unsigned failures=0; bool success=false;
        for (std::ptrdiff_t allowance=0;allowance<32;++allowance) {
            auto before=allocation::live;
            {
                Pair pair; if (auto error=pair.initialize()) return error;
                if (auto error=pump(pair)) return error;
                if (auto error=auth(pair)) return error;
                allocation::allowance=allowance; allocation::denied=false; watch_reads=true;
                auto error=pump(pair); watch_reads=false;
                if (allocation::denied) { if (error!=n::err_nomem) return 1; ++failures; }
                else { if (error || !pair.client_hooks.authenticated) return 2; success=true; }
                if (!pair.stop()) return 3;
            }
            if (allocation::live!=before) return 4;
            if (success) break;
        }
        if (!success || !failures) return 5;
        std::println("HTTP3 policy C++ allocation failures={} with exact NOMEM and no retained field refs",failures); return 0;
    }
    auto native_faults() -> int {
        unsigned failed=0;
        for (bool server:{false,true}) {
            bool success=false;
            for (std::ptrdiff_t allowance=0;allowance<1000;++allowance) {
                auto before=allocation::live;
                {
                    Pair pair; auto& memory=server ? pair.server_memory : pair.client_memory; memory.allowance=allowance;
                    auto error=pair.initialize(); if (!error) error=pump(pair); if (!error) error=auth(pair); if (!error) error=pump(pair);
                    if (memory.denied) { if (error!=n::err_nomem) { std::println("native H3 fault server={} allowance={} error={}",server,allowance,error); return 1; } ++failed; }
                    else { if (error || !pair.client_hooks.authenticated) return 2; success=true; }
                    if (!pair.stop()) return 3;
                }
                if (allocation::live!=before) return 4;
                if (success) break;
            }
            if (!success) return 5;
        }
        std::println("HTTP3 native allocation failures={} with zero retained native/C++ allocations",failed); return 0;
    }
}
auto main(int argc,char** argv) -> int {
    bool wrapped=argc==2 && std::string_view(argv[1])=="--wrapped-refs";
    if (argc!=1 && !wrapped) return 98;
    try {
        for (auto chunk:{1u,7u,4096u}) if (auto result=ordinary(chunk)) { std::println("H3 ordinary chunk={} failed {}",chunk,result); return 1; }
        if (auto result=qpack_cancel()) { std::println("H3 QPACK cancel failed {}",result); return 2; }
        if (auto result=retention()) { std::println("H3 reference retention failed {}",result); return 3; }
        if (auto result=transport_drain()) { std::println("H3 transport drain failed {}",result); return 12; }
        if (auto result=callback_actions()) { std::println("H3 callback actions failed {}",result); return 4; }
        if (auto result=limits()) { std::println("H3 field limits failed {}",result); return 6; }
        if (auto result=cpp_faults()) { std::println("H3 C++ faults failed {}",result); return 7; }
        if (auto result=body_resume()) { std::println("H3 body resume failed {}",result); return 8; }
        if (auto result=blocked_faults()) { std::println("H3 blocked faults failed {}",result); return 9; }
        if (auto result=owner_cost()) { std::println("H3 owner allocation cost failed {}",result); return 10; }
        if (auto result=native_faults()) { std::println("H3 native faults failed {}",result); return 5; }
        if (wrapped) {
            if (!references::acquired || references::acquired!=references::released || references::acquired!=references::expected_acquired || references::released!=references::expected_released) {
                std::println("H3 rcbuf wrapper calibration/balance failed actual={}/{} expected={}/{}",references::acquired,references::released,references::expected_acquired,references::expected_released); return 11;
            }
            std::println("calibrated native rcbuf wrapper acquired={} released={}; every retained field pair independently matched",references::acquired,references::released);
        }
        std::println("HTTP3 owner auth233/QPACK/partial accepted+ACK/body FIN/credit/block+unblock/cancel/ref retention/callback exceptions and stop passed; owner={} headers={} workload native peak={} bytes; owner construction/bind/stop C++ allocations=0",sizeof(q::Http3<Hooks>),sizeof(q::Http3Headers<>),native_peak);
    } catch (std::exception const& error) { std::println("H3 test exception {}",error.what()); return 99; }
}
