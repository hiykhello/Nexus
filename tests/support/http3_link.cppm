export module test.http3_link;
import std;
import crypto;
import quic.connection;
import quic.http3;
import quic.http3_headers;
import hysteria2.auth;
import http.header;
import ngtcp2;
import nghttp3;
import test.quic_tls_link;

export namespace test::http3_link {
    namespace n = ::ngtcp2;
    namespace h3 = ::nghttp3;
    namespace q=quic;
    namespace h=hysteria2;
    namespace support=test::quic_tls;
    using View=std::span<std::uint8_t const>;
    template<std::size_t Count> auto fields(std::array<http::HeaderField,Count> const& source) -> std::array<h3::nghttp3_nv,Count> {
        std::array<h3::nghttp3_nv,Count> out{};
        for (std::size_t i=0;i<Count;++i) { auto const& field=source[i]; out[i]={reinterpret_cast<std::uint8_t const*>(field.name.data()),reinterpret_cast<std::uint8_t const*>(field.value.data()),field.name.size(),field.value.size(),h3::nv_flag_none}; }
        return out;
    }
    struct Slot {
        std::int64_t id=-1;
        q::Http3Headers<> headers;
        std::array<std::uint8_t,12000> body{};
        std::size_t received=0,acked=0;
        bool body_sent=false,fin=false,ended=false;
    };
    struct Borrow { View bytes; std::uint64_t hash; };
    auto hash(View bytes) noexcept -> std::uint64_t { std::uint64_t out=1469598103934665603ULL; for (auto byte:bytes) out=(out^byte)*1099511628211ULL; return out; }
    template<class Tls> struct Application {
        using Transport=q::Connection<Tls,Application>;
        using Http3=q::Http3<Application>;
        Tls& tls;
        support::Memory memory;
        std::array<Slot,4> slots;
        Http3 http3{*this};
        Transport* transport=nullptr;
        bool server=false,authenticated=false,quic_closed_active=false,broken=false,held_during_callback=false;
        bool defer_native=false,stop_requested=false,io_joined=false;
        std::int64_t stop_stream=8;
        unsigned completed=0,quic_closed=0,http3_closed=0,reentered=0,closing_calls=0,action=0,acted=0,settings_count=0;
        int http3_error=0;
        std::uint64_t time=0,input=0,framing=0,payload=0,sent=0,acked=0;
        std::array<Borrow,16> borrowed{};
        std::size_t borrow_count=0;
        struct Offset { std::int64_t id=-1; std::uint64_t value=0; };
        std::array<Offset,8> offsets{};
        explicit Application(Tls& value):tls(value) {}
        auto slot(std::int64_t id) -> Slot& {
            auto out=std::ranges::find(slots,id,&Slot::id);
            if (out==slots.end()) out=std::ranges::find(slots,std::int64_t{-1},&Slot::id);
            if (out==slots.end()) throw std::runtime_error("bounded H3 slots");
            out->id=id; return *out;
        }
        auto refs_valid() noexcept -> bool {
            if (!authenticated) return true;
            auto parsed=server ? h::parse_client_auth(slots[0].headers.fields()).has_value() : h::parse_server_auth(slots[0].headers.fields()).has_value();
            if (!parsed || !slots[0].headers.size()) return false;
            for (std::size_t i=0;i<borrow_count;++i) if (hash(borrowed[i].bytes)!=borrowed[i].hash) return false;
            return true;
        }
        auto hold(std::span<h3::nghttp3_vec const> vectors,std::size_t count) noexcept -> void {
            borrow_count=0;
            for (auto const& vector:vectors) {
                if (!count) break;
                auto size=std::min(vector.len,count); auto bytes=View(vector.base,size);
                borrowed[borrow_count++]={bytes,hash(bytes)}; count-=size;
            }
            broken|=bool(count);
        }
        auto closing(Http3& owner,int) noexcept -> bool {
            ++closing_calls; broken|=owner.active() || !refs_valid();
            if (defer_native && !io_joined) { stop_requested=true; return false; }
            if (transport && transport->native()) {
                transport->stop();
                if (transport->native()) { held_during_callback=true; broken|=!owner.native() || !memory.used || !refs_valid(); }
            }
            return (!transport || !transport->native()) && !quic_closed_active;
        }
        auto connection_closed(Http3& owner,int) noexcept -> void {
            broken|=owner.native()!=nullptr || (transport && transport->native()) || quic_closed_active;
            ++http3_closed; borrow_count=0; for (auto& state:slots) state.headers.clear();
        }
        auto connection_closed(Transport& connection,int) noexcept -> void {
            ++quic_closed; quic_closed_active=true; broken|=connection.native()!=nullptr || !refs_valid();
            auto existed=http3.native()!=nullptr; http3.stop(); ++reentered;
            broken|=existed && (!http3.native() || http3.active() || !memory.used || !refs_valid());
            quic_closed_active=false; tls.cancel();
        }
        auto drain() noexcept -> void { if (http3.native() && !http3.active()) http3.stop(); }
        auto handshake_complete(Transport& connection) -> int {
            if (!tls.complete()) return n::err_callback_failure;
            ++completed;
            h3::nghttp3_settings settings{}; h3::nghttp3_settings_default_versioned(h3::settings_version,&settings);
            settings.qpack_max_dtable_capacity=settings.qpack_encoder_max_dtable_capacity=4096; settings.qpack_blocked_streams=2;
            auto error=http3.start(server,settings,memory.http3()); if (error) return n::err_callback_failure;
            if (server) h3::nghttp3_conn_set_max_client_streams_bidi(http3.native(),16);
            h3::nghttp3_conn_set_max_concurrent_streams(http3.native(),8);
            std::array<std::int64_t,3> ids{};
            for (auto& id:ids) if (auto error=n::ngtcp2_conn_open_uni_stream(connection.native(),&id,nullptr)) return error;
            return http3.bind(ids[0],ids[1],ids[2]);
        }
        auto handshake_confirmed(Transport&) -> int { return 0; }
        auto credit(std::int64_t id,std::size_t size) -> int {
            auto error=n::ngtcp2_conn_extend_max_stream_offset(transport->native(),id,size);
            if (!error) n::ngtcp2_conn_extend_max_offset(transport->native(),size); return error;
        }
        auto stream_data(Transport& connection,std::uint32_t flags,std::int64_t id,std::uint64_t offset,View bytes,void*) -> int {
            if (!tls.complete() || !http3.active()) { broken=true; return n::err_callback_failure; }
            if (defer_native && action==4 && id==stop_stream) {
                ++acted; stop_requested=true; http3.stop();
                held_during_callback=true; broken|=!connection.native() || !http3.native() || http3.active() || !refs_valid(); return 0;
            }
            if (action==4 && id==stop_stream) {
                ++acted; connection.stop(); http3.stop();
                held_during_callback=true; broken|=!connection.native() || !http3.native() || http3.active() || !refs_valid(); return 0;
            }
            auto state=std::ranges::find(offsets,id,&Offset::id);
            if (state==offsets.end()) state=std::ranges::find(offsets,std::int64_t{-1},&Offset::id);
            if (state==offsets.end() || state->value!=offset) return n::err_callback_failure;
            state->id=id; state->value+=bytes.size(); input+=bytes.size();
            auto consumed=http3.read(id,bytes,bool(flags&n::stream_data_flag_fin),time);
            if (!consumed) { http3_error=consumed.error(); return n::err_callback_failure; }
            framing+=*consumed; return credit(id,*consumed);
        }
        auto stream_acked(Transport&,std::int64_t id,std::uint64_t,std::uint64_t size,void*) -> int {
            acked+=size; if (!http3.active()) return 0;
            auto error=http3.acknowledged(id,size); if (error) { http3_error=error; return n::err_callback_failure; } return 0;
        }
        auto stream_close(Transport&,std::uint32_t,std::int64_t id,std::uint64_t,std::uint64_t,void*) -> int {
            if (!http3.active()) return 0;
            auto error=http3.close_stream(0,id,h3::h3_no_error,h3::h3_no_error); return error ? n::err_callback_failure : 0;
        }
        auto stream_limit(Transport&,std::int64_t id,std::uint64_t,void*) -> int { return http3.active() ? http3.unblock(id) : 0; }
        template<class... Args> auto stream_limit(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_reset(Args&&...) -> int { return 0; }
        template<class... Args> auto stop_sending(Args&&...) -> int { return 0; }
        template<class... Args> auto datagram(Args&&...) -> int { return 0; }
        template<class... Args> auto add_connection_id(Args&&...) -> int { return 0; }
        template<class... Args> auto remove_connection_id(Args&&...) -> int { return 0; }
        auto begin_headers(Http3&,std::int64_t id,bool,void*) -> int { slot(id).headers.clear(); return 0; }
        auto header(Http3& owner,std::int64_t id,std::int32_t,h3::nghttp3_rcbuf* name,h3::nghttp3_rcbuf* value,std::uint8_t,bool,void*) -> int {
            if (!slot(id).headers.append(name,value)) return h3::err_callback_failure;
            if (action==3 && id==stop_stream) { ++acted; owner.stop(); broken|=owner.active() || !owner.native() || !transport->native() || !refs_valid(); }
            return 0;
        }
        auto end_headers(Http3& owner,std::int64_t id,bool,bool,void*) -> int {
            auto& state=slot(id); state.ended=true;
            if (server) {
                if (id==0) {
                    auto parsed=h::parse_client_auth(state.headers.fields());
                    if (!parsed || parsed->credential!="test-password") return h3::err_callback_failure;
                    auto headers=h::ServerAuthHeaders::create({true,true,0}); if (!headers) return h3::err_callback_failure;
                    std::array<h3::nghttp3_nv,8> encoded{}; auto source=headers->fields();
                    for (std::size_t i=0;i<source.size();++i) encoded[i]={reinterpret_cast<std::uint8_t const*>(source[i].name.data()),reinterpret_cast<std::uint8_t const*>(source[i].value.data()),source[i].name.size(),source[i].value.size(),h3::nv_flag_none};
                    auto error=owner.response(id,std::span(encoded).first(source.size())); if (!error) authenticated=true; return error;
                }
                std::array<http::HeaderField,3> response{{{":status","200"},{"content-length","12000"},{"server","native-h3-transport"}}};
                for (std::size_t i=0;i<state.body.size();++i) state.body[i]=static_cast<std::uint8_t>(i*73);
                return owner.response(id,fields(response),true);
            }
            if (id==0) { auto parsed=h::parse_server_auth(state.headers.fields()); if (!parsed || !parsed->udp) return h3::err_callback_failure; authenticated=true; }
            return 0;
        }
        auto read_data(Http3&,std::int64_t id,std::span<h3::nghttp3_vec> output,std::uint32_t& flags,void*) -> h3::nghttp3_ssize {
            auto& state=slot(id); if (output.empty() || state.body_sent) return h3::err_callback_failure;
            output[0]={state.body.data(),state.body.size()}; state.body_sent=true; flags=h3::data_flag_eof; return 1;
        }
        auto data(Http3&,std::int64_t id,View bytes,void*) -> int {
            auto& state=slot(id); if (bytes.size()>state.body.size()-state.received) return h3::err_callback_failure;
            std::ranges::copy(bytes,state.body.begin()+state.received); state.received+=bytes.size(); payload+=bytes.size(); return credit(id,bytes.size());
        }
        auto deferred_consume(Http3&,std::int64_t id,std::size_t count,void*) -> int { framing+=count; return credit(id,count); }
        auto data_acked(Http3&,std::int64_t id,std::uint64_t size,void*) -> int { slot(id).acked+=size; return 0; }
        auto end_stream(Http3&,std::int64_t id,void*) -> int { slot(id).fin=true; return 0; }
        auto stream_closed(Http3&,std::uint32_t,std::int64_t,std::uint64_t,std::uint64_t,void*) -> int { return 0; }
        auto stop_sending(Http3&,std::int64_t,std::uint64_t,void*) -> int { return 0; }
        auto reset_stream(Http3&,std::int64_t,std::uint64_t,void*) -> int { return 0; }
        auto shutdown(Http3&,std::int64_t) -> int { return 0; }
        auto settings(Http3&,h3::nghttp3_settings const&) -> int { ++settings_count; return 0; }
    };
    struct Written { std::size_t bytes=0; std::int64_t stream=-1; std::size_t accepted=0; };
    template<class Peer> auto write(Peer& peer,std::span<std::uint8_t> output,std::uint64_t& now,bool hold=false,std::uint64_t step=1000000) -> std::expected<Written,int> {
        auto& app=peer.app; app.time=now; std::array<h3::nghttp3_vec,16> vectors{};
        if (app.http3.active()) {
            auto pending=app.http3.write(vectors); if (!pending) return std::unexpected(pending.error());
            if (pending->stream!=-1) {
                std::array<n::ngtcp2_vec,16> data{}; for (std::size_t i=0;i<pending->vectors;++i) data[i]={vectors[i].base,vectors[i].len};
                auto result=peer.connection.write_stream(output,nullptr,nullptr,pending->stream,std::span(data).first(pending->vectors),pending->fin,now+=step);
                if (!result && result.error()!=n::err_stream_data_blocked) return std::unexpected(result.error());
                if (result) {
                    if (result->stream_bytes>=0) {
                        auto count=static_cast<std::size_t>(result->stream_bytes); app.sent+=count;
                        if (hold && pending->stream==4 && count) app.hold(std::span(vectors).first(pending->vectors),count);
                        if (auto error=app.http3.accepted(pending->stream,count)) return std::unexpected(error);
                        return Written{result->packet_bytes,pending->stream,count};
                    }
                    return Written{result->packet_bytes};
                }
                app.http3.block(pending->stream);
            }
        }
        auto result=peer.connection.write_packet(output,nullptr,nullptr,now+=step);
        if (!result) return std::unexpected(result.error()); return Written{*result};
    }
    auto request(auto& peer,bool auth) -> int {
        std::int64_t stream=-1; auto error=n::ngtcp2_conn_open_bidi_stream(peer.connection.native(),&stream,nullptr); if (error) return error;
        if (!auth) {
            std::array<http::HeaderField,5> request{{{":method","GET"},{":scheme","https"},{":authority","cover.example"},{":path","/"},{"user-agent",stream==4 ? "first-dynamic-agent" : "second-dynamic-agent"}}};
            return peer.app.http3.request(stream,fields(request));
        }
        auto headers=h::ClientAuthHeaders::create("test-password",125000,"padding"); if (!headers) return h3::err_callback_failure;
        auto source=headers->fields(); std::array<h3::nghttp3_nv,8> encoded{};
        for (std::size_t i=0;i<source.size();++i) encoded[i]={reinterpret_cast<std::uint8_t const*>(source[i].name.data()),reinterpret_cast<std::uint8_t const*>(source[i].value.data()),source[i].name.size(),source[i].value.size(),static_cast<std::uint8_t>(source[i].name=="hysteria-auth" ? h3::nv_flag_never_index : h3::nv_flag_none)};
        return peer.app.http3.request(stream,std::span(encoded).first(source.size()));
    }
}
