import std;
import nexus.thirdparty.nghttp3;
import http.header;
import quic.varint;
import hysteria2.auth;
import hysteria2.dispatch;
import hysteria2.wire;

namespace h=hysteria2;
namespace q=quic;
namespace n=nex::nghttp3;
namespace {
    struct Frame { std::int64_t stream; std::vector<std::uint8_t> bytes; bool fin; };
    auto check(int error) -> void { if (error) throw std::runtime_error(n::nghttp3_strerror(error)); }
    auto fields(std::span<http::HeaderField const> source) -> std::vector<n::nghttp3_nv> {
        std::vector<n::nghttp3_nv> result; result.reserve(source.size());
        for (auto const& field:source) {
            auto flags=field.name=="hysteria-auth" ? n::nv_flag_never_index : n::nv_flag_none;
            result.push_back({reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.name.data())),
                reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.value.data())),field.name.size(),field.value.size(),flags});
        }
        return result;
    }
    struct FieldSection {
        std::vector<std::pair<std::string,std::string>> owned;
        std::size_t bytes=0;
        bool ended=false,fin=false;
        auto views() const -> std::vector<http::HeaderField> {
            std::vector<http::HeaderField> result;
            for (auto const& [key,value]:owned) result.push_back({key,value});
            return result;
        }
    };
    struct RoutedStream { h::StreamDispatch dispatch; std::vector<std::uint8_t> tcp; bool rejected=false; };
    struct Peer {
        n::nghttp3_conn* connection=nullptr;
        bool server,authenticated=false,poisoned=false;
        unsigned settings_received=0,completed=0,auth_sections=0;
        std::uint64_t input=0,credit=0,deferred=0,timestamp=1;
        std::map<std::int64_t,FieldSection> sections;
        std::map<std::int64_t,RoutedStream> routes;
        explicit Peer(bool server_):server(server_) {
            n::nghttp3_settings settings{};
            n::nghttp3_settings_default_versioned(n::settings_version,&settings);
            settings.max_field_section_size=h::max_auth_bytes;
            settings.qpack_max_dtable_capacity=4096; settings.qpack_encoder_max_dtable_capacity=4096; settings.qpack_blocked_streams=16;
            n::nghttp3_callbacks callbacks{};
            callbacks.begin_headers=[](n::nghttp3_conn*,std::int64_t stream,void* owner,void*) -> int {
                try { static_cast<Peer*>(owner)->sections[stream]=FieldSection{}; return 0; } catch (...) { return n::err_callback_failure; }
            };
            callbacks.recv_header=[](n::nghttp3_conn*,std::int64_t stream,std::int32_t,n::nghttp3_rcbuf* name,n::nghttp3_rcbuf* value,std::uint8_t,void* owner,void*) -> int {
                try {
                    auto& section=static_cast<Peer*>(owner)->sections.at(stream);
                    auto key=n::nghttp3_rcbuf_get_buf(name),text=n::nghttp3_rcbuf_get_buf(value);
                    if (section.owned.size()==h::max_auth_fields || key.len>h::max_auth_bytes-section.bytes ||
                        text.len>h::max_auth_bytes-section.bytes-key.len) return n::err_callback_failure;
                    section.bytes+=key.len+text.len;
                    section.owned.emplace_back(std::string(reinterpret_cast<char const*>(key.base),key.len),std::string(reinterpret_cast<char const*>(text.base),text.len));
                    return 0;
                } catch (...) { return n::err_callback_failure; }
            };
            callbacks.end_headers=[](n::nghttp3_conn*,std::int64_t stream,int fin,void* owner,void*) -> int {
                try { static_cast<Peer*>(owner)->end_headers(stream,fin); return 0; } catch (...) { return n::err_callback_failure; }
            };
            callbacks.end_stream=[](n::nghttp3_conn*,std::int64_t stream,void* owner,void*) -> int {
                try { auto& peer=*static_cast<Peer*>(owner); peer.sections.at(stream).fin=true; ++peer.completed; return 0; }
                catch (...) { return n::err_callback_failure; }
            };
            callbacks.deferred_consume=[](n::nghttp3_conn*,std::int64_t,std::size_t count,void* owner,void*) -> int {
                auto& peer=*static_cast<Peer*>(owner); peer.credit+=count; peer.deferred+=count; return 0;
            };
            callbacks.recv_settings=[](n::nghttp3_conn*,n::nghttp3_settings const*,void* owner) -> int {
                ++static_cast<Peer*>(owner)->settings_received; return 0;
            };
            auto create=server ? n::nghttp3_conn_server_new_versioned : n::nghttp3_conn_client_new_versioned;
            check(create(&connection,n::callbacks_version,&callbacks,n::settings_version,&settings,nullptr,this));
            try {
                if (server) n::nghttp3_conn_set_max_client_streams_bidi(connection,64);
                n::nghttp3_conn_set_max_concurrent_streams(connection,64);
                auto first=server ? 3 : 2;
                check(n::nghttp3_conn_bind_control_stream(connection,first));
                check(n::nghttp3_conn_bind_qpack_streams(connection,first+4,first+8));
            } catch (...) { n::nghttp3_conn_del(connection); connection=nullptr; throw; }
        }
        ~Peer() { n::nghttp3_conn_del(connection); }
        Peer(Peer const&)=delete;
        auto operator=(Peer const&) -> Peer& = delete;
        auto end_headers(std::int64_t stream,int) -> void {
            auto& section=sections.at(stream); section.ended=true;
            auto views=section.views();
            if (server) {
                auto parsed=h::parse_client_auth(views);
                if (parsed) {
                    if (parsed->credential!="test-password" || parsed->receive_bps!=125000) throw std::runtime_error("auth mismatch");
                    auto response=h::ServerAuthHeaders::create({true,true,0}); if (!response) throw std::runtime_error("auth response");
                    auto encoded=fields(response->fields());
                    check(n::nghttp3_conn_submit_response(connection,stream,encoded.data(),encoded.size(),nullptr));
                    authenticated=true; ++auth_sections;
                } else {
                    if (parsed.error()!=h::AuthError::not_auth) throw std::runtime_error("malformed request");
                    std::array<http::HeaderField,2> response{{{":status","200"},{"server","nexus-quic-dispatch"}}};
                    auto encoded=fields(response);
                    check(n::nghttp3_conn_submit_response(connection,stream,encoded.data(),encoded.size(),nullptr));
                }
            } else if (stream==0) {
                auto parsed=h::parse_server_auth(views);
                if (!parsed || !parsed->udp || !parsed->automatic) throw std::runtime_error("auth response mismatch");
                authenticated=true; ++auth_sections;
            }
        }
        auto http3(std::int64_t stream,std::span<std::uint8_t const> bytes,bool fin) -> void {
            if (poisoned) throw std::runtime_error("HTTP3 already failed");
            auto consumed=n::nghttp3_conn_read_stream2(connection,stream,bytes.data(),bytes.size(),fin,++timestamp);
            if (consumed<0) { poisoned=true; throw std::runtime_error(n::nghttp3_strerror(static_cast<int>(consumed))); }
            input+=bytes.size(); credit+=static_cast<std::uint64_t>(consumed);
        }
        auto receive(std::int64_t stream,std::span<std::uint8_t const> bytes,bool fin) -> void {
            if (!server || (stream&3)!=0) { http3(stream,bytes,fin); return; }
            auto& state=routes[stream];
            auto previous=state.dispatch.route();
            auto result=state.dispatch.feed(bytes,authenticated,fin);
            if (result.route==h::StreamRoute::pending) return;
            if (result.route==h::StreamRoute::rejected) { state.rejected=true; return; }
            if (previous==h::StreamRoute::pending) {
                auto prefix=state.dispatch.prefix();
                if (result.route==h::StreamRoute::tcp) state.tcp.insert(state.tcp.end(),prefix.begin(),prefix.end());
                else http3(stream,prefix,fin && result.consumed==bytes.size());
            }
            auto remaining=bytes.subspan(result.consumed);
            if (result.route==h::StreamRoute::tcp) state.tcp.insert(state.tcp.end(),remaining.begin(),remaining.end());
            else if (!remaining.empty() || (fin && previous!=h::StreamRoute::pending)) http3(stream,remaining,fin);
        }
        auto capture() -> std::vector<Frame> {
            std::vector<Frame> result;
            for (unsigned attempt=0;attempt<1024;++attempt) {
                std::array<n::nghttp3_vec,16> output{}; std::int64_t stream=-1; int fin=0;
                auto count=n::nghttp3_conn_writev_stream(connection,&stream,&fin,output.data(),output.size());
                if (count<0) { poisoned=true; throw std::runtime_error(n::nghttp3_strerror(static_cast<int>(count))); }
                if (stream==-1) return result;
                Frame frame{stream,{},bool(fin)};
                for (std::ptrdiff_t i=0;i<count;++i) frame.bytes.insert(frame.bytes.end(),output[i].base,output[i].base+output[i].len);
                check(n::nghttp3_conn_add_write_offset(connection,stream,frame.bytes.size())); result.push_back(std::move(frame));
            }
            throw std::runtime_error("HTTP3 capture did not drain");
        }
    };
    auto deliver(Peer& sender,Peer& receiver,Frame const& frame,std::size_t fragment=1) -> void {
        if (frame.bytes.empty()) receiver.receive(frame.stream,{},frame.fin);
        for (std::size_t offset=0;offset<frame.bytes.size();) {
            auto count=std::min(fragment,frame.bytes.size()-offset);
            receiver.receive(frame.stream,std::span(frame.bytes).subspan(offset,count),frame.fin && offset+count==frame.bytes.size()); offset+=count;
        }
        check(n::nghttp3_conn_add_ack_offset(sender.connection,frame.stream,frame.bytes.size()));
    }
    auto pump(Peer& first,Peer& second,std::size_t fragment=1) -> void {
        for (unsigned attempt=0;attempt<64;++attempt) {
            auto a=first.capture(); for (auto const& frame:a) deliver(first,second,frame,fragment);
            auto b=second.capture(); for (auto const& frame:b) deliver(second,first,frame,fragment);
            if (a.empty() && b.empty()) return;
        }
        throw std::runtime_error("HTTP3 pump did not converge");
    }
    auto submit_get(Peer& client,std::int64_t stream,std::string_view user_agent) -> void {
        std::array<http::HeaderField,5> request{{{":method","GET"},{":scheme","https"},{":authority","cover.example"},{":path","/"},{"user-agent",user_agent}}};
        auto encoded=fields(request); check(n::nghttp3_conn_submit_request(client.connection,stream,encoded.data(),encoded.size(),nullptr,nullptr));
    }
    auto prefix_cases() -> int {
        for (auto width:{2u,4u,8u}) {
            std::array<std::uint8_t,9> bytes{}; if (!q::write_varint(bytes,0x401,width)) return 1; bytes[width]=99;
            for (unsigned split=0;split<=width;++split) {
                h::StreamDispatch gate;
                auto first=gate.feed(std::span(bytes).first(split),true);
                if (first.consumed!=split || first.route!=(split==width ? h::StreamRoute::tcp : h::StreamRoute::pending)) return 2;
                auto rest=gate.feed(std::span(bytes).subspan(split,width+1-split),true);
                if (rest.route!=h::StreamRoute::tcp || rest.consumed!=width-split || gate.prefix().size()!=width ||
                    !std::ranges::equal(gate.prefix(),std::span(bytes).first(width))) return 3;
                if (gate.feed(bytes,false,true).route!=h::StreamRoute::tcp || gate.prefix().size()!=width) return 4;
            }
        }
        h::StreamDispatch preauth;
        if (preauth.feed(std::array<std::uint8_t,1>{0x44},false).route!=h::StreamRoute::pending) return 5;
        auto rejected=preauth.feed(std::array<std::uint8_t,1>{1},true);
        if (rejected.route!=h::StreamRoute::rejected || rejected.error!=h::DispatchError::unauthenticated) return 6;
        for (std::size_t size=0;size<8;++size) {
            h::StreamDispatch truncated;
            std::array<std::uint8_t,8> prefix{0xc0};
            auto result=truncated.feed(std::span(prefix).first(size),true,true);
            if (result.route!=h::StreamRoute::rejected || result.error!=h::DispatchError::truncated) return 7;
        }
        h::StreamDispatch ordinary;
        if (ordinary.feed(std::array<std::uint8_t,2>{1,0xff},false).route!=h::StreamRoute::http3 || ordinary.prefix().size()!=1) return 8;
        return 0;
    }
    auto mixed_connection(std::size_t fragment) -> int {
        Peer client(false),server(true); pump(client,server,fragment);
        if (client.settings_received!=1 || server.settings_received!=1 || client.authenticated || server.authenticated) return 1;
        auto raw=h::encode_tcp_request("example.com:443"); if (!raw) return 2;
        raw->insert(raw->end(),{7,8,9});
        server.receive(4,*raw,true);
        if (!server.routes.at(4).rejected || !server.routes.at(4).tcp.empty() || server.poisoned) return 3;
        auto auth=h::ClientAuthHeaders::create("test-password",125000,"pad"); if (!auth) return 4;
        auto encoded=fields(auth->fields()); check(n::nghttp3_conn_submit_request(client.connection,0,encoded.data(),encoded.size(),nullptr,nullptr));
        pump(client,server,fragment);
        if (!client.authenticated || !server.authenticated || client.auth_sections!=1 || server.auth_sections!=1 || !client.sections.at(0).fin || !server.sections.at(0).fin) return 5;
        auto h3_before=server.input;
        for (auto width:{2u,4u,8u}) {
            auto stream=static_cast<std::int64_t>(width*4);
            std::array<std::uint8_t,8> prefix{}; (void)q::write_varint(prefix,0x401,width);
            std::vector<std::uint8_t> wire(prefix.begin(),prefix.begin()+width); wire.insert(wire.end(),raw->begin()+2,raw->end());
            for (std::size_t offset=0;offset<wire.size();) {
                auto count=std::min(fragment,wire.size()-offset); server.receive(stream,std::span(wire).subspan(offset,count),offset+count==wire.size()); offset+=count;
            }
            auto const& tcp=server.routes.at(stream).tcp;
            h::TcpRequestDecoder decoder; auto result=decoder.feed(tcp);
            if (result.status!=h::WireStatus::accepted || !decoder.request() || decoder.request()->address!="example.com:443" ||
                !std::ranges::equal(std::span(tcp).subspan(result.consumed),std::array<std::uint8_t,3>{7,8,9})) return 6;
        }
        if (server.input!=h3_before) return 7;
        // Feed a later HTTP field section before its new QPACK encoder bytes.
        // It must unblock after those bytes arrive despite the skipped TCP IDs.
        submit_get(client,36,"nexus-quic-dispatch-first-unique-agent");
        auto frames=client.capture(); std::vector<Frame> encoder;
        for (auto const& frame:frames) {
            if (frame.stream==6) encoder.push_back(frame); else deliver(client,server,frame,fragment);
        }
        if (encoder.empty() || (server.sections.contains(36) && server.sections.at(36).ended)) return 8;
        for (auto const& frame:encoder) deliver(client,server,frame,fragment);
        pump(client,server,fragment);
        if (!server.sections.at(36).ended || !server.sections.at(36).fin || !client.sections.at(36).fin || !server.deferred) return 9;
        submit_get(client,40,"nexus-quic-dispatch-first-unique-agent"); pump(client,server,fragment);
        if (!server.sections.at(40).ended || !client.sections.at(40).fin || server.completed!=3 || client.completed!=3 ||
            server.input!=server.credit || client.input!=client.credit || server.poisoned || client.poisoned) return 10;
        return 0;
    }
}
auto main() -> int {
    try {
        if (auto result=prefix_cases()) { std::println("Hy2 stream prefix case {} failed",result); return result; }
        for (auto fragment:{1u,2u,7u,4096u}) {
            if (auto result=mixed_connection(fragment)) { std::println("HTTP3/Hy2 dispatch fragment={} case {} failed",fragment,result); return 20+result; }
        }
    } catch (std::exception const& error) { std::println("HTTP3/Hy2 dispatch exception: {}",error.what()); return 99; }
    std::println("HTTP3 memory auth 233, authenticated Hy2 0x401 streams, nonminimal prefixes, later GET/QPACK blocking and exact flow credits passed");
}
