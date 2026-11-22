import std;
import http2.server;
import nexus.thirdparty.nghttp2;
namespace h2=nex::nghttp2;
namespace http=http2;
struct Input { std::size_t received=0; bool ended=false,valid=true; };
struct Body { std::size_t sent=0; bool enabled=false; };
auto headers(void*,std::int32_t,std::span<http::Header const>,bool trailers,bool end) noexcept -> bool { return !trailers && !end; }
auto data(void* pointer,std::int32_t,std::span<std::byte const> input) noexcept -> http::DataDisposition {
    auto& state=*static_cast<Input*>(pointer);
    state.valid=state.valid && std::ranges::all_of(input,[](auto byte) { return byte==std::byte{197}; });
    state.received+=input.size();
    return state.valid ? http::DataDisposition::accepted : http::DataDisposition::failure;
}
auto ended(void* pointer,std::int32_t) noexcept -> bool { static_cast<Input*>(pointer)->ended=true; return true; }
auto closed(void*,std::int32_t,std::uint32_t) noexcept -> void {}
auto source(h2::nghttp2_session*,std::int32_t,std::uint8_t* output,std::size_t capacity,std::uint32_t* flags,
    h2::nghttp2_data_source* source,void*) noexcept -> h2::nghttp2_ssize {
    auto& body=*static_cast<Body*>(source->ptr);
    if (!body.enabled) return h2::NGHTTP2_ERR_DEFERRED;
    auto size=std::min({std::size_t{1024},capacity,32*1024-body.sent});
    std::fill_n(output,size,197); body.sent+=size;
    if (body.sent==32*1024) *flags|=h2::NGHTTP2_DATA_FLAG_EOF;
    return size;
}
auto nv(std::string_view name,std::string_view value) -> h2::nghttp2_nv {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),
        reinterpret_cast<std::uint8_t*>(const_cast<char*>(value.data())),name.size(),value.size(),0};
}
auto client_output(h2::nghttp2_session* client,http::ServerSession& server,bool once=false) -> bool {
    for (;;) {
        std::uint8_t const* bytes=nullptr;
        auto size=h2::nghttp2_session_mem_send2(client,&bytes);
        if (size<0) return false;
        if (!size) return true;
        auto input=std::span(reinterpret_cast<std::byte const*>(bytes),static_cast<std::size_t>(size));
        while (!input.empty()) {
            auto received=server.receive(input);
            if (!received || !*received || *received>input.size()) return false;
            input=input.subspan(*received);
        }
        if (once) return true;
    }
}
auto server_output(http::ServerSession& server,h2::nghttp2_session* client) -> bool {
    std::array<std::byte,4096> bytes{};
    for (;;) {
        auto size=server.output(bytes);
        if (!size) return false;
        if (!*size) return true;
        auto received=h2::nghttp2_session_mem_recv2(client,reinterpret_cast<std::uint8_t const*>(bytes.data()),*size);
        if (received!=static_cast<h2::nghttp2_ssize>(*size)) return false;
    }
}
auto check(std::size_t window,bool early) -> bool {
    Input input;
    http::ServerLimits limits{8,16,8192,65536,65536}; limits.input_window=window;
    auto server=http::ServerSession::create(limits,{&input,headers,data,ended,closed});
    if (!server) return false;
    h2::nghttp2_session_callbacks* callbacks=nullptr;
    if (h2::nghttp2_session_callbacks_new(&callbacks)) return false;
    h2::nghttp2_session* client=nullptr;
    auto error=h2::nghttp2_session_client_new(&client,callbacks,nullptr);
    h2::nghttp2_session_callbacks_del(callbacks);
    if (error) return false;
    std::unique_ptr<h2::nghttp2_session,decltype(&h2::nghttp2_session_del)> owner(client,h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(client,0,nullptr,0)) return false;
    if (!early && (!client_output(client,**server) || !server_output(**server,client) || !client_output(client,**server))) return false;
    Body body;
    h2::nghttp2_data_provider2 provider{}; provider.source.ptr=&body; provider.read_callback=source;
    std::array request{nv(":method","POST"),nv(":scheme","https"),nv(":authority","localhost"),nv(":path","/")};
    auto stream=h2::nghttp2_submit_request2(client,nullptr,request.data(),request.size(),&provider,nullptr);
    if (stream<1 || !client_output(client,**server) || !server_output(**server,client) || !client_output(client,**server)) return false;
    body.enabled=true;
    if (h2::nghttp2_session_resume_data(client,stream)) return false;
    for (unsigned count=0;count<512 && !input.ended;++count)
        if (!client_output(client,**server,true) || !server_output(**server,client)) return false;
    if (!input.valid || !input.ended || input.received!=32*1024 || body.sent!=32*1024) {
        std::cerr<<"window="<<window<<" early="<<early<<" sent="<<body.sent<<" received="<<input.received<<" ended="<<input.ended<<'\n';
        return false;
    }
    return true;
}
auto main() -> int {
    for (auto window:{2048u,65535u,131072u})
        for (bool early:{true,false}) if (!check(window,early)) return 1;
    std::cout<<"HTTP2 custom stream windows before/after SETTINGS ACK preserve receive credit and progress passed\n";
    return 0;
}
