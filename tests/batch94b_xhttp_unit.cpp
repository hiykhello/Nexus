import std;
import config;
import xhttp;
import memory.budget;
import http2.client;
import http2.server_streams;

namespace {
    auto require(bool condition,std::string_view label) -> void {
        if (!condition) throw std::runtime_error(std::string(label));
    }

    auto wire() -> void {
        std::array<std::uint8_t,16> random{};
        random[4]=0xAF;
        auto id=xhttp::session_id(random);
        require(id=="00000000-af00-4000-8000-000000000000" && xhttp::valid_session(id),"canonical UUID");
        auto changed=id;
        changed[9]='A';
        require(!xhttp::valid_session(changed),"uppercase UUID");
        changed=id;
        changed[14]='1';
        require(!xhttp::valid_session(changed),"UUID version");
        changed=id;
        changed[19]='7';
        require(!xhttp::valid_session(changed),"UUID variant");
        auto prefix=xhttp::normalize_path("/api/edge");
        require(prefix && *prefix=="/api/edge/","normalize endpoint");
        for (auto invalid:{"/./web","/edge/../next","/%2e%2e/","/api%2fedge/","/api//","/api\\edge","/path?query"})
            require(!xhttp::normalize_path(invalid),invalid);
        xhttp::Profile profile;
        profile.endpoint={.authority="example.test",.path=*prefix};
        for (auto place:{xhttp::Placement::referer,xhttp::Placement::query,xhttp::Placement::header}) {
            profile.padding={.minimum=100,.maximum=1000,.placement=place,.header="padding-unit"};
            for (auto sample:{0u,123u,900u,901u}) {
                auto request=xhttp::request(profile,profile.endpoint,xhttp::RequestKind::packet,id,7,sample,true);
                auto meta=xhttp::metadata(request.target,*prefix);
                require(meta && meta->session==id && meta->sequence==7,"packet target");
                require(xhttp::check_padding(profile.padding,request.target,request.fields),"padding location");
                require(xhttp::padding_bytes(profile.padding,sample).size()==100+sample%901,"padding range");
            }
        }
        for (auto suffix:{"/00","/-1","/1/", "/18446744073709551615"})
            require(!xhttp::metadata(*prefix+id+suffix,*prefix),"invalid sequence");
        require(!xhttp::metadata("/api/edge2/"+id,*prefix),"strict prefix boundary");
    }

    auto state() -> void {
        auto budget=std::make_shared<memory::Budget>(1024);
        xhttp::Limits limits{.post_bytes=5,.buffer_bytes=10,.buffered_posts=3};
        xhttp::Reassembly queue(limits,budget);
        std::array<std::uint8_t,4> first{1,2,3,4},second{5,6,7,8},third{9,10,11,12};
        require(queue.submit(1,second).has_value() && !queue.readable(),"admit out-of-order POST");
        require(queue.submit(1,second).error()==xhttp::PacketError::duplicate,"exclude duplicate");
        require(queue.submit(3,third).error()==xhttp::PacketError::window,"exclude outside window");
        require(queue.submit(0,first).has_value(),"admit first POST");
        require(queue.submit(2,third).error()==xhttp::PacketError::bytes,"aggregate budget");
        std::array<std::uint8_t,8> result{};
        require(queue.read(std::span(result).first(3))==3 && queue.expected_sequence()==0,"partial read");
        require(queue.read(std::span(result).subspan(3))==5 && result==std::array<std::uint8_t,8>{1,2,3,4,5,6,7,8},
            "ordered consumption");
        require(queue.submit(0,first).error()==xhttp::PacketError::stale && budget->used()==0,"reject stale and release memory");
        require(queue.submit(2,third).has_value(),"advance receive window");
        queue.close();
        require(budget->used()==0 && queue.submit(3,third).error()==xhttp::PacketError::closed,"release buffered bytes on close");

        using Kind=xhttp::RequestKind;
        using namespace std::chrono_literals;
        auto now=xhttp::Pairing::Clock::time_point{};
        xhttp::Pairing pairing{now+1s};
        require(pairing.attach(Kind::packet,now) && !pairing.attach(Kind::upload,now),"one upload mode");
        require(pairing.attach(Kind::download,now) && !pairing.attach(Kind::download,now),"one download");
        require(pairing.paired() && !pairing.expired(now+2s),"paired sessions retain ownership");
        xhttp::Pairing orphan{now+1s};
        require(orphan.expired(now+1s) && !orphan.attach(Kind::download,now+1s),"orphan deadline");

        xhttp::Mux mux({.concurrency=1,.connections=2,.reuse_times=1,.lifetime_ms=1000,.requests=2,.reusable_seconds=2});
        auto a=mux.acquire(now);
        auto b=mux.acquire(now);
        require(a && b && a->create && b->create && !mux.acquire(now),"connection and concurrency limits");
        require(mux.request(a->ticket,now) && mux.release(a->ticket),"initial request");
        auto reused=mux.acquire(now);
        require(reused && !reused->create && reused->ticket==a->ticket,"reuse available carrier");
        require(mux.request(a->ticket,now) && !mux.request(a->ticket,now),"HTTP request budget");
        require(mux.release(a->ticket) && mux.reclaimable(a->ticket,now) && mux.remove(a->ticket),"retire idle carrier");
        auto fresh=mux.acquire(now);
        require(fresh && fresh->create && fresh->ticket!=a->ticket && !mux.release(a->ticket),"generation isolation");
        require(!mux.request(b->ticket,now+1s) && mux.release(b->ticket) && mux.reclaimable(b->ticket,now+1s),"lifetime cap");
    }

    auto h2_streaming() -> void {
        auto client_result=http2::Client<2>::create();
        auto server_result=http2::ServerStreams<2>::create();
        require(client_result.has_value() && server_result.has_value(),"initialize H2 client and server");
        auto& client=**client_result;
        auto& server=**server_result;
        std::array<std::uint8_t,4096> wire;
        auto pump=[&]() {
            for (unsigned round=0;round<64;++round) {
                auto a=client.output(wire);
                require(a.has_value(),"serialize H2 request");
                if (*a) require(server.receive(std::span(wire).first(*a))==*a,"receive H2 request");
                auto b=server.output(wire);
                require(b.has_value(),"serialize H2 response");
                if (*b) require(client.receive(std::span(wire).first(*b))==*b,"receive H2 response");
                if (!*a && !*b) return;
            }
            require(false,"H2 frame exchange did not settle");
        };
        constexpr std::array headers{http2::FieldView{":method","POST"},http2::FieldView{":scheme","https"},
            http2::FieldView{":path","/edge/"},http2::FieldView{":authority","edge.test"}};
        auto first=client.submit(headers,{{},false});
        auto second=client.submit(headers,{{},false});
        require(first.has_value() && second.has_value(),"open two H2 streams");
        pump();
        auto incoming=server.accept();
        auto concurrent=server.accept();
        require(incoming && concurrent && *incoming!=*concurrent,"accept two independent streams");
        constexpr std::array response{http2::FieldView{":status","200"}};
        require(server.respond(*incoming,response).has_value(),"send streaming response headers");
        constexpr std::array<std::uint8_t,3> up{0,1,2};
        require(client.provide(*first,{up,false})==true,"queue raw H2 upload");
        pump();
        std::array<std::uint8_t,32> buffer{};
        auto received=server.pull(*incoming,buffer);
        require(received && *received==up.size() && std::ranges::equal(up,std::span(buffer).first(up.size())),"read raw H2 data");
        auto pending=server.pull(*concurrent,buffer);
        require(pending && !*pending,"isolated concurrent stream");
        require(client.provide(*first,{{},true})==true,"send independent upload FIN");
        pump();
        auto fin=server.pull(*incoming,buffer);
        require(fin && *fin==std::optional<std::size_t>{0},"receive independent upload FIN");
        constexpr std::array<std::uint8_t,4> down{0,3,255,4};
        require(server.provide(*incoming,{down,true})==true,"queue response after upload FIN");
        pump();
        auto reply=client.peek(*first);
        require(reply && std::ranges::equal(*reply,down) && client.response(*first)->remote_end,"preserve raw response and FIN");
        server.release(*incoming,false);
        server.release(*concurrent);
        pump();
        require(!server.failure() && !client.failure(),"stream reset stays local");
    }

    auto parse(std::string_view mode,std::string_view protocol,std::string_view extra) {
        return config::parse_kdl(std::format(R"kdl(schema-version 1
role "client"
inbounds {{ inbound "entry" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }} }}
outbounds {{
    outbound "direct" type="direct"
    outbound "edge" type="vless" {{
        server host="127.0.0.1" port=9000
        authentication {{ uuid-file "/private/uuid"; }}
        transport "xhttp" {{ mode "{}"; protocol "{}"; {}; }}
    }}
}}
routing {{ default-outbound "edge"; }}
)kdl",mode,protocol,extra));
    }

    auto configuration() -> void {
        auto parsed=parse("packet-up","h1",R"kdl(path "/edge"; x-padding-bytes "30-40"; no-grpc-header #true;
            header "user-agent" "test"; xmux { max-connections 3; }; download-settings {
                server host="127.0.0.1" port=9001; protocol "h2"; path "/read"; })kdl");
        require(parsed.has_value(),parsed ? "" : parsed.error());
        auto const& options=*parsed->vless_outbounds.front().config.xhttp;
        require(options.endpoint.path=="/edge/" && options.download->port==9001 &&
            options.download->endpoint.path=="/read/" && options.padding.maximum==40 &&
            options.mux.connections==3 && options.no_grpc_header,"XHTTP config wired to VLESS");
        require(!parse("stream-one","h1",R"(path "/")"),"forbid streaming on H1");
        require(!parse("packet-up","h1",R"(path "/../edge")"),"forbid unsafe prefix");
        require(!parse("packet-up","h1",R"(sc-max-buffered-posts 257)"),"cap reorder window");
        require(!parse("packet-up","h1",R"(x-padding-bytes "200-100")"),"forbid inverted padding");
        require(!parse("packet-up","h1",R"(header "connection" "upgrade")"),"forbid unsafe headers");
    }
}

int main() {
    wire();
    state();
    h2_streaming();
    configuration();
    std::println("XHTTP UUID/path, padding placement, packet reassembly, pairing deadline, xmux budgets, HTTP/2 streaming and KDL passed");
}
