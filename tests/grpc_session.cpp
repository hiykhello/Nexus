import std;
import grpc.headers;
import grpc.message;
import grpc.session;
namespace g=grpc;
struct Pair {
    std::unique_ptr<g::Session> client,server;
    bool failed=false;
    Pair(g::Limits limits={},g::ResponsePolicy policy=g::ResponsePolicy::standard) {
        auto profile=g::RequestProfile::create("nexus.Service","127.0.0.1:443",false);
        if (!profile) { failed=true; return; }
        auto c=g::Session::create(g::Role::client,*profile,policy,limits),s=g::Session::create(g::Role::server,*profile,g::ResponsePolicy::standard,limits);
        if (!c || !s) { failed=true; return; }
        client=std::move(*c); server=std::move(*s);
    }
    auto move(g::Session& from,g::Session& to,std::size_t chunk) -> std::size_t {
        std::array<std::uint8_t,16384> buffer{};
        std::size_t total=0;
        for (unsigned turn=0;turn<10000;++turn) {
            auto size=from.output(std::span(buffer).first(chunk));
            if (!size) { failed=true; return total; }
            if (!*size) return total;
            total+=*size;
            for (std::size_t offset=0;offset<*size;) {
                auto span=std::span(buffer).subspan(offset,std::min(std::size_t{3},*size-offset));
                auto received=to.receive(span);
                if (!received || !*received || *received>span.size()) { failed=true; return total; }
                offset+=*received;
            }
        }
        failed=true; return total;
    }
    auto pump(std::size_t chunk=127) -> std::size_t {
        std::size_t bytes=0;
        for (unsigned turn=0;turn<10000 && !failed;++turn) {
            auto c=move(*client,*server,chunk),s=failed ? 0 : move(*server,*client,chunk);
            bytes+=c+s;
            if (!c && !s) break;
        }
        return bytes;
    }
};
auto drain(g::Session& session) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> output;
    std::array<std::uint8_t,16384> buffer{};
    for (unsigned turn=0;turn<10000;++turn) {
        auto size=session.output(buffer);
        if (!size) return {};
        if (!*size) return output;
        output.insert(output.end(),buffer.begin(),buffer.begin()+*size);
    }
    return {};
}
auto data_frame(std::vector<std::uint8_t>& wire) -> std::span<std::uint8_t> {
    std::size_t offset=0;
    while (wire.size()-offset>=9) {
        auto size=(std::size_t(wire[offset])<<16)|(std::size_t(wire[offset+1])<<8)|wire[offset+2];
        if (size>wire.size()-offset-9) return {};
        if (wire[offset+3]==0) return std::span(wire).subspan(offset,9+size);
        offset+=9+size;
    }
    return {};
}
auto basic() -> bool {
    for (auto chunk:{1u,3u,127u,16384u}) {
        Pair pair; if (pair.failed) return false;
        pair.pump(chunk);
        if (pair.failed || !pair.client->ready() || !pair.server->ready()) return false;
        auto empty=pair.client->queue({});
        auto sent=pair.client->queue(std::array<std::uint8_t,3>{'a','b','c'});
        if (!empty || !*empty || !sent || !*sent || !pair.client->close_output()) return false;
        pair.pump(chunk);
        std::array<std::uint8_t,16> buffer{};
        auto read=pair.server->pull(buffer);
        if (pair.failed || !read || read->size!=3 || read->eof || std::string_view(reinterpret_cast<char*>(buffer.data()),3)!="abc" ||
            pair.server->uncredited_bytes() || !pair.server->remote_ended() || !pair.client->local_ended()) return false;
        auto eof=pair.server->pull(buffer);
        if (!eof || !eof->eof || eof->size || !pair.server->queue(std::array<std::uint8_t,2>{4,5}) || !pair.server->close_output()) return false;
        pair.pump(chunk);
        auto reply=pair.client->pull(buffer),end=pair.client->pull(buffer);
        if (pair.failed || !reply || reply->size!=2 || !end || !end->eof || pair.client->remote_status()!=0 ||
            pair.client->uncredited_bytes() || !pair.server->local_ended() || pair.server->queue({}) || !pair.client->finish_input() ||
            pair.client->library_peak()>4*1024*1024 || pair.server->library_peak()>4*1024*1024) return false;
    }
    return true;
}
auto flow_control() -> bool {
    g::Limits limits{2048,1032,1024,128*1024,64,4*1024*1024};
    Pair pair(limits); if (pair.failed) return false;
    pair.pump();
    std::vector<std::uint8_t> payload(1024,197);
    for (unsigned count=0;count<64;++count) {
        auto sent=pair.client->queue(payload); if (!sent || !*sent) return false;
    }
    auto full=pair.client->queue(payload);
    if (!full || *full) return false;
    pair.pump();
    auto fail=[&](std::string_view stage,std::size_t consumed=0) {
        std::cerr << "gRPC window " << stage << ": failed=" << pair.failed << " consumed=" << consumed
            << " uncredited=" << pair.server->uncredited_bytes() << " queued=" << pair.client->queued_bytes() << '\n'; return false;
    };
    if (pair.failed || pair.server->uncredited_bytes()!=2048 || !pair.client->queued_bytes()) return fail("initial stop");
    auto blocked=pair.client->queued_bytes();
    std::array<std::uint8_t,128> buffer{};
    auto first=pair.server->pull(buffer);
    if (!first || first->size!=128 || pair.server->uncredited_bytes()!=2048 || pair.pump() || pair.client->queued_bytes()!=blocked) return fail("partial Hunk credit");
    std::size_t total=128;
    for (unsigned turn=0;turn<10000 && total<64*1024;++turn) {
        auto read=pair.server->pull(buffer);
        if (!read || read->eof || (read->size && !std::ranges::all_of(std::span(buffer).first(read->size),[](auto byte) { return byte==197; }))) return fail("payload",total);
        total+=read->size;
        pair.pump();
        if (pair.failed || pair.server->uncredited_bytes()>2048) return fail("refill",total);
    }
    if (total!=64*1024 || pair.client->queued_bytes() || pair.server->uncredited_bytes()) return fail("completion",total);
    return true;
}
auto retained_queue() -> bool {
    g::Limits limit{2048,1032,1024,2064,64,4*1024*1024};
    Pair pair(limit); if (pair.failed) return false;
    pair.pump();
    std::vector<std::uint8_t> payload(1024,197);
    auto a=pair.client->queue(payload),b=pair.client->queue(payload);
    if (!a || !*a || !b || !*b) return false;
    pair.pump();
    if (pair.failed || pair.client->queued_bytes()!=16 || pair.client->retained_output_bytes()!=1032) return false;
    auto added=pair.client->queue(payload),full=pair.client->queue({});
    if (!added || !*added || !full || *full || pair.client->retained_output_bytes()!=2064) return false;
    std::array<std::uint8_t,4096> buffer{}; std::size_t total=0;
    for (unsigned turn=0;turn<100 && total<3*1024;++turn) {
        auto read=pair.server->pull(buffer); if (!read) return false;
        total+=read->size; pair.pump();
        if (pair.failed || pair.client->retained_output_bytes()>limit.output_bytes) return false;
    }
    if (total!=3*1024 || pair.client->retained_output_bytes()) return false;
    auto empty=pair.client->queue({});
    return empty && *empty && pair.client->retained_output_bytes()==5;
}
auto malformed_messages() -> bool {
    for (auto mode:{0,1,2}) {
        Pair pair; if (pair.failed) return false;
        pair.pump();
        if (!pair.client->queue(std::array<std::uint8_t,3>{1,2,3}) || !pair.client->close_output()) return false;
        auto wire=drain(*pair.client); auto frame=data_frame(wire);
        if (frame.size()<19) return false;
        if (mode==0) frame[9]=1;
        if (mode==1) frame[13]+=1;
        if (mode==2) frame[14]=8;
        if (!pair.server->receive(wire)) return false;
        std::array<std::uint8_t,16> buffer{}; auto read=pair.server->pull(buffer);
        auto expected=mode==1 ? g::Error::truncated : g::Error::message;
        if (read || read.error().error!=expected || !pair.server->uncredited_bytes()) return false;
    }
    return true;
}
auto missing_trailer() -> bool {
    for (auto policy:{g::ResponsePolicy::standard,g::ResponsePolicy::sing_box_lite}) {
        Pair pair({},policy); if (pair.failed) return false;
        pair.pump();
        if (!pair.server->queue(std::array<std::uint8_t,1>{7}) || !pair.server->close_output()) return false;
        auto wire=drain(*pair.server); auto frame=data_frame(wire);
        if (frame.size()<9) return false;
        frame[4]|=1;
        auto accepted=pair.client->receive(frame);
        if (policy==g::ResponsePolicy::standard) {
            if (accepted || accepted.error().error!=g::Error::headers) return false;
        } else {
            std::array<std::uint8_t,8> buffer{};
            auto data=pair.client->pull(buffer),end=pair.client->pull(buffer);
            if (!accepted || !data || data->size!=1 || buffer[0]!=7 || !end || !end->eof || pair.client->remote_status()) return false;
        }
    }
    return true;
}
auto scope_errors() -> bool {
    for (auto mode:{0,1,2,3}) {
        Pair pair; if (pair.failed) return false;
        pair.pump();
        if (mode==0) {
            if (!pair.server->close_output(12)) return false;
            auto wire=drain(*pair.server);
            auto accepted=pair.client->receive(wire);
            if (accepted || accepted.error().error!=g::Error::headers || pair.client->remote_status()!=12) return false;
        } else if (mode==1) {
            auto accepted=pair.client->receive(std::array<std::uint8_t,13>{0,0,4,3,0,0,0,0,1,0,0,0,8});
            if (accepted || accepted.error().error!=g::Error::reset || accepted.error().code!=8) return false;
        } else {
            std::array<std::uint8_t,17> goaway{0,0,8,7,0,0,0,0,0,0,0,0,0,0,0,0,0};
            auto accepted=mode==2 ? pair.client->receive(goaway) : pair.server->receive(goaway);
            if (mode==2 && (accepted || accepted.error().error!=g::Error::goaway)) return false;
            if (mode==3 && !accepted) return false;
        }
    }
    Pair pair; if (pair.failed) return false;
    pair.pump();
    auto eof=pair.client->finish_input();
    return !eof && eof.error().error==g::Error::truncated;
}
auto limits() -> bool {
    auto profile=g::RequestProfile::create("nexus.Service","host",false); if (!profile) return false;
    for (auto mode:{0,1,2,3,4}) {
        g::Limits limit;
        if (mode==0) limit.input_window=limit.message_bytes;
        if (mode==1) limit.hunk_bytes=g::max_hunk_bytes+1;
        if (mode==2) limit.output_messages=65;
        if (mode==3) limit.output_bytes=4;
        if (mode==4) limit.library_bytes=1;
        if (g::Session::create(g::Role::client,*profile,g::ResponsePolicy::standard,limit)) return false;
    }
    g::Limits limit; limit.output_bytes=10;
    auto session=g::Session::create(g::Role::client,*profile,g::ResponsePolicy::standard,limit);
    if (!session) return false;
    auto a=(*session)->queue({}),b=(*session)->queue({}),c=(*session)->queue({});
    return a && *a && b && *b && c && !*c;
}
auto main() -> int {
    if (!basic()) { std::println("gRPC bidirectional message/half-close test failed"); return 1; }
    if (!flow_control()) { std::println("gRPC deferred provider/window backpressure test failed"); return 2; }
    if (!malformed_messages()) { std::println("gRPC malformed/truncated message test failed"); return 3; }
    if (!missing_trailer()) { std::println("gRPC strict/lite termination test failed"); return 4; }
    if (!scope_errors()) { std::println("gRPC status/reset/GOAWAY/transport scope test failed"); return 5; }
    if (!limits()) { std::println("gRPC queue/window/library limits test failed"); return 6; }
    if (!retained_queue()) { std::println("gRPC partially emitted retained queue budget test failed"); return 7; }
    std::println("gRPC HTTP2 bidirectional framing, retained partial messages, deferred output, application window credit and strict/lite status tests passed");
}
