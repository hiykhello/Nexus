import std;
import http.connect;
namespace h=http;

auto exercise(std::string const& message,std::string_view expected_body,std::size_t split,bool head=false,bool close=false) -> bool {
    h::ResponseDecoder decoder(head); std::string wire; std::size_t offset=0, headers=0; bool complete=false;
    auto boundary=message.size()-4;
    while (offset<message.size() && !complete) {
        auto end=offset<split ? split : message.size();
        auto step=decoder.feed(std::string_view(message).substr(offset,end-offset));
        if (step.consumed>end-offset || step.event==h::ResponseEvent::malformed || step.event==h::ResponseEvent::truncated) return false;
        offset+=step.consumed;
        if (step.event==h::ResponseEvent::header) { ++headers; if (!step.informational) wire.clear(); }
        else wire+=step.wire;
        if (step.event==h::ResponseEvent::complete) complete=true;
        if (!step.consumed && step.event!=h::ResponseEvent::complete) return false;
        if (close && offset==boundary) break;
    }
    if (close) { auto end=decoder.finish(); complete=end.event==h::ResponseEvent::complete; }
    auto repeated=decoder.feed("tail");
    return complete && headers>=1 && offset==boundary && wire==expected_body && repeated.event==h::ResponseEvent::complete && repeated.consumed==0;
}
int main() {
    std::string fixed="HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloNEXT";
    std::string chunked="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-T: z\r\n\r\nNEXT";
    for (std::size_t i=0;i<=fixed.size();++i) if (!exercise(fixed,"hello",i)) return 1;
    for (std::size_t i=0;i<=chunked.size();++i) if (!exercise(chunked,"3\r\nabc\r\n0\r\n\r\n",i)) return 2;
    std::string head="HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nNEXT";
    for (std::size_t i=0;i<=head.size();++i) if (!exercise(head,"",i,true)) return 3;
    {
        h::ResponseDecoder d; auto header=d.feed("HTTP/1.0 200 OK\r\n\r\n"); auto body=d.feed("hello");
        if (header.event!=h::ResponseEvent::header || body.event!=h::ResponseEvent::data || body.wire!="hello" || d.finish().event!=h::ResponseEvent::complete) return 4;
    }
    for (auto version : {"HTTP/1.0", "HTTP/1.1"}) {
        h::ResponseDecoder d(false,true);
        auto header=d.feed(std::string(version)+" 200 OK\r\nX-Test: yes\r\n\r\n");
        auto body=d.feed("hello"); auto end=d.finish(); auto again=d.finish();
        if (header.event!=h::ResponseEvent::header || !header.wire.starts_with("HTTP/1.1 200 ") ||
            header.wire.find("Transfer-Encoding: chunked\r\n") == std::string::npos ||
            body.wire!="5\r\nhello\r\n" || end.wire!="0\r\n\r\n" || !again.wire.empty()) return 11;
    }
    {
        h::ResponseDecoder d; auto header=d.feed("HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n");
        std::string body(20000,'x'); body+="NEXT"; auto first=d.feed(body); auto last=d.feed(std::string_view(body).substr(first.consumed));
        if (header.event!=h::ResponseEvent::header || first.event!=h::ResponseEvent::data || first.consumed!=16384 ||
            last.event!=h::ResponseEvent::complete || last.consumed!=3616 || first.wire.size()+last.wire.size()!=20000) return 9;
    }
    {
        h::ResponseDecoder d; auto header=d.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        auto invalid=d.feed("1\r\naX");
        if (header.event!=h::ResponseEvent::header || invalid.event!=h::ResponseEvent::malformed || d.finish().event!=h::ResponseEvent::malformed) return 10;
    }
    for (auto status : {"204 No Content", "205 Reset Content", "304 Not Modified"}) {
        h::ResponseDecoder d;
        auto header=d.feed(std::string("HTTP/1.1 ")+status+"\r\n\r\n");
        auto extra=d.feed("unexpected");
        if (header.event!=h::ResponseEvent::header || extra.event!=h::ResponseEvent::complete || extra.consumed!=0) return 12;
        for (auto framing : {"Content-Length: 0\r\n"}) {
            h::ResponseDecoder invalid;
            if (invalid.feed(std::string("HTTP/1.1 ")+status+"\r\n"+framing+"\r\n").event!=h::ResponseEvent::header) return 13;
        }
    }
    for (auto status : {"204 No Content", "205 Reset Content", "304 Not Modified"}) {
        h::ResponseDecoder invalid;
        if (invalid.feed(std::string("HTTP/1.1 ")+status+"\r\nTransfer-Encoding: chunked\r\n\r\n").event!=h::ResponseEvent::malformed) return 14;
    }
    for (auto status : {"204 No Content", "205 Reset Content"}) {
        h::ResponseDecoder invalid;
        if (invalid.feed(std::string("HTTP/1.1 ")+status+"\r\nContent-Length: 1\r\n\r\n").event!=h::ResponseEvent::malformed) return 15;
    }
    for (auto text:{"HTTP/1.1 200", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na"}) {
        h::ResponseDecoder d; std::string_view rest=text;
        while (!rest.empty()) { auto step=d.feed(rest); if (!step.consumed) return 5; rest.remove_prefix(step.consumed); }
        if (d.finish().event!=h::ResponseEvent::truncated) return 6;
    }
    {
        h::ResponseDecoder d; std::string input;
        for (int i=0;i<9;++i) input+="HTTP/1.1 100 Continue\r\n\r\n";
        std::string_view rest=input; int count=0;
        while (!rest.empty()) { auto step=d.feed(rest); rest.remove_prefix(step.consumed); if (step.event==h::ResponseEvent::malformed) break; if (step.event!=h::ResponseEvent::header) return 7; ++count; }
        if (count!=8 || !rest.empty()) return 8;
    }
    std::cout << "HTTP response streaming boundaries, framing and EOF passed\n";
}
