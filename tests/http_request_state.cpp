import std;
import http.connect;

namespace h=http;

auto main() -> int {
    std::string scratch;
    h::RequestDecoder fixed;
    std::string header="POST http://example.test/path HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n";
    for (std::size_t n=0;n<header.size();++n) {
        auto step=fixed.feed(std::string_view(header).substr(0,n),scratch);
        if (step.event!=h::RequestEvent::need_more || step.consumed!=0) return 1;
    }
    auto first=fixed.feed(header+"helloNEXT",scratch);
    if (first.event!=h::RequestEvent::header || first.consumed!=header.size() ||
        fixed.request().destination.host!="example.test" || fixed.request().body_length!=5 ||
        !first.wire.starts_with("POST /path HTTP/1.1\r\n") || fixed.next_read_size()!=5) return 2;
    auto part=fixed.feed("he",scratch);
    if (part.event!=h::RequestEvent::data || part.consumed!=2 || part.wire!="he" || fixed.next_read_size()!=3) return 3;
    auto last=fixed.feed("lloNEXT",scratch);
    if (last.event!=h::RequestEvent::complete || last.consumed!=3 || last.wire!="llo" ||
        !fixed.complete() || fixed.finish().event!=h::RequestEvent::complete) return 4;

    h::RequestDecoder chunked;
    auto chunk_header=std::string_view("POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n");
    if (chunked.feed(chunk_header,scratch).event!=h::RequestEvent::header || !chunked.request().chunked) return 5;
    std::string body="4;foo=bar\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Test: ok\r\n\r\nNEXT";
    std::string normalized;
    std::size_t consumed=0;
    while (consumed<body.size()) {
        auto step=chunked.feed(std::string_view(body).substr(consumed,1),scratch);
        if (step.event==h::RequestEvent::malformed || !step.consumed) return 6;
        consumed+=step.consumed;
        normalized.append(step.wire);
        if (step.event==h::RequestEvent::complete) break;
    }
    if (normalized!="4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n" || body.substr(consumed)!="NEXT") return 7;

    h::RequestDecoder truncated;
    if (truncated.feed(header,scratch).event!=h::RequestEvent::header ||
        truncated.feed("ab",scratch).event!=h::RequestEvent::data ||
        truncated.finish().event!=h::RequestEvent::truncated ||
        truncated.feed("cde",scratch).event!=h::RequestEvent::malformed) return 8;
    h::RequestDecoder malformed;
    if (malformed.feed(chunk_header,scratch).event!=h::RequestEvent::header ||
        malformed.feed("1\r\nx!",scratch).event!=h::RequestEvent::malformed) return 9;
    h::RequestDecoder ambiguous;
    auto bad="POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
    if (ambiguous.feed(bad,scratch).event!=h::RequestEvent::malformed ||
        ambiguous.request().status!=h::ConnectStatus::malformed) return 10;

    h::ConnectDecoder connect;
    std::string connect_header="CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n";
    for (std::size_t n=0;n<connect_header.size();++n) {
        auto step=connect.feed(std::string_view(connect_header).substr(0,n));
        if (step.event!=h::ConnectEvent::need_more || step.consumed) return 11;
    }
    auto accepted=connect.feed(connect_header+"\x16\x03\x01");
    if (accepted.event!=h::ConnectEvent::accepted || accepted.consumed!=connect_header.size() ||
        connect.request().host!="example.test" || connect.request().port!=443 ||
        connect.feed("tail").consumed || connect.finish().event!=h::ConnectEvent::accepted) return 12;
    h::ConnectDecoder connect_truncated;
    if (connect_truncated.feed("CONNECT example.test:443 HTTP/1.1\r\n").event!=h::ConnectEvent::need_more ||
        connect_truncated.finish().event!=h::ConnectEvent::truncated ||
        connect_truncated.feed(connect_header).event!=h::ConnectEvent::truncated) return 13;
    h::ConnectDecoder connect_rejected;
    if (connect_rejected.feed("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n").event!=h::ConnectEvent::rejected ||
        connect_rejected.request().status!=h::ConnectStatus::unsupported ||
        connect_rejected.finish().event!=h::ConnectEvent::rejected) return 14;
    h::ConnectDecoder connect_limit;
    if (connect_limit.feed(std::string(h::max_connect_header_bytes,'x')).event!=h::ConnectEvent::rejected ||
        connect_limit.request().status!=h::ConnectStatus::too_large) return 15;

    h::BodyDecoder fixed_body(h::BodyMode::fixed,5);
    auto body_part=fixed_body.feed("he",scratch);
    if (body_part.event!=h::BodyEvent::data || body_part.wire!="he" || fixed_body.next_read_size()!=3) return 16;
    auto body_end=fixed_body.feed("lloNEXT",scratch);
    if (body_end.event!=h::BodyEvent::complete || body_end.consumed!=3 || body_end.wire!="llo" ||
        fixed_body.finish().event!=h::BodyEvent::complete) return 17;
    h::BodyDecoder body_truncated(h::BodyMode::fixed,3);
    if (body_truncated.feed("x",scratch).event!=h::BodyEvent::data ||
        body_truncated.finish().event!=h::BodyEvent::truncated ||
        body_truncated.feed("yz",scratch).event!=h::BodyEvent::malformed) return 18;
    h::BodyDecoder body_chunked(h::BodyMode::chunked);
    std::string chunks="1;ext=ok\r\nx\r\n0\r\nX-Test: discarded\r\n\r\nNEXT", normalized_body;
    std::size_t chunk_pos=0;
    while (chunk_pos<chunks.size()) {
        auto step=body_chunked.feed(std::string_view(chunks).substr(chunk_pos,1),scratch);
        if (step.event==h::BodyEvent::malformed || !step.consumed) return 19;
        chunk_pos+=step.consumed;
        normalized_body.append(step.wire);
        if (step.event==h::BodyEvent::complete) break;
    }
    if (normalized_body!="1\r\nx\r\n0\r\n\r\n" || chunks.substr(chunk_pos)!="NEXT") return 20;
    h::BodyDecoder body_close(h::BodyMode::close_delimited);
    std::string close_bytes(h::max_connect_header_bytes+1,'z');
    auto close_part=body_close.feed(close_bytes,scratch);
    if (close_part.event!=h::BodyEvent::data || close_part.consumed!=h::max_connect_header_bytes ||
        close_part.wire.size()!=h::max_connect_header_bytes ||
        body_close.feed(std::string_view(close_bytes).substr(close_part.consumed),scratch).wire!="z" ||
        body_close.finish().event!=h::BodyEvent::complete) return 21;
    return 0;
}
