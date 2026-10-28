import std;
import nexus.http.connect;

namespace h = nexus::http;

int main() {
    std::string request = "GET http://example.com:8080/x?q=1 HTTP/1.1\r\nHost: wrong.example\r\nConnection: x-private\r\nX-Private: secret\r\nX-Keep: value\r\n\r\n";
    for (std::size_t i = 0; i < request.size(); ++i)
        if (h::parse_forward_request(std::string_view(request).substr(0, i)).status != h::ConnectStatus::incomplete) return 1;
    auto parsed = h::parse_forward_request(request + "next request");
    if (parsed.status != h::ConnectStatus::accepted || parsed.destination.host != "example.com" ||
        parsed.destination.port != 8080 || parsed.wire.find("GET /x?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n") != 0 ||
        parsed.wire.find("x-private") != std::string::npos || parsed.wire.find("x-keep: value") == std::string::npos) return 1;
    for (auto text : {"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
                      "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: Host\r\n\r\n",
                      "GET http://example.com/%xx HTTP/1.1\r\nHost: example.com\r\n\r\n",
                      "GET http://user@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
                      "GET http://127.1/ HTTP/1.1\r\nHost: example.com\r\n\r\n"})
        if (h::parse_forward_request(text).status == h::ConnectStatus::accepted) return 1;
    auto post = h::parse_forward_request("POST http://example.com/a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloEXTRA");
    if (post.status != h::ConnectStatus::accepted || post.body_length != 5 || post.chunked ||
        post.consumed != std::string_view("POST http://example.com/a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n").size() ||
        post.wire.find("POST /a HTTP/1.1\r\n") != 0) return 1;
    post = h::parse_forward_request("PATCH http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: Chunked\r\n\r\n");
    if (post.status != h::ConnectStatus::accepted || !post.chunked) return 1;
    for (auto text : {"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                      "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                      "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 18446744073709551616\r\n\r\n",
                      "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                      "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: Content-Length\r\nContent-Length: 1\r\n\r\n"})
        if (h::parse_forward_request(text).status == h::ConnectStatus::accepted) return 1;
    auto expect = h::parse_forward_request("POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nExpect: 100-Continue\r\nContent-Length: 2\r\n\r\n");
    if (expect.status != h::ConnectStatus::accepted || expect.wire.find("expect: 100-Continue\r\n") == std::string::npos) return 1;
    for (auto text : {"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nExpect: other\r\n\r\n",
                      "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue, other\r\n\r\n",
                      "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nExpect: 100-continue\r\n\r\n"})
        if (h::parse_forward_request(text).status != h::ConnectStatus::expectation_failed) return 1;
    expect = h::parse_forward_request("POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: Expect\r\nExpect: 100-continue\r\n\r\n");
    if (expect.status != h::ConnectStatus::malformed) return 1;
    for (auto text : {"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
                      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
                      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
                      "HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 2\r\n\r\n",
                      "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n"})
        if (h::parse_forward_response(text, false).status == h::ConnectStatus::accepted) return 1;
    auto response = h::parse_forward_response("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\nabc", true);
    if (response.status != h::ConnectStatus::accepted || response.body_length != 0) return 1;
    response = h::parse_forward_response("HTTP/1.1 200 OK\r\n\r\nabc", false);
    if (response.status != h::ConnectStatus::accepted || response.body_length) return 1;
    response = h::parse_forward_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n", false);
    if (response.status != h::ConnectStatus::accepted || !response.chunked) return 1;
    for (auto text : {"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                      "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                      "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
                      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"})
        if (h::parse_forward_response(text, false).status == h::ConnectStatus::accepted) return 1;
    response = h::parse_forward_response("HTTP/1.1 103 Early Hints\r\nConnection: x-secret\r\nX-Secret: no\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 200 OK", false);
    if (response.status != h::ConnectStatus::accepted || !response.informational || response.body_length != 0 ||
        response.wire != "HTTP/1.1 103 Early Hints\r\nlink: </a>; rel=preload\r\n\r\n" ||
        response.consumed != std::string_view("HTTP/1.1 103 Early Hints\r\nConnection: x-secret\r\nX-Secret: no\r\nLink: </a>; rel=preload\r\n\r\n").size()) return 1;
    for (auto text : {"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n",
                      "HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\n",
                      "HTTP/1.0 100 Continue\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\n\r\n",
                      "HTTP/1.1 099 Invalid\r\n\r\n"})
        if (h::parse_forward_response(text, false).status == h::ConnectStatus::accepted) return 1;
    std::string body = "4;foo=\"a\\\"b\"\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Note: value\r\n\r\nEXTRA";
    for (std::size_t split = 0; split <= body.size(); ++split) {
        h::ChunkDecoder decoder;
        std::string output;
        auto status = decoder.consume(std::string_view(body).substr(0, split), output);
        if (status == h::ChunkStatus::incomplete) status = decoder.consume(std::string_view(body).substr(split), output);
        if (status != h::ChunkStatus::complete || output != "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") return 1;
    }
    for (std::size_t split = 0; split <= body.size(); ++split) {
        h::ChunkDecoder decoder; std::string output;
        auto first=decoder.consume_some(std::string_view(body).substr(0,split),output);
        std::size_t consumed=first.consumed; auto status=first.status;
        if (status==h::ChunkStatus::incomplete) {
            if (consumed!=split) return 1;
            auto second=decoder.consume_some(std::string_view(body).substr(split),output);
            consumed+=second.consumed; status=second.status;
        }
        auto after=decoder.consume_some(std::string_view(body).substr(consumed),output);
        if (status!=h::ChunkStatus::complete || consumed!=body.size()-5 || body.substr(consumed)!="EXTRA" ||
            after.status!=h::ChunkStatus::complete || after.consumed!=0 || output!="4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") return 1;
    }
    for (std::string text : std::vector<std::string>{"10000000000000000\r\n", "z\r\n", "1;x=\"unterminated\r\n",
                             "1\r\nxX", "0\r\nbad trailer\r\n\r\n", "0\r\nContent-Length: 0\r\n\r\n",
                             "0\r\nX: bad\x01\r\n\r\n",
                             std::string(8193, 'a') + "\r\n"}) {
        h::ChunkDecoder decoder;
        std::string output;
        if (decoder.consume(text, output) != h::ChunkStatus::malformed || output.ends_with("0\r\n\r\n")) return 1;
    }
    {
        h::ChunkDecoder decoder;
        std::string output;
        for (char c : body) {
            auto status = decoder.consume(std::string_view(&c, 1), output);
            if (status == h::ChunkStatus::malformed) return 1;
        }
        if (output != "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") return 1;
    }
    {
        h::ChunkDecoder decoder;
        std::string output, too_many = "0\r\n";
        for (int i = 0; i < 101; ++i) too_many += "x: y\r\n";
        if (decoder.consume(too_many + "\r\n", output) != h::ChunkStatus::malformed) return 1;
    }
    for (auto text : {"3\r\nab", "1\r\na\r", "0\r\nX: value\r\n"}) {
        h::ChunkDecoder decoder;
        std::string output;
        if (decoder.consume(text, output) != h::ChunkStatus::incomplete || output.ends_with("0\r\n\r\n")) return 1;
    }
    std::cout << "HTTP forward header validation and framing passed\n";
}
