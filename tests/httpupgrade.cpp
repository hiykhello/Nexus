import std;
import httpupgrade;
import http.header;

namespace h=httpupgrade;
auto bytes(std::string_view text) -> std::span<std::uint8_t const> {
    return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()};
}
auto request(std::string_view method="GET",std::string_view path="/tunnel",std::string_view fields={}) -> std::string {
    return std::string(method)+" "+std::string(path)+" HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+std::string(fields)+"\r\n";
}
auto main() -> int {
    auto server=h::Profile::server("cover.example","/tunnel"),client=h::Profile::client("cover.example","/tunnel");
    if (!server || !client) return 1;
    if (client->wire()!=request() || h::parse_request(client->wire(),*server).status!=h::Status::accepted ||
        h::parse_response(server->wire()).status!=h::Status::accepted) return 2;
    for (auto const* profile:{&*client,&*server}) {
        auto wire=std::string(profile->is_client() ? server->wire() : client->wire());
        auto input=wire+std::string("\0\x01\x02\xff",4);
        for (std::size_t split=0;split<=wire.size();++split) {
            h::HeaderDecoder decoder(*profile);
            auto first=decoder.feed(bytes(input).first(split)),second=decoder.feed(bytes(input).subspan(split));
            if ((split<wire.size() && first.status!=h::Status::incomplete) || second.status!=h::Status::accepted ||
                first.consumed+second.consumed!=wire.size() || decoder.feed(bytes(input)).consumed || decoder.finish()!=h::Status::accepted) return 3;
        }
        h::HeaderDecoder decoder(*profile);
        for (std::size_t index=0;index<wire.size();++index) {
            auto fed=decoder.feed(bytes(input).subspan(index,1));
            if (fed.consumed!=1 || fed.status!=(index+1==wire.size() ? h::Status::accepted : h::Status::incomplete)) return 4;
        }
        decoder.close();
        if (decoder.feed(bytes(input)).status!=h::Status::closed) return 5;
        h::HeaderDecoder truncated(*profile);
        if (truncated.feed(bytes(wire).first(wire.size()-1)).status!=h::Status::incomplete || truncated.finish()!=h::Status::truncated) return 6;
    }
    for (auto input:{request("POST"),request("GET","/tunnel/extra"),request("GET","/tunnel","Host: cover.example\r\n"),
                    request("GET","/tunnel","Content-Length: 1\r\n"),request("GET","/tunnel","Transfer-Encoding: chunked\r\n"),
                    request("GET","/tunnel","Content-Length: 0\r\nContent-Length: 0\r\n"),
                    request("GET","/tunnel","Expect: 100-continue\r\n"),
                    request("GET","/tunnel","Connection: Upgrade\r\n"),request("GET","/tunnel","Upgrade: websocket\r\n"),
                    request("GET","/tunnel","Malformed Header: x\r\n"),request("GET","/tunnel","X: value\nInjected: x\r\n")})
        if (h::parse_request(input,*server).status==h::Status::accepted) return 7;
    auto wrong_host=request(); wrong_host.replace(wrong_host.find("cover.example"),13,"wrong.example");
    if (h::parse_request(wrong_host,*server).status!=h::Status::host) return 8;
    auto list=request(); list.replace(list.find("Connection: Upgrade"),19,"Connection: keep-alive, Upgrade");
    if (h::parse_request(list,*server).status!=h::Status::upgrade) return 9;
    auto good=request("GET","/tunnel?query=ignored","User-Agent: client\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\nX-Unknown: one\r\nX-Unknown: two\r\nContent-Length: 0\r\n");
    if (h::parse_request(good,*server).status!=h::Status::accepted) return 10;
    auto decoded=h::Profile::server("cover.example","/tunnel/a b?c");
    if (!decoded || h::parse_request(request("GET","/tunnel%2Fa%20b%3Fc?ignored=1"),*decoded).status!=h::Status::accepted) return 11;
    for (auto target:{"/tunnel%", "/tunnel%z0", "/tunnel%00", "/tunnel#fragment", "http://cover.example/tunnel", "/tunnel path"})
        if (h::Profile::client("cover.example",target) || h::parse_request(request("GET",target),*server).status==h::Status::accepted) return 12;
    for (auto host:{"", "a\r\nInjected: x", "a b", "a@b", "a/b", "[::1", "::1", "cover.example:0", "cover.example:65536"})
        if (h::Profile::client(host)) return 13;
    for (auto host:{"cover.example:443", "127.0.0.1", "[::1]", "[2001:db8::1]:443"}) if (!h::Profile::client(host)) return 14;
    auto wildcard=h::Profile::server();
    if (!wildcard || h::parse_request(request("GET","/"),*wildcard).status!=h::Status::accepted) return 15;
    for (auto value:{"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                    "HTTP/1.0 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n",
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 1\r\n\r\n",
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: x\r\n\r\n"})
        if (h::parse_response(value).status==h::Status::accepted) return 16;
    std::array<h::Field,1> extra{{{"User-Agent","client"}}};
    auto custom=h::Profile::client("cover.example","/tunnel",extra);
    if (!custom || !custom->wire().contains("User-Agent: client\r\n")) return 17;
    for (auto name:{"Host","Connection","Upgrade","Content-Length","Sec-WebSocket-Key","Transfer-Encoding"}) {
        extra[0]={name,"x"}; if (h::Profile::client("cover.example","/",extra)) return 18;
    }
    extra[0]={"X","x\r\nInjected: y"};
    if (h::Profile::server({},"/",extra)) return 19;
    std::string oversized(http::max_header_bytes,'x');
    h::HeaderDecoder limited(*server);
    if (limited.feed(bytes(oversized)).status!=h::Status::too_large || limited.feed(bytes(oversized)).consumed) return 20;
    auto casefold=request();
    casefold.replace(casefold.find("Connection: Upgrade"),19,"cOnNeCtIoN: uPgRaDe");
    casefold.replace(casefold.find("Upgrade: websocket"),18,"uPgRaDe: WeBsOcKeT");
    if (h::parse_request(casefold,*server).status!=h::Status::accepted) return 21;
    std::println("HTTPUpgrade fixed-peer vectors, bounded headers, arbitrary fragments, pre-read boundaries and rejection passed");
}
