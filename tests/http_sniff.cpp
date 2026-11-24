import std;
import http.sniff;

int main() {
    using namespace http;
    unsigned failures=0;
    auto check=[&](bool passed,std::string_view label) { if (!passed) { ++failures; std::cerr << "FAIL: " << label << '\n'; } };
    std::string input="GET / HTTP/1.1\r\nHost: Example.COM:443\r\nX-Test: value\r\n\r\npayload";
    auto header_end=input.find("\r\n\r\n")+4;
    HttpSniffer sniffer;
    for (std::size_t i=0;i<header_end;++i)
        check(sniffer.inspect(std::string_view(input).substr(0,i)).status==SniffStatus::need_more,"incremental prefix");
    auto result=sniffer.inspect(input);
    check(result.status==SniffStatus::matched && result.domain=="Example.COM","borrow host without consuming payload");
    auto inspect=[](std::string_view value) { HttpSniffer sniff; return sniff.inspect(value); };
    check(inspect("GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n").status==SniffStatus::matched &&
          !inspect("GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n").domain,"numeric address has no domain");
    check(!inspect("GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n").domain,"IPv6 has no domain");
    check(inspect("GET / HTTP/1.1\r\nHost: [::::]:443\r\n\r\n").status==SniffStatus::malformed,"invalid IPv6 rejected");
    check(inspect("GET / HTTP/1.1\r\nHost: 999.2.3.4\r\n\r\n").status==SniffStatus::malformed,"invalid numeric IPv4 rejected");
    check(inspect("GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n").status==SniffStatus::malformed,"duplicate Host rejected");
    check(inspect("GET / HTTP/1.1\r\nHost: bad..test\r\n\r\n").status==SniffStatus::malformed,"invalid domain rejected");
    check(inspect("GET / HTTP/1.1\r\nHost: a.test:0\r\n\r\n").status==SniffStatus::malformed,"invalid port rejected");
    check(inspect("GET / HTTP/1.1\r\n\r\n").status==SniffStatus::malformed,"missing HTTP/1.1 Host rejected");
    check(inspect("GET / HTTP/1.0\r\n\r\n").status==SniffStatus::matched,"HTTP/1.0 may omit Host");
    check(inspect("not http\r\n\r\n").status==SniffStatus::not_http,"non-HTTP rejected");
    check(!inspect("CONNECT other.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n").domain,"CONNECT authority not substituted");
    check(!inspect("GET http://other.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n").domain,"absolute target authority not substituted");
    check(inspect("CONNECT A.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n").domain=="A.test","matching CONNECT authority");
    check(inspect("GET https://A.test/path?q=1 HTTP/1.1\r\nHost: a.test\r\n\r\n").domain=="A.test","matching absolute authority");
    check(inspect("CONNECT a.test HTTP/1.1\r\nHost: a.test\r\n\r\n").status==SniffStatus::malformed,"CONNECT requires port");
    check(!inspect("CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:8443\r\n\r\n").domain,"CONNECT conflicting port is unknown");
    check(inspect("CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n").domain=="a.test","CONNECT omitted Host port matches");
    check(inspect("CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n\r\n").name_kind==SniffNameKind::numeric,"matching CONNECT IPv4 is numeric");
    check(inspect("GET http://1.2.3.4/ HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n").name_kind==SniffNameKind::numeric,"matching absolute IPv4 is numeric");
    check(inspect("GET /redirect?next=https://example.com HTTP/1.1\r\nHost: target.example\r\n\r\n").domain=="target.example","origin-form query scheme preserves Host");
    check(inspect("GET / HTTP/1.1\r\nHost: 0x7f000001\r\n\r\n").status==SniffStatus::malformed,"hex IPv4 rejected");
    check(inspect("GET / HTTP/1.1\r\nHost: 0x7f.0.0.1\r\n\r\n").status==SniffStatus::malformed,"dotted hex IPv4 rejected");
    check(!inspect("GET https://a.test:8443/ HTTP/1.1\r\nHost: a.test\r\n\r\n").domain,"absolute conflicting port is unknown");
    check(inspect(std::string(16384,'x')).status==SniffStatus::too_large,"header budget");
    if (!failures) std::cout << "HTTP sniff incremental input and authority tests passed\n";
    return failures ? 1 : 0;
}
