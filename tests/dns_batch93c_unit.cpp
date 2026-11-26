import std;
import config;
import dns.message;
import dns.local_config;
import rules;

namespace {
    namespace dns=dns;
    auto check(bool pass,std::string_view name) -> void {
        if (!pass) throw std::runtime_error(std::string(name));
    }

    auto name(std::string_view domain) -> dns::Bytes {
        auto wire=dns::make_query(0,{std::string(domain),1});
        check(wire.has_value(),"encode test name");
        return {wire->begin()+12,wire->end()-4};
    }

    auto append(dns::Bytes& wire,std::string_view owner,std::uint16_t type,dns::Bytes const& data,
        std::size_t section=0) -> void {
        auto count=7+section*2;
        check(wire[count]<128 && data.size()<65536,"fixture length");
        ++wire[count];
        auto raw=name(owner);
        wire.insert(wire.end(),raw.begin(),raw.end());
        auto length=static_cast<std::uint16_t>(data.size());
        wire.insert(wire.end(),{static_cast<std::uint8_t>(type>>8),static_cast<std::uint8_t>(type),
            0,1,0,0,0,60,static_cast<std::uint8_t>(length>>8),static_cast<std::uint8_t>(length)});
        wire.insert(wire.end(),data.begin(),data.end());
    }

    auto response(dns::Question const& q) -> dns::Bytes {
        auto wire=dns::make_query(123,q);
        check(wire.has_value(),"fixture question");
        (*wire)[2]=0x81;
        (*wire)[3]=0x80;
        return std::move(*wire);
    }

    auto data(dns::Response const& response,std::size_t n) -> std::span<std::uint8_t const> {
        auto const& rr=response.records.at(n);
        return std::span(response.wire).subspan(rr.data_offset,rr.data_length);
    }

    auto compression() -> void {
        std::string suffix=".long-shared-name-for-compression.testing-tailnet.example";
        auto hop=[&](unsigned n) {return std::string("node")+std::to_string(n)+suffix;};
        dns::Question query{hop(0),1};
        auto wire=response(query);
        for (unsigned i=0;i<10;++i) append(wire,hop(i),5,name(hop(i+1)));
        append(wire,hop(10),1,{192,0,2,17});
        check(wire.size()>512,"uncompressed chain >512");
        auto parsed=dns::parse_response(wire,123,query);
        check(parsed.has_value(),"parse chain");
        auto compressed=dns::encode_response(*parsed,234,{});
        check(compressed && compressed->size()<=512,"compressed chain <=512");
        auto decoded=dns::parse_response(*compressed,234,query);
        check(decoded && decoded->records.size()==11,"chain round-trip");
        for (unsigned i=0;i<10;++i) {
            check(decoded->records[i].name==hop(i) && decoded->records[i].cname==hop(i+1),"CNAME identity");
            check(data(*decoded,i).size()<name(hop(i+1)).size(),"CNAME compression");
        }
        check(std::ranges::equal(data(*decoded,10),std::array{192,0,2,17}),"terminal A");

        dns::Question sections{"owner.example.test",1};
        auto combined=response(sections);
        auto hostname=name("target.example.test");
        append(combined,sections.name,12,hostname);
        auto mx=dns::Bytes{0,10};mx.insert(mx.end(),hostname.begin(),hostname.end());
        append(combined,sections.name,15,mx);
        auto soa=hostname;
        soa.insert(soa.end(),hostname.begin(),hostname.end());
        soa.resize(soa.size()+20);
        append(combined,sections.name,6,soa,1);
        append(combined,sections.name,2,hostname,1);
        auto https=dns::Bytes{0,1};https.insert(https.end(),hostname.begin(),hostname.end());
        auto srv=dns::Bytes{0,1,0,2,0,53};srv.insert(srv.end(),hostname.begin(),hostname.end());
        auto opaque=dns::Bytes{0xc0,0x0c,0xde,0xad};
        append(combined,sections.name,65,https,2);
        append(combined,sections.name,64,https,2);
        append(combined,sections.name,33,srv,2);
        append(combined,sections.name,65434,opaque,2);
        auto original=dns::parse_response(combined,123,sections);
        check(original.has_value(),"parse all sections");
        auto packed=dns::encode_response(*original,234,12);
        check(packed.has_value(),"compress all sections");
        auto verified=dns::parse_response(*packed,234,sections);
        check(verified && verified->records.size()==8,"decode all sections");
        for (unsigned i=0;i<4;++i)
            check(data(*verified,i).size()<data(*original,i).size() && verified->records[i].ttl==12,
                "standard RDATA compressed and TTL edited");
        for (unsigned i=4;i<8;++i)
            check(std::ranges::equal(data(*verified,i),data(*original,i)),"extension RDATA preserved");
    }

    auto pointer_boundary() -> void {
        dns::Question query{"q",1};
        for (std::size_t offset:{16383,16384}) {
            auto wire=response(query);
            auto padding=offset-wire.size()-11;
            append(wire,".",65435,dns::Bytes(padding,0xc0));
            check(wire.size()==offset,"fixture offset");
            append(wire,"boundary.unique",1,{192,0,2,1});
            append(wire,"boundary.unique",1,{192,0,2,2});
            auto parsed=dns::parse_response(wire,123,query);
            check(parsed.has_value(),"big wire parsed");
            auto result=dns::encode_response(*parsed,123,{});
            check(result.has_value(),"big wire encoded");
            auto verified=dns::parse_response(*result,123,query);
            check(verified.has_value(),"big wire round-trip");
            auto repeated=verified->records[1].data_offset+4;
            if (offset==16383) {
                check((*result)[repeated]==0xff && (*result)[repeated+1]==0xff,"boundary pointer");
                (*result)[repeated]=0xc0;(*result)[repeated+1]=0;
                check(!dns::parse_response(*result,123,query),"pointer into header refused");
            } else check((*result)[repeated]==8,"offset 16384 cannot be a target");
        }
    }

    auto compression_case_and_overflow() -> void {
        auto raw_name=[](std::string_view domain) -> dns::Bytes {
            dns::Bytes out;
            while (!domain.empty()) {
                auto dot=domain.find('.');
                auto label=domain.substr(0,dot);
                out.push_back(static_cast<std::uint8_t>(label.size()));
                out.insert(out.end(),label.begin(),label.end());
                if (dot==domain.npos) break;
                domain.remove_prefix(dot+1);
            }
            out.push_back(0);
            return out;
        };
        auto append_raw=[&](dns::Bytes& wire,std::string_view owner,std::uint16_t type,dns::Bytes const& rdata) {
            ++wire[7];
            auto raw=raw_name(owner);
            wire.insert(wire.end(),raw.begin(),raw.end());
            auto length=static_cast<std::uint16_t>(rdata.size());
            wire.insert(wire.end(),{static_cast<std::uint8_t>(type>>8),static_cast<std::uint8_t>(type),
                0,1,0,0,0,60,static_cast<std::uint8_t>(length>>8),static_cast<std::uint8_t>(length)});
            wire.insert(wire.end(),rdata.begin(),rdata.end());
        };
        // Case-insensitive suffix compression across mixed-case question + answers.
        dns::Bytes mixed{0,123,0x81,0x80,0,1,0,0,0,0,0,0};
        auto qraw=raw_name("Mixed.Example.Test");
        mixed.insert(mixed.end(),qraw.begin(),qraw.end());
        mixed.insert(mixed.end(),{0,1,0,1});
        append_raw(mixed,"Sub.EXAMPLE.test",5,raw_name("TARGET.Example.TEST"));
        append_raw(mixed,"a.sub.example.test",1,{192,0,2,55});
        dns::Question mixed_q{"mixed.example.test",1};
        auto parsed_mixed=dns::parse_response(mixed,123,mixed_q);
        check(parsed_mixed.has_value(),"parse mixed-case response");
        auto compressed_mixed=dns::encode_response(*parsed_mixed,456,{});
        check(compressed_mixed && compressed_mixed->size()<mixed.size(),"mixed-case suffix compressed");
        auto decoded_mixed=dns::parse_response(*compressed_mixed,456,mixed_q);
        check(decoded_mixed && decoded_mixed->records.size()==2,"mixed-case round-trip");
        check(decoded_mixed->records[0].name=="sub.example.test" && decoded_mixed->records[0].cname=="target.example.test","mixed-case cname");
        check(decoded_mixed->records[1].name=="a.sub.example.test" && std::ranges::equal(data(*decoded_mixed,1),std::array{192,0,2,55}),"mixed-case A");

        // >128 distinct suffixes (60 records x 3 unique labels = 180 unique suffixes):
        // early suffixes compress, tail emits uncompressed cleanly with zero error.
        dns::Question many_q{"root.many.test",1};
        auto many=response(many_q);
        for (unsigned i=0;i<60;++i) {
            auto owner="a"+std::to_string(i)+".b"+std::to_string(i)+".t"+std::to_string(i);
            append(many,owner,1,{192,0,2,static_cast<std::uint8_t>(i+1)});
        }
        append(many,"a0.b0.t0",1,{192,0,2,200});
        append(many,"a59.b59.t59",1,{192,0,2,201});
        auto parsed_many=dns::parse_response(many,123,many_q);
        check(parsed_many && parsed_many->records.size()==62,"parse >128 suffixes");
        auto encoded_many=dns::encode_response(*parsed_many,789,{});
        check(encoded_many && encoded_many->size()<many.size(),"encode >128 suffixes succeeds and compresses early entries");
        auto decoded_many=dns::parse_response(*encoded_many,789,many_q);
        check(decoded_many && decoded_many->records.size()==62,"round-trip >128 suffixes");
        for (unsigned i=0;i<60;++i) {
            auto expected="a"+std::to_string(i)+".b"+std::to_string(i)+".t"+std::to_string(i);
            check(decoded_many->records[i].name==expected,"owner preserved across >128 suffixes");
        }
        check(decoded_many->records[60].name=="a0.b0.t0" && decoded_many->records[61].name=="a59.b59.t59","tail records preserved");
    }

    auto view_config() -> void {
        std::string const skeleton=R"kdl(schema-version 1
role "client"
inbound "app" type="socks5" { listen host="127.0.0.1" port=12345; authentication "none"; }
outbound "direct" type="direct"
outbound "edge" type="http-connect" {
    server host="edge.test" port=18080
    domain-resolver "RESOLVER"
}
DNS
routing { default-outbound "edge"; }
)kdl";
        auto parse=[&](std::string_view resolver,std::string_view dns) {
            auto document=skeleton;
            document.replace(document.find("RESOLVER"),8,resolver);
            document.replace(document.find("\nDNS\n")+1,3,dns);
            return config::parse_kdl(document);
        };
        auto good=R"kdl(dns {
    server "wire" type="udp" host="127.0.0.1" port=20053
    server "fallback" type="udp" host="127.0.0.1" port=20054
    rule domain="edge.test" server="wire"
    view "dial" final="fallback"
    final "wire"
})kdl";
        auto view=parse("dial",good), server=parse("wire",good);
        check(view && view->tcp_proxy_outbounds.front().config.bootstrap_index==2,"view binds separately");
        check(server && server->tcp_proxy_outbounds.front().config.bootstrap_index==0,"physical tag stays compatible");
        auto missing=parse("missing",good);
        check(!missing && missing.error().contains("unknown DNS server or view"),"unknown name rejected");
        auto cycle=R"kdl(dns {
    server "wire" type="udp" host="127.0.0.1" port=20053
    server "loop" type="tls" host="127.0.0.1" port=853 server-name="resolver.test" ca-file="/tmp/ca.pem" detour="edge"
    rule domain="edge.test" server="loop"
    view "dial" final="wire"
})kdl";
        auto direct=parse("dial",cycle);
        check(!direct && direct.error().contains("dependency cycle"),"direct policy cycle rejected");
        std::string indirect=skeleton;
        indirect.replace(indirect.find("RESOLVER"),8,"dial");
        auto dependency=R"kdl(
outbound "lower" type="http-connect" {
    server host="127.0.0.1" port=18081
    detour "edge"
}
)kdl";
        std::string rules=cycle;
        rules.replace(rules.find("detour=\"edge\""),13,"detour=\"lower\"");
        indirect.replace(indirect.find("\nDNS\n")+1,3,std::string(dependency)+rules);
        auto graph=config::parse_kdl(indirect);
        check(!graph && graph.error().contains("dependency cycle"),"indirect cycle rejected");
    }

    auto datagram_rules() -> void {
        using namespace rules;
        auto udp=[](std::string_view ip,std::uint16_t port,bool query) {
            return ProgramInput{.ip=ip,.port=port,.network=Network::udp,.dns_query=query};
        };
        auto predicate=[](std::string type,std::string value) {
            return RuleSet{{Rule{std::move(type),std::move(value),{}}},2};
        };
        std::array instructions{
            ProgramRule{predicate("port","5354"),{ProgramActionKind::hijack_dns}},
            ProgramRule{{},{ProgramActionKind::hijack_dns}},
            ProgramRule{predicate("ip-cidr","192.0.2.3/32"),{ProgramActionKind::reject}},
            ProgramRule{predicate("port","4321"),{ProgramActionKind::route,2}},
            ProgramRule{{},{ProgramActionKind::route,0}}
        };
        auto program=RouteProgram::compile(instructions,3);
        check(program && program->has_dns_hijack(),"compile UDP guard program");
        auto action=[&](ProgramInput input) {
            auto next=program->preflight(input);
            check(next && next->step.has_value(),"UDP rule selected");
            return next->step->action;
        };
        auto address=std::string_view{"192.0.2.2"};
        check(action(udp(address,53,true)).kind==ProgramActionKind::hijack_dns,"standard DNS intercepted");
        check(action(udp(address,5354,true)).kind==ProgramActionKind::hijack_dns,"explicit nonstandard DNS intercepted");
        for (auto port:{53,5354})
            check(action(udp(address,port,false)).kind==ProgramActionKind::route,"non-DNS payload keeps evaluating");
        check(action(udp(address,1234,true))==ProgramAction{ProgramActionKind::route,0},"DNS payload alone cannot hijack");
        check(action(udp("192.0.2.3",1234,false)).kind==ProgramActionKind::reject,"new address reclassified");
        check(action(udp(address,4321,false))==ProgramAction{ProgramActionKind::route,2},"new port reclassified");
    }
}

int main() {
    compression();
    pointer_boundary();
    compression_case_and_overflow();
    view_config();
    datagram_rules();
    auto local=dns::parse_local_resolv("nameserver 100.100.100.100\nsearch first.test tailnet.ts.net\n");
    check(local.has_value(),"local private resolver config");
    check(dns::local_search_candidates(*local,"printer","printer")==
        std::vector<std::string>{"printer.first.test","printer.tailnet.ts.net","printer"},"ordered search");
    check(dns::local_search_candidates(*local,"printer.","printer")==std::vector<std::string>{"printer"},"absolute single label");
    check(dns::local_search_candidates(*local,"host.tailnet.ts.net.","host.tailnet.ts.net")==
        std::vector<std::string>{"host.tailnet.ts.net"},"absolute private FQDN");
    std::cout << "PASS DNS views and dependency cycles, RFC 1035/RFC 3597, offset bounds, rooted search and UDP isolation\n";
}
