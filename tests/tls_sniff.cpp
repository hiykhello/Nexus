import std;
import sniff.tls;

namespace {
    using Bytes=std::vector<std::uint8_t>;
    auto u16(Bytes& out,std::size_t n) -> void { out.push_back(static_cast<std::uint8_t>(n>>8)); out.push_back(static_cast<std::uint8_t>(n)); }
    auto hello(std::string_view hostname,bool extensions=true) -> Bytes {
        Bytes body{3,3}; body.resize(34,0); body.push_back(0); u16(body,2);
        body.insert(body.end(),{0x13,1,1,0});
        if (extensions) {
            Bytes value; u16(value,hostname.size()+3); value.push_back(0); u16(value,hostname.size());
            value.insert(value.end(),hostname.begin(),hostname.end());
            u16(body,value.size()+4); u16(body,0); u16(body,value.size()); body.insert(body.end(),value.begin(),value.end());
        }
        Bytes handshake{1,static_cast<std::uint8_t>(body.size()>>16),static_cast<std::uint8_t>(body.size()>>8),static_cast<std::uint8_t>(body.size())};
        handshake.insert(handshake.end(),body.begin(),body.end()); return handshake;
    }
    auto records(Bytes const& handshake,std::size_t split) -> Bytes {
        Bytes out;
        auto record=[&](std::span<std::uint8_t const> fragment) { out.insert(out.end(),{22,3,1}); u16(out,fragment.size()); out.insert(out.end(),fragment.begin(),fragment.end()); };
        record(std::span(handshake).first(split));
        if (split<handshake.size()) record(std::span(handshake).subspan(split));
        return out;
    }
}
int main(int argc,char** argv) {
    using namespace sniff;
    if (argc==2 && std::string_view(argv[1])=="--stdin") {
        std::vector<std::uint8_t> input;
        for (std::istreambuf_iterator<char> it(std::cin),end;it!=end;++it)
            input.push_back(static_cast<std::uint8_t>(*it));
        std::array<std::uint8_t,65536> scratch{};
        TlsSniffer sniffer;
        auto result=sniffer.feed(input,scratch);
        if (result.status!=TlsStatus::matched || !result.server_name) return 1;
        std::cout << *result.server_name << '\n';
        return 0;
    }
    unsigned failures=0;
    auto check=[&](bool value,std::string_view label) { if (!value) { ++failures; std::cerr << "FAIL: " << label << '\n'; } };
    auto handshake=hello("Example.COM");
    for (std::size_t split=1;split<=handshake.size();++split) {
        auto wire=records(handshake,split); auto original=wire;
        std::array<std::uint8_t,2048> scratch{};
        TlsSniffer sniffer; TlsStep last{TlsStatus::need_more};
        for (std::size_t i=0;i<wire.size();++i) {
            last=sniffer.feed(std::span(wire).subspan(i,1),scratch);
            if (last.consumed!=1 || (i+1<wire.size() && last.status!=TlsStatus::need_more)) {
                check(false,"byte and record fragmentation"); break;
            }
        }
        check(last.status==TlsStatus::matched && last.server_name=="Example.COM" && wire==original,"TLS SNI and wire preservation");
    }
    auto wire=records(handshake,handshake.size());
    wire.insert(wire.end(),{1,2,3});
    std::array<std::uint8_t,2048> scratch{};
    TlsSniffer complete; auto result=complete.feed(wire,scratch);
    check(result.status==TlsStatus::matched && result.consumed==wire.size()-3,"leave trailing wire bytes");
    auto noext=hello("",false); auto old_wire=records(noext,noext.size());
    TlsSniffer old; result=old.feed(old_wire,scratch);
    check(result.status==TlsStatus::matched && !result.server_name,"TLS 1.2 without extensions");
    auto invalid=hello("bad..example"); auto bad_wire=records(invalid,invalid.size());
    TlsSniffer bad; result=bad.feed(bad_wire,scratch);
    check(result.status==TlsStatus::malformed && !result.server_name,"invalid SNI rejected");
    auto duplicate=hello("example.test");
    Bytes extension(duplicate.begin()+47,duplicate.end());
    duplicate.insert(duplicate.end(),extension.begin(),extension.end());
    auto total=duplicate.size()-47;
    duplicate[45]=static_cast<std::uint8_t>(total>>8); duplicate[46]=static_cast<std::uint8_t>(total);
    auto length=duplicate.size()-4;
    duplicate[1]=static_cast<std::uint8_t>(length>>16); duplicate[2]=static_cast<std::uint8_t>(length>>8);
    duplicate[3]=static_cast<std::uint8_t>(length);
    auto duplicate_wire=records(duplicate,duplicate.size());
    TlsSniffer duplicate_sniffer; result=duplicate_sniffer.feed(duplicate_wire,scratch);
    check(result.status==TlsStatus::malformed && !result.server_name,"duplicate extension clears earlier SNI");
    auto broken=hello("example.test"); broken[52]=0xff;
    auto broken_wire=records(broken,broken.size()); TlsSniffer broken_sniffer;
    result=broken_sniffer.feed(broken_wire,scratch);
    check(result.status==TlsStatus::malformed && !result.server_name,"malformed SNI list rejected");
    TlsSniffer small; std::array<std::uint8_t,16> tiny{};
    check(small.feed(wire,tiny).status==TlsStatus::too_large,"bounded reassembly");
    TlsSniffer partial; check(partial.feed(std::span(wire).first(6),scratch).status==TlsStatus::need_more &&
        partial.finish()==TlsStatus::truncated,"truncated input distinguished");
    Bytes plain{0x47,0x45,0x54,0x20,0x2f}; TlsSniffer other;
    check(other.feed(plain,scratch).status==TlsStatus::not_tls,"other protocol rejected");
    TlsSniffer changed; std::array<std::uint8_t,2048> alternate{};
    check(changed.feed(std::span(wire).first(1),scratch).status==TlsStatus::need_more &&
          changed.feed(std::span(wire).subspan(1),alternate).status==TlsStatus::malformed,"scratch lifetime enforced");
    if (!failures) std::cout << "TLS sniff fragmented records, SNI and bounded scratch passed\n";
    return failures ? 1 : 0;
}
