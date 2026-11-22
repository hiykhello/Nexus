import std;
import tailscale.packet_filter;

namespace f=tailscale::packet_filter;

auto ipv4(unsigned a,unsigned b,unsigned c,unsigned d) -> f::Address {
    f::Address value;value.family=4;value.bytes[0]=a;value.bytes[1]=b;value.bytes[2]=c;value.bytes[3]=d;return value;
}
auto ipv6(std::array<std::uint8_t,16> bytes) -> f::Address {return {bytes,6};}
auto require(bool condition,int code) -> void {if(!condition)std::exit(code);}

auto reference() -> int {
    f::Filter filter;
    auto a=ipv4(100,64,1,2),b=ipv4(100,65,2,3);
    auto c=ipv6({0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,3});
    auto d=ipv6({0x20,1,0x0d,0xb8,0,1,0,0,0,0,0,0,0,0,0,1});
    auto emit=[&] {std::println("{}{}{}{}{}",filter.matches(a,b,6,80) ? 1 : 0,filter.matches(a,b,17,90) ? 1 : 0,
        filter.matches(a,b,132,80) ? 1 : 0,filter.matches(c,d,6,443) ? 1 : 0,filter.matches(c,d,132,443) ? 1 : 0);};
    require(filter.update(R"([{"SrcIPs":["100.64.0.0/10"],"DstPorts":[{"IP":"100.65.2.3","Ports":{"First":80,"Last":90}}]}])",std::nullopt).has_value(),31);emit();
    require(filter.update(std::nullopt,R"({"v6":[{"SrcIPs":["2001:db8::1-2001:db8::5"],"DstPorts":[{"IP":"2001:db8:1::/48","Ports":{"First":443,"Last":443}}],"IPProto":[6]}]})").has_value(),32);emit();
    require(filter.update(R"([{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}],"IPProto":[-1,999,132]}])",R"({"v6":null})").has_value(),33);emit();
    require(filter.update(std::nullopt,R"({"*":null,"empty":[]})").has_value(),34);emit();
    require(filter.update(R"([{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}])",R"({"base":[]})").has_value(),35);emit();
    require(filter.update(R"([{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}])",std::nullopt).has_value(),42);
    std::println("{}{}{}{}",filter.matches(a,b,6,80) ? 1 : 0,filter.matches(c,d,6,80) ? 1 : 0,
        filter.matches(a,d,6,80) ? 1 : 0,filter.matches(c,b,6,80) ? 1 : 0);
    return 0;
}

auto main(int argc,char** argv) -> int {
    if(argc==2 && std::string_view(argv[1])=="--reference")return reference();
    f::Filter filter;
    auto src=ipv4(100,64,1,2),dst=ipv4(100,65,2,3);
    require(!filter.received() && !filter.matches(src,dst,6,80),1);
    require(filter.update(std::nullopt,std::nullopt).has_value() && !filter.received(),2);
    std::string legacy=R"([{"SrcIPs":["100.64.0.0/10"],"DstPorts":[{"IP":"100.65.2.3","Ports":{"First":80,"Last":90}}]}])";
    require(filter.update(legacy,std::nullopt).has_value() && filter.received(),3);
    legacy.assign(legacy.size(),'x'); // Published rules do not borrow the frame.
    require(filter.matches(src,dst,6,80) && filter.matches(src,dst,17,90),4);
    require(filter.matches(src,dst,1,80) && filter.matches(src,dst,58,80),5);
    require(!filter.matches(src,dst,47,80) && !filter.matches(src,dst,6,91),6);
    require(!filter.matches(ipv4(1,2,3,4),dst,6,80),7);
    auto mapped=ipv6({0,0,0,0,0,0,0,0,0,0,0xff,0xff,100,64,1,2});
    require(!filter.matches(mapped,dst,6,80),41);
    constexpr std::string_view named=R"({"v6":[{"SrcIPs":["2001:db8::1-2001:db8::5"],"DstPorts":[{"IP":"2001:db8:1::/48","Ports":{"First":443,"Last":443}}],"IPProto":[6]}]})";
    require(filter.update(std::nullopt,named).has_value(),8);
    auto source6=ipv6({0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,3});
    auto dest6=ipv6({0x20,1,0x0d,0xb8,0,1,0,0,0,0,0,0,0,0,0,1});
    require(filter.matches(source6,dest6,6,443) && !filter.matches(source6,dest6,17,443),9);
    require(filter.chunks().size()==2 && filter.chunks()[0].name=="base" && filter.chunks()[1].name=="v6",10);
    constexpr std::string_view invalid=R"({"base":[{"SrcIPs":["100.64.0.1/10"],"DstPorts":[]}]})";
    require(!filter.update(std::nullopt,invalid) && filter.matches(src,dst,6,80) && filter.matches(source6,dest6,6,443),11);
    constexpr std::string_view wildcard=R"([{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}],"IPProto":[-1,999,132]}])";
    require(filter.update(wildcard,R"({"*":null,"only":[]})").has_value(),12);
    require(filter.chunks().size()==1 && filter.chunks()[0].name=="only" && !filter.matches(src,dst,132,80),13);
    require(filter.update(wildcard,R"({"only":null})").has_value(),14);
    require(filter.matches(src,dst,132,80) && filter.matches(source6,dest6,132,443),15);
    require(!filter.matches(src,dest6,132,80) && !filter.matches(source6,dst,132,80),43);
    require(!filter.matches(src,dst,6,80),16); // Out-of-range numbers do not activate defaults.
    constexpr std::string_view badcap=R"([{"SrcIPs":["cap:example"],"DstPorts":[]}])";
    constexpr std::string_view badgrant=R"([{"SrcIPs":["*"],"CapGrant":[{"Dsts":["0.0.0.0/0"],"Caps":["x"]}]}])";
    constexpr std::string_view duplicate=R"({"base":[],"base":null})";
    require(!filter.update(badcap,std::nullopt) && !filter.update(badgrant,std::nullopt) && !filter.update(std::nullopt,duplicate),17);
    require(filter.matches(src,dst,132,80),18); // Rejected transaction leaves old rule intact.
    require(filter.update(R"([])",R"({"base":null})").has_value(),19);
    require(filter.chunks().empty() && !filter.matches(src,dst,132,80),20);
    filter.clear();require(!filter.received() && filter.chunks().empty(),21);
    require(filter.update(std::nullopt,R"({})").has_value() && filter.received() && !filter.matches(src,dst,6,80),22);
    constexpr std::string_view range=R"([{"SrcIPs":["100.64.1.2-100.64.1.4"],"DstPorts":[{"IP":"100.65.2.0/24","Ports":{"First":7,"Last":7}}],"IPProto":[6]}])";
    require(filter.update(range,std::nullopt).has_value(),23);
    require(filter.matches(ipv4(100,64,1,4),dst,6,7) && !filter.matches(ipv4(100,64,1,5),dst,6,7),24);
    require(!filter.update(R"([{"SrcIPs":["100.64.1.4-100.64.1.2"]}])",std::nullopt),25);
    require(!filter.update(R"([{"SrcIPs":["*"],"SrcBits":[8]}])",std::nullopt),26);
    require(!filter.update(R"([{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Bits":24}]}])",std::nullopt),27);
    require(!filter.update(R"([{"SrcIPs":["*"],"FutureSecurityField":true}])",std::nullopt),28);
    require(!filter.update(std::nullopt,R"({"a":[],"\u0061":[]})"),29);
    require(filter.matches(src,dst,6,7),30);
    require(!filter.update(std::nullopt,R"([])") && !filter.update(R"({})",std::nullopt),36);
    require(!filter.update(R"([{"SrcIPs":{}}])",std::nullopt),37);
    filter.clear();std::string many="{";
    for(unsigned i=0;i<f::max_chunks;++i) {if(i)many+=',';many+=std::format("\"k{:02}\":[]",i);}
    many+='}';require(filter.update(std::nullopt,many).has_value() && filter.chunks().size()==f::max_chunks,38);
    require(filter.update(std::nullopt,R"({"new":[],"k00":null})").has_value() && filter.chunks().size()==f::max_chunks,39);
    require(!filter.update(std::nullopt,R"({"overflow":[]})") && filter.chunks().size()==f::max_chunks,40);
    std::println("Tailscale packet-filter rule parsing, updates, rollback and stateless matching passed");
}
