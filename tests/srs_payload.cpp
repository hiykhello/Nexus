import std;
import rules;
import rules.srs_payload;

namespace {
    auto check(bool condition,std::string_view message) -> void {
        if(!condition) {std::cerr<<message<<'\n';std::exit(1);}
    }
    auto decode(std::initializer_list<std::uint8_t> value) {
        return ::rules::decode_srs_payload(std::span(value.begin(),value.size()));
    }
}
auto main(int argc,char** argv) -> int {
    using namespace ::rules;
    if(argc==2) {
        std::ifstream file(argv[1],std::ios::binary);
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)),{});
        check(file.eof() || (file && !bytes.empty()),"cannot read SRS payload fixture");
        auto set=decode_srs_payload(bytes);check(bool(set),"real SRS payload rejected");
        auto matcher=Matcher::compile(*set);check(bool(matcher),"real SRS matcher rejected");
        auto hit=matcher->match({.domain="dns.example",.port=53,.network=Network::udp,.source_port=150});
        auto miss=matcher->match({.domain="other.example",.port=53,.network=Network::udp,.source_port=150});
        check(hit && *hit==std::optional<std::size_t>{0} && miss && !*miss,"real SRS condition groups differ");
        std::cout<<"sing-box SRS payload translated and matched\n";return 0;
    }
    if(argc==3 && std::string_view(argv[1])=="--ip") {
        std::ifstream file(argv[2],std::ios::binary);
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)),{});
        auto set=decode_srs_payload(bytes);check(bool(set),"real SRS IP payload rejected");
        auto matcher=Matcher::compile(*set);check(bool(matcher),"IP matcher rejected");
        auto in=matcher->match({.ip="192.0.2.129",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto keyword=matcher->match({.domain="dns.example",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto exact=matcher->match({.domain="exact.test",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto wrong_source=matcher->match({.ip="192.0.2.129",.port=53,.network=Network::udp,.source_ip="198.51.101.9"});
        auto outside=matcher->match({.ip="192.0.3.1",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto end=matcher->match({.ip="192.0.2.191",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto past=matcher->match({.ip="192.0.2.192",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto ipv6=matcher->match({.ip="2001:db8::1234",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        check(in && *in && keyword && *keyword && exact && *exact && wrong_source && !*wrong_source && outside && !*outside &&
              end && *end && past && !*past && ipv6 && *ipv6,
              "SRS IP grouping differs");
        auto source_set=decode_srs_payload(bytes,true);check(bool(source_set),"source-mode SRS payload rejected");
        auto source_matcher=Matcher::compile(*source_set);check(bool(source_matcher),"source-mode matcher rejected");
        auto source_original=source_matcher->match({.domain="exact.test",.port=53,.network=Network::udp,.source_ip="198.51.100.9"});
        auto source_cidr=source_matcher->match({.domain="exact.test",.port=53,.network=Network::udp,.source_ip="192.0.2.129"});
        auto source_miss=source_matcher->match({.domain="exact.test",.port=53,.network=Network::udp,.source_ip="203.0.113.1"});
        auto domain_miss=source_matcher->match({.domain="other.test",.port=53,.network=Network::udp,.source_ip="192.0.2.129"});
        check(source_original && *source_original && source_cidr && *source_cidr && source_miss && !*source_miss && domain_miss && !*domain_miss,
              "source-mode CIDR must join the source OR group and remain separate from domain");
        std::cout<<"sing-box IP ranges and domain/IP grouping passed\n";return 0;
    }
    if(argc==3 && std::string_view(argv[1])=="--domain") {
        std::ifstream file(argv[2],std::ios::binary);
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)),{});
        auto set=decode_srs_payload(bytes);check(bool(set),"real SRS domain payload rejected");
        auto matcher=Matcher::compile(*set);check(bool(matcher),"domain matcher rejected");
        for(auto [name,expected]:std::array<std::pair<std::string_view,bool>,11>{{
            {"exact.test",true},{"x.exact.test",false},{"root.test",true},{"a.root.test",true},
            {"notroot.test",false},{"only.test",false},{"a.only.test",true},{"deep.a.only.test",true},
            {"notonly.test",false},{"OTHER.ROOT.TEST",true},{"unrelated.test",false}}}) {
            auto match=matcher->match({.domain=name});
            check(match && bool(*match)==expected,"SRS domain match mismatch");
        }
        std::cout<<"sing-box exact, suffix and subdomain-only trie passed\n";return 0;
    }
    // One rule: (tcp OR udp) AND (source port 42 OR 100:200)
    // AND (destination port 53 OR keyword "dns").
    auto set=decode({1,0,1,2,3,'t','c','p',3,'u','d','p',7,1,0,42,
        8,1,7,'1','0','0',':','2','0','0',9,1,0,53,3,1,3,'d','n','s',255,0});
    check(bool(set),"valid grouped payload rejected");
    auto matcher=Matcher::compile(*set);check(bool(matcher),"translated matcher rejected");
    auto hit=matcher->match({.domain="dns.example",.port=53,.network=Network::udp,.source_port=150});
    check(hit && *hit==std::optional<std::size_t>{0},"grouped rule failed to match");
    auto miss=matcher->match({.domain="other.example",.port=53,.network=Network::udp,.source_port=150});
    check(miss && !*miss,"address and port groups were incorrectly ORed");
    auto logical=decode({1,1,1,2,0,9,1,0,53,255,0,0,9,1,1,187,255,0,1});
    check(bool(logical),"logical invert payload rejected");
    auto inverted=Matcher::compile(*logical);check(bool(inverted),"logical matcher rejected");
    auto yes=inverted->match({.port=80});auto no=inverted->match({.port=53});
    check(yes && *yes && no && !*no,"logical inversion changed semantics");
    auto qtypes=decode({1,0,0,2,0,1,0,28,255,0});
    check(bool(qtypes),"SRS query types rejected");
    auto questions=Matcher::compile(*qtypes);check(bool(questions),"query type matcher rejected");
    auto q1=questions->match_truth_mapped({.query_type=1});
    auto q28=questions->match_truth_mapped({.query_type=28});
    auto q15=questions->match_truth_mapped({.query_type=15});
    auto missing=questions->match_truth_mapped({});
    check(q1 && *q1==Matcher::Truth::yes && q28 && *q28==Matcher::Truth::yes && q15 && *q15==Matcher::Truth::no &&
          missing && *missing==Matcher::Truth::unknown,"SRS query types or missing metadata mismatch");
    auto process=decode({1,0,4,1,5,'^','d','n','s','$',11,2,3,'a','p','p',3,'d','n','s',
        12,1,8,'/','b','i','n','/','d','n','s',255,0});
    check(bool(process),"SRS bounded domain regex and process fields rejected");
    auto process_rules=Matcher::compile(*process);
    check(bool(process_rules),"SRS process matcher rejected");
    auto process_hit=process_rules->match_truth_mapped({.domain="DNS",.process_path="/bin/dns"});
    auto process_miss=process_rules->match_truth_mapped({.domain="dns",.process_path="/other/dns"});
    auto process_missing=process_rules->match_truth_mapped({.domain="dns"});
    check(process_hit && *process_hit==Matcher::Truth::yes && process_miss && *process_miss==Matcher::Truth::no &&
        process_missing && *process_missing==Matcher::Truth::unknown,"SRS process fields must be separate AND conditions");
    check(!decode({1,0,0,1,0,0,255,0}),"zero query type accepted");
    check(!decode({1,0,4,0,255,0}),"empty regex set accepted");
    check(!decode({1,0,4,1,5,'(','?','i',')','a',255,0}),"unsupported regex accepted");
    check(!decode({0x81,0,0,9,1,0,53,255,0}),"noncanonical rule count accepted");
    check(!decode({1,0,11,1,0,255,0}),"empty process name accepted");
    check(!decode({1,0,3,1,3,'D','N','S',255,0}),"uppercase keyword accepted");
    check(!decode({1,0,9,1,0,53,9,1,0,54,255,0}),"duplicate item accepted");
    check(!decode({1,0,10,1,3,':','8','0',255,0}),"zero-inclusive range accepted");
    check(!decode({1,0,9,1,0,53,255,2}),"invalid inversion accepted");
    check(!decode({1,0,9,1,0}),"truncated port accepted");
    check(!decode({1,0,9,1,0,53,255,0,0}),"trailing bytes accepted");
    check(!decode({1,0,6,1,0,0,0,0,0,0,0,1,4,192,0,2,9,4,192,0,2,1,255,0}),"reversed IP range accepted");
    check(!decode({1,0,6,1,0,0,0,0,0,0,0,1,4,192,0,2,1,16,0,255,0}),"mixed IP families accepted");
    check(!decode({1,0,2,0,0,1,0,0,0,0,0,0,0,1,0,255,0}),"malformed domain topology accepted");
    for(unsigned first=0;first<256;first+=13)for(unsigned last=first;last<256;last+=17) {
        std::vector<std::uint8_t> bytes{1,0,6,1,0,0,0,0,0,0,0,1,4,192,0,2,
            static_cast<std::uint8_t>(first),4,192,0,2,static_cast<std::uint8_t>(last),255,0};
        auto rule=decode_srs_payload(bytes);check(bool(rule),"bounded range rejected");
        auto compiled=Matcher::compile(*rule);check(bool(compiled),"range matcher rejected");
        for(unsigned probe=0;probe<256;++probe) {
            auto address=std::format("192.0.2.{}",probe);
            auto result=compiled->match({.ip=address});
            check(result && bool(*result)==(probe>=first && probe<=last),"range/CIDR boundary mismatch");
        }
    }
    std::cout<<"SRS payload grouping, logical inversion and strict rejection passed\n";
}
