import std;
import dns.message;
import dns.response_match;
import dns.response_addresses;
import dns.input_budget;
import rules;
#ifdef NEXUS_DNS_RESPONSE
import dns.response_program;
import dns.policy;
#endif
namespace d = dns;

auto main() -> int {
    {
        d::InputBudget budget(100);
        auto first=budget.acquire(30),second=budget.acquire(20);
        if(!first || !second || budget.used()!=50)return 211;
        *first=std::move(*second);
        if(budget.used()!=20)return 212;
        *first=std::move(*first);
        if(budget.used()!=20)return 213;
        first.reset();second.reset();
        if(budget.used()!=0)return 214;
    }
#ifdef NEXUS_DNS_RESPONSE
    {
        ::policy::DnsRule options;options.match_all=true;options.action=::policy::DnsAction::route_options;
        options.client_subnet=::policy::ResponsePrefix{{192,0,2},4,24};
        ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;route.server=0;
        std::array rules{options,route};
        if(!d::normalize_response_rule(rules[0],1) || !d::normalize_response_rule(rules[1],1)) return 147;
        d::ResponseWalk walk(rules,0);auto step=walk.next("test",1);
        if(!step || !step->subnet || !*step->subnet || (**step->subnet).address[2]!=2) return 148;
        rules[1].remove_client_subnet=true;
        d::ResponseWalk remove(rules,0);step=remove.next("test",1);
        if(!step || !step->subnet || *step->subnet) return 149;
    }
#endif
    std::string max_name=std::string(63,'A')+"."+std::string(63,'B')+"."+std::string(63,'C')+"."+std::string(61,'D');
    std::string max_lower=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(61,'d');
    for (auto const& [input,canonical] : std::vector<std::pair<std::string,std::string>>{
            {".","."},{"EXAMPLE.TeSt.","example.test"},{"!~.-_","!~.-_"},
            {max_name,max_lower},{max_name+".",max_lower}}) {
        auto actual=input;
        if (!d::canonicalize_name(actual) || actual!=canonical) return 100;
        auto from_input=d::make_query(0,{input,1}), from_canonical=d::make_query(0,{canonical,1});
        if (!from_input || !from_canonical || *from_input!=*from_canonical) return 101;
    }
    for (auto const& input : std::vector<std::string>{"","..","a..",".a","a..b",std::string(64,'A'),
            max_name+"D","a b","a\\b",std::string("a\0b",3),std::string("a\x7f",2)}) {
        auto actual=input;
        if (d::canonicalize_name(actual) || actual!=input || d::make_query(0,{input,1})) return 102;
    }
    d::Question question{"www.Example.com.",1};
    auto query = d::make_query(0x1234, question);
    d::Bytes expected{0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    if (!query || *query != expected) return 1;
    auto request=d::parse_query(*query);
    if (!request || request->id!=0x1234 || request->flags!=0x0100 || request->question.name!="www.example.com" || request->question.type!=1 || request->edns) return 116;
    {
        auto root=d::make_query(5,{".",1});auto maximum=d::make_query(5,{max_name,1});
        if(maximum)(*maximum)[13]='A';
        auto root_parsed=root ? d::parse_query(*root) : std::expected<d::QueryMessage,d::MessageError>(std::unexpected(d::MessageError::malformed));
        auto maximum_parsed=maximum ? d::parse_query(*maximum) : std::expected<d::QueryMessage,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!root_parsed || root_parsed->question.name!="." || !maximum_parsed || maximum_parsed->question.name!=max_lower)return 194;
        auto malformed=*query;malformed[12]=0xc0;malformed[13]=0x00;
        if(d::parse_query(malformed))return 195;
        malformed=*query;malformed[12]=0x40;if(d::parse_query(malformed))return 196;
        malformed=*query;malformed[13]=' ';if(d::parse_query(malformed))return 197;
        malformed=*query;malformed.resize(14);if(d::parse_query(malformed))return 198;
        // A 256-byte wire name exceeds the DNS name limit.
        auto too_long=*maximum;too_long.insert(too_long.end()-5,'d');++too_long[12+64+64+64];
        if(d::parse_query(too_long))return 199;
    }
    auto checked=*query;checked[3]|=d::checking_disabled_flag | d::authenticated_data_flag;
    auto checked_query=d::parse_query(checked);
    if (!checked_query || d::encode_query(*checked_query)!=checked) return 117;
    checked[3]|=0x80;if (d::parse_query(checked)) return 118;
    auto edns_query=d::make_edns_query(0x1234,question,1232);
    if (!edns_query) return 119;
    auto request_edns=*edns_query;request_edns[request_edns.size()-4]=0x80;
    request_edns[request_edns.size()-1]=7;
    request_edns.insert(request_edns.end(),{0,8,0,3,1,2,3});
    auto parsed_query=d::parse_query(request_edns);
    if(!parsed_query || !parsed_query->edns || !parsed_query->edns->dnssec_ok || parsed_query->edns->options.size()!=1 ||
       parsed_query->edns->options[0].code!=8 || parsed_query->edns->options[0].data!=d::Bytes{1,2,3}) return 120;
    auto encoded_query=d::encode_query(*parsed_query);
    if(!encoded_query || *encoded_query!=request_edns) return 129;
    auto query_with_cd=*parsed_query;query_with_cd.flags|=0x0010;query_with_cd.edns->version=2;
    encoded_query=d::encode_query(query_with_cd);
    auto roundtrip=encoded_query ? d::parse_query(*encoded_query) : std::expected<d::QueryMessage,d::MessageError>(std::unexpected(d::MessageError::malformed));
    if(!roundtrip || roundtrip->flags!=query_with_cd.flags || !roundtrip->edns || roundtrip->edns->version!=2 ||
       roundtrip->edns->options[0].data!=query_with_cd.edns->options[0].data) return 130;
    request_edns.pop_back();if(d::parse_query(request_edns)) return 121;
    {
        d::QueryEdns edns{1232,0,false,{{8,{0,1,25,0,192,0,2,128}}}};
        auto ecs=d::query_client_subnet(edns);
        if(!ecs || !*ecs || (**ecs).family!=1 || (**ecs).prefix!=25 || (**ecs).address[3]!=128) return 122;
        edns.options[0].data.back()=129;if(d::query_client_subnet(edns)) return 123;
        edns.options[0].data.back()=128;edns.options[0].data[3]=1;if(d::query_client_subnet(edns)) return 124;
        edns.options[0].data[3]=0;edns.options.push_back(edns.options[0]);if(d::query_client_subnet(edns)) return 125;
        edns.options.resize(1);edns.options[0].data={0,2,128,0};edns.options[0].data.resize(20,0xff);
        ecs=d::query_client_subnet(edns);if(!ecs || !*ecs || (**ecs).family!=2 || (**ecs).prefix!=128) return 126;
        edns.options[0].data={0,1,0,0};ecs=d::query_client_subnet(edns);if(!ecs || !*ecs || (**ecs).prefix!=0) return 127;
        edns.options.clear();ecs=d::query_client_subnet(edns);if(!ecs || *ecs) return 128;
        d::QueryMessage changed{1,0x0100,{"example.test",1},d::QueryEdns{1400,0,true,{{10,{1,2}}}}};
        d::ClientSubnet subnet{1,25,{192,0,2,128}};
        if(!d::set_query_client_subnet(changed,subnet) || changed.edns->options.size()!=2 ||
           changed.edns->options[0].code!=10 || changed.edns->options[0].data!=d::Bytes{1,2}) return 140;
        auto decoded=d::query_client_subnet(*changed.edns);
        if(!decoded || !*decoded || (**decoded).prefix!=25 || (**decoded).address[3]!=128) return 141;
        subnet.address[3]=129;
        if(d::set_query_client_subnet(changed,subnet) || changed.edns->options[1].data.back()!=128) return 142;
        if(!d::set_query_client_subnet(changed,{}) || changed.edns->options.size()!=1 || !changed.edns->dnssec_ok) return 143;
        changed.edns.reset();subnet.address[3]=128;
        if(!d::set_query_client_subnet(changed,subnet) || !changed.edns || changed.edns->udp_payload_size!=1232) return 144;
    }

    auto expected_edns=expected; expected_edns[11]=1;
    expected_edns.insert(expected_edns.end(),{0,0,41,4,0xd0,0,0,0,0,0,0});
    if (!edns_query || *edns_query!=expected_edns || d::make_edns_query(1,question,511) ||
        d::make_edns_query(1,question,4097) || d::make_edns_query(1,{"a..b",1},1232)) return 54;
    auto response = *query; response[2]=0x81; response[3]=0x80; response[7]=1;
    d::Bytes answer{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,127,0,0,1};
    response.insert(response.end(), answer.begin(), answer.end());
    auto parsed=d::parse_response(response,0x1234,question);
    if (!parsed || parsed->records.size()!=1 || parsed->records[0].name!="www.example.com" ||
        parsed->records[0].ttl!=60 || parsed->records[0].data_length!=4 ||
        parsed->wire[parsed->records[0].data_offset]!=127) return 2;
    {
        auto owned_wire=response;auto* bytes=owned_wire.data();
        auto owned=d::parse_owned_response(std::move(owned_wire),0x1234,question);
        if(!owned || owned->wire.data()!=bytes || owned->wire!=parsed->wire || owned->records.size()!=parsed->records.size() ||
           owned->records[0].name!=parsed->records[0].name || owned->records[0].data_offset!=parsed->records[0].data_offset)return 200;
        auto malformed=response;malformed.pop_back();
        auto borrowed=d::parse_response(malformed,0x1234,question);
        auto moved=d::parse_owned_response(std::move(malformed),0x1234,question);
        if(borrowed || moved || borrowed.error()!=moved.error())return 201;
    }
    {
        auto addresses=d::response_addresses(*parsed);
        if(!addresses || addresses->size()!=1 || (*addresses)[0].size!=4 || (*addresses)[0].bytes[0]!=127) return 160;
        d::Response hints{};hints.wire={0,1,0, 0,4,0,8,192,0,2,1,192,0,2,2, 0,6,0,16,
            0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        hints.records.push_back({"hint.test",65,1,60,d::Section::answer,0,hints.wire.size(),{}});
        auto extracted=d::response_addresses(hints);
        if(!extracted || extracted->size()!=3 || (*extracted)[1].bytes[3]!=2 || (*extracted)[2].size!=16 || (*extracted)[2].bytes[15]!=1) return 161;
        hints.rcode=3;extracted=d::response_addresses(hints);if(!extracted || !extracted->empty()) return 162;
        hints.rcode=0;hints.wire[6]=7;if(d::response_addresses(hints)) return 163;
        d::Response compressed{};compressed.wire={1,'x',0,0,1,0xc0,0,0,4,0,4,192,0,2,3};
        compressed.records.push_back({"hint.test",65,1,60,d::Section::answer,3,compressed.wire.size()-3,{}});
        extracted=d::response_addresses(compressed);if(!extracted || extracted->size()!=1 || (*extracted)[0].bytes[3]!=3) return 173;
        compressed.wire[6]=6;if(d::response_addresses(compressed)) return 174;
        d::Response chaos{};chaos.wire={0,0,1};
        chaos.records.push_back({"chaos.test",1,3,60,d::Section::answer,0,3,{}});
        extracted=d::response_addresses(chaos);if(!extracted || !extracted->empty()) return 175;
        d::Response oversized{};oversized.wire.resize(65536);
        extracted=d::response_addresses(oversized);if(extracted || extracted.error()!=d::MessageError::limit) return 183;
#ifdef NEXUS_DNS_RESPONSE
        ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;
        ::policy::DnsRule matched;matched.has_rule_set=true;matched.match_response=true;matched.action=::policy::DnsAction::respond;
        ::rules::RuleSet set{{{"or","",{{"domain-suffix","domain.test",{}},{"ip-cidr","127.0.0.0/8",{}}}}},2};
        if(!::policy::bind_dns_rule_set(matched,std::move(set)) || !matched.rule_set_needs_response ||
           !d::normalize_response_rule(evaluate,1) || !d::normalize_response_rule(matched,1)) return 164;
        std::array rules{evaluate,matched};d::ResponseWalk walk(rules,0);
        auto step=walk.next("other.test",1);if(!step || step->action!=::policy::DnsAction::evaluate) return 165;
        if(!walk.evaluated(*parsed)) return 166;
        step=walk.next("other.test",1);if(!step || step->action!=::policy::DnsAction::respond) return 167;
        d::ResponseWalk empty(rules,0);step=empty.next("other.test",1);if(!step || !empty.evaluated(d::Response{})) return 168;
        step=empty.next("other.test",1);if(!step || step->action!=::policy::DnsAction::route) return 169;
        d::ResponseWalk domain(rules,0);step=domain.next("domain.test",1);if(!step || !domain.evaluated(d::Response{})) return 170;
        step=domain.next("domain.test",1);if(!step || step->action!=::policy::DnsAction::respond) return 171;
        auto missing=std::array{matched};d::ResponseWalk no_response(missing,0);step=no_response.next("domain.test",1);
        if(!step || step->action!=::policy::DnsAction::route) return 172;
        std::array repeated{evaluate,matched,evaluate,matched};d::ResponseWalk refreshed(repeated,0);
        step=refreshed.next("other.test",1);if(!step || !refreshed.evaluated(d::Response{})) return 176;
        step=refreshed.next("other.test",1);if(!step || step->action!=::policy::DnsAction::evaluate || !refreshed.evaluated(*parsed)) return 177;
        step=refreshed.next("other.test",1);if(!step || step->action!=::policy::DnsAction::respond || step->rule!=3) return 178;
        std::array malformed_rules{evaluate,matched};d::ResponseWalk malformed(malformed_rules,0);
        step=malformed.next("other.test",65);if(!step || !malformed.evaluated(hints)) return 179;
        step=malformed.next("other.test",65);if(step || step.error()!=d::ResponseProgramError::invalid_response) return 180;
        auto filtered=matched;filtered.query_type=1;
        std::array filtered_rules{evaluate,filtered};d::ResponseWalk irrelevant(filtered_rules,0);
        step=irrelevant.next("other.test",65);if(!step || !irrelevant.evaluated(hints)) return 181;
        step=irrelevant.next("other.test",65);if(!step || step->action!=::policy::DnsAction::route) return 182;
        auto tagged_a=evaluate;tagged_a.evaluate_tag="a";
        auto tagged_b=evaluate;tagged_b.evaluate_tag="b";
        auto respond_a=matched;respond_a.match_response_tag="a";
        std::array tagged_rules{tagged_a,tagged_b,respond_a};
        if(!::policy::validate_dns_response_tags(tagged_rules)) return 184;
        d::ResponseWalk tagged(tagged_rules,0);step=tagged.next("other.test",1);
        if(!step || step->response_tag!="a" || !tagged.evaluated(*parsed)) return 185;
        step=tagged.next("other.test",1);if(!step || step->response_tag!="b" || !tagged.evaluated(d::Response{})) return 186;
        step=tagged.next("other.test",1);if(!step || step->action!=::policy::DnsAction::respond || step->response_tag!="a") return 187;
        auto selected=tagged.take_response();if(!selected || selected->wire!=parsed->wire) return 188;
        {
            d::InputBudget budget(1);
            d::ResponseWalk limited(tagged_rules,0,false,&budget);
            auto first=limited.next("other.test",1);if(!first)return 192;
            auto refused=limited.evaluated(*parsed);
            if(refused || refused.error()!=d::ResponseProgramError::resource_limit || budget.used())return 193;
        }
        {
            d::InputBudget budget(1024*1024);
            {
                d::ResponseWalk first(tagged_rules,0,false,&budget);
                auto first_step=first.next("other.test",1);if(!first_step || !first.evaluated(*parsed))return 194;
                auto held=budget.used();if(!held)return 195;
                d::InputBudget tight(held);
                {
                    d::ResponseWalk owner(tagged_rules,0,false,&tight), competitor(tagged_rules,0,false,&tight);
                    if(!owner.next("other.test",1) || !owner.evaluated(*parsed) || tight.used()!=held)return 196;
                    if(!competitor.next("other.test",1))return 197;
                    auto refused=competitor.evaluated(*parsed);
                    if(refused || refused.error()!=d::ResponseProgramError::resource_limit || tight.used()!=held)return 198;
                }
                if(tight.used())return 199;
                {
                    d::InputBudget no_addresses(held);
                    {
                        d::ResponseWalk limited(rules,0,false,&no_addresses);
                        if(!limited.next("other.test",1) || !limited.evaluated(*parsed) || no_addresses.used()!=held)return 204;
                        auto denied=limited.next("other.test",1);
                        if(denied || denied.error()!=d::ResponseProgramError::resource_limit || no_addresses.used()!=held)return 205;
                    }
                    if(no_addresses.used())return 206;
                }
                {
                    d::InputBudget enough(1024*1024);
                    {
                        d::ResponseWalk permitted(rules,0,false,&enough);
                        if(!permitted.next("other.test",1) || !permitted.evaluated(*parsed))return 207;
                        auto response_only=enough.used();auto match=permitted.next("other.test",1);
                        if(!match || match->action!=::policy::DnsAction::respond || enough.used()<=response_only)return 208;
                        auto response=permitted.take_response();if(!response || enough.used()!=response_only)return 209;
                    }
                    if(enough.used())return 210;
                }
                if(!first.next("other.test",1) || !first.evaluated(d::Response{}))return 201;
                auto selected_step=first.next("other.test",1);
                if(!selected_step || selected_step->action!=::policy::DnsAction::respond)return 202;
                auto transferred=first.take_response();if(!transferred || budget.used()<held)return 203;
            }
            if(budget.used())return 200;
        }
        auto duplicate=tagged_rules;duplicate[1].evaluate_tag="a";
        if(::policy::validate_dns_response_tags(duplicate)) return 189;
        auto forward=tagged_rules;forward[0].match_response=true;forward[0].match_response_tag="b";
        if(::policy::validate_dns_response_tags(forward)) return 190;
        auto conditional=tagged_a;conditional.match_all=false;conditional.domain="skip.test";
        auto inverted_tag=respond_a;inverted_tag.invert=true;
        std::array skipped{conditional,inverted_tag};d::ResponseWalk skipped_walk(skipped,0);
        step=skipped_walk.next("other.test",1);if(!step || step->action!=::policy::DnsAction::route) return 191;
#endif
    }
    {
        auto with_ecs=response;with_ecs[11]=1;
        with_ecs.insert(with_ecs.end(),{0,0,41,4,208,0,0,0,0,0,11,0,8,0,7,0,1,24,0,192,0,2});
        d::ClientSubnet subnet{1,24,{192,0,2}};
        if(!d::parse_addresses(with_ecs,0x1234,question,true,subnet) ||
           d::parse_addresses(with_ecs,0x1234,question,true)) return 145;
        subnet.address[2]=3;
        if(d::parse_addresses(with_ecs,0x1234,question,true,subnet)) return 146;
        auto parsed_ecs=d::parse_response(with_ecs,0x1234,question);
        d::QueryMessage client{0x4321,0x0100,question,d::QueryEdns{1232,0,false,{}}};
        d::QueryMessage upstream{0x1234,0x0100,question,d::QueryEdns{1232,0,false,{}}};
        d::ClientSubnet sent{1,24,{192,0,2}};
        if(!parsed_ecs || !d::set_query_client_subnet(client,subnet) || !d::set_query_client_subnet(upstream,sent)) return 150;
        auto restored=d::restore_response_ecs(client,upstream,*parsed_ecs);
        // The compact view must retain the same ECS semantics regardless of
        // large unrelated EDNS options on the upstream query.
        upstream.edns->options.push_back({65001,d::Bytes(60000,0x5a)});
        auto view=d::response_ecs_view(upstream);
        auto compact=view ? d::restore_response_ecs(client,*view,*parsed_ecs) : std::expected<d::Bytes,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!view || !restored || !compact || *restored!=*compact || sizeof(d::ResponseEcsView)>32) return 192;
        auto duplicate=upstream;duplicate.edns->options.push_back(duplicate.edns->options.front());
        if(d::response_ecs_view(duplicate))return 193;
        auto decoded=restored ? d::parse_response(*restored,client.id,question) : std::expected<d::Response,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!decoded || !d::validate_response_ecs(client,*decoded) || d::validate_response_ecs(upstream,*decoded)) return 151;
        auto restored_opt=std::ranges::find(decoded->records,std::uint16_t{41},&d::Record::type);
        if(restored_opt==decoded->records.end() || decoded->wire[restored_opt->data_offset+7]!=24) return 160;
        if(!d::set_query_client_subnet(client,{}))return 152;
        restored=d::restore_response_ecs(client,upstream,*parsed_ecs);
        decoded=restored ? d::parse_response(*restored,client.id,question) : std::expected<d::Response,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!decoded || !d::validate_response_ecs(client,*decoded) || !decoded->edns || decoded->edns->option_count) return 153;
        with_ecs[11]=3;
        auto target=with_ecs.size();
        with_ecs.insert(with_ecs.end(),{4,'l','a','t','e',0,0,1,0,1,0,0,0,60,0,4,192,0,2,1});
        with_ecs.push_back(static_cast<std::uint8_t>(0xc0|(target>>8)));
        with_ecs.push_back(static_cast<std::uint8_t>(target));
        with_ecs.insert(with_ecs.end(),{0,1,0,1,0,0,0,60,0,4,192,0,2,2});
        parsed_ecs=d::parse_response(with_ecs,0x1234,question);
        if(!parsed_ecs) return 154;
        restored=d::restore_response_ecs(client,upstream,*parsed_ecs);
        decoded=restored ? d::parse_response(*restored,client.id,question) : std::expected<d::Response,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!decoded || decoded->records.size()!=4 || decoded->records.back().name!="late") return 155;
        client.edns.reset();
        restored=d::restore_response_ecs(client,upstream,*parsed_ecs);
        decoded=restored ? d::parse_response(*restored,client.id,question) : std::expected<d::Response,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!decoded || decoded->edns || decoded->records.size()!=3 || decoded->records.back().name!="late") return 156;
        auto extended=with_ecs;
        extended[2] |= 0x04;extended[3] |= 0x20;
        auto opt=std::ranges::find(parsed_ecs->records,std::uint16_t{41},&d::Record::type);
        if(opt==parsed_ecs->records.end())return 157;
        auto opt_ttl=opt->ttl;auto mutated=*parsed_ecs;
        auto expected_rewrite=d::encode_response(*parsed_ecs,0x3456,7);
        if(!expected_rewrite || !d::rewrite_response(mutated,0x3456,7) || mutated.wire!=*expected_rewrite)return 218;
        auto mutated_opt=std::ranges::find(mutated.records,std::uint16_t{41},&d::Record::type);
        if(mutated_opt==mutated.records.end() || mutated_opt->ttl!=opt_ttl || mutated.records.front().ttl!=7)return 219;
        extended[opt->data_offset-6]=1;
        parsed_ecs=d::parse_response(extended,0x1234,question);
        if(!parsed_ecs || parsed_ecs->rcode<=15)return 158;
        restored=d::restore_response_ecs(client,upstream,*parsed_ecs);
        decoded=restored ? d::parse_response(*restored,client.id,question) : std::expected<d::Response,d::MessageError>(std::unexpected(d::MessageError::malformed));
        if(!decoded || decoded->rcode!=2 || decoded->edns || !decoded->records.empty() || (decoded->flags&0x0420)) return 159;
    }
    {
        d::ResponseCondition condition;condition.record_type=1;condition.record_ttl_min=60;condition.record_ttl_max=60;
        if (d::match_response(condition,&*parsed)!=d::ResponseTruth::yes) return 110;
        auto aged=*parsed;if (!d::age_response(aged,1,0x1234)) return 111;
        auto aged_wire=parsed->wire;
        if(!d::age_response_wire(*parsed,aged_wire,1,0x1234) || aged_wire!=aged.wire || parsed->records[0].ttl!=60) return 161;
        auto capped=parsed->wire;
        if(!d::age_response_wire(*parsed,capped,1,0xabcd,3))return 162;
        auto capped_response=d::parse_response(capped,0xabcd,question);
        if(!capped_response || capped_response->records[0].ttl!=3 || parsed->wire!=response)return 163;
        auto invalid=*parsed;invalid.records[0].ttl=59;auto unchanged=invalid.wire;
        if(d::age_response_wire(invalid,invalid.wire,1,0xabcd) || invalid.wire!=unchanged) return 164;
        if (d::match_response(condition,&aged)!=d::ResponseTruth::no) return 112;
        condition.record_ttl_min=59;condition.record_ttl_max=59;
        if (d::match_response(condition,&aged)!=d::ResponseTruth::yes) return 113;
        condition.record_ttl_min=60;
        if (d::match_response(condition,&aged)!=d::ResponseTruth::unknown) return 114;
        condition.record_ttl_min=0;condition.record_ttl_max=0;condition.record_type=41;
        auto opt=aged;opt.records[0].type=41;opt.records[0].ttl=0;
        if (d::match_response(condition,&opt)!=d::ResponseTruth::no) return 115;
    }
    {
        auto rewritten=d::encode_response(*parsed,0xbeef,42);
        if(!rewritten || (*rewritten)[0]!=0xbe || (*rewritten)[1]!=0xef || parsed->wire!=response || parsed->records[0].ttl!=60) return 131;
        auto decoded=d::parse_response(*rewritten,0xbeef,question);
        if(!decoded || decoded->records[0].ttl!=42) return 132;
        auto malformed=*parsed;malformed.records[0].ttl=59;
        if(d::encode_response(malformed,1,42)) return 133;
        auto owned=*parsed;auto* storage=owned.wire.data();
        if(!d::rewrite_response(owned,0xbeef,42) || owned.wire!=*rewritten || owned.wire.data()!=storage || owned.records[0].ttl!=42)return 215;
        auto before=malformed.wire;
        if(d::rewrite_response(malformed,1,42) || malformed.wire!=before || malformed.records[0].ttl!=59)return 216;
        if(!d::rewrite_response(owned,0x1234,{}) || owned.records[0].ttl!=42 || owned.wire[0]!=0x12 || owned.wire[1]!=0x34)return 217;
    }
    for (std::size_t i=0;i<response.size();++i)
        if (d::parse_response(std::span(response).first(i),0x1234,question)) return 3;
    if (d::parse_response(response,0x1235,question)) return 4;
    auto bad=response; bad[2]|=2;
    auto truncated=d::parse_response(bad,0x1234,question);
    if (truncated || truncated.error()!=d::MessageError::truncated) return 5;
    bad=response; bad[12]='\x03'; bad[13]='x';
    if (d::parse_response(bad,0x1234,question)) return 6;
    bad=response; bad[query->size()]=0xc0; bad[query->size()+1]=static_cast<std::uint8_t>(query->size());
    if (d::parse_response(bad,0x1234,question)) return 7;
    bad=response; bad[7]=129;
    auto limit=d::parse_response(bad,0x1234,question);
    if (limit || limit.error()!=d::MessageError::limit) return 8;
    if (d::make_query(0,{"a..b",1}) || d::make_query(0,{std::string(64,'a'),1})) return 9;
    bad=response; bad.push_back(0);
    if (d::parse_response(bad,0x1234,question)) return 10;
    bad=response; bad[13]='W';
    if (!d::parse_response(bad,0x1234,question)) return 11;
    bad=response; bad[query->size()+1]=0xff;
    if (d::parse_response(bad,0x1234,question)) return 12;
    bad=response; bad[query->size()]=0x40;
    if (d::parse_response(bad,0x1234,question)) return 13;
    bad=response; bad[3]=0x83; bad[7]=0; bad.resize(query->size());
    auto negative=d::parse_response(bad,0x1234,question);
    if (!negative || negative->rcode!=3 || !negative->records.empty()) return 14;
    bad=response; bad[7]=0; bad[9]=1;
    auto authority=d::parse_response(bad,0x1234,question);
    if (!authority || authority->records[0].section!=d::Section::authority) return 15;
    bad=response; bad[query->size()+10]=0; bad[query->size()+11]=5;
    if (d::parse_response(bad,0x1234,question)) return 16;
    auto root=d::make_query(9,{".",28});
    if (!root || root->size()!=17 || (*root)[12]!=0) return 17;
    d::Question other=question; other.type=28;
    if (d::parse_response(response,0x1234,other)) return 18;
    bad=response; bad.resize(query->size());
    bad.insert(bad.end(), {1,'a',0xc0,static_cast<std::uint8_t>(query->size())});
    bad.insert(bad.end(), answer.begin()+2, answer.end());
    if (d::parse_response(bad,0x1234,question)) return 19;
    bad=response; bad.resize(65536);
    auto oversized=d::parse_response(bad,0x1234,question);
    if (oversized || oversized.error()!=d::MessageError::limit) return 20;
    auto addresses=d::parse_addresses(response,0x1234,question);
    if (!addresses || addresses->addresses.size()!=1 || addresses->addresses[0].size!=4 ||
        addresses->addresses[0].bytes[0]!=127 || addresses->ttl!=60) return 21;
    bad=*query; bad[2]=0x81; bad[3]=0x80; bad[7]=2;
    d::Bytes alias{0xc0,0x0c,0,5,0,1,0,0,0,30,0,2,0xc0,0x10};
    d::Bytes terminal{0xc0,0x10,0,1,0,1,0,0,0,60,0,4,192,0,2,1};
    bad.insert(bad.end(),alias.begin(),alias.end());
    bad.insert(bad.end(),terminal.begin(),terminal.end());
    auto chained=d::parse_addresses(bad,0x1234,question);
    if (!chained || chained->canonical_name!="example.com" || chained->ttl!=30 ||
        chained->addresses.size()!=1 || chained->addresses[0].bytes[0]!=192) return 22;
    auto loop=bad; loop[query->size()+13]=0x0c;
    auto loop_result=d::parse_addresses(loop,0x1234,question);
    if (loop_result || loop_result.error()!=d::MessageError::alias_loop) return 23;
    auto conflict=bad; conflict[query->size()+alias.size()+1]=0x0c;
    if (d::parse_addresses(conflict,0x1234,question)) return 24;
    auto cross_family=*query; cross_family[2]=0x81; cross_family[3]=0x80; cross_family[7]=2;
    cross_family.insert(cross_family.end(),alias.begin(),alias.end());
    cross_family.insert(cross_family.end(),{0xc0,0x0c,0,28,0,1,0,0,0,60,0,16,
                                            0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1});
    if (!d::parse_response(cross_family,0x1234,question)) return 46;
    auto cross_result=d::parse_addresses(cross_family,0x1234,question);
    if (cross_result || cross_result.error()!=d::MessageError::malformed) return 42;
    cross_family[query->size()+alias.size()+1]=0x10;
    cross_result=d::parse_addresses(cross_family,0x1234,question);
    if (!cross_result || cross_result->canonical_name!="example.com") return 43;
    auto short_alias=bad; short_alias[query->size()+11]=1;
    if (d::parse_addresses(short_alias,0x1234,question)) return 25;
    auto unrelated=bad; unrelated[query->size()+alias.size()+1]=0x0c;
    unrelated.erase(unrelated.begin()+query->size(), unrelated.begin()+query->size()+alias.size());
    unrelated[7]=1;
    // Changing the owner to example.com excludes it from a query for www.example.com.
    unrelated[query->size()+1]=0x10;
    auto no_data=d::parse_addresses(unrelated,0x1234,question);
    if (!no_data || !no_data->addresses.empty() || no_data->ttl) return 26;
    auto nxdomain=response; nxdomain[3]=0x83;
    auto unsupported=d::parse_addresses(nxdomain,0x1234,question);
    if (unsupported || unsupported.error()!=d::MessageError::unsupported) return 27;
    auto wrong_length=response; wrong_length[query->size()+11]=3; wrong_length.pop_back();
    if (d::parse_addresses(wrong_length,0x1234,question)) return 28;
    d::Question q6{"example.com",28};
    auto q6wire=d::make_query(42,q6);
    if (!q6wire) return 29;
    auto v6=*q6wire; v6[2]=0x81; v6[3]=0x80; v6[7]=1;
    d::Bytes aaaa{0xc0,0x0c,0,28,0,1,0,0,0,0,0,16,0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    v6.insert(v6.end(),aaaa.begin(),aaaa.end());
    auto parsed6=d::parse_addresses(v6,42,q6);
    if (!parsed6 || parsed6->addresses.size()!=1 || parsed6->addresses[0].size!=16 ||
        parsed6->addresses[0].bytes[15]!=1 || parsed6->ttl!=0) return 30;
    auto reverse_family=*q6wire; reverse_family[2]=0x81; reverse_family[3]=0x80; reverse_family[7]=2;
    reverse_family.insert(reverse_family.end(),alias.begin(),alias.end());
    reverse_family[q6wire->size()+13]=0x0c;
    reverse_family.insert(reverse_family.end(),answer.begin(),answer.end());
    if (!d::parse_response(reverse_family,42,q6)) return 45;
    auto reverse_result=d::parse_addresses(reverse_family,42,q6);
    if (reverse_result || reverse_result.error()!=d::MessageError::malformed) return 44;
    auto opt=response; opt[11]=1;
    opt.insert(opt.end(),{0,0,41,0x10,0,1,0,0,0,0,0});
    auto opt_result=d::parse_addresses(opt,0x1234,question);
    if (opt_result || opt_result.error()!=d::MessageError::unsupported) return 31;
    auto edns=d::parse_response(opt,0x1234,question);
    if (!edns || !edns->edns || edns->rcode!=16 || edns->edns->udp_payload_size!=4096 ||
        edns->edns->version!=0 || edns->edns->flags!=0 || edns->edns->option_count!=0) return 47;
    auto opt_offset=response.size();
    auto noerror_opt=opt; noerror_opt[opt_offset+5]=0;
    if (!d::parse_addresses(noerror_opt,0x1234,question,true) || d::parse_addresses(noerror_opt,0x1234,question)) return 57;
    auto extended=opt; extended[3]=0x8f; extended[opt_offset+5]=0xff; extended[opt_offset+6]=2; extended[opt_offset+7]=0x80;
    auto extended_result=d::parse_response(extended,0x1234,question);
    if (!extended_result || extended_result->rcode!=4095 || !extended_result->edns ||
        extended_result->edns->version!=2 || extended_result->edns->flags!=0x8000) return 55;
    auto options=opt; options[opt_offset+9]=0; options[opt_offset+10]=7;
    options.insert(options.end(),{0,15,0,3,0,1,2});
    auto option_result=d::parse_response(options,0x1234,question);
    if (!option_result || !option_result->edns || option_result->edns->option_count!=1) return 48;
    options[opt_offset+5]=0;
    if (d::parse_addresses(options,0x1234,question,true)) return 58;
    for (std::size_t i=opt_offset;i<options.size();++i)
        if (d::parse_response(std::span(options).first(i),0x1234,question)) return 56;
    auto malformed_option=options; malformed_option[opt_offset+14]=4;
    if (d::parse_response(malformed_option,0x1234,question)) return 49;
    malformed_option=opt; malformed_option[opt_offset+10]=2; malformed_option.insert(malformed_option.end(),{0,1});
    if (d::parse_response(malformed_option,0x1234,question)) return 50;
    auto duplicate=opt; duplicate[11]=2;
    duplicate.insert(duplicate.end(),opt.begin()+opt_offset,opt.end());
    if (d::parse_response(duplicate,0x1234,question)) return 51;
    auto misplaced=opt; misplaced[11]=0; misplaced[7]=2;
    if (d::parse_response(misplaced,0x1234,question)) return 52;
    auto bad_owner=opt; bad_owner[opt_offset]=0xc0;
    if (d::parse_response(bad_owner,0x1234,question)) return 53;
    auto rrset=response; rrset[7]=2;
    auto second=answer; second[9]=10; second[12]=198; second[13]=51; second[14]=100; second[15]=2;
    rrset.insert(rrset.end(),second.begin(),second.end());
    auto rrset_result=d::parse_addresses(rrset,0x1234,question);
    if (!rrset_result || rrset_result->addresses.size()!=2 || rrset_result->ttl!=10) return 32;
    auto alias_only=bad; alias_only.resize(query->size()+alias.size()); alias_only[7]=1;
    auto pending=d::parse_addresses(alias_only,0x1234,question);
    if (!pending || !pending->addresses.empty() || pending->canonical_name!="example.com" || pending->ttl!=30) return 33;
    // Header byte 4 is zero, which looks like a root name but is not a name boundary.
    auto forged=response; forged[query->size()+1]=4;
    if (d::parse_response(forged,0x1234,question)) return 34;
    // Compressed owner may reuse a prior compressed owner boundary.
    auto pointer_chain=rrset;
    pointer_chain[response.size()+1]=static_cast<std::uint8_t>(query->size());
    if (!d::parse_addresses(pointer_chain,0x1234,question)) return 35;
    {
        // The last 14-bit offset remains a valid target, even when the
        // message extends beyond the addressable compression range.
        auto boundary=*query;boundary[2]=0x81;boundary[3]=0x80;boundary[7]=3;
        auto padding=std::size_t{16383}-boundary.size()-12;
        boundary.insert(boundary.end(),{0xc0,0x0c,0xfd,0xe8,0,1,0,0,0,1,
            static_cast<std::uint8_t>(padding>>8),static_cast<std::uint8_t>(padding)});
        boundary.resize(boundary.size()+padding,0);
        if(boundary.size()!=16383)return 202;
        boundary.insert(boundary.end(),{1,'x',0,0,1,0,1,0,0,0,1,0,4,127,0,0,1});
        boundary.insert(boundary.end(),{0xff,0xff,0,1,0,1,0,0,0,1,0,4,127,0,0,2});
        auto parsed_boundary=d::parse_response(boundary,0x1234,question);
        if(!parsed_boundary || parsed_boundary->records.size()!=3 || parsed_boundary->records.back().name!="x")return 203;
        // Offset 16382 lies in opaque RDATA, not a validated boundary.
        boundary[boundary.size()-15]=0xfe;
        if(d::parse_response(boundary,0x1234,question))return 204;
    }
    // A later owner may point to an earlier validated CNAME RDATA name.
    auto cname_wire=*query; cname_wire[2]=0x81; cname_wire[3]=0x80; cname_wire[7]=2;
    d::Bytes named_alias{0xc0,0x0c,0,5,0,1,0,0,0,10,0,8,5,'a','l','i','a','s',0xc0,0x10};
    auto alias_name_offset=cname_wire.size()+12;
    cname_wire.insert(cname_wire.end(),named_alias.begin(),named_alias.end());
    auto next=answer; next[1]=static_cast<std::uint8_t>(alias_name_offset);
    cname_wire.insert(cname_wire.end(),next.begin(),next.end());
    auto valid_chain=d::parse_addresses(cname_wire,0x1234,question);
    if (!valid_chain || valid_chain->canonical_name!="alias.example.com" ||
        valid_chain->addresses.size()!=1 || valid_chain->ttl!=10) return 36;
    auto contradictory=cname_wire; contradictory[3]=0x83;
    if (d::parse_nxdomain_alias(contradictory,0x1234,question)) return 62;
    auto negative_alias=*query; negative_alias[2]=0x81; negative_alias[3]=0x83; negative_alias[7]=1;
    negative_alias.insert(negative_alias.end(),named_alias.begin(),named_alias.end());
    auto negative_chain=d::parse_nxdomain_alias(negative_alias,0x1234,question);
    if (!negative_chain || negative_chain->canonical_name!="alias.example.com" || negative_chain->ttl!=10 ||
        d::parse_addresses(negative_alias,0x1234,question)) return 63;
    auto unrelated_negative=negative_alias; unrelated_negative[7]=2;
    auto unrelated_alias=named_alias; unrelated_alias[1]=0x10;
    unrelated_negative.insert(unrelated_negative.end(),unrelated_alias.begin(),unrelated_alias.end());
    if (d::parse_nxdomain_alias(unrelated_negative,0x1234,question)) return 64;
    // A pointer into a record's binary RDATA is never a known name boundary.
    auto payload_pointer=rrset; payload_pointer[response.size()+1]=static_cast<std::uint8_t>(query->size()+13);
    if (d::parse_response(payload_pointer,0x1234,question)) return 37;
    // NS RDATA name becomes a legal compression target for an additional RR.
    auto ns=*query; ns[2]=0x81; ns[3]=0x80; ns[9]=1; ns[11]=1;
    d::Bytes ns_record{0xc0,0x10,0,2,0,1,0,0,0,60,0,6,3,'n','s','1',0xc0,0x10};
    auto ns_offset=ns.size()+12;
    ns.insert(ns.end(),ns_record.begin(),ns_record.end());
    auto glue=answer; glue[1]=static_cast<std::uint8_t>(ns_offset);
    ns.insert(ns.end(),glue.begin(),glue.end());
    auto ns_parsed=d::parse_response(ns,0x1234,question);
    if (!ns_parsed || ns_parsed->records[1].name!="ns1.example.com") return 38;
    // MX and SOA validate their fixed fields and compressed name framing.
    auto mx=*query; mx[2]=0x81; mx[3]=0x80; mx[7]=1;
    mx.insert(mx.end(),{0xc0,0x0c,0,15,0,1,0,0,0,5,0,4,0,10,0xc0,0x10});
    if (!d::parse_response(mx,0x1234,question)) return 39;
    auto soa=*query; soa[2]=0x81; soa[3]=0x80; soa[9]=1;
    soa.insert(soa.end(),{0xc0,0x10,0,6,0,1,0,0,0,5,0,24,0xc0,0x10,0xc0,0x10});
    soa.insert(soa.end(),20,0);
    soa.back()=3;
    auto parsed_soa=d::parse_response(soa,0x1234,question);
    if (!parsed_soa || d::negative_ttl(*parsed_soa,"WWW.Example.com.")!=3 ||
        d::negative_ttl(*parsed_soa,"badexample.com") || d::negative_ttl(*parsed_soa,"invalid..name")) return 40;
    soa.back()=9;
    parsed_soa=d::parse_response(soa,0x1234,question);
    if (!parsed_soa || d::negative_ttl(*parsed_soa,"example.com")!=5) return 57;
    soa.back()=0;
    parsed_soa=d::parse_response(soa,0x1234,question);
    if (!parsed_soa || d::negative_ttl(*parsed_soa,"example.com")!=0) return 58;
    auto scoped=*parsed_soa;
    auto deeper=scoped.records[0]; deeper.name="www.example.com"; deeper.ttl=2;
    scoped.records.push_back(deeper);
    if (d::negative_ttl(scoped,"www.example.com")!=0) return 60;
    scoped.wire.back()=8;
    if (d::negative_ttl(scoped,"www.example.com")!=2 || d::negative_ttl(scoped,"example.com")!=5) return 61;
    auto unrelated_soa=*parsed_soa;
    unrelated_soa.records[0].section=d::Section::additional;
    if (d::negative_ttl(unrelated_soa,"example.com")) return 59;
    soa.pop_back(); soa[query->size()+11]=23;
    if (d::parse_response(soa,0x1234,question)) return 41;
    std::println("DNS query and bounded response framing passed");
}
