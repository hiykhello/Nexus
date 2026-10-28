import std;
import nexus.dns.message;
namespace d = nexus::dns;

auto main() -> int {
    d::Question question{"www.Example.com.",1};
    auto query = d::make_query(0x1234, question);
    d::Bytes expected{0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    if (!query || *query != expected) return 1;
    auto edns_query=d::make_edns_query(0x1234,question,1232);
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
    bad=response; bad.resize(4097);
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
