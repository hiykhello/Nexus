module dns.message;
import std;
import dns.message_wire;

namespace dns {
    using namespace message_wire;
    auto response_ecs_view(QueryMessage const& query) -> std::expected<ResponseEcsView,MessageError> {
        if(!query.edns)return ResponseEcsView{};
        auto subnet=query_client_subnet(*query.edns);if(!subnet)return std::unexpected(subnet.error());
        return ResponseEcsView{*subnet};
    }
    auto validate_response_ecs(QueryMessage const& query,Response const& response) -> std::expected<void,MessageError> {
        auto view=response_ecs_view(query);if(!view)return std::unexpected(view.error());
        return validate_response_ecs(*view,response);
    }
    auto validate_response_ecs(ResponseEcsView const& view,Response const& response) -> std::expected<void,MessageError> {
        auto const& requested=view.subnet;
        bool seen=false;
        for(auto const& record:response.records) {
            if(record.type!=41)continue;
            if(record.data_offset>response.wire.size() || record.data_length>response.wire.size()-record.data_offset)return std::unexpected(MessageError::malformed);
            auto options=std::span(response.wire).subspan(record.data_offset,record.data_length);
            for(std::size_t pos=0;pos<options.size();) {
                if(options.size()-pos<4)return std::unexpected(MessageError::malformed);
                auto code=get16(options,pos),length=get16(options,pos+2);pos+=4;
                if(length>options.size()-pos)return std::unexpected(MessageError::malformed);
                auto data=options.subspan(pos,length);pos+=length;
                if(code!=8)continue;
                if(seen || !requested || data.size()<4)return std::unexpected(MessageError::mismatch);
                seen=true;
                auto family=get16(data,0);auto source=data[2],scope=data[3];
                auto maximum=family==1 ? 32u : family==2 ? 128u : 0u;
                auto bytes=(static_cast<std::size_t>(source)+7)/8;
                if(!maximum || source>maximum || scope>maximum || data.size()!=4+bytes ||
                   (source%8 && (data.back() & ((1u<<(8-source%8))-1u))))return std::unexpected(MessageError::malformed);
                if(family!=requested->family || source!=requested->prefix || !std::equal(data.begin()+4,data.end(),requested->address.begin()))return std::unexpected(MessageError::mismatch);
            }
        }
        return {};
    }
    namespace {
    auto rebase_ecs_edit(Response const& response,Bytes& output,std::size_t start_edit,std::size_t removed,std::size_t added) -> std::expected<void,MessageError> {
        auto end_edit=start_edit+removed;
        // Record owners and the name-bearing RDATA understood by the
        // parser have known pointer locations. Rebase those pointers;
        // retain the conservative scan for opaque RDATA.
        auto name=[&](std::size_t& pos,std::size_t limit) -> bool {
            while(pos<limit) {
                auto size=response.wire[pos];
                if((size&0xc0)==0xc0) {
                    if(pos+1>=limit)return false;
                    auto target=(std::size_t(size&0x3f)<<8)|response.wire[pos+1];
                    if(pos>=end_edit && target>=start_edit) {
                        if(target<end_edit)return false;
                        target=target-removed+added;if(target>=16384)return false;
                        output[pos]=static_cast<std::uint8_t>(0xc0|(target>>8));output[pos+1]=static_cast<std::uint8_t>(target);
                    }
                    pos+=2;return true;
                }
                if(size&0xc0 || pos+1+size>limit)return false;
                pos+=1+size;if(!size)return true;
            }
            return false;
        };
        std::size_t cursor=12;
        if(!name(cursor,response.wire.size()) || cursor+4>response.wire.size())return std::unexpected(MessageError::malformed);
        cursor+=4;
        for(auto const& record:response.records) {
            auto owner=cursor;
            if(!name(owner,record.data_offset-10) || owner!=record.data_offset-10)return std::unexpected(MessageError::malformed);
            cursor=record.data_offset+record.data_length;
            if(record.data_offset<end_edit)continue;
            auto pos=record.data_offset,end=cursor;
            if(record.type==2 || record.type==3 || record.type==4 || record.type==5 || record.type==7 || record.type==8 || record.type==9 || record.type==12 || record.type==14 || record.type==15 || record.type==17 || record.type==18 || record.type==21 || record.type==26 || record.type==36 || record.type==39 || record.type==6 || record.type==33 || (record.type==1 && record.klass==3)) {
                if(record.type==15 || record.type==18 || record.type==21 || record.type==26 || record.type==36)pos+=2;
                if(record.type==33)pos+=6;
                if(!name(pos,end) || ((record.type==6 || record.type==14 || record.type==17 || record.type==26) && !name(pos,end)))return std::unexpected(MessageError::unsupported);
            } else if(record.type==35 || record.type==46 || record.type==47 || record.type==64 || record.type==65) {
                if(record.type==35) {
                    pos+=4;
                    for(unsigned i=0;i<3;++i) {
                        if(pos>=end || std::size_t(response.wire[pos])+1>end-pos)return std::unexpected(MessageError::malformed);
                        pos+=std::size_t(response.wire[pos])+1;
                    }
                } else if(record.type==46)pos+=18;
                else if(record.type==64 || record.type==65)pos+=2;
                if(!name(pos,end))return std::unexpected(MessageError::unsupported);
            } else if(record.type!=13 && record.type!=16 && record.type!=99 && record.type!=257 &&
                      (record.klass!=1 || (record.type!=1 && record.type!=28))) {
                for(;pos+1<end;++pos) {
                    if((response.wire[pos]&0xc0)!=0xc0)continue;
                    auto target=(std::size_t(response.wire[pos]&0x3f)<<8)|response.wire[pos+1];
                    if(target>=start_edit)return std::unexpected(MessageError::unsupported);
                }
            }
        }
        return {};
    }
    }
    auto complete_response_ecs(QueryMessage const& query,Response const& response) -> std::expected<Bytes,MessageError> {
        auto valid=validate_response_ecs(query,response);if(!valid)return std::unexpected(valid.error());
        auto output=copy_response_wire(response,query.id,{});if(!output)return std::unexpected(output.error());
        if(!query.edns)return output;
        auto subnet=query_client_subnet(*query.edns);if(!subnet)return std::unexpected(subnet.error());
        if(!*subnet)return output;
        auto original=std::ranges::find(query.edns->options,std::uint16_t{8},&QueryOption::code);
        auto opt=std::ranges::find(response.records,std::uint16_t{41},&Record::type);
        if(opt!=response.records.end()) {
            auto options=std::span(response.wire).subspan(opt->data_offset,opt->data_length);
            for(std::size_t pos=0;pos<options.size();) {
                auto code=get16(options,pos),length=get16(options,pos+2);pos+=4+length;
                if(code==8)return output;
            }
        }
        auto extra=std::size_t{4}+original->data.size();
        if(output->size()+extra+(opt==response.records.end() ? 11 : 0)>65535)return std::unexpected(MessageError::limit);
        if(opt==response.records.end()) {
            auto count=get16(*output,10);if(count==65535 || response.records.size()>=128)return std::unexpected(MessageError::limit);
            (*output)[10]=static_cast<std::uint8_t>((count+1)>>8);(*output)[11]=static_cast<std::uint8_t>(count+1);
            auto payload=std::clamp<std::uint16_t>(query.edns->udp_payload_size,512,4096);
            output->insert(output->end(),{0,0,41,static_cast<std::uint8_t>(payload>>8),static_cast<std::uint8_t>(payload),0,0,static_cast<std::uint8_t>(query.edns->dnssec_ok ? 0x80 : 0),0,0,0});
        } else {
            if(opt->data_length+extra>65535)return std::unexpected(MessageError::limit);
            auto insertion=opt->data_offset+opt->data_length;
            auto rebased=rebase_ecs_edit(response,*output,insertion,0,extra);
            if(!rebased)return std::unexpected(rebased.error());
        }
        auto length_offset=opt==response.records.end() ? output->size()-2 : opt->data_offset-2;
        auto length=static_cast<std::uint16_t>((opt==response.records.end() ? 0 : opt->data_length)+extra);
        (*output)[length_offset]=static_cast<std::uint8_t>(length>>8);(*output)[length_offset+1]=static_cast<std::uint8_t>(length);
        Bytes option;option.reserve(extra);put16(option,8);put16(option,static_cast<std::uint16_t>(original->data.size()));
        option.insert(option.end(),original->data.begin(),original->data.end());option[7]=0; // Global scope.
        auto insertion=opt==response.records.end() ? output->size() : opt->data_offset+opt->data_length;
        output->insert(output->begin()+insertion,option.begin(),option.end());
        return output;
    }
    auto restore_response_ecs(QueryMessage const& client,QueryMessage const& upstream,Response const& response)
        -> std::expected<Bytes,MessageError> {
        auto view=response_ecs_view(upstream);if(!view)return std::unexpected(view.error());
        return restore_response_ecs(client,*view,response);
    }
    auto restore_response_ecs(QueryMessage const& client,ResponseEcsView const& upstream,Response const& response)
        -> std::expected<Bytes,MessageError> {
        auto valid=validate_response_ecs(upstream,response);if(!valid)return std::unexpected(valid.error());
        if(!client.edns && response.edns) {
            if(response.rcode>15) {
                auto failure=encode_query(client);if(!failure)return std::unexpected(failure.error());
                // A locally generated SERVFAIL cannot inherit authoritative
                // or authenticated-data assertions from an upstream answer.
                auto flags=static_cast<std::uint16_t>((response.flags&0x8190u)|2u);
                (*failure)[2]=static_cast<std::uint8_t>(flags>>8);(*failure)[3]=static_cast<std::uint8_t>(flags);
                return failure;
            }
            auto opt=std::ranges::find(response.records,std::uint16_t{41},&Record::type);
            if(opt==response.records.end() || opt->data_offset<11 || !get16(response.wire,10))return std::unexpected(MessageError::malformed);
            auto output=copy_response_wire(response,client.id,{});if(!output)return std::unexpected(output.error());
            auto start=opt->data_offset-11, size=opt->data_length+11;
            auto rebased=rebase_ecs_edit(response,*output,start,size,0);
            if(!rebased)return std::unexpected(rebased.error());
            auto count=get16(*output,10)-1;
            (*output)[10]=static_cast<std::uint8_t>(count>>8);(*output)[11]=static_cast<std::uint8_t>(count);
            output->erase(output->begin()+start,output->begin()+start+size);
            if(!parse_response(*output,client.id,client.question))return std::unexpected(MessageError::malformed);
            return output;
        }
        auto requested=[](QueryMessage const& query) -> std::expected<std::optional<ClientSubnet>,MessageError> {
            return query.edns ? query_client_subnet(*query.edns) : std::expected<std::optional<ClientSubnet>,MessageError>{std::nullopt};
        };
        auto original=requested(client);
        if(!original)return std::unexpected(MessageError::malformed);
        if(*original==upstream.subnet)return complete_response_ecs(client,response);
        auto output=copy_response_wire(response,client.id,{});if(!output)return std::unexpected(output.error());
        auto opt=std::ranges::find(response.records,std::uint16_t{41},&Record::type);
        if(opt!=response.records.end()) {
            auto end=opt->data_offset+opt->data_length;
            for(auto pos=opt->data_offset;pos<end;) {
                auto code=get16(response.wire,pos);auto size=std::size_t(get16(response.wire,pos+2))+4;
                if(code==8) {
                    auto rebased=rebase_ecs_edit(response,*output,pos,size,0);
                    if(!rebased)return std::unexpected(rebased.error());
                    auto remaining=opt->data_length-size;
                    (*output)[opt->data_offset-2]=static_cast<std::uint8_t>(remaining>>8);
                    (*output)[opt->data_offset-1]=static_cast<std::uint8_t>(remaining);
                    output->erase(output->begin()+pos,output->begin()+pos+size);
                    break;
                }
                pos+=size;
            }
        }
        auto parsed=parse_response(*output,client.id,client.question);
        if(!parsed)return std::unexpected(parsed.error());
        auto restored=complete_response_ecs(client,*parsed);
        if(!restored || !*original)return restored;
        // The upstream answered a different subnet (or no subnet), so its
        // scope cannot describe the original client's address. Restrict
        // downstream reuse to the client's entire requested prefix.
        auto final=parse_response(*restored,client.id,client.question);
        if(!final)return std::unexpected(final.error());
        auto final_opt=std::ranges::find(final->records,std::uint16_t{41},&Record::type);
        if(final_opt==final->records.end())return std::unexpected(MessageError::malformed);
        auto end=final_opt->data_offset+final_opt->data_length;
        for(auto pos=final_opt->data_offset;pos<end;) {
            auto code=get16(*restored,pos);auto size=std::size_t(get16(*restored,pos+2))+4;
            if(code==8) {(*restored)[pos+7]=(**original).prefix;return restored;}
            pos+=size;
        }
        return std::unexpected(MessageError::malformed);
    }
}
