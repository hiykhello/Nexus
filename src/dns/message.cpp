module dns.message;
import std;

#include "message_wire.hpp"

namespace dns {
    using namespace message_wire;
    namespace {
        constexpr std::uint16_t query_flags=0x0100 | checking_disabled_flag | authenticated_data_flag;
        // A QUERY has exactly one question and no earlier name boundary to
        // which its first name can legally refer. Parse it without allocating
        // the full-message compression table used for response records.
        auto question_name(std::span<std::uint8_t const> data,std::size_t& position)
            -> std::expected<std::string,MessageError> {
            std::array<char,253> name{};
            std::size_t used=0,wire_size=1;
            for(;;) {
                if(position>=data.size())return std::unexpected(MessageError::malformed);
                auto size=data[position++];
                if(size&0xc0)return std::unexpected(MessageError::malformed);
                if(!size)return used ? std::string(name.data(),used) : std::string(".");
                if(size>data.size()-position || (wire_size+=size+1)>255)return std::unexpected(MessageError::malformed);
                if(used)name[used++]='.';
                for(std::size_t i=0;i<size;++i) {
                    auto character=data[position++];
                    if(!valid_char(character))return std::unexpected(MessageError::invalid_name);
                    name[used++]=static_cast<char>(lower(character));
                }
            }
        }
    }
    auto canonicalize_name(std::string& name) -> bool {
        if (!visit_labels(name,[](std::string_view) {})) return false;
        if (name!="." && name.ends_with('.')) name.pop_back();
        for (auto& character:name) character=static_cast<char>(lower(static_cast<std::uint8_t>(character)));
        return true;
    }
    auto query_client_subnet(QueryEdns const& edns) -> std::expected<std::optional<ClientSubnet>,MessageError> {
        std::optional<ClientSubnet> result;
        for(auto const& option:edns.options) {
            if(option.code!=8) continue;
            if(result || option.data.size()<4) return std::unexpected(MessageError::malformed);
            auto data=std::span(option.data);auto family=get16(data,0);auto bits=data[2];
            auto maximum=family==1 ? 32u : family==2 ? 128u : 0u;
            if(!maximum) return std::unexpected(MessageError::unsupported);
            auto bytes=(static_cast<std::size_t>(bits)+7)/8;
            if(bits>maximum || data[3]!=0 || data.size()!=4+bytes) return std::unexpected(MessageError::malformed);
            if(bits%8 && (data.back() & ((1u<<(8-bits%8))-1u))) return std::unexpected(MessageError::malformed);
            ClientSubnet subnet{family,bits,{}};std::copy(data.begin()+4,data.end(),subnet.address.begin());result=subnet;
        }
        return result;
    }
    auto set_query_client_subnet(QueryMessage& query,std::optional<ClientSubnet> subnet) -> std::expected<void,MessageError> {
        if(query.edns && !query_client_subnet(*query.edns))return std::unexpected(MessageError::malformed);
        Bytes data;
        if(subnet) {
            if(!valid_client_subnet(*subnet))return std::unexpected(MessageError::malformed);
            auto bytes=(std::size_t(subnet->prefix)+7)/8;
            put16(data,subnet->family);data.push_back(subnet->prefix);data.push_back(0);
            data.insert(data.end(),subnet->address.begin(),subnet->address.begin()+bytes);
        }
        if(!query.edns) {
            if(!subnet)return {};
            query.edns=QueryEdns{1232,0,false,{}};
        }
        auto& options=query.edns->options;
        auto found=std::ranges::find(options,std::uint16_t{8},&QueryOption::code);
        if(found!=options.end()) {
            if(subnet)found->data=std::move(data);else options.erase(found);
        } else if(subnet) {
            if(options.size()>=128)return std::unexpected(MessageError::limit);
            options.push_back({8,std::move(data)});
        }
        return {};
    }
    auto listener_query_cost(QueryMessage const& query) noexcept -> std::optional<std::size_t> {
        auto total=sizeof(QueryMessage);
        auto add=[&](std::size_t amount) noexcept {
            if(amount>std::numeric_limits<std::size_t>::max()-total)return false;
            total+=amount;return true;
        };
        if(!add(query.question.name.capacity()) || !add(1))return {};
        if(query.edns) {
            auto const& options=query.edns->options;
            if(options.capacity()>std::numeric_limits<std::size_t>::max()/sizeof(QueryOption) ||
               !add(options.capacity()*sizeof(QueryOption)))return {};
            for(auto const& option:options)if(!add(option.data.capacity()))return {};
        }
        return total;
    }
    auto parse_query(std::span<std::uint8_t const> data) -> std::expected<QueryMessage,MessageError> {
        if(data.size()<12 || data.size()>65535) return std::unexpected(MessageError::malformed);
        auto flags=get16(data,2);
        if((flags & ~query_flags)!=0 || get16(data,4)!=1 || get16(data,6) || get16(data,8) || get16(data,10)>1)
            return std::unexpected(MessageError::unsupported);
        std::size_t pos=12;
        auto name=question_name(data,pos);
        if(!name || data.size()-pos<4) return std::unexpected(MessageError::malformed);
        auto type=get16(data,pos),klass=get16(data,pos+2);pos+=4;
        if(!type || !klass) return std::unexpected(MessageError::malformed);
        QueryMessage result{get16(data,0),flags,Question{std::move(*name),type,klass},{}};
        if(get16(data,10)) {
            if(data.size()-pos<11 || data[pos]!=0 || get16(data,pos+1)!=41) return std::unexpected(MessageError::malformed);
            auto payload=get16(data,pos+3);auto ttl=get32(data,pos+5);auto size=get16(data,pos+9);pos+=11;
            if(size!=data.size()-pos || (ttl>>24) || (ttl&0x7fff)) return std::unexpected(MessageError::malformed);
            QueryEdns edns{payload,static_cast<std::uint8_t>(ttl>>16),bool(ttl&0x8000),{}};
            while(pos<data.size()) {
                if(data.size()-pos<4 || edns.options.size()>=128) return std::unexpected(MessageError::limit);
                auto code=get16(data,pos),length=get16(data,pos+2);pos+=4;
                if(length>data.size()-pos) return std::unexpected(MessageError::malformed);
                edns.options.push_back({code,Bytes(data.begin()+pos,data.begin()+pos+length)});pos+=length;
            }
            result.edns=std::move(edns);
        }
        if(pos!=data.size()) return std::unexpected(MessageError::malformed);
        return result;
    }
    auto query_error_response(std::span<std::uint8_t const> message) -> std::optional<Bytes> {
        if(message.size()<12 || (get16(message,2)&0x8000))return {};
        auto flags=get16(message,2);
        auto rcode=(flags&0x7800) ? 4u : 1u; // Unknown opcode: NOTIMP; otherwise FORMERR.
        auto reply_flags=static_cast<std::uint16_t>(0x8080u | (flags&0x7910u) | rcode);
        Bytes reply;reply.reserve(12);put16(reply,get16(message,0));put16(reply,reply_flags);
        for(unsigned i=0;i<4;++i)put16(reply,0);
        return reply;
    }
    auto encode_query(QueryMessage const& query) -> std::expected<Bytes,MessageError> {
        if((query.flags & ~query_flags)!=0 || !query.question.type || !query.question.klass) return std::unexpected(MessageError::unsupported);
        auto name=encode_name(query.question.name);if(!name)return std::unexpected(name.error());
        Bytes wire;wire.reserve(16+name->size());put16(wire,query.id);put16(wire,query.flags);put16(wire,1);
        put16(wire,0);put16(wire,0);put16(wire,query.edns ? 1 : 0);
        wire.insert(wire.end(),name->begin(),name->end());put16(wire,query.question.type);put16(wire,query.question.klass);
        if(query.edns) {
            if(query.edns->options.size()>128) return std::unexpected(MessageError::limit);
            std::size_t length=0;
            for(auto const& option:query.edns->options) {
                if(option.data.size()>65535 || length+4+option.data.size()>65535) return std::unexpected(MessageError::limit);
                length+=4+option.data.size();
            }
            if(wire.size()+11+length>65535) return std::unexpected(MessageError::limit);
            wire.push_back(0);put16(wire,41);put16(wire,query.edns->udp_payload_size);
            put16(wire,query.edns->version);put16(wire,query.edns->dnssec_ok ? 0x8000 : 0);put16(wire,static_cast<std::uint16_t>(length));
            for(auto const& option:query.edns->options) {put16(wire,option.code);put16(wire,static_cast<std::uint16_t>(option.data.size()));wire.insert(wire.end(),option.data.begin(),option.data.end());}
        }
        return wire;
    }
    auto make_query(std::uint16_t id, Question const& question) -> std::expected<Bytes, MessageError> {
        auto name = encode_name(question.name);
        if (!name) return std::unexpected(name.error());
        Bytes out; out.reserve(16 + name->size());
        put16(out, id); put16(out, 0x0100); put16(out, 1);
        put16(out, 0); put16(out, 0); put16(out, 0);
        out.insert(out.end(), name->begin(), name->end());
        put16(out, question.type); put16(out, question.klass);
        return out;
    }
    auto make_edns_query(std::uint16_t id, Question const& question, std::uint16_t payload)
        -> std::expected<Bytes, MessageError> {
        if (payload<512 || payload>4096) return std::unexpected(MessageError::limit);
        auto message=make_query(id,question);
        if (!message) return std::unexpected(message.error());
        (*message)[11]=1;
        message->push_back(0);
        put16(*message,41);
        put16(*message,payload);
        message->insert(message->end(),6,0);
        return message;
    }
}
