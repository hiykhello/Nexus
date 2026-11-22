export module dns.message_synthetic;
import std;
import dns.message;
import dns.policy;
import dns.predefined;

export namespace dns {
    [[nodiscard]] inline auto synthetic_message(QueryMessage const& query,policy::PredefinedResponse const& definition,std::uint8_t extended_rcode=0)
        -> std::expected<Bytes,MessageError> {
        auto response=predefined_response(definition,query.question);if(!response)return std::unexpected(response.error());
        auto wire=encode_response(*response,query.id,{});if(!wire)return std::unexpected(wire.error());
        (*wire)[2]=static_cast<std::uint8_t>(((*wire)[2]&~0x01u)|((query.flags>>8)&0x01u));
        (*wire)[3]=static_cast<std::uint8_t>(((*wire)[3]&~0x10u)|(query.flags&0x10u));
        if(query.edns) {
            auto count=std::uint16_t((std::uint16_t((*wire)[10])<<8)|(*wire)[11]);
            if(count==65535 || wire->size()+11>65535)return std::unexpected(MessageError::limit);
            ++count;(*wire)[10]=static_cast<std::uint8_t>(count>>8);(*wire)[11]=static_cast<std::uint8_t>(count);
            auto payload=std::clamp<std::uint16_t>(query.edns->udp_payload_size,512,4096);
            wire->insert(wire->end(),{0,0,41,static_cast<std::uint8_t>(payload>>8),static_cast<std::uint8_t>(payload),extended_rcode,0,static_cast<std::uint8_t>(query.edns->dnssec_ok ? 0x80 : 0),0,0,0});
            if(query.edns->version==0) {
                auto subnet=query_client_subnet(*query.edns);
                if(subnet && *subnet) {
                    auto parsed=parse_response(*wire,query.id,query.question);if(!parsed)return std::unexpected(parsed.error());
                    wire=complete_response_ecs(query,*parsed);if(!wire)return std::unexpected(wire.error());
                }
            }
        }
        return wire;
    }

    [[nodiscard]] inline auto udp_response_fits(QueryMessage const& query,Bytes wire) -> std::optional<Bytes> {
        auto capacity=query.edns ? std::clamp<std::size_t>(query.edns->udp_payload_size,512,65535) : 512;
        if(wire.size()<=capacity)return wire;
        auto parsed=parse_owned_response(std::move(wire),query.id,query.question);
        if(!parsed)return std::nullopt;
        auto packed=encode_response(*parsed,query.id,{});
        if(packed && packed->size()<=capacity)return std::move(*packed);
        policy::PredefinedResponse empty;
        empty.rcode=static_cast<std::uint8_t>(!query.edns && parsed->rcode>15 ? 2 : parsed->rcode&15);
        auto truncated=synthetic_message(query,empty,query.edns ? static_cast<std::uint8_t>(parsed->rcode>>4) : 0);
        if(!truncated)return std::nullopt;
        (*truncated)[2]=static_cast<std::uint8_t>((parsed->flags>>8)|0x02);
        (*truncated)[3]=static_cast<std::uint8_t>((parsed->flags&0xf0)|empty.rcode);
        return std::move(*truncated);
    }
}
