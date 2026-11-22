export module dns.predefined;
import std;
import dns.message;
import dns.policy;
import dns.corosio_resolver;

export namespace dns {
    // RDATA is supplied in uncompressed DNS wire form, including any names.
    // The resulting message is parsed by the same decoder as upstream replies.
    inline auto predefined_response(policy::PredefinedResponse const& definition,Question const& question)
        -> std::expected<Response,MessageError> {
        if (definition.rcode>15 || definition.records.size()>128) return std::unexpected(MessageError::limit);
        auto wire=make_query(0,question);
        if (!wire) return std::unexpected(wire.error());
        (*wire)[2]=0x81;(*wire)[3]=static_cast<std::uint8_t>(0x80|definition.rcode);
        auto put16=[&](std::uint16_t value) { wire->push_back(value>>8);wire->push_back(value); };
        auto put32=[&](std::uint32_t value) { put16(value>>16);put16(value); };
        for (unsigned section=0;section<3;++section) {
            std::uint16_t count=0;
            for (auto const& record:definition.records) {
                if (static_cast<unsigned>(record.section)!=section) continue;
                ++count;
                if (record.name=="@") { wire->push_back(0xc0);wire->push_back(0x0c); }
                else {
                    auto name=make_query(0,{record.name,1});
                    if (!name) return std::unexpected(name.error());
                    wire->insert(wire->end(),name->begin()+12,name->end()-4);
                }
                if (record.type==41) return std::unexpected(MessageError::unsupported);
                if (record.data.size()>65535 || wire->size()+10+record.data.size()>4096)
                    return std::unexpected(MessageError::limit);
                put16(record.type);put16(record.klass);put32(record.ttl);put16(record.data.size());
                wire->insert(wire->end(),record.data.begin(),record.data.end());
            }
            (*wire)[6+2*section]=count>>8;(*wire)[7+2*section]=count;
        }
        return parse_owned_response(std::move(*wire),0,question);
    }
    inline auto predefined_addresses(policy::PredefinedResponse const& definition,Question const& question)
        -> std::expected<AddressAnswer,detail::ResolveError> {
        using Error=detail::ResolveError;
        auto response=predefined_response(definition,question);
        if (!response) return std::unexpected(Error::protocol);
        if (response->rcode) return std::unexpected(response->rcode==3 ? Error::name_not_found :
            response->rcode==2 ? Error::server_failure : response->rcode==5 ? Error::refused : Error::protocol);
        auto answer=parse_addresses(response->wire,0,question);
        if (!answer) return std::unexpected(answer.error()==MessageError::alias_loop ? Error::alias_loop :
            answer.error()==MessageError::limit ? Error::limit : Error::protocol);
        if (answer->addresses.empty()) return std::unexpected(Error::no_data);
        return std::move(*answer);
    }
}
