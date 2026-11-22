export module snell.packet;
import std;
import snell.record;
export namespace snell {
    enum class AddressKind { domain,ipv4,ipv6 };
    struct Address { AddressKind kind; Bytes value; std::uint16_t port; };
    struct Packet { Address address; Bytes payload; };
    [[nodiscard]] auto encode_packet(Packet const& p,bool request) -> std::expected<Bytes,Error> {
        if(!p.address.port)return std::unexpected(Error::invalid_request);
        auto n=p.address.value.size();
        if((p.address.kind==AddressKind::domain && (!request || !n || n>255)) ||
           (p.address.kind==AddressKind::ipv4 && n!=4) || (p.address.kind==AddressKind::ipv6 && n!=16)) return std::unexpected(Error::invalid_request);
        Bytes out;if(request)out.push_back(1);
        if(p.address.kind==AddressKind::domain)out.push_back(n);
        else {if(request)out.push_back(0);out.push_back(p.address.kind==AddressKind::ipv4?4:6);}
        out.insert(out.end(),p.address.value.begin(),p.address.value.end());out.push_back(p.address.port>>8);out.push_back(p.address.port);
        if(p.payload.size()>max_payload-out.size())return std::unexpected(Error::invalid_length);
        out.insert(out.end(),p.payload.begin(),p.payload.end());return out;
    }
    [[nodiscard]] auto parse_packet(View input,bool request) -> std::expected<Packet,Error> {
        std::size_t p=0;if(request && (input.empty() || input[p++]!=1))return std::unexpected(Error::invalid_request);
        if(p>=input.size())return std::unexpected(Error::invalid_request);auto first=input[p++];AddressKind kind;std::size_t n;
        if(request && first) {kind=AddressKind::domain;n=first;}
        else {if(request){if(p>=input.size())return std::unexpected(Error::invalid_request);first=input[p++];}
            if(first==4){kind=AddressKind::ipv4;n=4;}else if(first==6){kind=AddressKind::ipv6;n=16;}else return std::unexpected(Error::invalid_request);}
        if(input.size()-p<n+2 || input.size()>max_payload)return std::unexpected(Error::invalid_length);
        Bytes value(input.begin()+p,input.begin()+p+n);p+=n;auto port=std::uint16_t((unsigned(input[p])<<8)|input[p+1]);p+=2;
        if(!port)return std::unexpected(Error::invalid_request);
        return Packet{Address{kind,std::move(value),port},Bytes(input.begin()+p,input.end())};
    }
}
