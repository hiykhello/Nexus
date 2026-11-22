module dns.message;
import std;

#include "message_wire.hpp"

namespace dns {
    using namespace message_wire;
    auto negative_ttl(Response const& response, std::string_view name) -> std::optional<std::uint32_t> {
        auto encoded=encode_name(name);
        if (!encoded) return {};
        std::size_t pos=0;
        NameBoundaries boundaries;
        auto canonical=name_at(*encoded,pos,boundaries);
        if (!canonical) return {};
        std::optional<std::uint32_t> ttl;
        std::size_t closest=0;
        for (auto const& record : response.records) {
            if (record.section!=Section::authority || record.type!=6 || record.klass!=1) continue;
            auto const& zone=record.name;
            if (zone!="." && *canonical!=zone &&
                !(canonical->size()>zone.size() && canonical->ends_with(zone) && (*canonical)[canonical->size()-zone.size()-1]=='.')) continue;
            if (record.data_offset>response.wire.size() || record.data_length<20 ||
                record.data_length>response.wire.size()-record.data_offset) continue;
            auto specificity=zone=="." ? 0 : zone.size();
            auto value=std::min(record.ttl,get32(response.wire,record.data_offset+record.data_length-4));
            if (!ttl || specificity>closest) { ttl=value; closest=specificity; }
            else if (specificity==closest) ttl=std::min(*ttl,value);
        }
        return ttl;
    }
    namespace {
    auto parse_address_chain(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected, bool accept_edns, bool negative,std::optional<ClientSubnet> subnet)
        -> std::expected<AddressAnswer, MessageError> {
        if (expected.klass != 1 || (expected.type != 1 && expected.type != 28))
            return std::unexpected(MessageError::unsupported);
        auto response = parse_response(data, id, expected);
        if (!response) return std::unexpected(response.error());
        if (response->rcode != (negative ? 3 : 0) || (response->edns && (!accept_edns || response->edns->version ||
            response->edns->flags || response->edns->option_count>(subnet ? 1u : 0u))))
            return std::unexpected(MessageError::unsupported);
        if(subnet) {
            QueryMessage query{id,0x0100,expected,{}};
            if(!set_query_client_subnet(query,subnet) || !validate_response_ecs(query,*response))return std::unexpected(MessageError::mismatch);
            if(response->edns && response->edns->option_count) {
                auto opt=std::ranges::find(response->records,std::uint16_t{41},&Record::type);
                if(opt==response->records.end() || opt->data_length<4 || get16(response->wire,opt->data_offset)!=8)
                    return std::unexpected(MessageError::unsupported);
            }
        }
        auto encoded = encode_name(expected.name);
        std::size_t offset = 0;
        NameBoundaries expected_boundaries;
        auto initial = name_at(*encoded, offset, expected_boundaries);
        AddressAnswer result{std::move(*initial), {}, {}, {}};
        std::vector<std::string> visited;
        auto add_ttl = [&](std::uint32_t ttl) {
            result.ttl = result.ttl ? std::min(*result.ttl, ttl) : ttl;
        };
        for (;;) {
            if (std::ranges::find(visited, result.canonical_name) != visited.end())
                return std::unexpected(MessageError::alias_loop);
            if (visited.size() == 16) return std::unexpected(MessageError::limit);
            visited.push_back(result.canonical_name);
            result.chain.push_back(result.canonical_name);
            std::optional<std::string> alias;
            bool address_record = false;
            for (auto const& record : response->records) {
                if (record.section != Section::answer || record.klass != 1 || record.name != result.canonical_name)
                    continue;
                if (record.type == 1 || record.type == 28) address_record = true;
                if (record.type == 5) {
                    if (!record.cname || (alias && *alias != *record.cname))
                        return std::unexpected(MessageError::malformed);
                    alias = *record.cname;
                    add_ttl(record.ttl);
                } else if (record.type == expected.type) {
                    auto size = expected.type == 1 ? 4u : 16u;
                    if (record.data_length != size) return std::unexpected(MessageError::malformed);
                    Address address{};
                    address.size = static_cast<std::uint8_t>(size);
                    std::copy_n(response->wire.begin() + record.data_offset, size, address.bytes.begin());
                    result.addresses.push_back(address);
                    add_ttl(record.ttl);
                }
            }
            if (!alias) {
                if (negative) {
                    if (!result.addresses.empty()) return std::unexpected(MessageError::malformed);
                    for (auto const& record : response->records) {
                        if (record.section!=Section::answer) continue;
                        if (record.klass!=1 || record.type!=5 ||
                            std::ranges::find(result.chain,record.name)==result.chain.end() || record.name==result.canonical_name)
                            return std::unexpected(MessageError::malformed);
                    }
                }
                return result;
            }
            if (address_record) return std::unexpected(MessageError::malformed);
            result.canonical_name = std::move(*alias);
        }
    }
    }
    auto parse_addresses(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected, bool accept_edns,std::optional<ClientSubnet> subnet)
        -> std::expected<AddressAnswer, MessageError> {
        return parse_address_chain(data,id,expected,accept_edns,false,subnet);
    }
    auto parse_nxdomain_alias(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected, bool accept_edns,std::optional<ClientSubnet> subnet)
        -> std::expected<AddressAnswer, MessageError> {
        return parse_address_chain(data,id,expected,accept_edns,true,subnet);
    }

}
