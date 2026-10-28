module nexus.dns.message;
import std;

namespace nexus::dns {
    namespace {
        auto lower(std::uint8_t c) -> std::uint8_t { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
        auto valid_char(std::uint8_t c) -> bool { return c >= 33 && c <= 126 && c != '.' && c != '\\'; }
        auto encode_name(std::string_view name) -> std::expected<Bytes, MessageError> {
            if (name == ".") return Bytes{0};
            if (name.ends_with('.')) name.remove_suffix(1);
            if (name.empty()) return std::unexpected(MessageError::invalid_name);
            Bytes output;
            while (!name.empty()) {
                auto dot = name.find('.');
                auto label = name.substr(0, dot);
                if (label.empty() || label.size() > 63 ||
                    !std::ranges::all_of(label, [](unsigned char c) { return valid_char(c); }))
                    return std::unexpected(MessageError::invalid_name);
                output.push_back(static_cast<std::uint8_t>(label.size()));
                for (unsigned char c : label) output.push_back(lower(c));
                if (dot == name.npos) break;
                name.remove_prefix(dot + 1);
                if (name.empty()) return std::unexpected(MessageError::invalid_name);
            }
            output.push_back(0);
            if (output.size() > 255) return std::unexpected(MessageError::invalid_name);
            return output;
        }
        auto put16(Bytes& out, std::uint16_t value) -> void { out.push_back(value >> 8); out.push_back(value & 255); }
        auto get16(std::span<std::uint8_t const> in, std::size_t at) -> std::uint16_t { return (std::uint16_t(in[at]) << 8) | in[at+1]; }
        auto get32(std::span<std::uint8_t const> in, std::size_t at) -> std::uint32_t {
            return (std::uint32_t(get16(in, at)) << 16) | get16(in, at+2);
        }
        auto name_at(std::span<std::uint8_t const> data, std::size_t& position,
                     std::vector<std::uint8_t>& boundaries) -> std::expected<std::string, MessageError> {
            auto cursor = position; std::size_t wire_size = 1, jumps = 0; bool jumped = false;
            std::string result;
            std::vector<std::size_t> local_boundaries;
            for (;;) {
                if (cursor >= data.size()) return std::unexpected(MessageError::malformed);
                if (!jumped) local_boundaries.push_back(cursor);
                auto n = data[cursor++];
                if ((n & 0xc0) == 0xc0) {
                    if (cursor >= data.size() || ++jumps > 128) return std::unexpected(MessageError::malformed);
                    auto target = (std::size_t(n & 0x3f) << 8) | data[cursor++];
                    if (target >= cursor - 2 || !boundaries[target]) return std::unexpected(MessageError::malformed);
                    if (!jumped) { position = cursor; jumped = true; }
                    cursor = target; continue;
                }
                if ((n & 0xc0) != 0) return std::unexpected(MessageError::malformed);
                if (!n) {
                    if (!jumped) position = cursor;
                    for (auto at : local_boundaries) boundaries[at] = 1;
                    return result.empty() ? "." : result;
                }
                if (cursor + n > data.size() || (wire_size += n + 1) > 255) return std::unexpected(MessageError::malformed);
                if (!result.empty()) result += '.';
                for (std::size_t i = 0; i < n; ++i) {
                    auto c = data[cursor++];
                    if (!valid_char(c)) return std::unexpected(MessageError::invalid_name);
                    result += static_cast<char>(lower(c));
                }
            }
        }
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
    auto parse_response(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected)
        -> std::expected<Response, MessageError> {
        if (data.size() > 4096) return std::unexpected(MessageError::limit);
        if (data.size() < 12) return std::unexpected(MessageError::malformed);
        auto flags = get16(data, 2);
        if (get16(data, 0) != id || !(flags & 0x8000) || (flags & 0x7800) || get16(data, 4) != 1)
            return std::unexpected(MessageError::mismatch);
        auto expected_name = encode_name(expected.name);
        if (!expected_name) return std::unexpected(expected_name.error());
        std::size_t expected_pos = 0;
        std::vector<std::uint8_t> expected_boundaries(expected_name->size());
        auto canonical = name_at(*expected_name, expected_pos, expected_boundaries);
        std::size_t pos = 12;
        std::vector<std::uint8_t> boundaries(data.size());
        auto name = name_at(data, pos, boundaries);
        if (!name) return std::unexpected(name.error());
        if (pos + 4 > data.size()) return std::unexpected(MessageError::malformed);
        if (*name != *canonical || get16(data, pos) != expected.type || get16(data, pos+2) != expected.klass)
            return std::unexpected(MessageError::mismatch);
        pos += 4;
        if (flags & 0x0200) return std::unexpected(MessageError::truncated);
        std::array counts{get16(data, 6),get16(data, 8),get16(data, 10)};
        if (std::size_t(counts[0]) + counts[1] + counts[2] > 128) return std::unexpected(MessageError::limit);
        Response result{flags, static_cast<std::uint16_t>(flags & 15), Bytes(data.begin(), data.end()), {}, {}};
        for (std::size_t section = 0; section < counts.size(); ++section) {
            for (std::size_t i = 0; i < counts[section]; ++i) {
                auto owner_start=pos;
                auto owner = name_at(data, pos, boundaries);
                if (!owner) return std::unexpected(owner.error());
                if (pos + 10 > data.size()) return std::unexpected(MessageError::malformed);
                auto type = get16(data, pos), klass = get16(data, pos+2);
                auto ttl = get32(data, pos+4); auto length = get16(data, pos+8); pos += 10;
                if (length > data.size() - pos) return std::unexpected(MessageError::malformed);
                if (type==41) {
                    if (section!=2 || result.edns || *owner!="." || data[owner_start]!=0)
                        return std::unexpected(MessageError::malformed);
                    std::size_t option=pos, end=pos+length, count=0;
                    while (option<end) {
                        if (end-option<4) return std::unexpected(MessageError::malformed);
                        auto size=get16(data,option+2);
                        option+=4;
                        if (size>end-option) return std::unexpected(MessageError::malformed);
                        option+=size;
                        ++count;
                    }
                    result.rcode |= static_cast<std::uint16_t>((ttl >> 24) << 4);
                    result.edns=Edns{klass,static_cast<std::uint8_t>(ttl >> 16),static_cast<std::uint16_t>(ttl),count};
                }
                std::optional<std::string> cname;
                if (type == 5 || type == 2 || type == 12 || type == 15 || type == 6) {
                    auto name_end = pos;
                    if (type == 15) {
                        if (length < 2) return std::unexpected(MessageError::malformed);
                        name_end += 2;
                    }
                    auto decoded = name_at(data, name_end, boundaries);
                    if (!decoded || name_end > pos + length) return std::unexpected(MessageError::malformed);
                    if (type == 6) {
                        auto mailbox = name_at(data, name_end, boundaries);
                        if (!mailbox || name_end > pos + length || pos + length - name_end != 20)
                            return std::unexpected(MessageError::malformed);
                    } else if (name_end != pos + length) return std::unexpected(MessageError::malformed);
                    if (type == 5) cname = std::move(*decoded);
                }
                result.records.push_back({std::move(*owner),type,klass,ttl,static_cast<Section>(section),pos,length,std::move(cname)});
                pos += length;
            }
        }
        if (pos != data.size()) return std::unexpected(MessageError::malformed);
        return result;
    }
    auto negative_ttl(Response const& response, std::string_view name) -> std::optional<std::uint32_t> {
        auto encoded=encode_name(name);
        if (!encoded) return {};
        std::size_t pos=0;
        std::vector<std::uint8_t> boundaries(encoded->size());
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
    auto parse_address_chain(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected, bool accept_edns, bool negative)
        -> std::expected<AddressAnswer, MessageError> {
        if (expected.klass != 1 || (expected.type != 1 && expected.type != 28))
            return std::unexpected(MessageError::unsupported);
        auto response = parse_response(data, id, expected);
        if (!response) return std::unexpected(response.error());
        if (response->rcode != (negative ? 3 : 0) || (response->edns && (!accept_edns || response->edns->version ||
            response->edns->flags || response->edns->option_count)))
            return std::unexpected(MessageError::unsupported);
        auto encoded = encode_name(expected.name);
        std::size_t offset = 0;
        std::vector<std::uint8_t> expected_boundaries(encoded->size());
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
    auto parse_addresses(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected, bool accept_edns)
        -> std::expected<AddressAnswer, MessageError> {
        return parse_address_chain(data,id,expected,accept_edns,false);
    }
    auto parse_nxdomain_alias(std::span<std::uint8_t const> data, std::uint16_t id, Question const& expected, bool accept_edns)
        -> std::expected<AddressAnswer, MessageError> {
        return parse_address_chain(data,id,expected,accept_edns,true);
    }

}
