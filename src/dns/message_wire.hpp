#pragma once
namespace dns {
    auto copy_response_wire(Response const&,std::uint16_t,std::optional<std::uint32_t>)
        -> std::expected<Bytes,MessageError>;
}
namespace dns::message_wire {
        inline auto lower(std::uint8_t c) -> std::uint8_t { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
        inline auto valid_char(std::uint8_t c) -> bool { return c >= 33 && c <= 126 && c != '.' && c != '\\'; }
        template<class Visitor>
        inline auto visit_labels(std::string_view name, Visitor&& visit) -> bool {
            if (name == ".") return true;
            if (name.ends_with('.')) name.remove_suffix(1);
            if (name.empty()) return false;
            std::size_t wire_size=1;
            while (!name.empty()) {
                auto dot = name.find('.');
                auto label = name.substr(0, dot);
                if (label.empty() || label.size() > 63 ||
                    !std::ranges::all_of(label, [](unsigned char c) { return valid_char(c); }))
                    return false;
                wire_size+=label.size()+1;
                if (wire_size>255) return false;
                visit(label);
                if (dot == name.npos) return true;
                name.remove_prefix(dot + 1);
                if (name.empty()) return false;
            }
            return true;
        }
        inline auto encode_name(std::string_view name) -> std::expected<Bytes, MessageError> {
            Bytes output;
            if (!visit_labels(name,[&](std::string_view label) {
                output.push_back(static_cast<std::uint8_t>(label.size()));
                for (unsigned char c : label) output.push_back(lower(c));
            })) return std::unexpected(MessageError::invalid_name);
            output.push_back(0);
            return output;
        }
        inline auto put16(Bytes& out, std::uint16_t value) -> void { out.push_back(value >> 8); out.push_back(value & 255); }
        inline auto get16(std::span<std::uint8_t const> in, std::size_t at) -> std::uint16_t { return (std::uint16_t(in[at]) << 8) | in[at+1]; }
        inline auto get32(std::span<std::uint8_t const> in, std::size_t at) -> std::uint32_t {
            return (std::uint32_t(get16(in, at)) << 16) | get16(in, at+2);
        }
        // Compression targets are 14-bit offsets. Boundaries beyond that
        // range cannot be referenced, even in a 65535-byte TCP message.
        struct NameBoundaries {
            std::bitset<16384> bits;
            inline auto contains(std::size_t offset) const noexcept -> bool {return offset<bits.size() && bits.test(offset);}
            inline auto add(std::size_t offset) noexcept -> void {if(offset<bits.size())bits.set(offset);}
        };
        inline auto name_at(std::span<std::uint8_t const> data, std::size_t& position,
                     NameBoundaries& boundaries) -> std::expected<std::string, MessageError> {
            auto cursor = position; std::size_t wire_size = 1, jumps = 0; bool jumped = false;
            std::string result;
            // A legal 255-byte name has at most 127 one-byte labels plus
            // the terminating root or pointer. Publish only after validation.
            std::array<std::size_t,128> local_boundaries{};std::size_t count=0;
            for (;;) {
                if (cursor >= data.size()) return std::unexpected(MessageError::malformed);
                if (!jumped) {
                    if(count==local_boundaries.size())return std::unexpected(MessageError::malformed);
                    local_boundaries[count++]=cursor;
                }
                auto n = data[cursor++];
                if ((n & 0xc0) == 0xc0) {
                    if (cursor >= data.size() || ++jumps > 128) return std::unexpected(MessageError::malformed);
                    auto target = (std::size_t(n & 0x3f) << 8) | data[cursor++];
                    if (target >= cursor - 2 || !boundaries.contains(target)) return std::unexpected(MessageError::malformed);
                    if (!jumped) { position = cursor; jumped = true; }
                    cursor = target; continue;
                }
                if ((n & 0xc0) != 0) return std::unexpected(MessageError::malformed);
                if (!n) {
                    if (!jumped) position = cursor;
                    for (std::size_t i=0;i<count;++i) boundaries.add(local_boundaries[i]);
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
