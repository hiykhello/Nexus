module http.connect;
import std;
import http.header;

namespace http {
    namespace {
        auto whitespace(std::string_view s, std::size_t& i) -> void {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        }
        auto chunk_size(std::string_view s, std::uint64_t& size) -> bool {
            auto digit_end = s.find_first_not_of("0123456789abcdefABCDEF");
            if (digit_end == 0) return false;
            if (digit_end == s.npos) digit_end = s.size();
            auto [end, ec] = std::from_chars(s.data(), s.data() + digit_end, size, 16);
            if (ec != std::errc{} || end != s.data() + digit_end) return false;
            auto i = digit_end;
            while (i < s.size()) {
                whitespace(s, i);
                if (i == s.size() || s[i++] != ';') return false;
                whitespace(s, i);
                auto begin = i;
                while (i < s.size() && header_token(s[i])) ++i;
                if (begin == i) return false;
                auto after_name = i;
                whitespace(s, i);
                if (i < s.size() && s[i] == '=') {
                    ++i; whitespace(s, i);
                    if (i < s.size() && s[i] == '"') {
                        ++i;
                        bool closed = false;
                        while (i < s.size()) {
                            auto c = static_cast<unsigned char>(s[i++]);
                            if (c == '"') { closed = true; break; }
                            if (c == '\\') {
                                if (i == s.size()) return false;
                                c = static_cast<unsigned char>(s[i++]);
                                if ((c < 32 && c != '\t') || c == 127) return false;
                            } else if ((c < 32 && c != '\t') || c == 127) return false;
                        }
                        if (!closed) return false;
                    } else {
                        begin = i;
                        while (i < s.size() && header_token(s[i])) ++i;
                        if (begin == i) return false;
                    }
                } else i = after_name;
            }
            return true;
        }
        auto trailer_field(std::string_view s) -> bool {
            auto field = split_header_field(s);
            if (!field) return false;
            std::string name(field->name);
            std::ranges::transform(name, name.begin(), [](char c) {
                return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
            });
            if (name == "transfer-encoding" || name == "content-length" || name == "host" ||
                name == "connection" || name == "keep-alive" || name == "proxy-authenticate" ||
                name == "proxy-authorization" || name == "trailer" || name == "upgrade") return false;
            return valid_header_field_value(field->value);
        }
    }

    auto ChunkDecoder::consume_some(std::string_view input, std::string& output) -> ChunkResult {
        auto initial_size=input.size();
        while (!input.empty() && state != State::complete && state != State::failed) {
            if (state == State::data) {
                auto n = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, input.size()));
                output.append(input.substr(0, n));
                input.remove_prefix(n);
                remaining -= n;
                if (remaining == 0) state = State::data_cr;
            } else if (state == State::data_cr || state == State::data_lf) {
                auto expected = state == State::data_cr ? '\r' : '\n';
                if (input.front() != expected) { state = State::failed; break; }
                input.remove_prefix(1);
                if (state == State::data_cr) state = State::data_lf;
                else { if (output_mode_==ChunkOutput::framed) output += "\r\n"; state = State::size; }
            } else {
                char c = input.front(); input.remove_prefix(1);
                if (state == State::trailer && ++trailer_bytes > max_connect_header_bytes) { state = State::failed; break; }
                if (c == '\n') {
                    if (line.empty() || line.back() != '\r') { state = State::failed; break; }
                    line.pop_back();
                    if (state == State::size) {
                        if (!chunk_size(line, remaining)) { state = State::failed; break; }
                        if (remaining == 0) state = State::trailer;
                        else {
                            if (output_mode_==ChunkOutput::framed) output += std::format("{:x}\r\n", remaining);
                            state = State::data;
                        }
                    } else if (line.empty()) {
                        if (output_mode_==ChunkOutput::framed) output += "0\r\n\r\n";
                        state = State::complete;
                    } else if (++trailer_fields > max_connect_fields || !trailer_field(line)) {
                        state = State::failed; break;
                    }
                    line.clear();
                } else {
                    if ((!line.empty() && line.back() == '\r') || (line.size() >= 8192 && c != '\r') || line.size() > 8192) { state = State::failed; break; }
                    line += c;
                }
            }
        }
        return {state == State::complete ? ChunkStatus::complete :
                state == State::failed ? ChunkStatus::malformed : ChunkStatus::incomplete,
                initial_size-input.size()};
    }
    auto ChunkDecoder::consume(std::string_view input, std::string& output) -> ChunkStatus {
        return consume_some(input,output).status;
    }
}
