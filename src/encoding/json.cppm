export module encoding.json;
import std;

export namespace encoding {
    // Escapes JSON string contents without surrounding quotes.
    [[nodiscard]] inline auto json_escape_raw(std::string_view in) -> std::string {
        std::string out;
        out.reserve(in.size() + 4);
        for (unsigned char c : in) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '\t') out += "\\t";
            else if (c >= 0x20) out.push_back(static_cast<char>(c));
        }
        return out;
    }

    // Escapes and wraps a string value in JSON double quotes.
    [[nodiscard]] inline auto json_quote(std::string_view in) -> std::string {
        std::string out;
        out.reserve(in.size() + 6);
        out.push_back('"');
        for (unsigned char c : in) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '\t') out += "\\t";
            else if (c >= 0x20) out.push_back(static_cast<char>(c));
        }
        out.push_back('"');
        return out;
    }
}
