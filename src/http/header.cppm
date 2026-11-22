export module http.header;
import std;

export namespace http {
    inline constexpr std::size_t max_header_bytes = 16384;
    inline constexpr std::size_t max_header_line_bytes = 8192;
    inline constexpr std::size_t max_header_fields = 100;

    [[nodiscard]] auto header_token(char c) noexcept -> bool;
    [[nodiscard]] auto trim_header_ows(std::string_view value) noexcept -> std::string_view;
    [[nodiscard]] auto valid_header_field_value(std::string_view value) noexcept -> bool;

    // Views borrow the supplied line. The value from split_header_field is raw;
    // callers can apply their own policy before checking or trimming it.
    struct HeaderField { std::string_view name, value; };

    [[nodiscard]] constexpr auto redirect_status(unsigned code) noexcept -> bool {
        return code==301 || code==302 || code==303 || code==307 || code==308;
    }
    [[nodiscard]] auto split_header_field(std::string_view line) noexcept -> std::optional<HeaderField>;

    enum class HeaderStatus { incomplete, complete, malformed, too_large };
    // The first line and field lines borrow input. Field syntax and protocol
    // policy are deliberately deferred to the caller, preserving check order.
    struct HeaderView {
        HeaderStatus status = HeaderStatus::incomplete;
        std::string_view first, field_lines;
        std::size_t consumed = 0;
    };
    [[nodiscard]] auto inspect_header(std::string_view input) noexcept -> HeaderView;

    enum class HeaderFieldStatus { field, end, malformed };
    struct HeaderFieldStep { HeaderFieldStatus status; HeaderField field; };
    // The caller keeps the input alive and unchanged. next() validates one
    // field at a time and leaves name/value as borrowed, case-preserving views.
    class HeaderFieldCursor {
        std::string_view remaining_;
        std::size_t count_ = 0;
    public:
        explicit HeaderFieldCursor(std::string_view field_lines) noexcept : remaining_(field_lines) {}
        [[nodiscard]] auto next() noexcept -> HeaderFieldStep;
    };
}

module :private;

namespace http {
    auto header_token(char c) noexcept -> bool {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
    }
    auto trim_header_ows(std::string_view value) noexcept -> std::string_view {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
        return value;
    }
    auto valid_header_field_value(std::string_view value) noexcept -> bool {
        for (unsigned char c : value) if ((c < 32 && c != '\t') || c == 127) return false;
        return true;
    }
    auto split_header_field(std::string_view line) noexcept -> std::optional<HeaderField> {
        auto colon = line.find(':');
        if (colon == line.npos || colon == 0 || !std::all_of(line.begin(), line.begin() + colon, header_token))
            return {};
        return HeaderField{line.substr(0, colon), line.substr(colon + 1)};
    }
    auto inspect_header(std::string_view input) noexcept -> HeaderView {
        auto end = input.find("\r\n\r\n");
        if (end == input.npos)
            return {input.size() >= max_header_bytes ? HeaderStatus::too_large : HeaderStatus::incomplete};
        auto consumed = end + 4;
        if (consumed > max_header_bytes) return {HeaderStatus::too_large};
        auto first_end = input.find("\r\n");
        if (first_end > max_header_line_bytes) return {HeaderStatus::malformed};
        auto fields_start = first_end + 2;
        return {HeaderStatus::complete, input.substr(0, first_end),
                input.substr(fields_start, end + 2 - fields_start), consumed};
    }
    auto HeaderFieldCursor::next() noexcept -> HeaderFieldStep {
        if (remaining_.empty()) return {HeaderFieldStatus::end, {}};
        auto end = remaining_.find("\r\n");
        if (end == remaining_.npos || end > max_header_line_bytes || count_ >= max_header_fields)
            return {HeaderFieldStatus::malformed, {}};
        auto field = split_header_field(remaining_.substr(0, end));
        if (!field) return {HeaderFieldStatus::malformed, {}};
        field->value = trim_header_ows(field->value);
        if (!valid_header_field_value(field->value)) return {HeaderFieldStatus::malformed, {}};
        remaining_.remove_prefix(end + 2);
        ++count_;
        return {HeaderFieldStatus::field, *field};
    }
}
