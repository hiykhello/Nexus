module logging.record;
import std;
import logging.core;

namespace logging {
    namespace {
        auto utf8_sequence(std::string_view text) noexcept -> std::pair<std::size_t, unsigned> {
            unsigned first = static_cast<unsigned char>(text.front());
            if (first < 0x80) return {1, first};
            std::size_t length;
            unsigned code;
            if (first >= 0xc2 && first <= 0xdf) {
                length = 2;
                code = first & 0x1f;
            } else if (first >= 0xe0 && first <= 0xef) {
                length = 3;
                code = first & 0x0f;
            } else if (first >= 0xf0 && first <= 0xf4) {
                length = 4;
                code = first & 0x07;
            } else return {0, first};

            if (text.size() < length) return {0, first};
            for (auto ch : text.substr(1, length - 1)) {
                unsigned byte = static_cast<unsigned char>(ch);
                if ((byte & 0xc0) != 0x80) return {0, first};
                code = (code << 6) | (byte & 0x3f);
            }
            if ((length == 3 && code < 0x800) || (length == 4 && code < 0x10000) ||
                (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff)
                return {0, first};
            return {length, code};
        }

        auto escape(char* out, std::string_view text, bool json) noexcept -> char* {
            constexpr std::string_view hex = "0123456789abcdef";
            while (!text.empty()) {
                auto [length, code] = utf8_sequence(text);
                if (length == 0 || code <= 0x1f || (code >= 0x7f && code <= 0x9f) ||
                    code == 0x2028 || code == 0x2029) {
                    *out++ = '\\';
                    if (code == '\n') *out++ = 'n';
                    else if (code == '\r') *out++ = 'r';
                    else if (code == '\t') *out++ = 't';
                    else {
                        if (json || code > 0xff) {
                            *out++ = 'u';
                            *out++ = hex[(code >> 12) & 0xf];
                            *out++ = hex[(code >> 8) & 0xf];
                        } else {
                            *out++ = 'x';
                        }
                        *out++ = hex[(code >> 4) & 0xf];
                        *out++ = hex[code & 0xf];
                    }
                } else {
                    if (code == '\\' || code == '"') *out++ = '\\';
                    out = std::ranges::copy(text.substr(0, length), out).out;
                }
                text.remove_prefix(std::max(length, std::size_t{1}));
            }
            return out;
        }

        auto utc(char* out, std::int64_t wall) -> char* {
            using namespace std::chrono;
            sys_time<nanoseconds> instant{nanoseconds(wall)};
            auto day = floor<days>(instant);
            year_month_day date(day);
            hh_mm_ss time(instant - day);
            return std::format_to(out, "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
                int(date.year()), unsigned(date.month()), unsigned(date.day()),
                time.hours().count(), time.minutes().count(), time.seconds().count(),
                time.subseconds().count());
        }

        auto event_name(LogSlot const& slot) noexcept -> std::string_view {
            return slot.event_code == std::numeric_limits<std::uint32_t>::max() ? "log.dropped" : "";
        }
    }

    auto encode_line(LogSlot const& slot, Output output, std::array<char, line_capacity>& buffer) -> std::string_view {
        auto cursor = buffer.data();
        auto event = event_name(slot);
        if (output.format == Format::jsonl) {
            cursor = std::format_to(cursor,
                R"({{"monotonic_ns":{},"wall_epoch_ns":{},"level":"{}","domain":"{}","event_code":{},"worker_id":{},"session_id":{},"generation":{},"truncated":{})",
                slot.monotonic_ns, slot.wall_epoch_ns, name(slot.level), name(slot.domain), slot.event_code,
                slot.context.worker_id, slot.context.session_id, slot.context.generation, slot.truncated);
            if (output.timestamp == Timestamp::rfc3339) {
                cursor = std::format_to(cursor, ",\"timestamp\":\"");
                cursor = utc(cursor, slot.wall_epoch_ns);
                *cursor++ = '"';
            } else if (output.timestamp == Timestamp::monotonic) {
                cursor = std::format_to(cursor, ",\"timestamp\":{}", slot.monotonic_ns);
            }
            if (!event.empty()) cursor = std::format_to(cursor, ",\"event\":\"{}\"", event);
            cursor = std::format_to(cursor, ",\"message\":\"");
        } else {
            if (output.timestamp == Timestamp::rfc3339) {
                cursor = utc(cursor, slot.wall_epoch_ns);
                *cursor++ = ' ';
            } else if (output.timestamp == Timestamp::monotonic) {
                cursor = std::format_to(cursor, "{}ns ", slot.monotonic_ns);
            }
            cursor = std::format_to(cursor, "{} {} event={} worker={} session={} generation={}{} ",
                name(slot.level), name(slot.domain), slot.event_code, slot.context.worker_id,
                slot.context.session_id, slot.context.generation, slot.truncated ? " truncated=true" : "");
            if (!event.empty()) cursor = std::format_to(cursor, "{} ", event);
        }
        cursor = escape(cursor, {slot.message.data(), slot.message_size}, output.format == Format::jsonl);
        if (output.format == Format::jsonl) {
            *cursor++ = '"';
            *cursor++ = '}';
        }
        *cursor++ = '\n';
        return {buffer.data(), cursor};
    }
}
