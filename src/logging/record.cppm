export module logging.record;
import std;
import logging.core;

export namespace logging {
    // Every message byte can expand to six bytes. The fixed metadata includes
    // both clocks, numeric context and the optional display timestamp.
    inline constexpr std::size_t line_capacity = message_capacity * 6 + 512;
    auto encode_line(LogSlot const& slot, Output output, std::array<char, line_capacity>& buffer) -> std::string_view;
}
