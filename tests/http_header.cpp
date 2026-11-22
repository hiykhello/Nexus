import std;
import http.header;
import http.connect;

namespace h = http;

auto main() -> int {
    std::string input = "GET / HTTP/1.1\r\nHost: example.test\r\nX-Mixed: \t value\t \r\n\r\nTAIL";
    auto header = h::inspect_header(input);
    if (header.status != h::HeaderStatus::complete || header.first != "GET / HTTP/1.1" ||
        header.consumed != input.size() - 4 || header.first.data() != input.data()) return 1;
    h::HeaderFieldCursor cursor(header.field_lines);
    auto host = cursor.next(), mixed = cursor.next(), end = cursor.next();
    if (host.status != h::HeaderFieldStatus::field || host.field.name != "Host" || host.field.value != "example.test" ||
        host.field.name.data() != input.data() + input.find("Host:") ||
        mixed.status != h::HeaderFieldStatus::field || mixed.field.name != "X-Mixed" || mixed.field.value != "value" ||
        end.status != h::HeaderFieldStatus::end || cursor.next().status != h::HeaderFieldStatus::end) return 2;
    auto raw = h::split_header_field("X: \t value\t ");
    if (!raw || raw->name != "X" || raw->value != " \t value\t " ||
        h::trim_header_ows(raw->value) != "value" || !h::valid_header_field_value(raw->value) ||
        h::split_header_field("bad name: value") || h::split_header_field(": value")) return 3;
    if (h::valid_header_field_value("bad\x01") || h::valid_header_field_value("bad\x7f") ||
        !h::valid_header_field_value("ok\t\xff")) return 4;
    for (std::size_t i = 0; i < input.size() - 4; ++i)
        if (h::inspect_header(std::string_view(input).substr(0, i)).status != h::HeaderStatus::incomplete) return 5;
    if (h::inspect_header(std::string(h::max_header_bytes, 'x')).status != h::HeaderStatus::too_large ||
        h::inspect_header(std::string(8193, 'x') + "\r\n\r\n").status != h::HeaderStatus::malformed ||
        h::inspect_header(std::string(8192, 'x') + "\r\n\r\n").status != h::HeaderStatus::complete ||
        h::inspect_header("\r\n\r\nTAIL").consumed != 4) return 6;
    std::string exact = "GET / HTTP/1.1\r\nA:" + std::string(8190, 'a') + "\r\nB:";
    exact += std::string(h::max_header_bytes - exact.size() - 4, 'b') + "\r\n\r\n";
    if (h::inspect_header(exact).status != h::HeaderStatus::complete ||
        h::inspect_header(exact).consumed != h::max_header_bytes) return 14;
    exact.insert(exact.size() - 4, "b");
    if (h::inspect_header(exact).status != h::HeaderStatus::too_large) return 15;
    std::string limited = "GET / HTTP/1.1\r\n";
    for (std::size_t i = 0; i < h::max_header_fields; ++i) limited += "X: y\r\n";
    limited += "\r\n";
    auto view = h::inspect_header(limited);
    h::HeaderFieldCursor hundred(view.field_lines);
    for (std::size_t i = 0; i < h::max_header_fields; ++i)
        if (hundred.next().status != h::HeaderFieldStatus::field) return 7;
    if (hundred.next().status != h::HeaderFieldStatus::end) return 8;
    limited.insert(limited.size() - 2, "X: y\r\n");
    view = h::inspect_header(limited);
    h::HeaderFieldCursor too_many(view.field_lines);
    for (std::size_t i = 0; i < h::max_header_fields; ++i)
        if (too_many.next().status != h::HeaderFieldStatus::field) return 9;
    if (too_many.next().status != h::HeaderFieldStatus::malformed ||
        too_many.next().status != h::HeaderFieldStatus::malformed) return 10;
    for (std::size_t length : {std::size_t(8192), std::size_t(8193)}) {
        std::string line = "X:" + std::string(length - 2, 'a') + "\r\n";
        h::HeaderFieldCursor fields(line);
        auto expected = length == 8192 ? h::HeaderFieldStatus::field : h::HeaderFieldStatus::malformed;
        if (fields.next().status != expected) return 11;
    }
    for (auto text : {"NoColon\r\n", "X : value\r\n", "X: bad\x01\r\n", "X: no terminator"}) {
        h::HeaderFieldCursor invalid(text);
        if (invalid.next().status != h::HeaderFieldStatus::malformed) return 12;
    }
    using enum h::ConnectStatus;
    if (h::parse_connect("GET / HTTP/1.1\r\nBad Field\r\n\r\n").status != unsupported ||
        h::parse_connect("CONNECT example.test:443 HTTP/1.1\r\nContent-Length: 0\r\nBad Field\r\n\r\n").status != unsupported ||
        h::parse_connect("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\nConnection: ,\r\n\r\n").status != accepted ||
        h::parse_forward_request("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nConnection: ,\r\n\r\n").status != malformed ||
        h::parse_forward_request("POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nUpgrade: x\r\nBad Field\r\n\r\n").status != malformed) return 13;
    std::cout << "HTTP header borrowed views, lexical limits and policy ordering passed\n";
}
