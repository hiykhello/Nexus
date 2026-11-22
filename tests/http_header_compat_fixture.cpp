// Differential fixture: one hex-encoded input per line, see http_header_compat.py.
import std;
import http.connect;

namespace h = http;
namespace {
    bool tracking = false;
    std::size_t allocations = 0, bytes = 0;
}
void* operator new(std::size_t n) {
    if (tracking) { ++allocations; bytes += n; }
    if (auto p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace {
    auto hex(std::string_view s) -> std::string {
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(s.size() * 2);
        for (auto c : s) {
            auto v = static_cast<unsigned char>(c);
            out += digits[v >> 4]; out += digits[v & 15];
        }
        return out;
    }
    auto unhex(std::string_view s) -> std::string {
        auto digit = [](char c) -> unsigned { return c <= '9' ? c - '0' : c - 'a' + 10; };
        std::string out;
        out.reserve(s.size() / 2);
        for (std::size_t i = 0; i + 1 < s.size(); i += 2)
            out += static_cast<char>((digit(s[i]) << 4) | digit(s[i + 1]));
        return out;
    }
    struct Hash {
        std::uint64_t value = 1469598103934665603ull;
        auto add(std::uint64_t n) -> void {
            for (unsigned i = 0; i < 8; ++i) { value ^= n & 255; value *= 1099511628211ull; n >>= 8; }
        }
        auto add(std::string_view s) -> void {
            add(s.size());
            for (auto c : s) { value ^= static_cast<unsigned char>(c); value *= 1099511628211ull; }
        }
    };
    auto connect_summary(h::ConnectRequest const& r) -> std::string {
        auto address = std::string_view(reinterpret_cast<char const*>(r.address.data()), r.address.size());
        return std::format("{}:{}:{}:{}:{}:{}", static_cast<int>(r.status), r.consumed,
                           static_cast<int>(r.kind), hex(r.host), hex(address), r.port);
    }
    auto stride(char mode, std::size_t offset) -> std::size_t {
        if (mode == '1') return 1;
        if (mode == '2') return (offset * 7 + 3) % 31 + 1;
        return (offset * 11 + 4093) % 8192 + 1;
    }
    auto connect_stream(std::string const& input, char mode) -> std::uint64_t {
        Hash hash; h::ConnectDecoder decoder;
        for (std::size_t n = 0; n < input.size();) {
            n = std::min(input.size(), n + stride(mode, n));
            auto step = decoder.feed(std::string_view(input).substr(0, n));
            hash.add(static_cast<unsigned>(step.event)); hash.add(step.consumed);
            if (step.event != h::ConnectEvent::need_more) break;
        }
        auto end = decoder.finish();
        hash.add(static_cast<unsigned>(end.event)); hash.add(end.consumed);
        hash.add(connect_summary(decoder.request()));
        return hash.value;
    }
    auto request_stream(std::string const& input, char mode) -> std::uint64_t {
        Hash hash; h::RequestDecoder decoder; std::string scratch;
        for (std::size_t n = 0; n < input.size();) {
            n = std::min(input.size(), n + stride(mode, n));
            auto step = decoder.feed(std::string_view(input).substr(0, n), scratch);
            hash.add(static_cast<unsigned>(step.event)); hash.add(step.consumed); hash.add(step.wire);
            if (step.event != h::RequestEvent::need_more) break;
        }
        auto end = decoder.finish();
        hash.add(static_cast<unsigned>(end.event)); hash.add(end.consumed); hash.add(end.wire);
        return hash.value;
    }
    auto response_stream(std::string const& input, char mode, bool head) -> std::uint64_t {
        Hash hash; h::ResponseDecoder decoder(head, true);
        for (std::size_t n = 0; n < input.size();) {
            auto step = decoder.feed(std::string_view(input).substr(n, stride(mode, n)));
            hash.add(static_cast<unsigned>(step.event)); hash.add(step.consumed);
            hash.add(step.wire); hash.add(step.informational);
            n += step.consumed;
            if (!step.consumed || step.event == h::ResponseEvent::complete || step.event == h::ResponseEvent::malformed) break;
        }
        auto end = decoder.finish();
        hash.add(static_cast<unsigned>(end.event)); hash.add(end.consumed); hash.add(end.wire);
        return hash.value;
    }
    auto chunk_stream(std::string const& input, char mode) -> std::uint64_t {
        Hash hash; h::ChunkDecoder decoder; std::string output;
        for (std::size_t n = 0; n < input.size();) {
            auto step = decoder.consume_some(std::string_view(input).substr(n, stride(mode, n)), output);
            hash.add(static_cast<unsigned>(step.status)); hash.add(step.consumed);
            n += step.consumed;
            if (!step.consumed || step.status != h::ChunkStatus::incomplete) break;
        }
        hash.add(output);
        return hash.value;
    }
}

auto main() -> int {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.size() < 2 || (line.size() - 2) % 2) return 2;
        auto input = unhex(std::string_view(line).substr(2));
        auto kind = line[0], mode = line[1];
        allocations = bytes = 0; tracking = true;
        if (kind == 'C') {
            auto result = h::parse_connect(input); tracking = false;
            auto count = allocations, size = bytes;
            std::cout << connect_summary(result) << ':' << count << ':' << size << ':' << connect_stream(input, mode) << '\n';
        } else if (kind == 'F') {
            auto result = h::parse_forward_request(input); tracking = false;
            auto count = allocations, size = bytes;
            std::cout << static_cast<int>(result.status) << ':' << connect_summary(result.destination) << ':'
                      << result.consumed << ':' << result.body_length << ':' << result.chunked << ':' << result.head << ':'
                      << hex(result.wire) << ':' << count << ':' << size << ':' << request_stream(input, mode) << '\n';
        } else if (kind == 'R' || kind == 'H') {
            auto result = h::parse_forward_response(input, kind == 'H'); tracking = false;
            auto count = allocations, size = bytes;
            std::cout << static_cast<int>(result.status) << ':' << result.consumed << ':'
                      << result.body_length.has_value() << ':' << result.body_length.value_or(0) << ':'
                      << result.chunked << ':' << result.informational << ':' << hex(result.wire) << ':'
                      << count << ':' << size << ':' << response_stream(input, mode, kind == 'H') << '\n';
        } else if (kind == 'T') {
            h::ChunkDecoder decoder; std::string output;
            auto result = decoder.consume_some(input, output); tracking = false;
            auto count = allocations, size = bytes;
            std::cout << static_cast<int>(result.status) << ':' << result.consumed << ':' << hex(output) << ':'
                      << count << ':' << size << ':' << chunk_stream(input, mode) << '\n';
        } else return 3;
    }
}
