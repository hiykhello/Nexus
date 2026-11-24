export module encoding.base64_key;
import std;
import encoding.base64;

export namespace encoding {
    auto decode_key(std::span<char const> input, std::span<std::uint8_t> output) -> bool {
        if (!input.empty() && input.back() == '\n') input = input.first(input.size() - 1);
        return decode_base64_exact(input, output);
    }
}
