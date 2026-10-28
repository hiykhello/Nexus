import std;
import nexus.socks5;

namespace s = nexus::socks5;

static auto check(bool condition, char const* message) -> bool {
    if (!condition) std::cerr << message << '\n';
    return condition;
}

static auto greeting_tests() -> bool {
    std::vector<std::uint8_t> greeting{5, 3, 2, 0, 3, 0xaa};
    for (std::size_t n = 0; n < 5; ++n) {
        auto result = s::parse_greeting(std::span(greeting).first(n));
        if (!check(result.status == s::Status::incomplete && result.consumed == 0,
                   "partial greeting consumed data")) return false;
    }
    auto result = s::parse_greeting(greeting);
    if (!check(result.status == s::Status::accepted && result.consumed == 5,
               "greeting or trailing payload incorrect")) return false;
    if (!check(s::parse_greeting(greeting, 2).status == s::Status::accepted,
               "password method not selected")) return false;
    if (!check(s::parse_greeting(greeting, 4).status == s::Status::no_acceptable_method,
               "unoffered method selected")) return false;
    greeting[3] = 1;
    result = s::parse_greeting(greeting);
    if (!check(result.status == s::Status::no_acceptable_method && result.consumed == 5,
               "unsupported method accepted")) return false;
    greeting = {5, 0};
    if (!check(s::parse_greeting(greeting).status == s::Status::no_acceptable_method,
               "empty method list accepted")) return false;
    greeting = {4};
    return check(s::parse_greeting(greeting).status == s::Status::invalid_version,
                 "invalid greeting version accepted");
}

static auto request_frame(std::uint8_t type, std::vector<std::uint8_t> address) -> bool {
    std::vector<std::uint8_t> request{5, 1, 0, type};
    if (type == 3) request.push_back(static_cast<std::uint8_t>(address.size()));
    request.insert(request.end(), address.begin(), address.end());
    request.push_back(0x12);
    request.push_back(0x34);
    auto const frame_size = request.size();
    request.push_back(0xee);
    for (std::size_t n = 0; n < frame_size; ++n) {
        auto result = s::parse_request(std::span(request).first(n));
        if (!check(result.status == s::Status::incomplete && result.consumed == 0,
                   "partial request consumed data")) return false;
    }
    auto result = s::parse_request(request);
    return check(result.status == s::Status::accepted && result.consumed == frame_size &&
                 result.address_type == type && result.port == 0x1234 &&
                 result.address_length == address.size() &&
                 std::equal(address.begin(), address.end(), result.address.begin()),
                 "request address, port, or payload boundary incorrect");
}

static auto invalid_tests() -> bool {
    using enum s::Status;
    struct Case { std::vector<std::uint8_t> bytes; s::Status expected; };
    std::vector<Case> cases{
        {{4}, invalid_version}, {{5, 1, 1, 1}, invalid_reserved},
        {{5, 2, 0, 1}, unsupported_command}, {{5, 3, 0, 1}, unsupported_command},
        {{5, 1, 0, 5}, unsupported_address}, {{5, 1, 0, 3, 0}, invalid_address},
    };
    for (auto const& item : cases) {
        if (!check(s::parse_request(item.bytes).status == item.expected,
                   "invalid request incorrectly classified")) return false;
    }
    return true;
}

int main() {
    std::vector<std::uint8_t> ipv6(16);
    for (std::size_t n = 0; n < ipv6.size(); ++n) ipv6[n] = static_cast<std::uint8_t>(n);
    std::vector<std::uint8_t> longest_domain(255, 'x');
    if (!greeting_tests() || !request_frame(1, {127, 0, 0, 1}) ||
        !request_frame(4, ipv6) || !request_frame(3, {'e', 'x', 'a', 'm', 'p', 'l', 'e'}) ||
        !request_frame(3, longest_domain) || !invalid_tests()) return 1;
    std::cout << "SOCKS5 greeting and CONNECT request parsing passed\n";
}
